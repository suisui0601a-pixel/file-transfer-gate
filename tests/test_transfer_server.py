import concurrent.futures
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import transfer_server as app


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name) / "state"
        self.password = secrets.token_urlsafe(20)
        app.init_state(self.state, self.password)
        self.store = app.Store(self.state)

    def test_password_and_tokens_are_not_persisted_in_plaintext(self):
        status, token = self.store.unlock(self.password, "first")
        self.assertEqual(status, "ok")
        self.assertTrue(self.store.valid(token))
        for file in self.state.iterdir():
            if file.is_file():
                data = file.read_bytes()
                self.assertNotIn(self.password.encode(), data)
                self.assertNotIn(token.encode(), data)

    def test_fresh_state_uses_wal(self):
        with self.store.connect() as db:
            self.assertEqual(db.execute("PRAGMA journal_mode").fetchone()[0], "wal")

    def test_wrong_password_does_not_consume_quota(self):
        self.assertEqual(self.store.unlock("incorrect", "first")[0], "wrong")
        self.assertEqual(self.store.used(), 0)

    def test_concurrent_unlocks_are_capped_at_three(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as workers:
            results = list(workers.map(lambda i: self.store.unlock(self.password, str(i)), range(8)))
        self.assertEqual(sum(result == "ok" for result, _ in results), 3)
        self.assertEqual(self.store.used(), 3)
        for result, token in results:
            if result == "ok":
                self.assertTrue(self.store.valid(token))

    def test_reset_is_idempotent_and_retains_sessions(self):
        tokens = [self.store.unlock(self.password, str(i))[1] for i in range(3)]
        config = (self.state / "config.json").read_bytes()
        self.assertTrue(self.store.reset("operation-1"))
        self.assertEqual(self.store.used(), 0)
        self.assertTrue(all(self.store.valid(token) for token in tokens))
        self.assertEqual(config, (self.state / "config.json").read_bytes())
        self.assertEqual(self.store.unlock(self.password, "new")[0], "ok")
        self.assertFalse(self.store.reset("operation-1"))
        self.assertEqual(self.store.used(), 1)

    def test_explicit_session_revocation(self):
        token = self.store.unlock(self.password, "first")[1]
        self.assertTrue(self.store.reset("revoke-1", revoke_sessions=True))
        self.assertFalse(self.store.valid(token))

    def test_rate_limit(self):
        for _ in range(5):
            self.assertEqual(self.store.unlock("incorrect", "same-client")[0], "wrong")
        self.assertEqual(self.store.unlock(self.password, "same-client")[0], "rate")
        self.assertEqual(self.store.used(), 0)

    def test_invalid_password_config_is_rejected(self):
        (self.state / "config.json").write_text(json.dumps({"salt": "invalid", "password_hash": "0" * 64}))
        with self.assertRaises(ValueError):
            app.Store(self.state)

    def test_missing_database_does_not_silently_reset(self):
        missing = Path(self.temp.name) / "missing"
        missing.mkdir()
        (missing / "config.json").write_bytes((self.state / "config.json").read_bytes())
        with self.assertRaises(ValueError):
            app.Store(missing)
        self.assertFalse((missing / "access.sqlite3").exists())

    def test_empty_database_does_not_silently_reset(self):
        bad = Path(self.temp.name) / "bad"
        bad.mkdir()
        (bad / "config.json").write_bytes((self.state / "config.json").read_bytes())
        sqlite3.connect(bad / "access.sqlite3").close()
        with self.assertRaises(ValueError):
            app.Store(bad)

    def test_runtime_missing_database_does_not_create_one(self):
        renamed = self.state / "saved.sqlite3"
        (self.state / "access.sqlite3").rename(renamed)
        with self.assertRaises(sqlite3.OperationalError):
            self.store.used()
        self.assertFalse((self.state / "access.sqlite3").exists())

    def test_legacy_schema_and_grants_survive(self):
        token = self.store.unlock(self.password, "first")[1]
        with self.store.connect() as db:
            db.execute("DROP TABLE reset_events")
        reopened = app.Store(self.state)
        self.assertEqual(reopened.used(), 1)
        self.assertTrue(reopened.valid(token))

    def test_init_refuses_existing_state(self):
        config = (self.state / "config.json").read_bytes()
        with self.assertRaises(ValueError):
            app.init_state(self.state, "other-password")
        self.assertEqual(config, (self.state / "config.json").read_bytes())


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.files = Path(self.temp.name)
        self.file = self.files / "sample.bin"
        self.file.write_bytes(bytes(range(256)) * 128)
        self.manifest = self.files / "current.json"
        app.prepare_manifest(self.file, self.manifest)
        self.catalog = app.AssetCatalog(self.files, self.manifest)

    def test_hash_and_content_addressed_url(self):
        asset = self.catalog.load()
        self.assertEqual(asset.sha256, hashlib.sha256(self.file.read_bytes()).hexdigest())
        self.assertIn(asset.sha256, asset.url)
        self.assertEqual(asset, self.catalog.load())

    def test_tampering_is_rejected(self):
        self.catalog.load()
        before = self.file.stat()
        self.file.write_bytes(b"X" * before.st_size)
        os.utime(self.file, ns=(before.st_atime_ns, before.st_mtime_ns + 1000000000))
        with self.assertRaises(ValueError):
            self.catalog.load()

    def test_path_traversal_and_control_names_are_rejected(self):
        for name in ["../secret", "..\\secret", "/secret", "..", "line\nname", "C:secret"]:
            self.manifest.write_text(json.dumps({"filename": name, "bytes": 0, "sha256": "0" * 64}))
            with self.assertRaises(ValueError):
                self.catalog.load()

    def test_wrong_size_and_digest_are_rejected(self):
        meta = json.loads(self.manifest.read_text())
        for changed in [dict(meta, bytes=meta["bytes"] + 1), dict(meta, sha256="0" * 64)]:
            self.manifest.write_text(json.dumps(changed))
            with self.assertRaises(ValueError):
                self.catalog.load()

    def test_manifest_corruption_is_rejected(self):
        self.manifest.write_text("{")
        with self.assertRaises(ValueError):
            self.catalog.load()

    def test_symlink_is_rejected_if_supported(self):
        link = self.files / "link.bin"
        try:
            link.symlink_to(self.file)
        except (OSError, NotImplementedError):
            self.skipTest("This account cannot create symbolic links")
        with self.assertRaises(ValueError):
            app.prepare_manifest(link, self.manifest)


class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root / "state"
        self.files = self.root / "data"
        self.files.mkdir()
        self.file = self.files / "sample.bin"
        self.blob = bytes(range(256)) * 1024
        self.file.write_bytes(self.blob)
        self.manifest = self.files / "current.json"
        self.meta = app.prepare_manifest(self.file, self.manifest)
        self.password = secrets.token_urlsafe(20)
        app.init_state(self.state, self.password)
        self.origin = "https://files.example.com"
        self.server = app.create_server("127.0.0.1", 0, self.state, self.files, self.manifest, self.origin, legacy_session_cookie="old_session", legacy_csrf_cookie="old_csrf", legacy_downloads={"/archive.bin": self.meta["sha256"]})
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.close)
        self.url = self.server.catalog.load().url

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

    def req(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=10)
        conn.request(method, path, body, headers or {})
        res = conn.getresponse()
        result = res.status, dict(res.getheaders()), res.read(), res.getheaders()
        conn.close()
        return result

    def form(self):
        status, headers, body, _ = self.req("GET", "/")
        self.assertEqual(status, 200)
        csrf = re.search(rb'name="csrf" value="([^"]+)"', body).group(1).decode()
        return csrf, app.CSRF_COOKIE + "=" + csrf

    def unlock(self, password=None, origin=None, cookie=None):
        csrf, jar = self.form()
        body = urllib.parse.urlencode({"csrf": csrf, "password": self.password if password is None else password})
        return self.req("POST", "/unlock", body, {"Cookie": cookie or jar, "Origin": origin or self.origin, "Content-Type": "application/x-www-form-urlencoded"})

    def lease(self):
        result = self.unlock()
        self.assertEqual(result[0], 303)
        return result[1]["Set-Cookie"].split(";")[0]

    def test_generic_password_only_page(self):
        status, headers, body, _ = self.req("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn("文件传输".encode(), body)
        self.assertNotIn(b'name="username"', body)
        self.assertNotIn(b"example.com", body)
        self.assertNotIn(b"github", body.lower())
        self.assertEqual(headers["Referrer-Policy"], "same-origin")

    def test_wrong_password_and_origin_do_not_consume_quota(self):
        self.assertEqual(self.unlock(password="incorrect")[0], 403)
        self.assertEqual(self.unlock(origin="https://wrong.example")[0], 403)
        self.assertEqual(self.server.store.used(), 0)

    def test_maximum_utf8_password_request_is_parsed(self):
        result = self.unlock(password="🚀" * 128)
        self.assertEqual(result[0], 403)
        self.assertIn("访问密码不正确".encode(), result[2])
        self.assertEqual(self.server.store.used(), 0)

    def test_null_origin_is_rejected(self):
        self.assertEqual(self.unlock(origin="null")[0], 403)
        self.assertEqual(self.server.store.used(), 0)

    def test_csrf_mismatch_is_rejected(self):
        self.assertEqual(self.unlock(cookie=app.CSRF_COOKIE + "=" + "A" * 43)[0], 403)
        self.assertEqual(self.server.store.used(), 0)

    def test_secure_cookie_and_same_session_reuse(self):
        status, headers, _, _ = self.unlock()
        for flag in ["Secure", "HttpOnly", "SameSite=Strict", "Path=/"]:
            self.assertIn(flag, headers["Set-Cookie"])
        cookie = headers["Set-Cookie"].split(";")[0]
        for _ in range(3):
            self.assertEqual(self.req("GET", "/", headers={"Cookie": cookie})[0], 200)
            self.assertEqual(self.req("POST", "/unlock", b"ignored", {"Cookie": cookie})[0], 303)
        self.assertEqual(self.server.store.used(), 1)

    def test_three_unlocks_then_contact_administrator(self):
        first = self.lease()
        self.lease()
        self.lease()
        result = self.req("GET", "/")
        self.assertEqual(result[0], 403)
        self.assertIn("请联系管理员".encode(), result[2])
        self.assertNotIn(b"3", re.sub(rb"<style>.*?</style>", b"", result[2]))
        self.assertEqual(self.req("GET", self.url, headers={"Cookie": first})[2], self.blob)
        self.assertEqual(self.server.store.used(), 3)

    def test_full_head_range_suffix_and_resume(self):
        cookie = self.lease()
        full = self.req("GET", self.url, headers={"Cookie": cookie})
        self.assertEqual(full[0], 200)
        self.assertEqual(full[2], self.blob)
        head = self.req("HEAD", self.url, headers={"Cookie": cookie})
        self.assertEqual(head[0], 200)
        self.assertEqual(int(head[1]["Content-Length"]), len(self.blob))
        self.assertEqual(head[2], b"")
        for value, expected in [("bytes=123-456", self.blob[123:457]), ("bytes=-123", self.blob[-123:]), ("bytes=200000-", self.blob[200000:])]:
            result = self.req("GET", self.url, headers={"Cookie": cookie, "Range": value})
            self.assertEqual(result[0], 206)
            self.assertEqual(result[2], expected)
        self.assertEqual(self.server.store.used(), 1)

    def test_invalid_ranges(self):
        cookie = self.lease()
        for value in ["bytes=-0", "bytes=4-1", "bytes=999999-", "bytes=0-1,4-8", "bytes=-", "other=1-2", "bytes=" + "9" * 5000 + "-"]:
            self.assertEqual(self.req("GET", self.url, headers={"Cookie": cookie, "Range": value})[0], 416)

    def test_if_range_mismatch_does_not_append_to_wrong_object(self):
        cookie = self.lease()
        result = self.req("GET", self.url, headers={"Cookie": cookie, "Range": "bytes=3-9", "If-Range": '"wrong"'})
        self.assertEqual(result[0], 200)
        self.assertEqual(result[2], self.blob)

    def test_hot_file_update_retires_old_download_url(self):
        cookie = self.lease()
        second = self.files / "second.bin"
        second.write_bytes(b"replacement-data")
        app.prepare_manifest(second, self.manifest)
        new_url = self.server.catalog.load().url
        self.assertNotEqual(new_url, self.url)
        self.assertEqual(self.req("GET", self.url, headers={"Cookie": cookie})[0], 410)
        self.assertEqual(self.req("GET", "/archive.bin", headers={"Cookie": cookie})[0], 410)
        self.assertEqual(self.req("GET", new_url, headers={"Cookie": cookie})[2], b"replacement-data")
        self.assertEqual(self.server.store.used(), 1)

    def test_legacy_download_is_bound_to_original_hash(self):
        cookie = self.lease()
        self.assertEqual(self.req("GET", "/archive.bin", headers={"Cookie": cookie})[2], self.blob)

    def test_legacy_session_migrates_without_another_unlock(self):
        cookie = self.lease()
        token = cookie.split("=", 1)[1]
        result = self.req("GET", "/", headers={"Cookie": "old_session=" + token})
        self.assertEqual(result[0], 200)
        sets = [value for key, value in result[3] if key.lower() == "set-cookie"]
        self.assertTrue(any(value.startswith(app.SESSION_COOKIE + "=" + token) for value in sets))
        self.assertEqual(self.server.store.used(), 1)

    def test_legacy_csrf_form_can_complete(self):
        csrf, _ = self.form()
        result = self.req("POST", "/unlock", urllib.parse.urlencode({"csrf": csrf, "password": self.password}), {"Cookie": "old_csrf=" + csrf, "Origin": self.origin, "Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(result[0], 303)
        self.assertEqual(self.server.store.used(), 1)

    def test_empty_file(self):
        cookie = self.lease()
        empty = self.files / "empty.bin"
        empty.write_bytes(b"")
        app.prepare_manifest(empty, self.manifest)
        url = self.server.catalog.load().url
        self.assertEqual(self.req("GET", url, headers={"Cookie": cookie})[2], b"")
        self.assertEqual(self.req("GET", url, headers={"Cookie": cookie, "Range": "bytes=0-"})[0], 416)

    def test_unicode_filename(self):
        cookie = self.lease()
        unicode_file = self.files / "测试文件.bin"
        unicode_file.write_bytes(b"unicode-file")
        app.prepare_manifest(unicode_file, self.manifest)
        url = self.server.catalog.load().url
        result = self.req("GET", url, headers={"Cookie": cookie})
        self.assertEqual(result[2], b"unicode-file")
        self.assertIn("filename*=UTF-8''", result[1]["Content-Disposition"])
        self.assertNotIn("测试", result[1]["Content-Disposition"])

    def test_integrity_failure_is_closed(self):
        cookie = self.lease()
        self.file.write_bytes(b"short")
        result = self.req("GET", self.url, headers={"Cookie": cookie})
        self.assertEqual(result[0], 503)
        self.assertNotIn(b"short", result[2])

    def test_no_upload_directory_or_admin_endpoint(self):
        for path in ["/state/config.json", "/data/", "/reset", "/.git/config", "/../secret"]:
            self.assertEqual(self.req("GET", path)[0], 404)
        self.assertEqual(self.req("PUT", "/upload", b"x")[0], 405)
        self.assertEqual(self.req("POST", "/reset", b"x")[0], 404)
        self.assertEqual(self.req("GET", self.url)[0], 303)


class RestartTests(unittest.TestCase):
    def test_real_process_restart_retains_password_session_and_counter(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state, data = root / "state", root / "data"
            data.mkdir()
            file = data / "file.bin"
            file.write_bytes(b"persistent-transfer" * 100)
            manifest = data / "current.json"
            password = secrets.token_urlsafe(20)
            init = subprocess.run([sys.executable, str(ROOT / "transfer_server.py"), "init", "--state", str(state), "--password-stdin"], input=password.encode(), capture_output=True, timeout=15)
            self.assertEqual(init.returncode, 0, init.stderr.decode())
            app.prepare_manifest(file, manifest)
            token = app.Store(state).unlock(password, "parent")[1]
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                port = probe.getsockname()[1]
            command = [sys.executable, "-B", str(ROOT / "transfer_server.py"), "serve", "--bind", "127.0.0.1", "--port", str(port), "--state", str(state), "--files", str(data), "--manifest", str(manifest), "--origin", "https://files.example.com"]
            for cycle in range(2):
                child = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                try:
                    deadline = time.monotonic() + 15
                    while True:
                        try:
                            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
                            conn.request("GET", "/", headers={"Cookie": app.SESSION_COOKIE + "=" + token})
                            res = conn.getresponse()
                            body = res.read()
                            self.assertEqual(res.status, 200)
                            self.assertIn(b"file.bin", body)
                            conn.close()
                            break
                        except OSError:
                            if time.monotonic() > deadline:
                                self.fail("Child HTTP server did not become ready")
                            time.sleep(0.05)
                    self.assertEqual(app.Store(state).used(), 1)
                finally:
                    child.terminate()
                    child.wait(timeout=10)
                    if child.stderr:
                        child.stderr.close()
            self.assertTrue(app.Store(state).valid(token))


if __name__ == "__main__":
    unittest.main()
