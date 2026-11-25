"""Password-only, three-unlock file delivery behind a trusted HTTPS reverse proxy."""
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
import argparse
import getpass
import hashlib
import hmac
import html
import http.cookies
import http.server
import json
import mimetypes
import os
import re
import secrets
import sqlite3
import stat
import sys
import threading
import time
import urllib.parse
import ui

LIMIT = 3
SESSION_COOKIE = "transfer_session"
CSRF_COOKIE = "transfer_csrf"


class Store:
    def __init__(self, path, *, create=False):
        self.path = Path(path)
        self.config = json.loads((self.path / "config.json").read_text(encoding="utf-8"))
        if not isinstance(self.config, dict) or not isinstance(self.config.get("salt"), str) or not isinstance(self.config.get("password_hash"), str) or not re.fullmatch(r"[0-9a-f]{32}", self.config["salt"]) or not re.fullmatch(r"[0-9a-f]{64}", self.config["password_hash"]):
            raise ValueError("Invalid private password configuration")
        self.db = self.path / "access.sqlite3"
        if not create and not self.db.is_file():
            raise ValueError("Access database missing; restore it rather than silently resetting access")
        self.hashlock = threading.Lock()
        self.lock = threading.Lock()
        self.rate = {}
        with self.connect(create=create) as db:
            if create:
                db.execute("PRAGMA journal_mode=WAL")
                db.execute("CREATE TABLE quota(id INTEGER PRIMARY KEY CHECK(id=1),used INTEGER NOT NULL CHECK(used BETWEEN 0 AND 3))")
                db.execute("INSERT INTO quota VALUES(1,0)")
                db.execute("CREATE TABLE sessions(token_hash TEXT PRIMARY KEY,created REAL NOT NULL)")
            else:
                if [r[1] for r in db.execute("PRAGMA table_info(quota)")] != ["id", "used"] or [r[1] for r in db.execute("PRAGMA table_info(sessions)")] != ["token_hash", "created"]:
                    raise ValueError("Unknown access database; refusing an implicit reset")
                rows = db.execute("SELECT id,used FROM quota").fetchall()
                if len(rows) != 1 or rows[0][0] != 1 or not 0 <= rows[0][1] <= LIMIT:
                    raise ValueError("Invalid quota state")
                if db.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                    raise ValueError("Access database integrity check failed")
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("CREATE TABLE IF NOT EXISTS reset_events(operation_id TEXT PRIMARY KEY,created REAL NOT NULL,revoke_sessions INTEGER NOT NULL)")

    @contextmanager
    def connect(self, *, create=False):
        target = str(self.db) if create else self.db.absolute().as_uri() + "?mode=rw"
        db = sqlite3.connect(target, timeout=10, uri=not create)
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA temp_store=MEMORY")
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def used(self):
        with self.connect() as db:
            return db.execute("SELECT used FROM quota WHERE id=1").fetchone()[0]

    def valid(self, token):
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}", token or ""):
            return False
        with self.connect() as db:
            return db.execute("SELECT 1 FROM sessions WHERE token_hash=?", (hashlib.sha256(token.encode()).hexdigest(),)).fetchone() is not None

    def unlock(self, password, client):
        now = time.monotonic()
        with self.lock:
            attempts = [t for t in self.rate.get(client, []) if now - t < 60]
            if len(self.rate) > 512:
                self.rate = {key: value for key, value in self.rate.items() if value and now - value[-1] < 60}
            if len(self.rate) > 1024 or len(attempts) >= 5:
                return "rate", None
            self.rate[client] = attempts
            attempts.append(now)
        if self.used() >= LIMIT:
            return "exhausted", None
        with self.hashlock:
            digest = hashlib.scrypt(password.encode(), salt=bytes.fromhex(self.config["salt"]), n=16384, r=8, p=1, dklen=32, maxmem=67108864)
        if not hmac.compare_digest(digest.hex(), self.config["password_hash"]):
            return "wrong", None
        token = secrets.token_urlsafe(32)
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT used FROM quota WHERE id=1").fetchone()[0] >= LIMIT:
                return "exhausted", None
            db.execute("INSERT INTO sessions VALUES(?,?)", (hashlib.sha256(token.encode()).hexdigest(), time.time()))
            db.execute("UPDATE quota SET used=used+1 WHERE id=1")
        return "ok", token

    def reset(self, operation_id, *, revoke_sessions=False):
        if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", operation_id):
            raise ValueError("A unique administrative operation ID is required")
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM reset_events WHERE operation_id=?", (operation_id,)).fetchone():
                return False
            db.execute("UPDATE quota SET used=0 WHERE id=1")
            if revoke_sessions:
                db.execute("DELETE FROM sessions")
            db.execute("INSERT INTO reset_events VALUES(?,?,?)", (operation_id, time.time(), int(revoke_sessions)))
        return True


def init_state(path, password):
    if not 1 <= len(password) <= 128:
        raise ValueError("Password must contain 1 to 128 characters")
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    if (path / "config.json").exists() or (path / "access.sqlite3").exists():
        raise ValueError("Refusing to overwrite existing access state")
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1, dklen=32, maxmem=67108864)
    with (path / "config.json").open("x", encoding="utf-8") as out:
        json.dump({"salt": salt.hex(), "password_hash": digest.hex()}, out)
    if os.name == "posix":
        os.chmod(path / "config.json", 0o600)
    Store(path, create=True)


@dataclass(frozen=True)
class Asset:
    path: Path
    filename: str
    size: int
    sha256: str
    identity: tuple

    @property
    def url(self):
        return "/download/" + self.sha256 + "/" + urllib.parse.quote(self.filename, safe="")

    @property
    def etag(self):
        return '"' + self.sha256 + '"'


def hash_file(source):
    digest = hashlib.sha256()
    while True:
        block = source.read(1024 * 1024)
        if not block:
            return digest.hexdigest()
        digest.update(block)


def identity(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def open_regular(path):
    if path.is_symlink():
        raise ValueError("Symbolic file links are not served")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
    out = os.fdopen(fd, "rb")
    if not stat.S_ISREG(os.fstat(out.fileno()).st_mode):
        out.close()
        raise ValueError("Only regular files are served")
    return out


class AssetCatalog:
    def __init__(self, files, manifest):
        self.files = Path(files).resolve(strict=True)
        self.manifest = Path(manifest)
        self.lock = threading.Lock()
        self.cached = None

    def load(self):
        with self.lock:
            raw = self.manifest.read_bytes()
            if len(raw) > 16384:
                raise ValueError("Manifest too large")
            meta = json.loads(raw)
            name, size, digest = meta["filename"], meta["bytes"], meta["sha256"]
            if not isinstance(name, str) or not name or name in (".", "..") or ":" in name or any(c in name for c in "/\\") or any(ord(c) < 32 or ord(c) == 127 for c in name) or len(name.encode()) > 255:
                raise ValueError("Invalid filename")
            if type(size) is not int or size < 0 or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise ValueError("Invalid file identity")
            path = self.files / name
            with open_regular(path) as source:
                before = os.fstat(source.fileno())
                key = identity(before)
                if before.st_size != size:
                    raise ValueError("File size mismatch")
                asset = Asset(path, name, size, digest, key)
                if self.cached == asset:
                    return asset
                actual = hash_file(source)
                if identity(os.fstat(source.fileno())) != key or actual != digest:
                    raise ValueError("File changed or checksum mismatch")
            self.cached = asset
            return asset


def prepare_manifest(file, manifest):
    file, manifest = Path(file).absolute(), Path(manifest).absolute()
    if file.parent.resolve(strict=True) != manifest.parent.resolve(strict=True) or file == manifest:
        raise ValueError("The file and manifest must be distinct files in the same directory")
    with open_regular(file) as source:
        before = identity(os.fstat(source.fileno()))
        digest = hash_file(source)
        if identity(os.fstat(source.fileno())) != before:
            raise ValueError("File changed while preparing manifest")
    meta = {"version": 1, "filename": file.name, "bytes": before[2], "sha256": digest}
    temp = manifest.with_name(".manifest-" + secrets.token_hex(12) + ".tmp")
    try:
        with temp.open("x", encoding="utf-8") as out:
            json.dump(meta, out, ensure_ascii=False)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temp, manifest)
        if os.name == "posix":
            fd = os.open(manifest.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
    finally:
        if temp.exists():
            temp.unlink()
    return meta


def page(body, *, layout='access', title='文件传输'):
    return ui.document(body, layout=layout, title=title)


EXHAUSTED = page("<h1>请联系管理员</h1><p>当前入口暂不可解锁，请联系文件提供方获取访问安排。</p>")
UPDATED = page('<h1>文件已更新</h1><p>请返回首页获取当前文件，旧下载地址无法续传到不同的文件。</p><p><a href="/">返回首页</a></p>')
UNAVAILABLE = page("<h1>文件暂不可用</h1><p>请稍后重试或联系文件提供方。</p>")


def create_server(bind, port, state, files, manifest, origin, *, legacy_session_cookie=None, legacy_csrf_cookie=None, legacy_downloads=None, trust_proxy=False, extension=None):
    if extension:
        store, catalog = extension.store, extension.catalog
    else:
        from admin_service import control_enabled
        if control_enabled(state):
            raise ValueError("Administrator state requires --enable-admin; do not downgrade live state")
        store, catalog = Store(state), AssetCatalog(files, manifest)
        catalog.load()  # Fail closed before listening if the initial file is invalid.
    legacy_downloads = legacy_downloads or {}
    for name in (legacy_session_cookie, legacy_csrf_cookie):
        if name is not None and not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", name):
            raise ValueError("Invalid legacy cookie name")

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "FileTransfer"
        sys_version = ""

        def setup(self):
            super().setup()
            self.connection.settimeout(30)
            self.migration_token = None

        def log_message(self, fmt, *args):
            candidate = str(args[1]) if len(args) > 1 else ""
            status = int(candidate) if candidate.isdigit() and 100 <= int(candidate) <= 599 else None
            method = self.command if self.command and re.fullmatch(r"[A-Z]{1,16}", self.command) else "OTHER"
            print(json.dumps({"event": "http", "method": method, "status": status}), flush=True)

        def cookies(self):
            try:
                jar = http.cookies.SimpleCookie()
                jar.load(self.headers.get("Cookie", ""))
                return {key: value.value for key, value in jar.items()}
            except http.cookies.CookieError:
                return {}

        def auth(self):
            if extension and extension.can_download(self):
                return True
            jar = self.cookies()
            self.migration_token = None
            if store.valid(jar.get(SESSION_COOKIE, "")):
                return True
            if legacy_session_cookie and store.valid(jar.get(legacy_session_cookie, "")):
                self.migration_token = jar[legacy_session_cookie]
                return True
            return False

        def common_headers(self):
            csp = "default-src 'none'; style-src 'self'; script-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
            for key, value in [("Cache-Control", "private, no-store"), ("X-Content-Type-Options", "nosniff"), ("X-Frame-Options", "DENY"), ("Referrer-Policy", getattr(self, "referrer_policy", "same-origin")), ("Content-Security-Policy", csp)]:
                self.send_header(key, value)
            if self.migration_token:
                self.send_header("Set-Cookie", SESSION_COOKIE + "=" + self.migration_token + "; Path=/; Secure; HttpOnly; SameSite=Strict")
                self.send_header("Set-Cookie", legacy_session_cookie + "=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0")

        def reply(self, status, body=b"", extra=()):
            self.send_response(status)
            self.common_headers()
            if not any(key.lower() == "content-type" for key, _ in extra):
                self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            for key, value in extra:
                self.send_header(key, value)
            self.end_headers()
            if self.command != "HEAD" and body:
                try:
                    self.wfile.write(body)
                except OSError:
                    pass
            self.close_connection = True

        def asset(self):
            if extension:
                return getattr(self, "selected_asset", None)
            try:
                return catalog.load()
            except (OSError, ValueError, KeyError, TypeError):
                self.reply(503, UNAVAILABLE)
                return None

        def do_HEAD(self):
            self.do_GET()

        def handle_expect_100(self):
            if extension and self.path == "/admin/upload" and not extension.preflight_upload(self):
                return False
            return super().handle_expect_100()

        def show_login(self, message='', status=200):
            csrf = secrets.token_urlsafe(32)
            self.reply(status, page(ui.login_body(csrf, message)), [("Set-Cookie", CSRF_COOKIE + "=" + csrf + "; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=600")])

        def do_GET(self):
            if self.path in ui.ASSETS:
                name, content_type = ui.ASSETS[self.path]
                self.reply(200, (ui.STATIC/name).read_bytes(), [("Content-Type", content_type)])
                return
            if extension and extension.handle_get(self):
                return
            if self.path == "/":
                if self.auth():
                    asset = self.asset()
                    if asset is not None:
                        body = '<div class="page-heading"><div class="hero-mark">'+ui.icon('check')+'</div><div><h1>文件已就绪</h1><p>选择文件，开始下一次交付。</p></div></div>'+ui.file_card(asset.filename,asset.size,asset.sha256,asset.url)
                        self.reply(200, page(body,layout='download'))
                    return
                if store.used() >= LIMIT:
                    self.reply(403, EXHAUSTED)
                    return
                self.show_login()
                return
            if not self.path.startswith("/download/") and self.path not in legacy_downloads:
                self.reply(404)
                return
            if not self.auth():
                self.reply(303, extra=[("Location", "/")])
                return
            asset = self.asset()
            if asset is None:
                return
            if self.path != asset.url and legacy_downloads.get(self.path) != asset.sha256:
                self.reply(410, UPDATED)
                return
            size, start, end, status = asset.size, 0, asset.size - 1, 200
            value = self.headers.get("Range")
            if self.headers.get("If-Range") not in (None, asset.etag):
                value = None
            if value:
                match = re.fullmatch(r"bytes=(\d*)-(\d*)", value)
                try:
                    if len(value) > 128 or not match or not any(match.groups()) or size == 0:
                        raise ValueError()
                    first, last = match.groups()
                    if first:
                        start = int(first)
                        end = min(end, int(last)) if last else end
                    else:
                        suffix = int(last)
                        if suffix <= 0:
                            raise ValueError()
                        start = max(0, size - suffix)
                    if start >= size or end < start:
                        raise ValueError()
                except ValueError:
                    self.reply(416, extra=[("Content-Range", f"bytes */{size}")])
                    return
                status = 206
            try:
                source = open_regular(asset.path)
                if identity(os.fstat(source.fileno())) != asset.identity:
                    source.close()
                    self.reply(503, UNAVAILABLE)
                    return
            except (OSError, ValueError):
                self.reply(503, UNAVAILABLE)
                return
            if not self.auth():
                source.close()
                self.reply(303, extra=[("Location", "/")])
                return
            sent, expected, started, result = 0, max(0, end - start + 1), time.monotonic(), "complete"
            with source:
                self.send_response(status)
                self.common_headers()
                self.send_header("Content-Type", mimetypes.guess_type(asset.filename)[0] or "application/octet-stream")
                self.send_header("Content-Length", str(expected))
                fallback = asset.filename if re.fullmatch(r"[A-Za-z0-9_.-]{1,200}", asset.filename) else "download.bin"
                self.send_header("Content-Disposition", 'attachment; filename="' + fallback + '"; filename*=UTF-8\'\'' + urllib.parse.quote(asset.filename, safe=""))
                self.send_header("Accept-Ranges", "bytes")
                self.send_header("ETag", asset.etag)
                self.send_header("Connection", "close")
                if status == 206:
                    self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
                self.end_headers()
                if self.command != "HEAD":
                    try:
                        source.seek(start)
                        while sent < expected:
                            chunk = source.read(min(expected - sent, 262144))
                            if not chunk:
                                result = "source_short_read"
                                break
                            self.wfile.write(chunk)
                            sent += len(chunk)
                    except OSError:
                        result = "connection_interrupted"
            self.close_connection = True
            if self.command != "HEAD":
                print(json.dumps({"event": "transfer", "bytes_sent": sent, "expected_bytes": expected, "seconds": round(time.monotonic() - started, 3), "result": result}), flush=True)

        def do_POST(self):
            if extension and extension.handle_post(self):
                return
            if self.path != "/unlock":
                self.reply(404)
                return
            if self.auth():
                self.reply(303, extra=[("Location", "/")])
                return
            if store.used() >= LIMIT:
                self.reply(403, EXHAUSTED)
                return
            if self.headers.get("Origin") not in (None, origin):
                self.reply(403, page('<h1>请求来源不匹配</h1><p><a href="/">返回首页重试</a></p>'))
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 2048 or self.headers.get("Transfer-Encoding"):
                    raise ValueError()
                fields = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8"), strict_parsing=True)
                csrf, password = fields.get("csrf", [""])[0], fields.get("password", [""])[0]
                jar = self.cookies()
                names = [CSRF_COOKIE] + ([legacy_csrf_cookie] if legacy_csrf_cookie else [])
                if not re.fullmatch(r"[A-Za-z0-9_-]{43}", csrf) or not any(hmac.compare_digest(csrf, jar.get(name, "")) for name in names):
                    self.reply(403, page('<h1>登录页面已过期</h1><p><a href="/">返回首页刷新后重试</a></p>'))
                    return
                if len(password) > 128:
                    raise ValueError()
            except (ValueError, UnicodeError, OSError):
                self.reply(400)
                return
            client = self.headers.get("X-Real-IP", self.client_address[0]) if trust_proxy else self.client_address[0]
            result, token = store.unlock(password, client)
            if result == "ok":
                self.reply(303, extra=[("Location", "/"), ("Set-Cookie", SESSION_COOKIE + "=" + token + "; Path=/; Secure; HttpOnly; SameSite=Strict")])
            elif result == "exhausted":
                self.reply(403, EXHAUSTED)
            elif result == "rate":
                self.show_login('请稍后重试。',429)
            else:
                self.show_login('访问密码不正确，请重试。',403)

        def deny(self):
            self.reply(405, extra=[("Allow", "GET, HEAD, POST")])

        do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_CONNECT = do_TRACE = deny

    class Server(http.server.ThreadingHTTPServer):
        daemon_threads = True
        request_queue_size = 16

        def __init__(self, *args, **kwargs):
            self.slots = threading.BoundedSemaphore(8)
            super().__init__(*args, **kwargs)

        def process_request(self, request, address):
            if not self.slots.acquire(False):
                request.close()
                return
            try:
                super().process_request(request, address)
            except Exception:
                self.slots.release()
                raise

        def process_request_thread(self, *args):
            try:
                super().process_request_thread(*args)
            finally:
                self.slots.release()

    server = Server((bind, port), Handler)
    server.store, server.catalog, server.extension = store, catalog, extension
    return server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init", help="Create fresh private password and session state")
    init.add_argument("--state", required=True)
    init.add_argument("--password-stdin", action="store_true")
    prepare = commands.add_parser("prepare", help="Hash an immutable file and atomically publish its manifest")
    prepare.add_argument("--file", required=True)
    prepare.add_argument("--manifest", required=True)
    reset = commands.add_parser("reset", help="Restore three successful unlocks; preserve existing sessions by default")
    reset.add_argument("--state", required=True)
    reset.add_argument("--operation-id", required=True)
    reset.add_argument("--revoke-sessions", action="store_true")
    bootstrap = commands.add_parser("admin-bootstrap", help="Issue private first-activation token (24 hours); never publish it")
    bootstrap.add_argument("--state", required=True)
    serve = commands.add_parser("serve", help="Serve only the configured file through an HTTPS reverse proxy")
    serve.add_argument("--state", required=True)
    serve.add_argument("--files", required=True)
    serve.add_argument("--manifest")
    serve.add_argument("--enable-admin", action="store_true")
    serve.add_argument("--max-upload-bytes", type=int, default=4*1024**3)
    serve.add_argument("--reserve-bytes", type=int, default=1024**3)
    serve.add_argument("--origin", required=True)
    serve.add_argument("--bind", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)
    serve.add_argument("--legacy-session-cookie")
    serve.add_argument("--legacy-csrf-cookie")
    serve.add_argument("--legacy-download", action="append", default=[], metavar="PATH=SHA256")
    serve.add_argument("--trust-proxy", action="store_true")
    args = parser.parse_args()
    if args.command == "init":
        password = sys.stdin.read().removesuffix("\n").removesuffix("\r") if args.password_stdin else getpass.getpass("Access password: ")
        init_state(args.state, password)
        print(json.dumps({"initialized": True}))
    elif args.command == "prepare":
        print(json.dumps(prepare_manifest(args.file, args.manifest)))
    elif args.command == "reset":
        from admin_service import control_enabled, ControlStore
        store = ControlStore(args.state) if control_enabled(args.state) else Store(args.state)
        changed = store.reset(args.operation_id, revoke_sessions=args.revoke_sessions)
        print(json.dumps({"applied": changed, "already_applied": not changed}))
    elif args.command == "admin-bootstrap":
        from admin_service import ControlStore
        print(json.dumps(ControlStore(args.state).new_bootstrap()))
    else:
        parsed = urllib.parse.urlsplit(args.origin)
        if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            parser.error("--origin must be the exact public HTTPS origin")
        legacy = {}
        for mapping in args.legacy_download:
            try:
                path, digest = mapping.rsplit("=", 1)
                if not path.startswith("/") or "?" in path or "#" in path or not re.fullmatch(r"[0-9a-f]{64}", digest):
                    raise ValueError()
                legacy[path] = digest
            except ValueError:
                parser.error("--legacy-download requires PATH=SHA256")
        if not args.enable_admin and not args.manifest:
            parser.error("--manifest is required without --enable-admin")
        if args.max_upload_bytes < 1 or args.reserve_bytes < 0:
            parser.error("Invalid upload limits")
        extension = None
        if args.enable_admin:
            from admin_service import AdminService
            extension = AdminService(args.state, args.files, args.manifest, args.origin.rstrip("/"), max_upload=args.max_upload_bytes, reserve=args.reserve_bytes, legacy_session_cookie=args.legacy_session_cookie, legacy_csrf_cookie=args.legacy_csrf_cookie, legacy_downloads=legacy, trust_proxy=args.trust_proxy)
        create_server(args.bind, args.port, args.state, args.files, args.manifest, args.origin.rstrip("/"), legacy_session_cookie=args.legacy_session_cookie, legacy_csrf_cookie=args.legacy_csrf_cookie, legacy_downloads=legacy, trust_proxy=args.trust_proxy, extension=extension).serve_forever()


if __name__ == "__main__":
    sys.modules.setdefault("transfer_server", sys.modules[__name__])
    main()
