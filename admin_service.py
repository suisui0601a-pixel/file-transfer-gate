"""Optional administrator console and managed-file catalog (stdlib only)."""
from contextlib import contextmanager, closing
from pathlib import Path
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import shutil
import sqlite3
import threading
import time
import urllib.parse
import transfer_server as base

DEFAULT_ADMIN_PASSWORD = "cosine123"
ADMIN_COOKIE = "transfer_admin"
CLAIM_COOKIE = "transfer_setup"
ADMIN_TTL = 8 * 3600
MAX_QUOTA = 1_000_000


def token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def valid_token(token):
    return bool(re.fullmatch(r"[A-Za-z0-9_-]{43}", token or ""))


def password_digest(password, salt):
    return hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1, dklen=32, maxmem=67108864).hex()


def csrf_for(token):
    return hmac.new(token.encode(), b"file-transfer-admin-csrf", hashlib.sha256).hexdigest()


def control_enabled(path):
    with closing(sqlite3.connect((Path(path)/"access.sqlite3").absolute().as_uri() + "?mode=ro", uri=True)) as db:
        return bool(db.execute("SELECT 1 FROM sqlite_master WHERE name='control_meta'").fetchone())


class ControlStore(base.Store):
    @contextmanager
    def connect(self, *, create=False):
        with super().connect(create=create) as db:
            db.row_factory = sqlite3.Row
            yield db

    def __init__(self, path):
        super().__init__(path)
        with self.connect() as db:
            present = db.execute("SELECT 1 FROM sqlite_master WHERE name='control_meta'").fetchone()
        salt = secrets.token_hex(16)
        digest = password_digest(DEFAULT_ADMIN_PASSWORD, salt) if not present else None
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            found = db.execute("SELECT 1 FROM sqlite_master WHERE name='control_meta'").fetchone()
            if found:
                row = db.execute("SELECT * FROM control_meta WHERE id=1").fetchone()
                if not row or row["version"] != 2:
                    raise ValueError("Unknown administrator state")
                return
            original_used = db.execute("SELECT used FROM quota WHERE id=1").fetchone()[0]
            statements = [
                "CREATE TABLE control_meta(id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL,catalog_imported INTEGER NOT NULL DEFAULT 0)",
                "CREATE TABLE quota_v2(id INTEGER PRIMARY KEY CHECK(id=1),remaining INTEGER NOT NULL CHECK(remaining BETWEEN 0 AND 1000000),used INTEGER NOT NULL CHECK(used>=0),reset_value INTEGER NOT NULL CHECK(reset_value BETWEEN 0 AND 1000000))",
                "CREATE TABLE verifiers(role TEXT PRIMARY KEY CHECK(role IN ('access','admin')),salt TEXT NOT NULL,digest TEXT NOT NULL,epoch INTEGER NOT NULL,needs_change INTEGER NOT NULL)",
                "CREATE TABLE admin_sessions(token_hash TEXT PRIMARY KEY,epoch INTEGER NOT NULL,created REAL NOT NULL,expires REAL NOT NULL)",
                "CREATE TABLE bootstrap(id INTEGER PRIMARY KEY CHECK(id=1),token_hash TEXT NOT NULL,expires REAL NOT NULL)",
                "CREATE TABLE files(id TEXT PRIMARY KEY,name TEXT NOT NULL,storage TEXT NOT NULL UNIQUE,size INTEGER NOT NULL,sha256 TEXT NOT NULL,identity_json TEXT NOT NULL,status TEXT NOT NULL,created REAL NOT NULL,error TEXT NOT NULL DEFAULT '')",
                "CREATE UNIQUE INDEX published_file_identity ON files(name,sha256) WHERE status='published'",
                "CREATE TABLE uploads(id TEXT PRIMARY KEY,name TEXT NOT NULL,storage TEXT NOT NULL UNIQUE,expected INTEGER NOT NULL,identity_json TEXT,status TEXT NOT NULL,created REAL NOT NULL,error TEXT NOT NULL DEFAULT '')",
                "CREATE TABLE admin_events(id INTEGER PRIMARY KEY,event TEXT NOT NULL,details TEXT NOT NULL,created REAL NOT NULL)",
            ]
            for statement in statements:
                db.execute(statement)
            db.execute("INSERT INTO control_meta VALUES(1,2,0)")
            db.execute("INSERT INTO quota_v2 VALUES(1,?,?,?)", (base.LIMIT-original_used, original_used, base.LIMIT))
            db.execute("INSERT INTO verifiers VALUES('access',?,?,1,0)", (self.config["salt"], self.config["password_hash"]))
            db.execute("INSERT INTO verifiers VALUES('admin',?,?,1,1)", (salt, digest))
            # A v1 binary cannot allocate stale extra grants after migration.
            db.execute("UPDATE quota SET used=3 WHERE id=1")
            self.event(db, "migrate", {"version": 2})

    @staticmethod
    def event(db, event, details):
        db.execute("INSERT INTO admin_events(event,details,created) VALUES(?,?,?)", (event, json.dumps(details), time.time()))

    def verifier(self, role, db=None):
        if db is None:
            with self.connect() as conn:
                return dict(conn.execute("SELECT * FROM verifiers WHERE role=?", (role,)).fetchone())
        return dict(db.execute("SELECT * FROM verifiers WHERE role=?", (role,)).fetchone())

    def matches(self, password, verifier):
        with self.hashlock:
            return hmac.compare_digest(password_digest(password, verifier["salt"]), verifier["digest"])

    def quota(self):
        with self.connect() as db:
            return dict(db.execute("SELECT * FROM quota_v2 WHERE id=1").fetchone())

    def used(self):
        return self.quota()["used"]

    def admin_session(self, token, db=None):
        if not valid_token(token):
            return None
        if db is None:
            with self.connect() as conn:
                return self.admin_session(token, conn)
        row = db.execute("SELECT s.*,v.needs_change FROM admin_sessions s JOIN verifiers v ON v.role='admin' AND v.epoch=s.epoch WHERE s.token_hash=? AND s.expires>?", (token_hash(token), time.time())).fetchone()
        return dict(row) if row else None

    def require_admin(self, db, token, *, initial=False):
        session = self.admin_session(token, db)
        if not session or (session["needs_change"] and not initial):
            raise PermissionError("Administrator session unavailable")
        return session

    def claim_valid(self, token, db=None):
        if not valid_token(token):
            return False
        if db is None:
            with self.connect() as conn:
                return self.claim_valid(token, conn)
        row = db.execute("SELECT 1 FROM bootstrap WHERE id=1 AND token_hash=? AND expires>?", (token_hash(token), time.time())).fetchone()
        return bool(row)

    def new_bootstrap(self):
        token, expiry = secrets.token_urlsafe(32), time.time()+86400
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if not self.verifier("admin", db)["needs_change"]:
                raise ValueError("Administrator already initialized; default bootstrap is disabled")
            db.execute("INSERT OR REPLACE INTO bootstrap VALUES(1,?,?)", (token_hash(token), expiry))
            db.execute("DELETE FROM admin_sessions")
            self.event(db, "bootstrap_issued", {})
        return {"token": token, "expires": expiry}

    def _rate_allowed(self, client):
        now = time.monotonic()
        with self.lock:
            attempts = [t for t in self.rate.get(client, []) if now-t < 60]
            if len(self.rate) > 512:
                self.rate = {key:value for key,value in self.rate.items() if value and now-value[-1] < 60}
            if len(attempts) >= 5 or len(self.rate) > 1024:
                return False
            self.rate[client] = attempts+[now]
            return True

    def login(self, password, client, *, claim="", viewer=""):
        if not 1 <= len(password) <= 128 or not self._rate_allowed(client):
            return "rate", None
        admin = self.verifier("admin")
        if self.matches(password, admin) and (not admin["needs_change"] or self.claim_valid(claim)):
            token = secrets.token_urlsafe(32)
            with self.connect() as db:
                db.execute("BEGIN IMMEDIATE")
                current = self.verifier("admin", db)
                if current["epoch"] != admin["epoch"]:
                    return "wrong", None
                if current["needs_change"]:
                    if not self.claim_valid(claim, db):
                        return "wrong", None
                    db.execute("DELETE FROM bootstrap")
                db.execute("INSERT INTO admin_sessions VALUES(?,?,?,?)", (token_hash(token), current["epoch"], time.time(), time.time()+ADMIN_TTL))
                self.event(db, "admin_login", {"initial": bool(current["needs_change"])})
            return "admin", token
        access = self.verifier("access")
        if not self.matches(password, access):
            return "wrong", None
        token = secrets.token_urlsafe(32)
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if self.verifier("access", db)["epoch"] != access["epoch"]:
                return "wrong", None
            if valid_token(viewer) and db.execute("SELECT 1 FROM sessions WHERE token_hash=?", (token_hash(viewer),)).fetchone():
                return "reuse", None
            quota = db.execute("SELECT * FROM quota_v2 WHERE id=1").fetchone()
            if quota["remaining"] <= 0:
                return "exhausted", None
            db.execute("INSERT INTO sessions VALUES(?,?)", (token_hash(token), time.time()))
            db.execute("UPDATE quota_v2 SET remaining=remaining-1,used=used+1 WHERE id=1")
        return "viewer", token

    def unlock(self, password, client):
        result, token = self.login(password, client)
        return ("ok" if result == "viewer" else result), token

    def change_password(self, role, password, admin_token, *, current_password="", revoke_viewers=False):
        if role not in ("access", "admin") or not 1 <= len(password) <= 128:
            raise ValueError("密码长度应为 1–128 位。")
        if role == "admin" and (len(password) < 12 or password == DEFAULT_ADMIN_PASSWORD):
            raise ValueError("管理员新密码至少 12 位，且不能使用初始默认密码。")
        target, other = self.verifier(role), self.verifier("access" if role == "admin" else "admin")
        if self.matches(password, other):
            raise ValueError("访问密码与管理员密码必须不同。")
        if role == "admin" and not target["needs_change"] and not self.matches(current_password, target):
            raise ValueError("当前管理员密码不正确。")
        salt = secrets.token_hex(16)
        with self.hashlock:
            digest = password_digest(password, salt)
        new_token = secrets.token_urlsafe(32) if role == "admin" else None
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self.require_admin(db, admin_token, initial=(role == "admin"))
            if self.verifier(role, db)["epoch"] != target["epoch"] or self.verifier(other["role"], db)["epoch"] != other["epoch"]:
                raise ValueError("凭据状态已变化，请刷新后重试。")
            db.execute("UPDATE verifiers SET salt=?,digest=?,epoch=epoch+1,needs_change=0 WHERE role=?", (salt, digest, role))
            if role == "admin":
                db.execute("DELETE FROM admin_sessions")
                db.execute("DELETE FROM bootstrap")
                db.execute("INSERT INTO admin_sessions VALUES(?,?,?,?)", (token_hash(new_token), target["epoch"]+1, time.time(), time.time()+ADMIN_TTL))
            elif revoke_viewers:
                db.execute("DELETE FROM sessions")
            self.event(db, "password_changed", {"role": role, "revoke_viewers": revoke_viewers})
        return new_token

    def adjust_quota(self, admin_token, action, amount):
        if type(amount) is not int or not 0 <= amount <= MAX_QUOTA or action not in ("add", "subtract", "reset") or (action != "reset" and amount == 0):
            raise ValueError("请输入有效的次数。")
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self.require_admin(db, admin_token)
            row = db.execute("SELECT * FROM quota_v2 WHERE id=1").fetchone()
            value = row["remaining"]+amount if action == "add" else row["remaining"]-amount if action == "subtract" else amount
            if not 0 <= value <= MAX_QUOTA:
                raise ValueError("剩余次数不能小于 0 或超过 1000000。")
            if action == "reset":
                db.execute("UPDATE quota_v2 SET remaining=?,reset_value=?,used=0 WHERE id=1", (value, value))
            else:
                db.execute("UPDATE quota_v2 SET remaining=? WHERE id=1", (value,))
            self.event(db, "quota_changed", {"action": action, "amount": amount})

    def reset(self, operation_id, *, revoke_sessions=False):
        if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", operation_id):
            raise ValueError("Invalid operation ID")
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM reset_events WHERE operation_id=?", (operation_id,)).fetchone():
                return False
            db.execute("UPDATE quota_v2 SET remaining=reset_value,used=0 WHERE id=1")
            if revoke_sessions:
                db.execute("DELETE FROM sessions")
            db.execute("INSERT INTO reset_events VALUES(?,?,?)", (operation_id, time.time(), int(revoke_sessions)))
            self.event(db, "quota_reset_cli", {"operation": operation_id})
        return True


class ManagedCatalog:
    def __init__(self, store, files, manifest=None, *, max_upload=4*1024**3, reserve=1024**3):
        self.store, self.files = store, Path(files).resolve(strict=True)
        self.max_upload, self.reserve = max_upload, reserve
        self.lock, self.upload_slot = threading.RLock(), threading.Lock()
        self.cache = {}
        self.blocked = set()
        with store.connect() as db:
            imported = db.execute("SELECT catalog_imported FROM control_meta WHERE id=1").fetchone()[0]
        if not imported:
            asset = base.AssetCatalog(files, manifest).load() if manifest and Path(manifest).is_file() else None
            with store.connect() as db:
                db.execute("BEGIN IMMEDIATE")
                if not db.execute("SELECT catalog_imported FROM control_meta WHERE id=1").fetchone()[0]:
                    if asset:
                        file_id = secrets.token_hex(16)
                        db.execute("INSERT INTO files VALUES(?,?,?,?,?,?,'published',?,'')", (file_id, asset.filename, asset.path.name, asset.size, asset.sha256, json.dumps(asset.identity), time.time()))
                        self.cache[file_id] = asset
                    db.execute("UPDATE control_meta SET catalog_imported=1 WHERE id=1")
        with store.connect() as db:
            db.execute("UPDATE uploads SET status='interrupted',error='进程在上传完成前退出' WHERE status='writing'")
        # Verify once before listening, rather than hashing GiB files during an HTTP request.
        for row in self.rows():
            try:
                self.get(link_for(row))
            except (OSError,ValueError,KeyError,TypeError):
                self.blocked.add(row['id'])

    @staticmethod
    def validate_name(name):
        if not isinstance(name, str) or not name or name in (".", "..") or any(c in name for c in "/\\:") or any(ord(c)<32 or ord(c)==127 for c in name) or len(name.encode())>255:
            raise ValueError("文件名不合法。")
        return name

    def rows(self, *, all_files=False):
        with self.store.connect() as db:
            query = "SELECT * FROM files" + ("" if all_files else " WHERE status='published'") + " ORDER BY created DESC,id"
            return [dict(row) for row in db.execute(query)]

    def interrupted(self):
        with self.store.connect() as db:
            return [dict(row) for row in db.execute("SELECT * FROM uploads WHERE status IN ('interrupted','failed') ORDER BY created DESC")]

    def get(self, url):
        with self.lock:
            for row in self.rows():
                expected = "/download/"+row["sha256"]+"/"+urllib.parse.quote(row["name"], safe="")
                if url != expected:
                    continue
                if row['id'] in self.blocked:
                    raise ValueError('File verification failed at startup')
                path = self.files/self.validate_storage(row["storage"])
                with base.open_regular(path) as source:
                    info = os.fstat(source.fileno())
                    key = base.identity(info)
                    asset = base.Asset(path, row["name"], row["size"], row["sha256"], key)
                    if key != tuple(json.loads(row["identity_json"])) or info.st_size != row["size"]:
                        raise ValueError("File identity changed")
                    if self.cache.get(row["id"]) != asset:
                        if base.hash_file(source) != row["sha256"] or base.identity(os.fstat(source.fileno())) != key:
                            raise ValueError("File integrity mismatch")
                        self.cache[row["id"]] = asset
                    return asset
        return None

    @staticmethod
    def validate_storage(name):
        return ManagedCatalog.validate_name(name)

    def receive(self, source, size, name, admin_token):
        name = self.validate_name(name)
        if not 0 <= size <= self.max_upload:
            raise OverflowError("文件超过上传大小限制。")
        if shutil.disk_usage(self.files).free-size < self.reserve:
            raise OSError("服务器可用空间不足，已保留安全余量。")
        if not self.upload_slot.acquire(False):
            raise BlockingIOError("已有上传进行中，请稍后重试。")
        upload_id = secrets.token_hex(16)
        storage = ".payload-"+upload_id
        path = self.files/storage
        created, file_identity, published = False, None, False
        try:
            with self.store.connect() as db:
                db.execute("BEGIN IMMEDIATE")
                self.store.require_admin(db, admin_token)
                db.execute("INSERT INTO uploads VALUES(?,?,?,?,NULL,'writing',?,'')", (upload_id, name, storage, size, time.time()))
            with path.open("xb") as out:
                created = True
                if os.name == "posix":
                    os.chmod(path, 0o600)
                file_identity = base.identity(os.fstat(out.fileno()))
                with self.store.connect() as db:
                    db.execute("UPDATE uploads SET identity_json=? WHERE id=?", (json.dumps(file_identity), upload_id))
                digest, received, checkpoint = hashlib.sha256(), 0, 0
                while received < size:
                    chunk = source.read(min(1024*1024, size-received))
                    if not chunk:
                        raise ValueError("上传在传输完成前中断。")
                    out.write(chunk)
                    digest.update(chunk)
                    received += len(chunk)
                    if received-checkpoint >= 8*1024*1024:
                        checkpoint = received
                        if not self.store.admin_session(admin_token) or shutil.disk_usage(self.files).free < self.reserve:
                            raise PermissionError("上传已取消：会话失效或可用空间不足。")
                out.flush()
                os.fsync(out.fileno())
                file_identity = base.identity(os.fstat(out.fileno()))
            sha = digest.hexdigest()
            if os.name == "posix":
                fd = os.open(self.files, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
            with self.lock, self.store.connect() as db:
                db.execute("BEGIN IMMEDIATE")
                self.store.require_admin(db, admin_token)
                duplicate = db.execute("SELECT id FROM files WHERE name=? AND sha256=? AND status='published'", (name, sha)).fetchone()
                file_id = duplicate["id"] if duplicate else secrets.token_hex(16)
                if not duplicate:
                    db.execute("INSERT INTO files VALUES(?,?,?,?,?,?,'published',?,'')", (file_id, name, storage, size, sha, json.dumps(file_identity), time.time()))
                    self.cache[file_id] = base.Asset(path,name,size,sha,file_identity)
                db.execute("UPDATE uploads SET status=? WHERE id=?", ("duplicate" if duplicate else "complete", upload_id))
                self.store.event(db, "file_uploaded", {"file_id": file_id, "bytes": size, "duplicate": bool(duplicate)})
            published = not bool(duplicate)
            return {"id": file_id, "name": name, "bytes": size, "sha256": sha, "duplicate": bool(duplicate)}
        except Exception:
            with self.store.connect() as db:
                db.execute("UPDATE uploads SET status='failed',error='上传未完成，未发布' WHERE id=? AND status='writing'", (upload_id,))
            raise
        finally:
            if created and not published:
                try:
                    with self.store.connect() as db:
                        published = bool(db.execute("SELECT 1 FROM files WHERE storage=?",(storage,)).fetchone())
                except (OSError,sqlite3.Error):
                    published = True  # Unknown commit outcome: preserve, never delete a possibly published file.
            if created and not published:
                try:
                    info = path.lstat()
                    if file_identity and (info.st_dev, info.st_ino) == tuple(file_identity[:2]) and not path.is_symlink():
                        path.unlink()
                except OSError:
                    pass
            self.upload_slot.release()

    def delete(self, file_id, sha, admin_token):
        with self.lock:
            with self.store.connect() as db:
                db.execute("BEGIN IMMEDIATE")
                self.store.require_admin(db, admin_token)
                row = db.execute("SELECT * FROM files WHERE id=? AND sha256=?", (file_id, sha)).fetchone()
                if not row:
                    raise KeyError("文件记录不存在。")
                if row["status"] == "deleted":
                    return
                db.execute("UPDATE files SET status='delete_pending',error='' WHERE id=?", (file_id,))
                self.store.event(db, "file_delete_requested", {"file_id": file_id})
            self.cache.pop(file_id, None)
            path = self.files/self.validate_storage(row["storage"])
            status, error = "deleted", ""
            try:
                info = path.lstat()
                if path.is_symlink() or base.identity(info) != tuple(json.loads(row["identity_json"])):
                    raise ValueError("文件身份已变化，已阻断清理，请人工核对。")
                path.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                status, error = "delete_pending", "文件暂被占用或无法删除，可稍后重试。"
            except ValueError as exc:
                status, error = "delete_pending", str(exc)
            with self.store.connect() as db:
                db.execute("UPDATE files SET status=?,error=? WHERE id=?", (status, error, file_id))

    def delete_incomplete(self, upload_id, admin_token):
        with self.lock:
            with self.store.connect() as db:
                db.execute("BEGIN IMMEDIATE")
                self.store.require_admin(db, admin_token)
                row = db.execute("SELECT * FROM uploads WHERE id=? AND status IN ('interrupted','failed')", (upload_id,)).fetchone()
                if not row:
                    raise KeyError("未完成上传记录不存在。")
            path = self.files/self.validate_storage(row["storage"])
            if path.exists():
                info = path.lstat()
                expected = json.loads(row["identity_json"]) if row["identity_json"] else None
                if not expected or path.is_symlink() or (info.st_dev, info.st_ino) != tuple(expected[:2]):
                    raise ValueError("临时文件身份无法确认，未执行清理。")
                path.unlink()
            with self.store.connect() as db:
                db.execute("UPDATE uploads SET status='cleaned',error='' WHERE id=?", (upload_id,))
                self.store.event(db, "incomplete_upload_removed", {"upload_id": upload_id})


def cookie(name, token, age=None):
    return name+"="+token+"; Path=/; Secure; HttpOnly; SameSite=Strict"+("; Max-Age="+str(age) if age is not None else "")


def link_for(row):
    return "/download/"+row["sha256"]+"/"+urllib.parse.quote(row["name"], safe="")


def console_page(body):
    style = base.STYLE + "main{max-width:960px;margin:5vh auto}section{padding:22px 0;border-top:1px solid #8884}label{display:block;margin:12px 0 5px}.row{display:flex;gap:12px;align-items:center;flex-wrap:wrap}.row input{width:160px}input[type=checkbox]{width:auto}button.danger{background:#9b3535;color:white}.file{padding:16px 0;border-top:1px solid #8883;overflow-wrap:anywhere}progress{width:100%}.muted{color:#7c8590}code{overflow-wrap:anywhere}h2{font-size:20px}"
    return ('<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>文件管理</title><style>'+style+'</style><main>'+body+'</main><script src="/admin/app.js" defer></script></html>').encode()


class AdminService:
    def __init__(self, state, files, manifest, origin, *, max_upload=4*1024**3, reserve=1024**3, legacy_session_cookie=None, legacy_csrf_cookie=None, legacy_downloads=None, trust_proxy=False):
        self.store = ControlStore(state)
        self.catalog = ManagedCatalog(self.store, files, manifest, max_upload=max_upload, reserve=reserve)
        self.origin, self.legacy_session_cookie, self.legacy_csrf_cookie = origin, legacy_session_cookie, legacy_csrf_cookie
        self.legacy_downloads, self.trust_proxy = legacy_downloads or {}, trust_proxy

    @staticmethod
    def admin_token(handler):
        return handler.cookies().get(ADMIN_COOKIE, "")

    def can_download(self, handler):
        session = self.store.admin_session(self.admin_token(handler))
        return bool(session and not session["needs_change"])

    def viewer_token(self, handler):
        jar = handler.cookies()
        for name in (base.SESSION_COOKIE, self.legacy_session_cookie):
            if name and self.store.valid(jar.get(name, "")):
                return jar[name]
        return ""

    def login_form(self, handler, message="", status=200):
        csrf = secrets.token_urlsafe(32)
        body = '<h1>文件传输</h1>'+message+'<form method="post" action="/unlock"><input type="hidden" name="csrf" value="'+csrf+'"><label for="password">请输入密码</label><input id="password" type="password" name="password" autocomplete="current-password" required maxlength="128"><p><button type="submit">进入</button></p></form>'
        handler.reply(status, base.page(body), [("Set-Cookie", cookie(base.CSRF_COOKIE, csrf, 600))])

    def dashboard(self, handler, session):
        token = self.admin_token(handler)
        csrf = '<input type="hidden" name="csrf" value="'+csrf_for(token)+'">'
        def form(action, content):
            return '<form method="post" action="'+action+'">'+csrf+content+'</form>'
        initial = bool(session["needs_change"])
        password_fields = '<input type="hidden" name="role" value="admin">'
        if not initial:
            password_fields += '<label>当前管理员密码</label><input type="password" name="current" autocomplete="current-password" required maxlength="128">'
        password_fields += '<label>新管理员密码（至少 12 位）</label><input type="password" name="password" autocomplete="new-password" minlength="12" maxlength="128" required><label>再次输入</label><input type="password" name="confirm" autocomplete="new-password" minlength="12" maxlength="128" required><p><button>保存管理员密码</button></p>'
        body = '<h1>'+('首次设置' if initial else '文件管理')+'</h1><p>'+('请先设置新的管理员密码，再使用管理功能。' if initial else '管理传输文件与访问权限。')+'</p>'
        if initial:
            body += form('/admin/password', password_fields)
        else:
            quota = self.store.quota()
            body += '<section><h2>解锁额度</h2><p>剩余 <strong>'+str(quota["remaining"])+'</strong> 次 · 自上次重置已成功解锁 '+str(quota["used"])+' 次</p><p class="muted">访客页面不显示次数；现有会话刷新、下载与续传不重复计数。</p>'
            for action, label, value in [('add','增加',1),('subtract','减少',1),('reset','重置为',quota['reset_value'])]:
                body += form('/admin/quota','<div class="row"><input type="hidden" name="action" value="'+action+'"><input type="number" name="amount" min="'+('0' if action=='reset' else '1')+'" max="1000000" value="'+str(value)+'" aria-label="'+label+'次数" required><button>'+label+'</button></div>')
            body += '</section><section><h2>访问密码</h2>'+form('/admin/password','<input type="hidden" name="role" value="access"><label>新访问密码</label><input type="password" name="password" autocomplete="new-password" maxlength="128" required><label>再次输入</label><input type="password" name="confirm" autocomplete="new-password" maxlength="128" required><label><input type="checkbox" name="revoke" value="yes"> 同时撤销已有访客会话</label><p><button>保存访问密码</button></p>')+'</section>'
            body += '<section><h2>上传文件</h2><p>单文件最多 '+format(self.catalog.max_upload/2**30,'.2f')+' GiB；保留 '+format(self.catalog.reserve/2**30,'.2f')+' GiB 磁盘余量。完整上传后发布。</p><form id="upload-form" data-csrf="'+csrf_for(token)+'"><input type="file" id="upload-file" required aria-label="选择上传文件"><p><button id="upload-start">上传</button> <button id="upload-cancel" type="button" hidden>取消</button></p><progress id="upload-progress" value="0" max="100" hidden></progress><p id="upload-status" role="status"></p></form></section><section><h2>文件列表</h2>'
            rows = self.catalog.rows(all_files=True)
            active = [row for row in rows if row['status']!='deleted']
            if not active:
                body += '<p class="muted">暂无文件。</p>'
            for row in active:
                body += '<div class="file"><strong>'+html.escape(row['name'])+'</strong><p>'+format(row['size']/2**20,'.2f')+' MiB · '+('可下载' if row['status']=='published' else '删除待处理')+'</p><small>SHA-256 '+row['sha256']+'</small><p>'
                if row['status']=='published':
                    body += '<a href="'+link_for(row)+'">下载</a>'
                if row['error']:
                    body += html.escape(row['error'])
                body += '</p>'+form('/admin/delete','<input type="hidden" name="id" value="'+row['id']+'"><input type="hidden" name="sha" value="'+row['sha256']+'"><button class="danger" data-confirm="确认删除此文件？删除后无法从网站恢复。">'+('删除文件' if row['status']=='published' else '重试删除')+'</button>')+'</div>'
            for row in self.catalog.interrupted():
                body += '<div class="file"><strong>未完成上传：'+html.escape(row['name'])+'</strong><p>未向访客发布。</p>'+form('/admin/cleanup','<input type="hidden" name="id" value="'+row['id']+'"><button class="danger" data-confirm="确认清理此未完成上传？">清理残留</button>')+'</div>'
            body += '</section><section><h2>管理员密码</h2>'+form('/admin/password',password_fields)+'</section>'
        body += '<section>'+form('/admin/logout','<button>退出管理</button>')+'</section>'
        handler.reply(200, console_page(body))

    def handle_get(self, handler):
        path = handler.path
        if path.startswith('/admin/activate/'):
            token = path.removeprefix('/admin/activate/')
            handler.referrer_policy = 'no-referrer'
            if not self.store.claim_valid(token):
                handler.reply(403, base.page('<h1>激活链接已失效</h1><p>请联系管理员。</p>'))
            else:
                handler.reply(303, extra=[('Location','/'),('Set-Cookie',cookie(CLAIM_COOKIE,token,600))])
            return True
        if path == '/admin/app.js':
            if not self.store.admin_session(self.admin_token(handler)):
                handler.reply(403)
            else:
                data = (Path(__file__).parent/'static'/'admin.js').read_bytes()
                handler.send_response(200)
                handler.common_headers()
                handler.send_header('Content-Type','text/javascript; charset=utf-8')
                handler.send_header('Content-Length',str(len(data)))
                handler.send_header('Connection','close')
                handler.end_headers()
                if handler.command != 'HEAD':
                    handler.wfile.write(data)
                handler.close_connection = True
            return True
        if path == '/admin':
            session = self.store.admin_session(self.admin_token(handler))
            if session:
                self.dashboard(handler,session)
            else:
                handler.reply(303,extra=[('Location','/')])
            return True
        if path == '/':
            if self.store.admin_session(self.admin_token(handler)):
                handler.reply(303,extra=[('Location','/admin')])
            elif self.viewer_token(handler):
                handler.auth()  # Migrate legacy viewer cookie without charging another unlock.
                body = '<h1>文件已就绪</h1>'
                rows = self.catalog.rows()
                if not rows:
                    body += '<p>暂无可下载文件，请联系管理员。</p>'
                for row in rows:
                    body += '<div><p>'+html.escape(row['name'])+'</p><a class="button" href="'+link_for(row)+'">下载 · '+format(row['size']/2**30,'.2f')+' GiB</a><p><small>SHA-256 '+row['sha256']+'</small></p></div>'
                csrf = secrets.token_urlsafe(32)
                body += '<p>支持断点续传。</p><details><summary>使用其他密码</summary><form method="post" action="/unlock"><input type="hidden" name="csrf" value="'+csrf+'"><input type="password" name="password" maxlength="128" autocomplete="current-password" required aria-label="密码"><p><button>进入</button></p></form></details>'
                handler.reply(200,base.page(body),[('Set-Cookie',cookie(base.CSRF_COOKIE,csrf,600))])
            else:
                exhausted = self.store.quota()['remaining']==0
                self.login_form(handler,'<p>当前入口暂不可解锁，请联系管理员。</p>' if exhausted else '<p>请输入访问密码。</p>')
            return True
        if path.startswith('/download/') or path in self.legacy_downloads:
            if not handler.auth():
                return False
            url = path
            if path in self.legacy_downloads:
                row = next((r for r in self.catalog.rows() if r['sha256']==self.legacy_downloads[path]),None)
                url = link_for(row) if row else ''
            try:
                asset = self.catalog.get(url)
            except (OSError,ValueError,KeyError,TypeError):
                handler.reply(503,base.UNAVAILABLE)
                return True
            if asset is None:
                handler.reply(410,base.UPDATED)
                return True
            handler.selected_asset = asset
            return False
        return False

    def fields(self, handler):
        if handler.headers.get('Transfer-Encoding') or handler.headers.get('Content-Encoding'):
            raise ValueError('不支持此请求编码。')
        length = int(handler.headers.get('Content-Length','0'))
        if not 0 < length <= 16384:
            raise ValueError('请求大小不合法。')
        body = handler.rfile.read(length)
        if len(body)!=length:
            raise ValueError('请求未完成。')
        fields = urllib.parse.parse_qs(body.decode('utf-8'),strict_parsing=True,max_num_fields=12)
        if any(len(values)!=1 for values in fields.values()):
            raise ValueError('重复的请求字段。')
        return {key:values[0] for key,values in fields.items()}

    def authorize_post(self, handler, csrf):
        token = self.admin_token(handler)
        if handler.headers.get('Origin') != self.origin or not valid_token(token) or not hmac.compare_digest(csrf_for(token),csrf):
            raise PermissionError('请求验证失败，请刷新后重试。')
        with self.store.connect() as db:
            self.store.require_admin(db,token,initial=(handler.path in ('/admin/password','/admin/logout')))
        return token

    def upload_parameters(self, handler):
        token = self.authorize_post(handler,handler.headers.get('X-CSRF-Token',''))
        if handler.headers.get('Transfer-Encoding') or handler.headers.get('Content-Encoding') or not re.fullmatch(r'\d{1,12}',handler.headers.get('Content-Length','')):
            raise ValueError('上传需要明确的文件长度。')
        size = int(handler.headers['Content-Length'])
        name = self.catalog.validate_name(urllib.parse.unquote(handler.headers.get('X-File-Name',''),errors='strict'))
        if size > self.catalog.max_upload:
            raise OverflowError('文件超过上传大小限制。')
        if shutil.disk_usage(self.catalog.files).free-size < self.catalog.reserve:
            raise OSError('服务器空间不足。')
        return token,size,name

    def preflight_upload(self, handler):
        try:
            self.upload_parameters(handler)
            return True
        except (ValueError,PermissionError,OverflowError,OSError):
            handler.reply(403,base.page('<h1>上传请求未通过验证</h1>'))
            return False

    def handle_post(self, handler):
        if handler.path != '/unlock' and not handler.path.startswith('/admin/'):
            return False
        upload = handler.path=='/admin/upload'
        try:
            if handler.path == '/unlock':
                if handler.headers.get('Origin') not in (None,self.origin):
                    raise PermissionError('请求来源不匹配。')
                fields = self.fields(handler)
                csrf, password = fields.get('csrf',''), fields.get('password','')
                jar = handler.cookies()
                names = (base.CSRF_COOKIE,self.legacy_csrf_cookie)
                if not valid_token(csrf) or not any(hmac.compare_digest(csrf,jar.get(name,'')) for name in names if name):
                    raise PermissionError('登录页面已过期，请返回首页刷新。')
                if not 1 <= len(password) <= 128:
                    raise ValueError('密码长度不合法。')
                client = handler.headers.get('X-Real-IP',handler.client_address[0]) if self.trust_proxy else handler.client_address[0]
                result, token = self.store.login(password,client,claim=jar.get(CLAIM_COOKIE,''),viewer=self.viewer_token(handler))
                if result == 'admin':
                    handler.reply(303,extra=[('Location','/admin'),('Set-Cookie',cookie(ADMIN_COOKIE,token,ADMIN_TTL)),('Set-Cookie',cookie(CLAIM_COOKIE,'',0))])
                elif result in ('viewer','reuse'):
                    headers = [('Location','/')]
                    if token:
                        headers.append(('Set-Cookie',cookie(base.SESSION_COOKIE,token)))
                    handler.reply(303,extra=headers)
                else:
                    self.login_form(handler,'<p>'+('请稍后重试。' if result=='rate' else '当前入口暂不可解锁，请联系管理员。' if result=='exhausted' else '密码不正确，请重试。')+'</p>',429 if result=='rate' else 403)
                return True
            if upload:
                token,size,name = self.upload_parameters(handler)
                result = self.catalog.receive(handler.rfile,size,name,token)
                handler.reply(201,json.dumps(result,ensure_ascii=False).encode(),[('Content-Type','application/json; charset=utf-8')])
                return True
            fields = self.fields(handler)
            token = self.authorize_post(handler,fields.get('csrf',''))
            if handler.path == '/admin/password':
                if fields.get('password') != fields.get('confirm'):
                    raise ValueError('两次输入的密码不一致。')
                renewed = self.store.change_password(fields.get('role'),fields.get('password',''),token,current_password=fields.get('current',''),revoke_viewers=fields.get('revoke')=='yes')
                headers = [('Location','/admin')]
                if renewed:
                    headers.append(('Set-Cookie',cookie(ADMIN_COOKIE,renewed,ADMIN_TTL)))
                handler.reply(303,extra=headers)
                return True
            if handler.path == '/admin/quota':
                amount = fields.get('amount','')
                if not re.fullmatch(r'\d{1,7}',amount):
                    raise ValueError('请输入有效的次数。')
                self.store.adjust_quota(token,fields.get('action'),int(amount))
            elif handler.path == '/admin/delete':
                self.catalog.delete(fields.get('id',''),fields.get('sha',''),token)
            elif handler.path == '/admin/cleanup':
                self.catalog.delete_incomplete(fields.get('id',''),token)
            elif handler.path == '/admin/logout':
                with self.store.connect() as db:
                    db.execute('DELETE FROM admin_sessions WHERE token_hash=?',(token_hash(token),))
                handler.reply(303,extra=[('Location','/'),('Set-Cookie',cookie(ADMIN_COOKIE,'',0))])
                return True
            else:
                handler.reply(404)
                return True
            handler.reply(303,extra=[('Location','/admin')])
        except (ValueError,UnicodeError,KeyError,PermissionError,OverflowError,BlockingIOError,OSError,sqlite3.Error) as exc:
            status = 403 if isinstance(exc,PermissionError) else 413 if isinstance(exc,OverflowError) else 409 if isinstance(exc,BlockingIOError) else 507 if isinstance(exc,OSError) else 503 if isinstance(exc,sqlite3.Error) else 400
            message = str(exc) if isinstance(exc,(ValueError,PermissionError,OverflowError,BlockingIOError)) else '操作未完成，请稍后重试或联系管理员。'
            if upload:
                handler.reply(status,json.dumps({'error':message},ensure_ascii=False).encode(),[('Content-Type','application/json; charset=utf-8')])
            else:
                handler.reply(status,base.page('<h1>操作未完成</h1><p>'+html.escape(message)+'</p><p><a href="/admin">返回</a></p>'))
        return True
