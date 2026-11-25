import concurrent.futures
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.parse
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import transfer_server as base
import admin_service as admin

ORIGIN = 'https://files.example.com'


class Fixture:
    def setup_files(self, *, manifest=True):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state, self.files = self.root/'state', self.root/'files'
        self.files.mkdir()
        self.access = secrets.token_urlsafe(20)
        self.password = 'private-admin-'+secrets.token_urlsafe(20)
        base.init_state(self.state,self.access)
        self.original = self.files/'example.zip'
        self.data = b'original payload\0'+os.urandom(512)
        self.original.write_bytes(self.data)
        self.manifest = self.files/'current.json' if manifest else None
        if self.manifest:
            base.prepare_manifest(self.original,self.manifest)
        self.service = admin.AdminService(self.state,self.files,self.manifest,ORIGIN,reserve=0,max_upload=1024*1024)
        self.store, self.catalog = self.service.store,self.service.catalog
        self.sequence = 0

    def login(self, password=None, **kwargs):
        self.sequence += 1
        return self.store.login(password or self.access,'test-'+str(self.sequence),**kwargs)

    def owner(self):
        claim = self.store.new_bootstrap()['token']
        result, token = self.login(admin.DEFAULT_ADMIN_PASSWORD,claim=claim)
        self.assertEqual(result,'admin')
        return self.store.change_password('admin',self.password,token)

    def start_http(self):
        self.server = base.create_server('127.0.0.1',0,self.state,self.files,self.manifest,ORIGIN,extension=self.service)
        self.thread = threading.Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_http)

    def stop_http(self):
        if getattr(self,'server',None):
            self.server.shutdown()
            self.server.server_close()
            self.thread.join(5)
            self.server = None

    def request(self,method,path,body=None,headers=None):
        conn = http.client.HTTPConnection('127.0.0.1',self.server.server_port,timeout=10)
        conn.request(method,path,body,headers or {})
        response = conn.getresponse()
        result = response.status,dict(response.getheaders()),response.read(),response.getheaders()
        conn.close()
        return result

    def post(self,path,fields,token=None,origin=ORIGIN):
        headers = {'Origin':origin,'Content-Type':'application/x-www-form-urlencoded'}
        fields = dict(fields)
        if token:
            headers['Cookie'] = admin.ADMIN_COOKIE+'='+token
            fields.setdefault('csrf',admin.csrf_for(token))
        return self.request('POST',path,urllib.parse.urlencode(fields),headers)


class ControlStoreTests(Fixture,unittest.TestCase):
    def setUp(self):
        self.setup_files()

    def test_migration_preserves_verifier_quota_and_sessions(self):
        state = self.root/'legacy'
        base.init_state(state,self.access)
        old = base.Store(state)
        tokens = [old.unlock(self.access,str(i))[1] for i in range(2)]
        config = (state/'config.json').read_bytes()
        new = admin.ControlStore(state)
        self.assertEqual(new.quota()['remaining'],1)
        self.assertEqual(new.used(),2)
        self.assertTrue(all(new.valid(token) for token in tokens))
        self.assertEqual((state/'config.json').read_bytes(),config)
        self.assertEqual(base.Store(state).used(),3)
        self.assertEqual(admin.ControlStore(state).quota()['remaining'],1)
        self.assertTrue(admin.control_enabled(state))

    def test_plain_default_password_cannot_enter_admin(self):
        self.assertEqual(self.login(admin.DEFAULT_ADMIN_PASSWORD)[0],'wrong')
        self.assertEqual(self.store.quota()['remaining'],3)
        with self.store.connect() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM admin_sessions').fetchone()[0],0)

    def test_bootstrap_restricted_until_password_changed_and_consumed_once(self):
        claim = self.store.new_bootstrap()['token']
        result, token = self.login(admin.DEFAULT_ADMIN_PASSWORD,claim=claim)
        self.assertEqual(result,'admin')
        self.assertTrue(self.store.admin_session(token)['needs_change'])
        self.assertFalse(self.store.claim_valid(claim))
        self.assertEqual(self.login(admin.DEFAULT_ADMIN_PASSWORD,claim=claim)[0],'wrong')
        with self.assertRaises(PermissionError):
            self.store.adjust_quota(token,'add',1)
        with self.assertRaises(PermissionError):
            self.store.change_password('access','other',token)
        with self.assertRaises(ValueError):
            self.store.change_password('admin','short',token)
        new = self.store.change_password('admin',self.password,token)
        self.assertFalse(self.store.admin_session(token))
        self.assertFalse(self.store.admin_session(new)['needs_change'])
        with self.assertRaises(ValueError):
            self.store.new_bootstrap()

    def test_expired_bootstrap_rejected(self):
        claim = self.store.new_bootstrap()['token']
        with self.store.connect() as db:
            db.execute('UPDATE bootstrap SET expires=0')
        self.assertFalse(self.store.claim_valid(claim))
        self.assertEqual(self.login(admin.DEFAULT_ADMIN_PASSWORD,claim=claim)[0],'wrong')

    def test_admin_login_with_exhausted_quota_does_not_charge(self):
        token = self.owner()
        self.store.adjust_quota(token,'reset',0)
        self.assertEqual(self.login(self.password)[0],'admin')
        self.assertEqual(self.store.quota()['remaining'],0)
        self.assertEqual(self.login()[0],'exhausted')

    def test_password_change_and_optional_viewer_revocation(self):
        token = self.owner()
        viewer = self.login()[1]
        self.store.change_password('access','new-access',token)
        self.assertEqual(self.login(self.access)[0],'wrong')
        self.assertTrue(self.store.valid(viewer))
        self.assertEqual(self.login('new-access')[0],'viewer')
        self.store.change_password('access','another-access',token,revoke_viewers=True)
        self.assertFalse(self.store.valid(viewer))
        self.assertEqual(self.login('another-access')[0],'viewer')

    def test_admin_change_requires_current_password_and_rotates_sessions(self):
        token = self.owner()
        second = self.login(self.password)[1]
        with self.assertRaises(ValueError):
            self.store.change_password('admin','another-long-password',token,current_password='wrong')
        renewed = self.store.change_password('admin','another-long-password',token,current_password=self.password)
        self.assertTrue(self.store.admin_session(renewed))
        self.assertFalse(self.store.admin_session(token))
        self.assertFalse(self.store.admin_session(second))
        self.assertEqual(self.login(self.password)[0],'wrong')
        self.assertEqual(self.login('another-long-password')[0],'admin')

    def test_password_roles_must_differ(self):
        token = self.owner()
        with self.assertRaises(ValueError):
            self.store.change_password('access',self.password,token)
        with self.assertRaises(ValueError):
            self.store.change_password('admin',self.access,token,current_password=self.password)

    def test_quota_controls_and_idempotent_cli_reset(self):
        token = self.owner()
        self.store.adjust_quota(token,'add',4)
        self.store.adjust_quota(token,'subtract',2)
        self.assertEqual(self.store.quota()['remaining'],5)
        self.store.adjust_quota(token,'reset',8)
        viewer = self.login()[1]
        self.assertEqual(self.store.quota()['remaining'],7)
        self.assertTrue(self.store.reset('reset-1'))
        self.assertEqual(self.store.quota()['remaining'],8)
        self.login()
        self.assertFalse(self.store.reset('reset-1'))
        self.assertEqual(self.store.quota()['remaining'],7)
        self.assertTrue(self.store.valid(viewer))
        for action,amount in [('add',0),('subtract',9),('reset',-1),('reset',1000001),('arbitrary',2)]:
            with self.assertRaises(ValueError):
                self.store.adjust_quota(token,action,amount)

    def test_concurrent_viewers_capped_and_existing_session_reuses(self):
        self.owner()
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(lambda i:self.store.login(self.access,'client-'+str(i)),range(6)))
        self.assertEqual(sum(result=='viewer' for result,_ in results),3)
        token = next(token for result,token in results if result=='viewer')
        self.assertEqual(self.login(viewer=token)[0],'reuse')
        self.assertEqual(self.store.used(),3)

    def test_concurrent_admin_quota_adjustments_do_not_lose_updates(self):
        token = self.owner()
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda _:self.store.adjust_quota(token,'add',1),range(20)))
        self.assertEqual(self.store.quota()['remaining'],23)

    def test_credentials_and_tokens_are_not_plaintext_on_disk(self):
        claim = self.store.new_bootstrap()['token']
        limited = self.login(admin.DEFAULT_ADMIN_PASSWORD,claim=claim)[1]
        token = self.store.change_password('admin',self.password,limited)
        viewer = self.login()[1]
        for file in self.state.iterdir():
            if file.is_file():
                data = file.read_bytes()
                for secret in [self.access,self.password,admin.DEFAULT_ADMIN_PASSWORD,claim,limited,token,viewer]:
                    self.assertNotIn(secret.encode(),data)

    def test_unknown_control_version_fails_closed(self):
        with self.store.connect() as db:
            db.execute('UPDATE control_meta SET version=999')
        with self.assertRaises(ValueError):
            admin.ControlStore(self.state)

    def test_v1_mode_refuses_migrated_database(self):
        with self.assertRaises(ValueError):
            base.create_server('127.0.0.1',0,self.state,self.files,self.manifest,ORIGIN)


class CatalogTests(Fixture,unittest.TestCase):
    def setUp(self):
        self.setup_files()
        self.token = self.owner()

    def test_upload_exact_bytes_hash_and_duplicate(self):
        payload = os.urandom(3212)
        before = self.store.quota()
        result = self.catalog.receive(io.BytesIO(payload),len(payload),'中文.zip',self.token)
        row = next(row for row in self.catalog.rows() if row['id']==result['id'])
        asset = self.catalog.get(admin.link_for(row))
        self.assertEqual(asset.path.read_bytes(),payload)
        self.assertEqual(result['sha256'],hashlib.sha256(payload).hexdigest())
        duplicate = self.catalog.receive(io.BytesIO(payload),len(payload),'中文.zip',self.token)
        self.assertTrue(duplicate['duplicate'])
        self.assertEqual(duplicate['id'],result['id'])
        self.assertEqual(len(self.catalog.rows()),2)
        self.assertEqual(self.store.quota(),before)
        self.assertEqual(len(list(self.files.glob('.payload-*'))),1)

    def test_empty_upload(self):
        result = self.catalog.receive(io.BytesIO(b''),0,'empty.txt',self.token)
        self.assertEqual(result['sha256'],hashlib.sha256(b'').hexdigest())

    def test_upload_limits_and_names_before_create(self):
        before = set(self.files.iterdir())
        for name in ['../outside','a/b','a\\b','C:foo','\x00bad','..','x'*256]:
            with self.assertRaises(ValueError):
                self.catalog.receive(io.BytesIO(b'a'),1,name,self.token)
        with self.assertRaises(OverflowError):
            self.catalog.receive(io.BytesIO(b''),self.catalog.max_upload+1,'large.zip',self.token)
        with mock.patch.object(admin.shutil,'disk_usage',return_value=type('Disk',(),{'free':0})()):
            with self.assertRaises(OSError):
                self.catalog.receive(io.BytesIO(b'a'),1,'full.zip',self.token)
        self.assertEqual(set(self.files.iterdir()),before)

    def test_partial_upload_not_published_and_owned_temp_removed(self):
        with self.assertRaises(ValueError):
            self.catalog.receive(io.BytesIO(b'short'),100,'broken.zip',self.token)
        self.assertEqual(len(self.catalog.rows()),1)
        self.assertEqual(list(self.files.glob('.payload-*')),[])
        self.assertEqual(self.catalog.interrupted()[0]['status'],'failed')

    def test_upload_rechecks_admin_at_publish(self):
        stream = io.BytesIO(b'payload')
        original_read = stream.read
        def read(size):
            data = original_read(size)
            with self.store.connect() as db:
                db.execute('DELETE FROM admin_sessions')
            return data
        stream.read = read
        with self.assertRaises(PermissionError):
            self.catalog.receive(stream,7,'revoked.zip',self.token)
        self.assertEqual(len(self.catalog.rows()),1)
        self.assertEqual(list(self.files.glob('.payload-*')),[])

    def test_single_active_upload(self):
        self.catalog.upload_slot.acquire()
        try:
            with self.assertRaises(BlockingIOError):
                self.catalog.receive(io.BytesIO(b'a'),1,'a',self.token)
        finally:
            self.catalog.upload_slot.release()

    def test_delete_and_restart_do_not_resurrect_manifest(self):
        row = self.catalog.rows()[0]
        url = admin.link_for(row)
        self.catalog.delete(row['id'],row['sha256'],self.token)
        self.assertFalse(self.original.exists())
        self.assertIsNone(self.catalog.get(url))
        reopened = admin.AdminService(self.state,self.files,self.manifest,ORIGIN,reserve=0)
        self.assertEqual(reopened.catalog.rows(),[])
        self.assertTrue(reopened.store.admin_session(self.token))

    def test_changed_file_not_deleted_or_served(self):
        row = self.catalog.rows()[0]
        self.original.write_bytes(b'changed')
        with self.assertRaises(ValueError):
            self.catalog.get(admin.link_for(row))
        self.catalog.delete(row['id'],row['sha256'],self.token)
        self.assertEqual(self.original.read_bytes(),b'changed')
        self.assertEqual(self.catalog.rows(),[])
        self.assertEqual(self.catalog.rows(all_files=True)[0]['status'],'delete_pending')

    def test_failed_unlink_stays_blocked_and_can_retry(self):
        row = self.catalog.rows()[0]
        with mock.patch.object(Path,'unlink',side_effect=PermissionError('busy')):
            self.catalog.delete(row['id'],row['sha256'],self.token)
        self.assertTrue(self.original.exists())
        self.assertEqual(self.catalog.rows(),[])
        self.catalog.delete(row['id'],row['sha256'],self.token)
        self.assertFalse(self.original.exists())

    def test_interrupted_upload_recovery_and_explicit_cleanup(self):
        path = self.files/'.payload-known'
        path.write_bytes(b'partial')
        identity = base.identity(path.stat())
        with self.store.connect() as db:
            db.execute("INSERT INTO uploads VALUES('known','partial.zip',?,100,?,'writing',1,'')",(path.name,json.dumps(identity)))
        reopened = admin.ManagedCatalog(self.store,self.files,self.manifest,reserve=0)
        self.assertTrue(path.exists())
        self.assertEqual(reopened.interrupted()[0]['status'],'interrupted')
        self.assertEqual(len(reopened.rows()),1)
        reopened.delete_incomplete('known',self.token)
        self.assertFalse(path.exists())
        self.assertEqual(reopened.interrupted(),[])

    def test_unknown_incomplete_identity_refuses_cleanup(self):
        path = self.files/'.payload-unknown'
        path.write_bytes(b'keep')
        with self.store.connect() as db:
            db.execute("INSERT INTO uploads VALUES('unknown','a',?,100,NULL,'interrupted',1,'')",(path.name,))
        with self.assertRaises(ValueError):
            self.catalog.delete_incomplete('unknown',self.token)
        self.assertEqual(path.read_bytes(),b'keep')

    def test_no_manifest_empty_catalog_supported(self):
        other = self.root/'empty'
        other.mkdir()
        state = self.root/'empty-state'
        base.init_state(state,self.access)
        service = admin.AdminService(state,other,None,ORIGIN,reserve=0)
        self.assertEqual(service.catalog.rows(),[])

    def test_symlink_is_not_followed_for_managed_file(self):
        row = self.catalog.rows()[0]
        target = self.root/'private.txt'
        target.write_bytes(b'never serve')
        link = self.files/'link'
        try:
            link.symlink_to(target)
        except (OSError,NotImplementedError):
            self.skipTest('Symbolic link privilege is unavailable')
        with self.store.connect() as db:
            db.execute('UPDATE files SET storage=? WHERE id=?',(link.name,row['id']))
        with self.assertRaises((OSError,ValueError)):
            self.catalog.get(admin.link_for(row))
        self.catalog.delete(row['id'],row['sha256'],self.token)
        self.assertEqual(target.read_bytes(),b'never serve')

    def test_process_killed_mid_upload_recovers_only_as_incomplete(self):
        code = '''import sys,io,os;import admin_service as a
s=a.AdminService(sys.argv[1],sys.argv[2],sys.argv[3],sys.argv[4],reserve=0)
class Interrupted:
 def read(self,size): os._exit(37)
s.catalog.receive(Interrupted(),1024,'crashed.zip',sys.argv[5])'''
        process = subprocess.run([sys.executable,'-B','-c',code,str(self.state),str(self.files),str(self.manifest),ORIGIN,self.token],cwd=ROOT,capture_output=True,timeout=30)
        self.assertEqual(process.returncode,37,process.stderr)
        reopened = admin.ManagedCatalog(self.store,self.files,self.manifest,reserve=0)
        self.assertEqual(len(reopened.rows()),1)
        incomplete = reopened.interrupted()
        self.assertEqual(len(incomplete),1)
        self.assertEqual(incomplete[0]['status'],'interrupted')
        self.assertTrue((self.files/incomplete[0]['storage']).exists())
        reopened.delete_incomplete(incomplete[0]['id'],self.token)
        self.assertFalse((self.files/incomplete[0]['storage']).exists())


class AdminHTTPTests(Fixture,unittest.TestCase):
    def setUp(self):
        self.setup_files()
        self.start_http()

    def test_initial_activation_and_password_setup_over_http(self):
        claim = self.store.new_bootstrap()['token']
        result = self.request('GET','/admin/activate/'+claim)
        self.assertEqual(result[0],303)
        self.assertEqual(result[1]['Referrer-Policy'],'no-referrer')
        self.assertTrue(self.store.claim_valid(claim))
        form = self.request('GET','/')
        csrf = re.search(rb'name="csrf" value="([^"]+)"',form[2]).group(1).decode()
        result = self.request('POST','/unlock',urllib.parse.urlencode({'password':admin.DEFAULT_ADMIN_PASSWORD,'csrf':csrf}),{'Origin':ORIGIN,'Cookie':admin.CLAIM_COOKIE+'='+claim+'; '+base.CSRF_COOKIE+'='+csrf})
        self.assertEqual(result[0],303)
        value = next(v for k,v in result[3] if k=='Set-Cookie' and v.startswith(admin.ADMIN_COOKIE+'='))
        token = value.split(';')[0].split('=',1)[1]
        self.assertIn('HttpOnly',value)
        limited = self.request('GET','/admin',headers={'Cookie':admin.ADMIN_COOKIE+'='+token})
        self.assertIn('首次设置'.encode(),limited[2])
        self.assertNotIn(b'upload-form',limited[2])
        self.assertEqual(self.post('/admin/quota',{'action':'add','amount':'3'},token)[0],403)
        self.assertEqual(self.post('/admin/password',{'role':'admin','password':self.password,'confirm':self.password},token)[0],303)
        self.assertFalse(self.store.admin_session(token))
        self.assertFalse(self.store.claim_valid(claim))

    def test_same_homepage_password_field_routes_admin_and_viewer(self):
        owner = self.owner()
        self.store.adjust_quota(owner,'reset',0)
        page = self.request('GET','/')
        self.assertEqual(page[0],200)
        self.assertNotIn(b'cosine123',page[2])
        csrf = re.search(rb'name="csrf" value="([^"]+)"',page[2]).group(1).decode()
        result = self.request('POST','/unlock',urllib.parse.urlencode({'password':self.password,'csrf':csrf}),{'Origin':ORIGIN,'Cookie':base.CSRF_COOKIE+'='+csrf})
        self.assertEqual(result[0],303)
        self.assertEqual(result[1]['Location'],'/admin')
        self.assertEqual(self.store.quota()['remaining'],0)

    def test_viewer_has_no_admin_privileges(self):
        token = self.login()[1]
        self.assertEqual(self.request('GET','/admin',headers={'Cookie':base.SESSION_COOKIE+'='+token})[0],303)
        self.assertEqual(self.post('/admin/quota',{'action':'add','amount':'1'},token)[0],403)
        self.assertEqual(self.request('GET','/admin/app.js')[0],403)

    def test_admin_csrf_and_origin_required(self):
        token = self.owner()
        before = self.store.quota()
        self.assertEqual(self.post('/admin/quota',{'action':'add','amount':'1'},token,origin='https://attacker.example')[0],403)
        self.assertEqual(self.post('/admin/quota',{'action':'add','amount':'1','csrf':'wrong'},token)[0],403)
        self.assertEqual(self.request('POST','/admin/quota',b'action=add&amount=1',{'Cookie':admin.ADMIN_COOKIE+'='+token})[0],403)
        self.assertEqual(self.store.quota(),before)
        self.assertEqual(self.post('/admin/quota',{'action':'add','amount':'2'},token)[0],303)
        self.assertEqual(self.store.quota()['remaining'],5)

    def test_upload_download_range_delete_over_http(self):
        token = self.owner()
        headers = {'Cookie':admin.ADMIN_COOKIE+'='+token,'Origin':ORIGIN,'X-CSRF-Token':admin.csrf_for(token),'X-File-Name':urllib.parse.quote('文档.bin')}
        result = self.request('POST','/admin/upload',b'abcdef',headers)
        self.assertEqual(result[0],201)
        self.assertEqual(result[1]['Content-Type'],'application/json; charset=utf-8')
        meta = json.loads(result[2])
        row = next(row for row in self.catalog.rows() if row['id']==meta['id'])
        url = admin.link_for(row)
        self.assertEqual(self.request('GET',url)[0],303)
        result = self.request('GET',url,headers={'Cookie':admin.ADMIN_COOKIE+'='+token,'Range':'bytes=1-3'})
        self.assertEqual((result[0],result[2]),(206,b'bcd'))
        self.assertEqual(self.store.quota()['remaining'],3)
        result = self.post('/admin/delete',{'id':row['id'],'sha':row['sha256']},token)
        self.assertEqual(result[0],303)
        self.assertEqual(self.request('GET',url,headers={'Cookie':admin.ADMIN_COOKIE+'='+token})[0],410)

    def test_unauthorized_or_oversize_upload_creates_no_file(self):
        before = set(self.files.iterdir())
        self.assertEqual(self.request('POST','/admin/upload',b'a',{'Origin':ORIGIN,'X-File-Name':'bad'})[0],403)
        token = self.owner()
        headers = {'Origin':ORIGIN,'Cookie':admin.ADMIN_COOKIE+'='+token,'X-CSRF-Token':admin.csrf_for(token),'X-File-Name':'large','Content-Length':str(self.catalog.max_upload+1)}
        self.assertEqual(self.request('POST','/admin/upload',b'',headers)[0],413)
        self.assertEqual(set(self.files.iterdir()),before)

    def test_dashboard_escaping_and_external_script_csp(self):
        token = self.owner()
        self.catalog.receive(io.BytesIO(b'a'),1,'<script>&.zip',token)
        response = self.request('GET','/admin',headers={'Cookie':admin.ADMIN_COOKIE+'='+token})
        self.assertEqual(response[0],200)
        self.assertIn(b'&lt;script&gt;&amp;.zip',response[2])
        self.assertNotIn(b'<script>&',response[2])
        self.assertIn("script-src 'self'",response[1]['Content-Security-Policy'])
        response = self.request('GET','/admin/app.js',headers={'Cookie':admin.ADMIN_COOKIE+'='+token})
        self.assertEqual(response[0],200)
        self.assertIn(b'XMLHttpRequest',response[2])
        self.assertNotIn(b'innerHTML',response[2])

    def test_public_page_hides_counts_and_upload_routes(self):
        token = self.login()[1]
        response = self.request('GET','/',headers={'Cookie':base.SESSION_COOKIE+'='+token})
        self.assertEqual(response[0],200)
        self.assertNotIn('剩余'.encode(),response[2])
        self.assertNotIn(b'upload-form',response[2])
        self.assertIn(self.original.name.encode(),response[2])

    def test_access_password_change_logout_and_admin_password_change(self):
        token = self.owner()
        fields = {'role':'access','password':'fresh-access','confirm':'fresh-access'}
        self.assertEqual(self.post('/admin/password',fields,token)[0],303)
        self.assertEqual(self.login('fresh-access')[0],'viewer')
        self.assertEqual(self.post('/admin/logout',{},token)[0],303)
        self.assertFalse(self.store.admin_session(token))

    def test_wrong_login_and_rejected_csrf_do_not_charge(self):
        response = self.request('GET','/')
        csrf = re.search(rb'name="csrf" value="([^"]+)"',response[2]).group(1).decode()
        result = self.request('POST','/unlock',urllib.parse.urlencode({'csrf':csrf,'password':'wrong'}),{'Cookie':base.CSRF_COOKIE+'='+csrf,'Origin':ORIGIN})
        self.assertEqual(result[0],403)
        self.assertEqual(self.post('/unlock',{'csrf':csrf,'password':self.access})[0],403)
        self.assertEqual(self.store.quota()['remaining'],3)

    def test_real_process_restart_preserves_admin_quota_files_and_sessions(self):
        owner = self.owner()
        viewer = self.login()[1]
        result = self.catalog.receive(io.BytesIO(b'restarted content'),17,'restart.txt',owner)
        self.stop_http()
        code = '''import sys,json;from pathlib import Path;import admin_service as a
s=a.AdminService(sys.argv[1],sys.argv[2],sys.argv[3],sys.argv[4],reserve=0)
assert s.store.admin_session(sys.argv[5]);assert s.store.valid(sys.argv[6])
r=next(r for r in s.catalog.rows() if r['id']==sys.argv[7]);assert s.catalog.get(a.link_for(r)).path.read_bytes()==b'restarted content'
assert s.store.quota()['remaining']==2
print(json.dumps({'reopened':True,'file_count':len(s.catalog.rows())}))'''
        env = dict(os.environ,PYTHONDONTWRITEBYTECODE='1')
        process = subprocess.run([sys.executable,'-B','-c',code,str(self.state),str(self.files),str(self.manifest),ORIGIN,owner,viewer,result['id']],cwd=ROOT,env=env,capture_output=True,text=True,timeout=30)
        self.assertEqual(process.returncode,0,process.stderr)
        self.assertEqual(json.loads(process.stdout),{'reopened':True,'file_count':2})

    def test_expect_continue_unauthorized_upload_rejected_before_body(self):
        conn = socket.create_connection(('127.0.0.1',self.server.server_port),timeout=5)
        try:
            conn.sendall(b'POST /admin/upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10000\r\nExpect: 100-continue\r\n\r\n')
            data = conn.recv(4096)
            self.assertIn(b'403',data)
            self.assertNotIn(b'100 Continue',data)
        finally:
            conn.close()

    def test_admin_can_enter_from_existing_viewer_session_without_charging(self):
        self.owner()
        viewer = self.login()[1]
        response = self.request('GET','/',headers={'Cookie':base.SESSION_COOKIE+'='+viewer})
        csrf = re.search(rb'name="csrf" value="([^"]+)"',response[2]).group(1).decode()
        response = self.request('POST','/unlock',urllib.parse.urlencode({'csrf':csrf,'password':self.password}),{'Origin':ORIGIN,'Cookie':base.SESSION_COOKIE+'='+viewer+'; '+base.CSRF_COOKIE+'='+csrf})
        self.assertEqual(response[0],303)
        self.assertEqual(response[1]['Location'],'/admin')
        self.assertEqual(self.store.quota()['remaining'],2)

    def test_legacy_cookie_and_download_alias_preserved_in_admin_mode(self):
        viewer = self.login()[1]
        self.service.legacy_session_cookie = 'old_session'
        self.service.legacy_downloads = {'/old.zip':hashlib.sha256(self.data).hexdigest()}
        self.stop_http()
        self.server = base.create_server('127.0.0.1',0,self.state,self.files,self.manifest,ORIGIN,extension=self.service,legacy_session_cookie='old_session',legacy_downloads=self.service.legacy_downloads)
        self.thread = threading.Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()
        response = self.request('GET','/',headers={'Cookie':'old_session='+viewer})
        self.assertTrue(any(k=='Set-Cookie' and v.startswith(base.SESSION_COOKIE+'='+viewer) for k,v in response[3]))
        response = self.request('GET','/old.zip',headers={'Cookie':'old_session='+viewer,'Range':'bytes=0-7'})
        self.assertEqual((response[0],response[2]),(206,self.data[:8]))
        self.assertEqual(self.store.quota()['remaining'],2)


if __name__ == '__main__':
    unittest.main()
