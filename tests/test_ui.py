from html.parser import HTMLParser
import io
from pathlib import Path
import re
import unittest
import urllib.parse
import ui
import transfer_server as base
import admin_service as admin
import test_admin_service as fixtures


class Elements(HTMLParser):
    def __init__(self, body):
        super().__init__()
        self.tags=[]
        self.feed(body.decode())

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag,dict(attrs)))


class FormattingTests(unittest.TestCase):
    def test_sizes_cover_small_files_and_decimal_boundaries(self):
        cases={0:'0 B',1:'1 B',999:'999 B',1000:'1 KB',1024:'1.02 KB',2_500_000:'2.5 MB',62_400_000:'62.4 MB',999_999:'1 MB',1_000_000_000:'1 GB',4*1024**3:'4.29 GB'}
        for size,expected in cases.items():
            self.assertEqual(ui.format_size(size),expected)
        for size in (-1,1.5,True,'100'):
            with self.assertRaises(ValueError):
                ui.format_size(size)

    def test_file_markup_escapes_filename_url_and_error(self):
        body=ui.file_card('<img onerror=bad>',500,'a'*64,'/?a="bad',error='<script>bad</script>')
        self.assertNotIn('<img',body)
        self.assertNotIn('<script>',body)
        self.assertIn('&lt;img',body)
        self.assertIn('&quot;bad',body)
        self.assertIn('&lt;script&gt;',body)

    def test_normal_text_palette_meets_contrast_in_both_themes(self):
        css=(ui.STATIC/'app.css').read_text(encoding='utf-8')
        themes=re.findall(r':root\s*\{([^}]+)\}',css)
        self.assertEqual(len(themes),2)
        def luminance(color):
            channels=[int(color[i:i+2],16)/255 for i in (1,3,5)]
            linear=[c/12.92 if c<=.04045 else ((c+.055)/1.055)**2.4 for c in channels]
            return sum(c*w for c,w in zip(linear,(.2126,.7152,.0722)))
        def contrast(a,b):
            a,b=sorted((luminance(a),luminance(b)))
            return (b+.05)/(a+.05)
        for theme in themes:
            colors=dict(re.findall(r'--([\w-]+)\s*:\s*(#[0-9a-f]{3}(?:[0-9a-f]{3})?)\b',theme))
            colors={key:('#'+''.join(c*2 for c in value[1:])) if len(value)==4 else value for key,value in colors.items()}
            for text,background in [('ink','card'),('muted','card'),('muted','bg'),('accent','card'),('accent','accent-soft'),('btn-ink','btn'),('danger','danger-soft')]:
                self.assertGreaterEqual(contrast(colors[text],colors[background]),4.5,(text,background,colors))


class UIHTTPTests(fixtures.Fixture,unittest.TestCase):
    def setUp(self):
        self.setup_files()
        self.start_http()

    def test_static_files_are_same_origin_and_do_not_charge_quota(self):
        before=self.store.quota()
        for path,content_type in [('/assets/app.css','text/css'),('/assets/app.js','text/javascript')]:
            result=self.request('GET',path)
            self.assertEqual(result[0],200)
            self.assertTrue(result[1]['Content-Type'].startswith(content_type))
            self.assertEqual(result[1]['X-Content-Type-Options'],'nosniff')
            self.assertNotIn('unsafe-inline',result[1]['Content-Security-Policy'])
            head=self.request('HEAD',path)
            self.assertEqual(head[0],200)
            self.assertEqual(head[2],b'')
        for path in ['/assets/../state/config.json','/assets/admin.js','/assets/app.css?other','/assets/unknown.css']:
            self.assertEqual(self.request('GET',path)[0],404)
        self.assertEqual(self.store.quota(),before)

    def test_public_html_uses_external_css_and_no_inline_executable_code(self):
        result=self.request('GET','/')
        elements=Elements(result[2])
        self.assertIn(('link',{'rel':'stylesheet','href':'/assets/app.css'}),elements.tags)
        self.assertTrue(any(tag=='script' and attrs.get('src')=='/assets/app.js' for tag,attrs in elements.tags))
        self.assertFalse(any('style' in attrs or any(key.startswith('on') for key in attrs) for tag,attrs in elements.tags))
        self.assertNotIn(b'<style>',result[2])

    def test_wrong_password_returns_same_form_with_new_csrf_and_no_password_echo(self):
        form=self.request('GET','/')
        csrf=re.search(rb'name="csrf" value="([^"]+)"',form[2]).group(1).decode()
        wrong='deliberately-wrong-private-value'
        result=self.request('POST','/unlock',urllib.parse.urlencode({'csrf':csrf,'password':wrong}),{'Cookie':base.CSRF_COOKIE+'='+csrf,'Origin':fixtures.ORIGIN})
        self.assertEqual(result[0],403)
        self.assertIn(b'role="alert"',result[2])
        self.assertIn(b'action="/unlock"',result[2])
        self.assertIn(b'aria-describedby="login-message"',result[2])
        self.assertNotIn(wrong.encode(),result[2])
        next_csrf=re.search(rb'name="csrf" value="([^"]+)"',result[2]).group(1).decode()
        self.assertNotEqual(next_csrf,csrf)
        self.assertEqual(self.store.quota()['remaining'],3)

    def test_visitor_download_is_honest_small_size_and_hash_folded(self):
        viewer=self.login()[1]
        result=self.request('GET','/',headers={'Cookie':base.SESSION_COOKIE+'='+viewer})
        self.assertEqual(result[0],200)
        self.assertIn(ui.format_size(len(self.data)).encode(),result[2])
        self.assertNotIn(b'0.00 GiB',result[2])
        self.assertNotIn(b'<progress',result[2])
        self.assertIn('下载进度由浏览器显示'.encode(),result[2])
        elements=Elements(result[2])
        checks=[attrs for tag,attrs in elements.tags if tag=='details' and attrs.get('class')=='checksum']
        self.assertEqual(len(checks),1)
        self.assertNotIn('open',checks[0])
        self.assertTrue(any(tag=='button' and attrs.get('data-copy')==self.catalog.rows()[0]['sha256'] for tag,attrs in elements.tags))
        self.assertNotIn('剩余'.encode(),result[2])
        self.assertEqual(self.store.quota()['remaining'],2)

    def test_activation_form_is_visible_even_with_existing_viewer_session(self):
        viewer=self.login()[1]
        claim=self.store.new_bootstrap()['token']
        result=self.request('GET','/',headers={'Cookie':base.SESSION_COOKIE+'='+viewer+'; '+admin.CLAIM_COOKIE+'='+claim})
        self.assertIn('管理员首次设置'.encode(),result[2])
        self.assertNotIn('文件已就绪'.encode(),result[2])
        self.assertTrue(self.store.claim_valid(claim))
        self.assertEqual(self.store.quota()['remaining'],2)

    def test_admin_has_emphasized_quota_and_native_file_input_accessible_label(self):
        owner=self.owner()
        result=self.request('GET','/admin',headers={'Cookie':admin.ADMIN_COOKIE+'='+owner})
        self.assertIn(b'class="quota-value">3<small>',result[2])
        self.assertIn(b'data-max-bytes="1048576"',result[2])
        self.assertIn(b'<label for="upload-file"',result[2])
        self.assertIn('尚未选择文件'.encode(),result[2])
        self.assertIn(b'aria-label="',result[2])
        elements=Elements(result[2])
        picker=next(attrs for tag,attrs in elements.tags if tag=='input' and attrs.get('id')=='upload-file')
        self.assertIn('visually-hidden',picker['class'])
        self.assertEqual(picker['aria-describedby'],'file-name')
        ids=[attrs['id'] for tag,attrs in elements.tags if 'id' in attrs]
        self.assertEqual(len(ids),len(set(ids)))
        self.assertIn(b'aria-label="',result[2])

    def test_long_filename_is_escaped_and_only_canonical_download_url_used(self):
        owner=self.owner()
        name='很长的文件名称'*10+'.zip'
        self.catalog.receive(io.BytesIO(b'long'),4,name,owner)
        viewer=self.login()[1]
        result=self.request('GET','/',headers={'Cookie':base.SESSION_COOKIE+'='+viewer})
        self.assertIn(name.encode(),result[2])
        self.assertIn(urllib.parse.quote(name,safe='').encode(),result[2])

    def test_corrupt_file_does_not_display_verified_badge_or_download_link(self):
        viewer=self.login()[1]
        self.original.write_bytes(b'corrupt')
        result=self.request('GET','/',headers={'Cookie':base.SESSION_COOKIE+'='+viewer})
        self.assertEqual(result[0],200)
        self.assertIn('暂不可用'.encode(),result[2])
        self.assertNotIn('已校验'.encode(),result[2])
        self.assertFalse(any(tag=='a' and attrs.get('href','').startswith('/download/') for tag,attrs in Elements(result[2]).tags))


if __name__=='__main__':
    unittest.main()
