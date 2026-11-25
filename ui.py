"""Shared, dependency-free HTML components for public and administrator pages."""
from pathlib import Path
import html

STATIC = Path(__file__).resolve().parent / 'static'
ASSETS = {'/assets/app.css': ('app.css','text/css; charset=utf-8'),
          '/assets/app.js': ('app.js','text/javascript; charset=utf-8')}


def icon(name, css='icon'):
    paths = {
        'gate': '<rect x="4" y="3" width="15" height="18" rx="4"/><path d="M8 12h8m-3-3 3 3-3 3"/>',
        'lock': '<rect x="5" y="10" width="14" height="11" rx="3"/><path d="M8 10V7a4 4 0 0 1 8 0v3m-4 5v2"/>',
        'file': '<path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9zm0 0v6h6M8 13h8m-8 4h5"/>',
        'check': '<path d="m5 12 4 4L19 6"/>',
        'download': '<path d="M12 3v12m-4-4 4 4 4-4M5 16v4h14v-4"/>',
        'upload': '<path d="M12 16V4m-4 4 4-4 4 4M4 17v4h16v-4"/>',
        'arrow': '<path d="M4 12h16m-6-6 6 6-6 6"/>',
        'copy': '<rect x="8" y="8" width="12" height="13" rx="2"/><path d="M16 8V3H3v13h5"/>',
        'trash': '<path d="M4 6h16M9 6V3h6v3M6 6l1 15h10l1-15M10 10v7m4-7v7"/>',
    }
    return '<svg class="'+css+'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">'+paths[name]+'</svg>'


def format_size(size):
    if type(size) is not int or size < 0:
        raise ValueError('Invalid file size')
    value = float(size)
    units = ('B','KB','MB','GB','TB','PB','EB')
    unit = 0
    while value >= 1000 and unit < len(units)-1:
        value /= 1000
        unit += 1
    rendered = str(size) if not unit else f'{value:.2f}'.rstrip('0').rstrip('.')
    if unit and float(rendered) >= 1000 and unit < len(units)-1:
        rendered = f'{value/1000:.2f}'.rstrip('0').rstrip('.')
        unit += 1
    return rendered+' '+units[unit]


def document(body, *, title='文件传输', layout='access', admin_script=False):
    script = '<script src="/admin/app.js" defer></script>' if admin_script else ''
    return ('<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark"><title>'+html.escape(title)+'</title><link rel="stylesheet" href="/assets/app.css"><script src="/assets/app.js" defer></script>'+script+'</head><body><main class="shell '+layout+'-shell" id="main">'+body+'</main><footer class="site-footer">仅密码访问 · 可自托管</footer></body></html>').encode()


def login_body(csrf, message='', *, heading='文件传输', description='一个密码，打开传输入口。'):
    notice = '<div class="notice" role="alert" id="login-message">'+message+'</div>' if message else ''
    return '<div class="hero-mark">'+icon('gate')+'</div><h1>'+heading+'</h1><p class="lede">'+description+'</p>'+notice+'<form class="login-form" method="post" action="/unlock"><input type="hidden" name="csrf" value="'+csrf+'"><label for="password">访问密码</label><input id="password" type="password" name="password" autocomplete="current-password" required autofocus maxlength="128" aria-label="访问密码"'+(' aria-describedby="login-message"' if message else '')+'><button class="full" type="submit">进入'+icon('arrow')+'</button></form><p class="footnote">'+icon('lock')+'仅密码，无需用户名</p>'


def checksum(digest):
    escaped = html.escape(digest, quote=True)
    return '<details class="checksum"><summary>校验值 <span class="muted">SHA-256</span></summary><div class="checksum-body"><code>'+escaped+'</code><button type="button" class="secondary small" data-copy="'+escaped+'">'+icon('copy')+'复制校验值</button><span class="copy-result muted" role="status" aria-live="polite"></span></div></details>'


def file_card(name,size,digest,url, *, actions='',status='可下载',error='',admin=False):
    heading = 'h3' if admin else 'h2'
    badge = '<span class="pill">'+icon('check')+'已校验</span>' if status=='可下载' else '<span class="status-text">'+html.escape(status)+'</span>'
    button = '<a class="button'+(' secondary small' if admin else '')+'" href="'+html.escape(url,quote=True)+'">'+icon('download')+'下载文件</a>' if url else ''
    note = '<p class="file-note muted">支持断点续传，下载进度由浏览器显示。</p>' if not admin and url else ''
    return '<article class="file-card"><div class="file-top"><span class="file-icon">'+icon('file')+'</span><div class="file-info"><'+heading+' class="file-name">'+html.escape(name)+'</'+heading+'><div class="file-meta"><span>'+format_size(size)+'</span>'+badge+'</div></div></div><div class="file-actions">'+button+actions+'</div>'+note+('<p class="error-text">'+html.escape(error)+'</p>' if error else '')+checksum(digest)+'</article>'
