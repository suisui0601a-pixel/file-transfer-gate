const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = path.join(__dirname, '..');
function element(extra = {}) {
  return Object.assign({
    handlers: {}, hidden: false, disabled: false, value: 0, textContent: '',
    classList: { values: new Set(), add(x) { this.values.add(x); }, remove(x) { this.values.delete(x); }, toggle(x, active) { active ? this.values.add(x) : this.values.delete(x); } },
    addEventListener(event, handler) { this.handlers[event] = handler; },
  }, extra);
}
function uploader() {
  const elements = {
    'upload-form': element({ dataset: { csrf: 'a'.repeat(64), maxBytes: '1000' } }),
    'upload-file': element({ files: [] }), 'file-name': element(),
    'upload-start': element(), 'upload-cancel': element({ hidden: true }),
    'upload-progress': element({ hidden: true }), 'upload-status': element(),
  };
  const requests = [];
  let reloads = 0;
  class Request {
    constructor() { this.upload = {}; this.headers = {}; requests.push(this); }
    open(method, url) { this.method = method; this.url = url; }
    setRequestHeader(key, value) { this.headers[key] = value; }
    send(file) { this.file = file; }
    abort() { this.onabort(); }
  }
  vm.runInNewContext(fs.readFileSync(path.join(root, 'static/admin.js'), 'utf8'), {
    document: { querySelectorAll() { return []; }, getElementById(id) { return elements[id]; } },
    XMLHttpRequest: Request, window: { location: { reload() { reloads++; } } },
  });
  const select = file => { elements['upload-file'].files = file ? [file] : []; elements['upload-file'].handlers.change(); };
  const submit = () => elements['upload-form'].handlers.submit({ preventDefault() {} });
  return { elements, requests, select, submit, get reloads() { return reloads; } };
}

test('localized file label uses textContent and clears on deselection', () => {
  const u = uploader();
  u.select({ name: '<b>项目.zip</b>', size: 10 });
  assert.equal(u.elements['file-name'].textContent, '<b>项目.zip</b>');
  u.select(null);
  assert.equal(u.elements['file-name'].textContent, '尚未选择文件');
});
test('oversize file rejected before creating a request', () => {
  const u = uploader();
  u.select({ name: 'large.zip', size: 1001 }); u.submit();
  assert.equal(u.requests.length, 0);
  assert.match(u.elements['upload-status'].textContent, /超过/);
});
test('real progress event reaches verification phase, not simulated publication', () => {
  const u = uploader(); u.select({ name: '项目.zip', size: 100 }); u.submit();
  const req = u.requests[0];
  assert.equal(req.url, '/admin/upload');
  assert.equal(req.headers['X-File-Name'], encodeURIComponent('项目.zip'));
  assert.equal(req.headers['X-CSRF-Token'], 'a'.repeat(64));
  req.upload.onprogress({ lengthComputable: true, loaded: 81, total: 100 });
  assert.equal(u.elements['upload-progress'].value, 81);
  req.upload.onprogress({ lengthComputable: true, loaded: 100, total: 100 });
  assert.match(u.elements['upload-status'].textContent, /校验并发布/);
  assert.equal(u.reloads, 0);
  req.status = 201; req.onload(); assert.equal(u.reloads, 1);
});
test('server rejection restores controls and never reloads', () => {
  const u = uploader(); u.select({ name: 'a.zip', size: 10 }); u.submit();
  const req = u.requests[0]; req.status = 507; req.responseText = JSON.stringify({ error: '空间不足' }); req.onload();
  assert.equal(u.elements['upload-status'].textContent, '空间不足');
  assert.equal(u.elements['upload-start'].disabled, false);
  assert.equal(u.elements['upload-file'].disabled, false);
  assert.equal(u.elements['upload-cancel'].hidden, true);
  assert.equal(u.reloads, 0);
  u.submit(); assert.equal(u.requests.length, 2);
});
test('cancel and network failure leave the uploader retryable', () => {
  const u = uploader(); u.select({ name: 'a.zip', size: 10 }); u.submit();
  u.elements['upload-cancel'].handlers.click();
  assert.match(u.elements['upload-status'].textContent, /已取消/);
  assert.equal(u.elements['upload-status'].classList.values.has('error-text'), false);
  u.submit(); u.requests[1].onerror();
  assert.match(u.elements['upload-status'].textContent, /连接中断/);
  assert.equal(u.elements['upload-start'].disabled, false);
});
test('delete confirmation cancellation prevents submission', () => {
  const button = element({ dataset: { confirm: '确认删除？' } }); let prevented = false;
  vm.runInNewContext(fs.readFileSync(path.join(root, 'static/admin.js'), 'utf8'), {
    document: { querySelectorAll() { return [button]; }, getElementById() { return null; } }, window: { confirm() { return false; } },
  });
  button.handlers.click({ preventDefault() { prevented = true; } }); assert.equal(prevented, true);
});
async function clipboard(reject = false) {
  const result = element(); let copied; let selected = false;
  const details = { querySelector(selector) { return selector === '.copy-result' ? result : {}; } };
  const button = element({ dataset: { copy: 'f'.repeat(64) }, closest() { return details; } });
  vm.runInNewContext(fs.readFileSync(path.join(root, 'static/app.js'), 'utf8'), {
    document: { querySelectorAll() { return [button]; }, createRange() { return { selectNodeContents() {} }; } },
    navigator: { clipboard: { async writeText(value) { if (reject) throw Error('Denied'); copied = value; } } },
    window: { getSelection() { return { removeAllRanges() {}, addRange() { selected = true; } }; } },
  });
  await button.handlers.click(); return { result, copied, selected };
}
test('hash copied without network or mutation', async () => {
  const c = await clipboard(); assert.equal(c.copied, 'f'.repeat(64)); assert.match(c.result.textContent, /已复制/);
});
test('clipboard denial selects the hash and describes manual copying', async () => {
  const c = await clipboard(true); assert.equal(c.selected, true); assert.match(c.result.textContent, /手动复制/);
});
