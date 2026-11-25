"use strict";
document.querySelectorAll("[data-confirm]").forEach(button => {
  button.addEventListener("click", event => {
    if (!window.confirm(button.dataset.confirm)) event.preventDefault();
  });
});
const form = document.getElementById("upload-form");
if (form) {
  const picker = document.getElementById("upload-file");
  const start = document.getElementById("upload-start");
  const cancel = document.getElementById("upload-cancel");
  const progress = document.getElementById("upload-progress");
  const status = document.getElementById("upload-status");
  let request = null;
  cancel.addEventListener("click", () => { if (request) request.abort(); });
  form.addEventListener("submit", event => {
    event.preventDefault();
    const file = picker.files[0];
    if (!file || request) return;
    const xhr = new XMLHttpRequest();
    request = xhr;
    xhr.open("POST", "/admin/upload");
    xhr.setRequestHeader("X-CSRF-Token", form.dataset.csrf);
    xhr.setRequestHeader("X-File-Name", encodeURIComponent(file.name));
    xhr.setRequestHeader("Content-Type", "application/octet-stream");
    progress.hidden = false;
    progress.value = 0;
    cancel.hidden = false;
    start.disabled = true;
    picker.disabled = true;
    status.textContent = "正在上传…";
    xhr.upload.onprogress = event => {
      if (event.lengthComputable) {
        progress.value = event.loaded / event.total * 100;
        status.textContent = progress.value >= 100 ? "传输完成，正在校验并发布…" : "已上传 " + progress.value.toFixed(1) + "%";
      }
    };
    const done = message => {
      status.textContent = message;
      start.disabled = false;
      picker.disabled = false;
      cancel.hidden = true;
      request = null;
    };
    xhr.onload = () => {
      if (xhr.status === 201) {
        window.location.reload();
      } else {
        let message = "上传失败（" + xhr.status + "），请刷新后重试。";
        try { message = JSON.parse(xhr.responseText).error || message; } catch (_) { /* Proxy may return plain errors. */ }
        done(message);
      }
    };
    xhr.onerror = () => done("连接中断，未完成的文件不会发布。请刷新后检查。");
    xhr.onabort = () => done("已取消。未完成的文件不会发布。");
    xhr.send(file);
  });
}
