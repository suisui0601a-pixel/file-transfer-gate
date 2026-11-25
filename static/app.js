"use strict";
document.querySelectorAll("[data-copy]").forEach(button => {
  button.addEventListener("click", async () => {
    const value = button.dataset.copy;
    const details = button.closest(".checksum");
    const result = details.querySelector(".copy-result");
    if (!/^[a-f0-9]{64}$/.test(value)) return;
    try {
      await navigator.clipboard.writeText(value);
      result.textContent = "校验值已复制。";
    } catch (_) {
      const range = document.createRange();
      range.selectNodeContents(details.querySelector("code"));
      const selection = window.getSelection();
      if (selection) {
        selection.removeAllRanges();
        selection.addRange(range);
      }
      result.textContent = "自动复制不可用，已选中校验值，请手动复制。";
    }
  });
});
