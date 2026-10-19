// 1) Ask before risky actions (forms with data-confirm).
document.querySelectorAll("form[data-confirm]").forEach(function (form) {
  form.addEventListener("submit", function (e) {
    if (!window.confirm(form.dataset.confirm)) e.preventDefault();
  });
});

// 2) On the upload page, compute SHA-256 in the browser so the server can cross-check it.
var fileInput = document.getElementById("file");
if (fileInput && window.crypto && window.crypto.subtle) {
  fileInput.addEventListener("change", async function () {
    var box = document.getElementById("hashbox");
    var out = document.getElementById("hashval");
    var hidden = document.getElementById("client_sha256");
    hidden.value = "";
    box.hidden = true;
    var file = fileInput.files[0];
    if (!file || file.size > 100 * 1024 * 1024) return;
    var buf = await file.arrayBuffer();
    var digest = await window.crypto.subtle.digest("SHA-256", buf);
    var hex = Array.from(new Uint8Array(digest)).map(function (b) {
      return b.toString(16).padStart(2, "0");
    }).join("");
    hidden.value = hex;
    out.textContent = hex;
    box.hidden = false;
  });
}
