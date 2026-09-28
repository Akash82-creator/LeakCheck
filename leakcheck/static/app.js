(function () {
  "use strict";
  var result = document.getElementById("result");
  var demo = document.body.getAttribute("data-demo") === "1";
  var MAX_BYTES = 1000000;

  function show(html) {
    result.innerHTML = html;
    result.focus();
  }

  function request(method, path, body) {
    show('<p class="summary">Checking locally&hellip;</p>');
    var opts = { method: method, cache: "no-store" };
    if (body !== undefined) {
      opts.headers = { "Content-Type": "application/octet-stream" };
      opts.body = body;
    }
    fetch(path, opts)
      .then(function (r) { return r.text(); })
      .then(show)
      .catch(function () {
        show('<p class="error">Could not reach the local checker. Is it still running?</p>');
      });
  }

  var buttons = document.querySelectorAll("[data-sample]");
  Array.prototype.forEach.call(buttons, function (b) {
    b.addEventListener("click", function () {
      request("GET", "api/sample/" + b.getAttribute("data-sample"));
    });
  });

  if (demo) { return; }

  var paste = document.getElementById("paste");
  var file = document.getElementById("file");
  var drop = document.getElementById("drop");

  document.getElementById("check").addEventListener("click", function () {
    var text = paste.value.trim();
    if (!text) {
      show('<p class="error">Paste a PSBT (base64) or drop a .psbt file first.</p>');
      return;
    }
    request("POST", "api/analyze", text);
  });

  document.getElementById("clear").addEventListener("click", function () {
    paste.value = "";
    file.value = "";
    result.innerHTML = "";
  });

  function sendFile(f) {
    if (!f) { return; }
    if (f.size > MAX_BYTES) {
      /* Refuse before reading: the server would reject it anyway (1 MB). */
      show('<p class="error">That file is far larger than any PSBT, so it was not read.</p>');
      return;
    }
    var reader = new FileReader();
    reader.onload = function () { request("POST", "api/analyze", reader.result); };
    reader.readAsArrayBuffer(f);
  }

  file.addEventListener("change", function () { sendFile(file.files[0]); });
  drop.addEventListener("click", function () { file.click(); });
  drop.addEventListener("keydown", function (ev) {
    if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); file.click(); }
  });
  ["dragenter", "dragover"].forEach(function (t) {
    drop.addEventListener(t, function (ev) { ev.preventDefault(); drop.classList.add("over"); });
  });
  ["dragleave", "drop"].forEach(function (t) {
    drop.addEventListener(t, function (ev) { ev.preventDefault(); drop.classList.remove("over"); });
  });
  drop.addEventListener("drop", function (ev) { sendFile(ev.dataTransfer.files[0]); });
})();
