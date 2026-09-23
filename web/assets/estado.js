/* SMCP — estado.js: página "Estado en vivo" (lee /api/status real). */
(function () {
  "use strict";

  var $ = function (id) { return document.getElementById(id); };
  var out = $("live-out");

  function setApi(up, label) {
    var pip = $("api-pip");
    pip.classList.remove("up", "down");
    pip.classList.add(up ? "up" : "down");
    $("api-label").textContent = label;
  }

  function fill(status) {
    $("s-test-fns").textContent = status.test_fns != null ? status.test_fns : "—";
    $("s-test-files").textContent = status.test_files != null ? status.test_files : "—";
    $("s-core").textContent = status.core_modules != null ? status.core_modules : "—";
    $("s-demos").textContent = status.demos ? status.demos.length : "—";
    $("s-pages").textContent = status.web_pages != null ? status.web_pages : "—";
    $("s-funcs").textContent = status.functions != null ? status.functions : "—";
    $("updated-at").textContent = status.updated_at || "—";

    var core = $("core-list");
    core.innerHTML = "";
    (status.core || []).forEach(function (m) {
      var s = document.createElement("span");
      s.className = "live-chip ok";
      s.textContent = m.replace(/\.py$/, "");
      core.appendChild(s);
    });

    var demos = $("demo-list");
    demos.innerHTML = "";
    (status.demos || []).forEach(function (d) {
      var s = document.createElement("span");
      s.className = "live-chip";
      s.textContent = d;
      demos.appendChild(s);
    });
  }

  function refreshStatus() {
    setApi(false, "consultando…");
    return fetch("/api/status")
      .then(function (r) {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
      })
      .then(function (j) {
        fill(j);
        setApi(true, "API arriba");
      })
      .catch(function (e) {
        setApi(false, "API caída (" + e.message + ")");
        out.className = "visible err";
        out.textContent =
          "No se pudo leer /api/status.\n" +
          "Arranca el servidor:  python api_server.py  →  http://127.0.0.1:8099\n" +
          String(e);
      });
  }

  function runFn(id, btn) {
    if (!btn || btn.disabled) return;
    var prev = btn.textContent;
    btn.disabled = true;
    btn.textContent = "corriendo…";
    out.className = "visible";
    out.textContent = "POST /api/run/" + id + " …";
    fetch("/api/run/" + id, { method: "POST" })
      .then(function (r) { return r.json(); })
      .then(function (j) {
        out.className = "visible " + (j.ok ? "ok" : "err");
        var head = (j.ok ? "OK" : "FAIL") +
          " · " + id + " · " + (j.secs != null ? j.secs + "s" : "") +
          (j.code != null ? " · code " + j.code : "") + "\n";
        out.textContent = head + (j.stdout || "") +
          (j.stderr ? "\n--- stderr ---\n" + j.stderr : "") +
          (j.error ? "\n" + j.error : "");
        out.scrollTop = out.scrollHeight;
        if (id === "tests" || id === "demo") refreshStatus();
      })
      .catch(function (e) {
        out.className = "visible err";
        out.textContent = "Error lanzando " + id + ": " + e;
      })
      .finally(function () {
        btn.disabled = false;
        btn.textContent = prev;
      });
  }

  function init() {
    refreshStatus();
    $("btn-status").addEventListener("click", refreshStatus);
    $("btn-tests").addEventListener("click", function () { runFn("tests", this); });
    $("btn-demo").addEventListener("click", function () { runFn("demo", this); });
    $("btn-taint").addEventListener("click", function () { runFn("taint", this); });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
