/* SMCP — estado.js: dashboard de proyecto + runs + config. */
(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };
  var out = null;

  function show(msg, cls) {
    out = $("live-out");
    if (!out) return;
    out.className = "visible " + (cls || "");
    out.textContent = msg;
    out.scrollTop = out.scrollHeight;
  }

  function fillStatus(status) {
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
    SMCP.setApi(false, "consultando…");
    return SMCP.get("/api/status")
      .then(function (j) {
        fillStatus(j);
        SMCP.setApi(true, "API arriba");
      })
      .catch(function (e) {
        SMCP.setApi(false, "API caída (" + e.message + ")");
        show("No se pudo leer /api/status.\nArranca: python api_server.py → http://127.0.0.1:8099\n" + e, "err");
      });
  }

  function refreshConfig() {
    return Promise.all([
      SMCP.get("/api/config").catch(function () { return null; }),
      SMCP.get("/api/health").catch(function () { return null; })
    ]).then(function (pair) {
      var c = pair[0];
      var h = pair[1];
      if (c) {
        $("cfg-model").textContent = c.model || "(sin model)";
        $("cfg-base").textContent = c.base_url || "(sin base_url)";
        $("cfg-key").textContent = c.api_key_set
          ? (c.api_key_masked || "set") + " · set"
          : "(vacío)";
      }
      if (h) {
        var m = h.model || {};
        if (!m.configured) $("cfg-reach").textContent = "sin endpoint configurado";
        else if (m.reachable) {
          $("cfg-reach").textContent =
            "OK · " + (m.model_id || m.model) + " · " + m.latency_ms + "ms";
        } else $("cfg-reach").textContent = "NO reachable · " + (m.error || "");

        if (m.configured && m.reachable) SMCP.setApi(true, "API + endpoint OK");
        else if (m.configured) SMCP.setApi(true, "API arriba · modelo caído");
        else SMCP.setApi(true, "API arriba · sin endpoint");
      }
    });
  }

  function refreshRuns() {
    return SMCP.get("/api/runs").then(function (j) {
      var tb = $("runs-table").querySelector("tbody");
      tb.innerHTML = "";
      if (!j.runs || !j.runs.length) {
        tb.innerHTML = '<tr><td colspan="6" style="color:var(--muted)">— sin runs —</td></tr>';
        return;
      }
      j.runs.forEach(function (r) {
        var tr = document.createElement("tr");
        var tasks = r.task_count != null ? r.task_count
          : (r.tasks ? r.tasks.length : "—");
        tr.innerHTML =
          "<td>" + SMCP.esc(r.id) + "</td>" +
          "<td>" + SMCP.esc(r.status) + "</td>" +
          "<td>" + SMCP.esc(r.backend || "") + "</td>" +
          "<td>" + SMCP.esc(tasks) + "</td>" +
          "<td>" + SMCP.esc(r.rounds != null ? r.rounds : "—") + "</td>" +
          "<td>" + SMCP.fmtSecs(r.wall_s) + "</td>";
        tb.appendChild(tr);
      });
    }).catch(function () { /* leave table */ });
  }

  function runFn(id, btn) {
    if (!btn || btn.disabled) return;
    var prev = btn.textContent;
    btn.disabled = true;
    btn.textContent = "corriendo…";
    show("POST /api/run/" + id + " …");
    SMCP.post("/api/run/" + id)
      .then(function (j) {
        show(
          (j.ok ? "OK" : "FAIL") + " · " + id + " · " +
          (j.secs != null ? j.secs + "s" : "") +
          (j.code != null ? " · code " + j.code : "") + "\n" +
          (j.stdout || "") +
          (j.stderr ? "\n--- stderr ---\n" + j.stderr : "") +
          (j.error ? "\n" + j.error : ""),
          j.ok ? "ok" : "err"
        );
        if (id === "tests" || id === "demo") refreshStatus();
      })
      .catch(function (e) {
        show("Error lanzando " + id + ": " + e.message, "err");
      })
      .finally(function () {
        btn.disabled = false;
        btn.textContent = prev;
      });
  }

  function probe() {
    show("probe…");
    SMCP.post("/api/config/probe", { check_completion: false })
      .then(function (j) {
        show(SMCP.jpretty(j), j.reachable ? "ok" : "err");
        refreshConfig();
      })
      .catch(function (e) {
        show("probe error: " + e.message, "err");
      });
  }

  function init() {
    refreshStatus();
    refreshConfig();
    refreshRuns();
    $("btn-status").addEventListener("click", function () {
      refreshStatus();
      refreshConfig();
      refreshRuns();
    });
    $("btn-tests").addEventListener("click", function () { runFn("tests", this); });
    $("btn-demo").addEventListener("click", function () { runFn("demo", this); });
    $("btn-taint").addEventListener("click", function () { runFn("taint", this); });
    $("btn-probe").addEventListener("click", probe);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
