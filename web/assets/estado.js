/* SMCP — estado.js: dashboard de proyecto + runs + config. */
(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };
  var out = null;

  function esc(s) {
    return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  function show(msg, cls) {
    out = $("live-out");
    if (!out) return;
    out.className = "visible " + (cls || "");
    var text = String(msg == null ? "" : msg);
    var first = text.split("\n")[0];
    // Headline de resumen pytest: "N passed · M failed…" → color en la 1ª línea.
    if (/\b\d+\s+(passed|failed|error)\b/.test(first)) {
      var ok = first.indexOf("[FAIL]") === -1 && /0 failed/.test(first);
      var lines = text.split("\n");
      lines[0] = '<span class="' + (ok ? "sum-ok" : "sum-err") + '">' + esc(lines[0]) + "</span>";
      out.innerHTML = lines.map(function (l, i) {
        return i === 0 ? l : esc(l);
      }).join("\n");
    } else {
      out.textContent = text;
    }
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
        show(formatRun(id, j), j.ok ? "ok" : "err");
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

  /** Resumen pytest arriba; warnings al final (fuera del cuerpo principal). */
  function formatRun(id, j) {
    var head =
      (j.ok ? "OK" : "FAIL") + " · " + id +
      (j.secs != null ? " · " + j.secs + "s" : "") +
      (j.code != null ? " · code " + j.code : "");
    if (id === "tests" && j.summary && j.summary.parsed) {
      var lines = [
        j.ok ? j.summary.headline : j.summary.headline + "  [FAIL]",
        head
      ];
      if (j.summary.body) lines.push("", j.summary.body);
      if (j.summary.warnings_text) {
        lines.push("", "--- warnings (" + j.summary.warnings + ") ---", j.summary.warnings_text);
      }
      if (j.error) lines.push("", j.error);
      return lines.join("\n");
    }
    return (
      head + "\n" +
      (j.stdout || "") +
      (j.stderr ? "\n--- stderr ---\n" + j.stderr : "") +
      (j.error ? "\n" + j.error : "")
    );
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
        if ($("cfg-in-model") && document.activeElement !== $("cfg-in-model")) {
          $("cfg-in-model").value = c.model || "";
        }
        if ($("cfg-in-base") && document.activeElement !== $("cfg-in-base")) {
          $("cfg-in-base").value = c.base_url || "";
        }
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

  function saveConfig() {
    var body = {};
    var model = $("cfg-in-model") ? $("cfg-in-model").value.trim() : "";
    var base = $("cfg-in-base") ? $("cfg-in-base").value.trim() : "";
    var key = $("cfg-in-key") ? $("cfg-in-key").value : "";
    if (model) body.model = model;
    if (base) body.base_url = base;
    if (key) body.api_key = key;
    if (!Object.keys(body).length) {
      show("Nada que guardar (model/base_url/api_key vacíos).", "err");
      return;
    }
    show("PUT /api/config …");
    SMCP.put("/api/config", body).then(function (j) {
      if ($("cfg-in-key")) $("cfg-in-key").value = "";
      show("config guardada · " + j.path + "\nupdated: " + (j.updated || []).join(", ") +
        "\nmodel=" + j.model + "\nbase_url=" + j.base_url +
        "\napi_key=" + (j.api_key_masked || (j.api_key_set ? "set" : "empty")), "ok");
      refreshConfig();
    }).catch(function (e) {
      show("config error: " + e.message + (e.body && e.body.detail ? "\n" + SMCP.jpretty(e.body.detail) : ""), "err");
    });
  }

  function probeMeshLLM() {
    show("GET /api/meshllm …");
    SMCP.get("/api/meshllm").then(function (j) {
      show(SMCP.jpretty(j), j.reachable ? "ok" : "err");
    }).catch(function (e) {
      show("meshllm error: " + e.message, "err");
    });
  }

  function startLive() {
    // Lightweight live tick: refresh signals + runs while page is open.
    var live = SMCP.poll("/api/status", 4000, function (st) {
      fillStatus(st);
      var lbl = $("live-poll-lbl");
      if (lbl) lbl.textContent = "live · " + (st.updated_at || "");
    });
    live.start();
    var runs = SMCP.poll("/api/runs", 2500, function (j) {
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
    });
    runs.start();
    window.addEventListener("pagehide", function () {
      live.stop();
      runs.stop();
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
    startLive();
    $("btn-status").addEventListener("click", function () {
      refreshStatus();
      refreshConfig();
      refreshRuns();
    });
    $("btn-tests").addEventListener("click", function () { runFn("tests", this); });
    $("btn-demo").addEventListener("click", function () { runFn("demo", this); });
    $("btn-taint").addEventListener("click", function () { runFn("taint", this); });
    $("btn-probe").addEventListener("click", probe);
    var save = $("btn-cfg-save");
    if (save) save.addEventListener("click", saveConfig);
    var mesh = $("btn-meshllm");
    if (mesh) mesh.addEventListener("click", probeMeshLLM);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
