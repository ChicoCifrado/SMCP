/* SMCP — ledger.js: tabla de entradas + verifier check. */
(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };
  var runSel = "";

  function msg(t, cls) {
    var el = $("led-msg");
    if (!el) return;
    el.textContent = t || "";
    el.className = cls || "";
  }

  function fmtTs(ts) {
    if (!ts) return "—";
    try {
      return new Date(ts * 1000).toISOString().slice(11, 19);
    } catch (e) {
      return String(ts);
    }
  }

  function loadRuns() {
    return SMCP.get("/api/runs").then(function (j) {
      var sel = $("run-sel");
      if (!sel) return;
      sel.innerHTML = '<option value="">(último)</option>';
      (j.runs || []).forEach(function (r) {
        var o = document.createElement("option");
        o.value = r.id;
        o.textContent = r.id + " · " + r.status;
        sel.appendChild(o);
      });
      runSel = sel.value;
    }).catch(function () { /* sin runs */ });
  }

  function loadLedger() {
    var q = runSel ? "?run=" + encodeURIComponent(runSel) : "";
    msg("cargando…");
    SMCP.get("/api/ledger" + q).then(function (j) {
      var meta = $("led-meta");
      if (meta) meta.textContent = "run " + j.run.id + " · " + j.run.status;
      var chain = $("chain-badge");
      if (chain) {
        chain.textContent = "chain: " + (j.chain_ok ? "OK ✓" : "FAIL ✗");
        chain.className = "badge " + (j.chain_ok ? "ok" : "bad");
      }
      var cnt = $("count-badge");
      if (cnt) cnt.textContent = "entries: " + j.count;
      var table = $("led-table");
      if (!table) return;
      var tb = table.querySelector("tbody");
      tb.innerHTML = "";
      if (!j.entries || !j.entries.length) {
        tb.innerHTML = '<tr><td colspan="7" class="muted">sin entradas</td></tr>';
        msg("ledger vacío", "");
        return;
      }
      j.entries.forEach(function (e) {
        var tr = document.createElement("tr");
        tr.innerHTML =
          "<td>" + SMCP.esc(e.seq) + "</td>" +
          "<td>" + SMCP.esc(e.author) + "</td>" +
          "<td>" + SMCP.esc(e.label) + "</td>" +
          '<td class="' + (e.accepted ? "ok" : "no") + '">' + (e.accepted ? "yes" : "no") + "</td>" +
          '<td class="muted">' + SMCP.esc(e.reason || "") + "</td>" +
          '<td class="muted">' + SMCP.esc((e.digest || "").slice(0, 12)) + "</td>" +
          '<td class="muted">' + fmtTs(e.ts) + "</td>";
        tb.appendChild(tr);
      });
      msg("ok · " + j.count + " entradas · chain " + (j.chain_ok ? "OK" : "FAIL"),
          j.chain_ok ? "ok" : "err");
    }).catch(function (e) {
      var table = $("led-table");
      if (table) {
        var tb = table.querySelector("tbody");
        tb.innerHTML = '<tr><td colspan="7" class="muted">' + SMCP.esc(e.message) + "</td></tr>";
      }
      var chain = $("chain-badge");
      if (chain) chain.textContent = "chain: —";
      var cnt = $("count-badge");
      if (cnt) cnt.textContent = "entries: —";
      msg(e.message, "err");
    });
  }

  function verify() {
    var kind = $("v-kind").value;
    var body = { kind: kind };
    if (kind === "trajectory") {
      body.result = $("v-result").value;
      body.gist = $("v-gist").value;
    } else {
      body.raw = $("v-raw").value;
      body.gist = $("v-gist").value;
      try {
        body.claims = JSON.parse($("v-claims").value || "[]");
      } catch (e) {
        show("claims JSON inválido: " + e.message, "err");
        return;
      }
    }
    var btn = $("btn-verify");
    btn.disabled = true;
    show("verifying…");
    SMCP.post("/api/verifier/check", body).then(function (r) {
      var html = "ok=" + r.ok + "\nreasons: " + (r.reasons || []).join("; ");
      show(html, r.ok ? "ok" : "err");
      if (r.bullet_report && r.bullet_report.length) {
        var t = document.createElement("table");
        t.className = "claims";
        t.innerHTML = "<tr><th>#</th><th>claim</th><th>ok</th><th>why</th></tr>";
        r.bullet_report.forEach(function (b, i) {
          var tr = document.createElement("tr");
          tr.innerHTML = "<td>" + (b.index != null ? b.index : i) + "</td>" +
            "<td>" + SMCP.esc(b.claim || "") + "</td>" +
            '<td class="' + (b.ok ? "ok" : "no") + '">' + (b.ok ? "✓" : "✗") + "</td>" +
            '<td class="muted">' + SMCP.esc(b.why || "") + "</td>";
          t.appendChild(tr);
        });
        $("ver-out").appendChild(t);
      }
    }).catch(function (e) {
      show("error: " + e.message, "err");
    }).finally(function () {
      btn.disabled = false;
    });
  }

  function show(text, cls) {
    var el = $("ver-out");
    el.className = "visible " + (cls || "");
    el.textContent = text;
  }

  function exportLedger() {
    var q = runSel ? "?run=" + encodeURIComponent(runSel) : "";
    msg("exportando…");
    SMCP.get("/api/ledger/export" + q).then(function (j) {
      var blob = new Blob([JSON.stringify(j, null, 2)], { type: "application/json" });
      var url = URL.createObjectURL(blob);
      var a = document.createElement("a");
      a.href = url;
      a.download = "ledger-" + (j.run && j.run.id ? j.run.id : "export") + ".json";
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(function () { URL.revokeObjectURL(url); }, 2000);
      msg("export ok · " + j.count + " entradas · chain " + (j.chain_ok ? "OK" : "FAIL"),
          j.chain_ok ? "ok" : "err");
    }).catch(function (e) {
      msg("export error: " + e.message, "err");
    });
  }

  function init() {
    var kind = $("v-kind");
    if (kind) {
      kind.addEventListener("change", function () {
        var sf = $("source-fields");
        if (sf) sf.style.display = this.value === "source" ? "" : "none";
      });
    }
    var rel = $("btn-reload");
    if (rel) {
      rel.addEventListener("click", function () {
        runSel = $("run-sel") ? $("run-sel").value : "";
        loadLedger();
      });
    }
    var exp = $("btn-export");
    if (exp) exp.addEventListener("click", exportLedger);
    var rs = $("run-sel");
    if (rs) {
      rs.addEventListener("change", function () {
        runSel = this.value;
        loadLedger();
      });
    }
    var bv = $("btn-verify");
    if (bv) bv.addEventListener("click", verify);
    loadRuns().then(loadLedger);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
