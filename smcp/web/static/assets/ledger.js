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

  // ---- libro de inferencias (API /api/inferences) ----
  function infMsg(t, cls) {
    var el = $("inf-msg");
    if (!el) return;
    el.textContent = t;
    el.className = cls || "";
  }

  function loadInferences() {
    var mesh = $("inf-mesh") ? $("inf-mesh").value : "";
    var server = $("inf-server") ? $("inf-server").value : "";
    var q = [];
    if (mesh) q.push("mesh_id=" + encodeURIComponent(mesh));
    if (server) q.push("server=" + encodeURIComponent(server));
    var path = "/api/inferences" + (q.length ? "?" + q.join("&") : "");
    infMsg("cargando…");
    SMCP.get(path).then(function (j) {
      var recs = j.records || [];
      var totals = j.totals || {};
      var cnt = $("inf-count");
      var sat = $("inf-sats");
      var del = $("inf-delm");
      if (cnt) cnt.textContent = "inferencias: " + recs.length;
      if (sat) sat.textContent = "sats: " + (totals.satoshis != null ? totals.satoshis : (totals.sats || "—"));
      if (del) del.textContent = "DELM: " + (totals.delm != null ? totals.delm : "—");
      var table = $("inf-table");
      if (!table) { infMsg("ok"); return; }
      var tb = table.querySelector("tbody");
      tb.innerHTML = "";
      if (!recs.length) {
        var tr0 = document.createElement("tr");
        tr0.innerHTML = '<td colspan="6" class="muted">sin inferencias</td>';
        tb.appendChild(tr0);
        infMsg("sin inferencias");
        return;
      }
      recs.forEach(function (r) {
        var tr = document.createElement("tr");
        var cobro = [];
        if (r.satoshis) cobro.push(r.satoshis + " sats");
        if (r.delm_amount) cobro.push(r.delm_amount + " DELM");
        tr.innerHTML =
          '<td class="muted" title="' + SMCP.esc(r.txid || "") + '">' +
            SMCP.esc((r.txid || "").slice(0, 12)) + "…</td>" +
          "<td>" + SMCP.esc(r.mesh_id || "") + "</td>" +
          '<td class="muted">' + SMCP.esc((r.server_pubkey || "").slice(0, 12)) + "…</td>" +
          '<td class="muted">' + SMCP.esc((r.requester_pubkey || "").slice(0, 12)) + "…</td>" +
          "<td>" + SMCP.esc(cobro.join(" + ") || "—") + "</td>" +
          '<td class="muted">' + fmtTs(r.completed_at || r.timestamp) + "</td>";
        tb.appendChild(tr);
      });
      infMsg("ok · " + recs.length + " inferencias", "ok");
    }).catch(function (e) {
      infMsg("error: " + e.message, "err");
    });
  }

  function loadInferenceTotals() {
    infMsg("totales…");
    SMCP.get("/api/inferences/totals").then(function (j) {
      var t = j.totals || {};
      infMsg("totales: " + (t.inferences != null ? t.inferences : "?") +
        " inferencias · " + (t.satoshis != null ? t.satoshis : "?") +
        " sats · " + (t.delm != null ? t.delm : "?") + " DELM", "ok");
      if ($("inf-sats")) $("inf-sats").textContent = "sats: " + (t.satoshis != null ? t.satoshis : "—");
      if ($("inf-delm")) $("inf-delm").textContent = "DELM: " + (t.delm != null ? t.delm : "—");
    }).catch(function (e) {
      infMsg("error: " + e.message, "err");
    });
  }

  // ---- verificar una inferencia ajena por SPV (BRC-96) ----
  function spvShow(text, cls) {
    var el = $("spv-out");
    if (!el) return;
    el.className = "visible " + (cls || "");
    el.textContent = text;
  }

  function verifySPV() {
    var txid = ($("spv-txid") || {}).value || "";
    var mesh = ($("spv-mesh") || {}).value || "";
    var requester = ($("spv-requester") || {}).value || "";
    var funding = parseInt(($("spv-funding") || {}).value || "0", 10);
    var txHex = ($("spv-txhex") || {}).value || "";
    var idx = parseInt(($("spv-index") || {}).value || "0", 10);
    var pathRaw = ($("spv-path") || {}).value || "[]";
    var root = ($("spv-root") || {}).value || "";
    var height = parseInt(($("spv-height") || {}).value || "1", 10);
    var headerRoot = ($("spv-headeroot") || {}).value || "";
    var raw = ($("spv-raw") || {}).value || "";

    if (!txid || !mesh || !requester || !txHex) {
      spvShow("falta: txid, mesh_id, requester_pubkey y tx_hex son obligatorios", "err");
      return;
    }
    var path;
    try {
      path = JSON.parse(pathRaw);
    } catch (e) {
      spvShow("path JSON inválido: " + e.message, "err");
      return;
    }
    var body = {
      mesh_id: mesh,
      requester_pubkey: requester,
      funding_sats: funding,
      tx_hex: txHex,
      inclusion: {
        txid: txid, index: idx, path: path,
        merkle_root: root, height: height
      },
      header: {
        merkle_root: headerRoot || root, height: height,
        raw: raw
      }
    };
    var btn = $("btn-spv-verify");
    if (btn) btn.disabled = true;
    spvShow("verificando por SPV…");
    SMCP.post("/api/inferences/" + encodeURIComponent(txid) + "/verify", body).then(function (r) {
      var lines = [
        "ok=" + r.ok,
        "verified=" + r.verified,
        "inclusion=" + r.inclusion,
        "reason=" + (r.reason || ""),
        "txid=" + (r.txid || txid),
        "server_pubkey=" + (r.server_pubkey || "—"),
        "inference_id=" + (r.inference_id || "—"),
        "header.height=" + (r.header && r.header.height != null ? r.header.height : "—"),
        "header.block_hash=" + (r.header && r.header.block_hash ? r.header.block_hash : "—")
      ];
      spvShow(lines.join("\n"), r.ok ? "ok" : "err");
    }).catch(function (e) {
      var detail = (e.body && (e.body.detail || e.body.error)) || e.message;
      spvShow("error: " + detail, "err");
    }).finally(function () {
      if (btn) btn.disabled = false;
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
    // ---- libro de inferencias + verificacion SPV ----
    var ir = $("btn-inf-reload");
    if (ir) ir.addEventListener("click", loadInferences);
    var it = $("btn-inf-totals");
    if (it) it.addEventListener("click", loadInferenceTotals);
    var sp = $("btn-spv-verify");
    if (sp) sp.addEventListener("click", verifySPV);
    loadInferences();
    loadRuns().then(loadLedger);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
