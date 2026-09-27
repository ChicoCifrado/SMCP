/* SMCP — malla.js: la malla en el navegador (intercambio + reparto).

   Superficie web de `delm mesh`, y —esto es lo importante— **el mismo estado**:
   `delm.core.contrib.default_state_path()` lo resuelven la CLI y la API, así que
   aportar desde aquí se ve en `delm mesh status` y al revés.

   Tres decisiones de UI que no son cosméticas:

   * **El veredicto del plan va primero que el gráfico.** La pregunta del
     operador es "¿esto corre o no?", y la respuesta es un sí/no con motivo
     accionable, no un gráfico de barras.
   * **Se muestra siempre lo que el sistema no prueba.** La VRAM declarada es
     una afirmación firmada, no una atestación: dejarlo escrito en la propia
     página es parte del contrato, no una nota al pie.
   * **Ninguna acción escribe sin que se vea qué va a pasar**: `contribute` dice
     qué firma y qué nonce quema; `observe` dice cuántos créditos suma.
*/
(function () {
  "use strict";

  var SMCP = (window.SMCP = window.SMCP || {});
  var $ = function (id) { return document.getElementById(id); };
  var MESH = "";

  function esc(s) { return SMCP.esc(s); }
  function num(id) { return parseFloat(($(id) || {}).value) || 0; }
  function str(id) { return (($(id) || {}).value || "").trim(); }
  function gb(v) { return (v == null ? "?" : Number(v).toFixed(1)) + "G"; }
  function secs(s) { return SMCP.fmtSecs(s); }

  function meta(id, text) { var el = $(id); if (el) el.textContent = text || ""; }

  function busy(btn, on, label) {
    if (!btn) return;
    if (on) { btn.dataset.prev = btn.textContent; btn.disabled = true; btn.textContent = label || "…"; }
    else { btn.disabled = false; if (btn.dataset.prev) btn.textContent = btn.dataset.prev; }
  }

  /* ------------------------------------------------------------- estado */
  function fillPeers(peers) {
    var tb = $("m-peers").querySelector("tbody");
    if (!peers || !peers.length) {
      tb.innerHTML = '<tr><td colspan="7" style="color:var(--muted)">— ningún nodo ha aportado capacidad todavía —</td></tr>';
      return;
    }
    tb.innerHTML = "";
    peers.forEach(function (p) {
      var tr = document.createElement("tr");
      tr.innerHTML =
        "<td>" + esc(p.peer_id) + "</td>" +
        "<td>" + esc(p.backend || "—") + "</td>" +
        '<td class="num">' + esc(gb(p.vram_gb)) + "</td>" +
        '<td><span class="pill ' + (p.alive ? "ok" : "") + '">' + (p.alive ? "sí" : "NO") + "</span></td>" +
        '<td class="num">' + esc(secs(p.seconds_observed)) + "</td>" +
        '<td class="num">' + esc(Number(p.credits_available).toFixed(2)) + "</td>" +
        '<td class="num">' + esc(Number(p.entitlement).toFixed(2)) + "</td>";
      tb.appendChild(tr);
    });
  }

  function fillMesh(j) {
    MESH = j.mesh_id || MESH;
    meta("mesh-id-label", "malla " + MESH);
    $("m-vram").textContent = gb(j.vram_verified_gb);
    $("m-nodes").textContent = (j.peers || []).length;
    $("m-chain").textContent = (j.chain_ok ? "íntegra" : "ALTERADA");
    $("m-chain").className = "num" + (j.chain_ok ? "" : " bad");
    $("m-rej").textContent = j.rejections || 0;
    $("m-rej").className = "num" + (j.rejections ? " bad" : "");
    meta("m-endpoint", "endpoint de inferencia: " + (j.endpoint || "—"));
    fillPeers(j.peers);
  }

  function refresh(btn) {
    busy(btn, true, "leyendo…");
    return SMCP.get("/api/mesh" + (MESH ? "?mesh_id=" + encodeURIComponent(MESH) : ""))
      .then(function (j) {
        fillMesh(j);
        SMCP.setApi(true, "API arriba");
      })
      .catch(function (e) {
        SMCP.setApi(false, "API caída (" + e.message + ")");
        meta("m-endpoint", "no se pudo leer /api/mesh: " + e.message);
      })
      .finally(function () { busy(btn, false); });
  }

  function audit(btn) {
    busy(btn, true, "auditando…");
    SMCP.get("/api/mesh/check" + (MESH ? "?mesh_id=" + encodeURIComponent(MESH) : ""))
      .then(function (j) {
        var lines = [
          "veredicto : " + (j.ok ? "OK" : "PROBLEMAS"),
          "cadena    : " + j.chain_entries + " entradas · " + (j.chain_ok ? "íntegra" : "ALTERADA"),
          "digest    : " + (j.state_digest || "—"),
          "rechazos  : " + (j.rejections || 0),
          "saldos    : " + (j.negative_balances && j.negative_balances.length
            ? "NEGATIVOS: " + j.negative_balances.join(", ") : "todos >= 0"),
          "",
          "lo que NO prueba: " + j.not_proven
        ];
        (j.refusals || []).forEach(function (r) {
          lines.splice(4, 0, "  - seq " + r.seq + " " + r.peer_id + ": " + r.reason);
        });
        window.alert(lines.join("\n"));
        return refresh(null);
      })
      .catch(function (e) { window.alert("check error: " + e.message); })
      .finally(function () { busy(btn, false); });
  }

  /* ---------------------------------------------------------angian: firma */
  function contribute(btn) {
    var vram = num("c-vram");
    if (!(vram > 0)) { meta("c-meta", "indica al menos 0.5G de VRAM"); return; }
    busy(btn, true, "firmando…");
    var body = {
      peer_id: str("c-peer") || "local",
      vram_gb: vram,
      ram_gb: num("c-ram"),
      cpu_cores: num("c-cores"),
      backend: str("c-backend") || "cuda"
    };
    SMCP.post("/api/mesh/contribute" + (MESH ? "?mesh_id=" + encodeURIComponent(MESH) : ""), body)
      .then(function (j) {
        fillMesh(j);
        meta("c-meta", "admitido · firma " + j.sig_kind + " · digest " +
          String(j.digest).slice(0, 16) + "… · identidad " + j.identity_path);
      })
      .catch(function (e) {
        meta("c-meta", "rechazado: " + e.message);
      })
      .finally(function () { busy(btn, false); });
  }

  function observe(btn) {
    var seconds = num("c-seconds");
    if (!(seconds > 0)) { meta("c-meta", "indica cuántos segundos se ha visto al nodo"); return; }
    busy(btn, true, "acreditando…");
    SMCP.post("/api/mesh/observe" + (MESH ? "?mesh_id=" + encodeURIComponent(MESH) : ""),
      { peer_id: str("c-peer") || "local", seconds: seconds })
      .then(function (j) {
        fillMesh(j);
        meta("c-meta", "+" + seconds + "s observado · créditos " +
          Number(j.credits).toFixed(3));
      })
      .catch(function (e) { meta("c-meta", "error: " + e.message); })
      .finally(function () { busy(btn, false); });
  }

  /* --------------------------------------------------------------- plan */
  function renderPlan(j) {
    var out = $("plan-out");
    out.innerHTML = "";
    var head = document.createElement("div");
    head.className = "fit-verdict " + (j.ok ? "ok" : "bad");
    var mem = Number(j.memory_required_gb).toFixed(1);
    var tot = Number(j.total_vram_gb).toFixed(1);
    head.innerHTML =
      '<div class="vh">plan de reparto</div>' +
      '<div class="vm ' + (j.ok ? "ok" : "bad") + '">' +
      esc(j.model) + " — " + (j.ok
        ? j.node_count + " nodo(s) · " + esc(j.reason)
        : "no se puede repartir (" + esc(j.reason) + ")") +
      "</div>" +
      '<div class="vd">' + esc(mem) + "G requeridos · " + esc(tot) +
      "G verificados en la malla" + (j.llmfit ? " · " + esc(j.llmfit) : "") +
      " · endpoint " + esc(j.endpoint) + "</div>" +
      (j.notes && j.notes.length
        ? '<div class="vs">' + j.notes.map(function (n) { return esc(n); }).join("<br>") + "</div>"
        : "");
    out.appendChild(head);

    if (!j.ok || !j.stages || !j.stages.length) return;

    var list = document.createElement("div");
    list.style.marginTop = "12px";
    j.stages.forEach(function (s) {
      var row = document.createElement("div");
      row.className = "stage";
      var pct = Math.max(2, Math.min(100, Math.round(s.utilization * 100)));
      var layers = s.first_layer == null ? "por memoria"
        : "capas " + s.first_layer + "-" + s.last_layer;
      row.innerHTML =
        '<span class="nm" title="' + esc(s.peer_id) + '">' + esc(s.peer_id) + "</span>" +
        '<span class="bar"><i style="width:' + pct + '%"></i></span>' +
        '<span class="mt">' + esc(gb(s.memory_gb)) + " de " + esc(gb(s.peer_vram_gb)) +
        " · " + pct + "% · " + esc(layers) + "</span>";
      list.appendChild(row);
    });
    out.appendChild(list);
  }

  function plan(btn) {
    var model = str("p-model");
    if (!model) { meta("p-meta", "indica el modelo"); return; }
    var p = new URLSearchParams();
    p.set("model", model);
    if (MESH) p.set("mesh_id", MESH);
    var mem = num("p-mem");
    if (mem > 0) p.set("memory_gb", String(mem));
    if (num("p-layers") > 0) p.set("layers", String(num("p-layers")));
    if (num("p-reserve") > 0) p.set("reserve_gb", String(num("p-reserve")));
    var uc = str("p-usecase");
    if (uc) p.set("use_case", uc);
    busy(btn, true, "dimensionando…");
    SMCP.get("/api/mesh/plan?" + p.toString())
      .then(function (j) {
        if (j.available === false) {
          meta("p-meta", "llmfit no disponible: " + j.hint);
          renderPlan({ ok: false, model: model, reason: "llmfit_no_disponible",
                       memory_required_gb: 0, total_vram_gb: j.vram_verified_gb,
                       endpoint: j.endpoint, notes: [j.hint] });
          return;
        }
        meta("p-meta", j.ok ? "plan OK" : "plan rechazado: " + j.reason);
        renderPlan(j);
      })
      .catch(function (e) { meta("p-meta", "plan error: " + e.message); })
      .finally(function () { busy(btn, false); });
  }

  function init() {
    if (!$("btn-mesh")) return;      // la página no tiene la sección
    $("btn-mesh").addEventListener("click", function () { refresh(this); });
    $("btn-mesh-check").addEventListener("click", function () { audit(this); });
    $("btn-contrib").addEventListener("click", function () { contribute(this); });
    $("btn-observe").addEventListener("click", function () { observe(this); });
    $("btn-plan").addEventListener("click", function () { plan(this); });
    $("p-model").addEventListener("keydown", function (e) {
      if (e.key === "Enter") plan($("btn-plan"));
    });
    refresh(null);
  }

  SMCP.malla = { refresh: refresh, plan: plan };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
