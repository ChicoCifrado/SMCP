/* SMCP — fit.js: dimensionar el modelo local a ESTE hardware (llmfit).

   Superficie web de `delm fit`: la misma pregunta, el mismo adaptador y las
   mismas tres respuestas que la CLI (delm/core/llmfit.py + delm/cli.py):

     GET  /api/fit         → tabla de lo que cabe + veredicto de la config
     POST /api/fit/apply   → adoptar un modelo de la tabla como config

   Decisiones que no son negotiate:

   * **El veredicto se pinta siempre**, aunque la tabla esté filtrada: es la
     señal que evita el fallo caro (cargar 27B en una tarjeta de 16 GB). Un
     modelo que no cabe sale en rojo; uno que llmfit no conoce sale neutro,
     porque la config manda y llmfit solo asesora.
   * **Ausencia de llmfit no es un error de red**: `available: false` trae el
     hint de instalación y se muestra tal cual, sin spinner eterno.
   * **Ningún secret llega al navegador**: la fila de la tabla no lleva key, y
     `apply` reutiliza el endpoint de config, que ya enmascara.
*/
(function () {
  "use strict";

  var SMCP = (window.SMCP = window.SMCP || {});
  var $ = function (id) { return document.getElementById(id); };

  function esc(s) { return SMCP.esc(s); }
  function val(id) {
    var el = $(id);
    return el ? String(el.value || "").trim() : "";
  }

  function query(extra) {
    var p = new URLSearchParams();
    var limit = val("fit-limit");
    if (limit) p.set("limit", limit);
    ["use-case", "min-fit", "runtime", "sort"].forEach(function (k) {
      var v = val("fit-" + k);
      if (v) p.set(k.replace("-", "_"), v);
    });
    var s = val("fit-search");
    if (s) p.set("search", s);
    if (extra) Object.keys(extra).forEach(function (k) { p.set(k, extra[k]); });
    return p.toString();
  }

  function gb(v) {
    if (v == null) return "—";
    return Number(v).toFixed(1) + "G";
  }

  function fillSystem(sys) {
    $("fit-gpu").textContent = sys && sys.gpu_name
      ? (sys.has_gpu ? sys.gpu_name : "sin GPU")
      : "—";
    $("fit-ram").textContent = sys && sys.total_ram_gb ? gb(sys.total_ram_gb) : "—";
    $("fit-cpu").textContent = sys && sys.cpu_cores
      ? sys.cpu_cores + (sys.cpu_name ? " · " + String(sys.cpu_name).split("(")[0].trim().slice(0, 22) : "")
      : "—";
  }

  function fillVerdict(check) {
    var box = $("fit-verdict");
    if (!check || !box) return;
    box.style.display = "block";
    box.className = "fit-verdict";
    var model = $("fit-verdict-model");
    var detail = $("fit-verdict-detail");
    var sugg = $("fit-verdict-suggest");

    if (!check.model) {
      model.className = "vm";
      model.textContent = "sin modelo configurado";
      detail.textContent = "configura uno (arriba) o elige uno de la tabla.";
      sugg.innerHTML = "";
      return;
    }
    if (!check.matched) {
      // Desconocido ≠ roto: llmfit no conoce ese id y no puede juzgarlo.
      model.className = "vm";
      model.textContent = check.model + " — no está en el catálogo de llmfit";
      detail.textContent = "veredicto desconocido (la configuración manda; llmfit solo asesora).";
      sugg.innerHTML = "";
      return;
    }
    if (check.runnable) {
      box.className = "fit-verdict ok";
      model.className = "vm ok";
      model.textContent = check.model + " — " + (check.fit_label || check.fit_level);
    } else {
      box.className = "fit-verdict bad";
      model.className = "vm bad";
      model.textContent = check.model + " — " + (check.fit_label || check.fit_level) + " · NO cabe en este host";
    }
    var bits = [];
    if (check.best_quant) bits.push("quant " + check.best_quant);
    if (check.memory_required_gb != null) bits.push(gb(check.memory_required_gb) + " resident");
    if (check.estimated_tps != null) bits.push(Number(check.estimated_tps).toFixed(1) + " tok/s");
    if (check.runtime) bits.push(check.runtime);
    detail.textContent = bits.join("  ·  ");
    sugg.innerHTML = (check.suggestions || []).length
      ? "sugerencias: " + check.suggestions.map(function (s) {
          return "<b>" + esc(s) + "</b>";
        }).join(" · ")
      : "";

    // Recomendacion proactiva: modelos que caben en la
    // memoria de ejecucion del host (independientemente de
    // cuanta haya). Siempre visible — es la regla del core.
    var recBox = $("fit-verdict-rec");
    var recList = $("fit-verdict-list");
    var recMem = $("fit-verdict-mem");
    var recs = check.recommendations || [];
    if (recBox && recList && recs.length) {
      recBox.style.display = "block";
      if (recMem && check.exec_memory_gb != null) {
        recMem.textContent = "presupuesto de ejecución: " + gb(check.exec_memory_gb) +
          " × headroom " + Number(check.headroom || 0.85).toFixed(2);
      }
      recList.innerHTML = recs.map(function (r) {
        return "<li><b>" + esc(r) + "</b></li>";
      }).join("");
    } else if (recBox) {
      recBox.style.display = "none";
    }
  }

  function fillTable(models) {
    var wrap = $("fit-wrap");
    var tb = $("fit-table").querySelector("tbody");
    if (!models || !models.length) {
      wrap.style.display = "block";
      tb.innerHTML = '<tr><td colspan="7" style="color:var(--muted)">— ninguna fila con esos filtros —</td></tr>';
      return;
    }
    tb.innerHTML = "";
    models.forEach(function (m) {
      var tr = document.createElement("tr");
      var lvl = String(m.fit_level || "");
      tr.innerHTML =
        "<td>" + esc(m.name) + "</td>" +
        "<td>" + esc(m.params_b != null ? m.params_b + "B" : "—") + "</td>" +
        "<td>" + esc(m.best_quant || "—") + "</td>" +
        '<td><span class="fit-level ' + esc(lvl) + '">' + esc(m.fit_label || lvl || "—") + "</span></td>" +
        "<td>" + esc(gb(m.memory_required_gb)) + "</td>" +
        "<td>" + esc(m.estimated_tps != null ? Number(m.estimated_tps).toFixed(1) : "—") + "</td>" +
        '<td class="pick"><button class="pick-btn" type="button" data-model="' + esc(m.name) + '">usar</button></td>';
      tb.appendChild(tr);
    });
    wrap.style.display = "block";
    Array.prototype.forEach.call(tb.querySelectorAll(".pick-btn"), function (btn) {
      btn.addEventListener("click", function () { apply(btn.getAttribute("data-model"), btn); });
    });
  }

  function showUnavailable(hint) {
    var box = $("fit-unavail");
    $("fit-wrap").style.display = "none";
    $("fit-verdict").style.display = "none";
    if (!box) return;
    box.style.display = "block";
    box.textContent = "llmfit no disponible en este host.\n\n" + (hint || "");
  }

  function load(btn, onlyCheck) {
    if (btn && btn.disabled) return;
    var prev = btn ? btn.textContent : null;
    if (btn) { btn.disabled = true; btn.textContent = "midiendo…"; }
    $("fit-unavail").style.display = "none";
    if (onlyCheck) $("fit-wrap").style.display = "none";

    // El veredicto se pide con limit=1: la fila no se pinta, pero el catálogo
    // llega entero al servidor (fetch sin estrechar) para poder juzgar.
    var qs = query(onlyCheck ? { limit: 1 } : null);
    SMCP.get("/api/fit?" + qs)
      .then(function (j) {
        if (!j.available) {
          showUnavailable(j.hint);
          return;
        }
        fillSystem(j.system);
        $("fit-count").textContent = j.total_models != null ? j.total_models : "—";
        $("fit-meta").textContent = "llmfit · " + (j.secs != null ? j.secs + "s" : "?") + " · " +
          (j.models ? j.models.length : 0) + " filas";
        fillVerdict(j.check);
        if (!onlyCheck) fillTable(j.models);
      })
      .catch(function (e) {
        showUnavailable("error de la API: " + e.message);
      })
      .finally(function () {
        if (btn) { btn.disabled = false; btn.textContent = prev; }
      });
  }

  function apply(model, btn) {
    if (!model) return;
    var prev = btn.textContent;
    btn.disabled = true;
    btn.textContent = "guardando…";
    var body = { model: model };
    // Si el operador ya tiene una base_url local, se conserva: el modelo que
    // elige la tabla no debe reescribir el endpoint que está sirviendo.
    var base = $("cfg-in-base") ? $("cfg-in-base").value.trim() : "";
    if (base) body.base_url = base;
    SMCP.post("/api/fit/apply", body)
      .then(function (j) {
        // Contrato entre los dos módulos de la página: fit.js no conoce el
        // estado.html, solo dispara el evento y quien lo escucha refresca.
        window.dispatchEvent(new CustomEvent("smcp:config-changed", { detail: j }));
        if ($("cfg-in-model") && document.activeElement !== $("cfg-in-model")) {
          $("cfg-in-model").value = j.model || model;
        }
        load(null, true);
      })
      .catch(function (e) {
        window.alert("No se pudo guardar la config: " + e.message);
      })
      .finally(function () {
        btn.disabled = false;
        btn.textContent = prev;
      });
  }

  function init() {
    if (!$("btn-fit")) return;   // la página no tiene la sección
    $("btn-fit").addEventListener("click", function () { load(this, false); });
    $("btn-fit-check").addEventListener("click", function () { load(this, true); });
    $("fit-search").addEventListener("keydown", function (e) {
      if (e.key === "Enter") load($("btn-fit"), false);
    });
  }

  SMCP.fit = { load: load, apply: apply };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
