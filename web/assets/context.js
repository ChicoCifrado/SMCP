/* SMCP — context.js: listar gists, detalle, unfold, render(). */
(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };
  var state = { run: "", data: null, selected: null };

  function msg(t, cls) {
    var el = $("ctx-msg");
    el.textContent = t || "";
    el.className = cls || "";
  }

  function loadRuns() {
    return SMCP.get("/api/runs").then(function (j) {
      var sel = $("run-sel");
      sel.innerHTML = '<option value="">(último)</option>';
      (j.runs || []).forEach(function (r) {
        var o = document.createElement("option");
        o.value = r.id;
        o.textContent = r.id + " · " + r.status + (r.backend ? " · " + r.backend : "");
        sel.appendChild(o);
      });
      var params = new URLSearchParams(location.search);
      var want = params.get("run") || "";
      if (want) sel.value = want;
      state.run = sel.value;
    });
  }

  function loadContext() {
    var q = state.run ? "?run=" + encodeURIComponent(state.run) : "";
    msg("cargando…");
    return SMCP.get("/api/context" + q).then(function (j) {
      state.data = j;
      $("ctx-meta").textContent =
        "run " + j.run.id + " · " + j.size + " gists · " + j.run.status;
      renderList(j);
      var params = new URLSearchParams(location.search);
      var label = params.get("label");
      if (label) select(label);
      else if (j.gists && j.gists.length) select(j.gists[0].label);
      else {
        $("detail").innerHTML = '<div class="empty">Sin gists en este run.</div>';
      }
      msg("ok · " + j.size + " gists", "ok");
    }).catch(function (e) {
      $("gist-list").innerHTML = '<div class="empty">—</div>';
      $("detail").innerHTML = '<div class="empty">Sin contexto: ' + SMCP.esc(e.message) + "</div>";
      msg(e.message, "err");
    });
  }

  function renderList(j) {
    var list = $("gist-list");
    list.innerHTML = "";
    if (!j.gists || !j.gists.length) {
      list.innerHTML = '<div class="empty">— sin gists —</div>';
      return;
    }
    j.gists.forEach(function (g) {
      var b = document.createElement("button");
      b.type = "button";
      b.className = "ctx-item";
      b.dataset.label = g.label;
      var t = j.taint && j.taint[g.label];
      var tname = SMCP.taintName(t || 0);
      var tcls = t >= 2 ? "conf" : t >= 1 ? "susp" : "clean";
      b.innerHTML =
        '<span class="kind">' + SMCP.esc(g.kind) + "</span>" +
        '<span class="lbl">' + SMCP.esc(g.label) + "</span>" +
        '<span class="sn">' + SMCP.esc((g.gist || "").slice(0, 80)) + "</span>" +
        '<span class="badge ' + tcls + '">' + tname + "</span>";
      b.addEventListener("click", function () { select(g.label); });
      list.appendChild(b);
    });
  }

  function select(label) {
    state.selected = label;
    Array.prototype.forEach.call(document.querySelectorAll(".ctx-item"), function (el) {
      el.classList.toggle("active", el.dataset.label === label);
    });
    var q = state.run ? "?run=" + encodeURIComponent(state.run) : "";
    // GET /api/context/{label}?run=
    var path = "/api/context/" + encodeURIComponent(label) +
      (state.run ? (q.charAt(0) === "?" ? "&" : "?") + "run=" + encodeURIComponent(state.run) : "");
    // path already has encoded label; rebuild cleanly
    path = "/api/context/" + encodeURIComponent(label);
    if (state.run) path += "?run=" + encodeURIComponent(state.run);
    SMCP.get(path).then(function (j) {
      renderDetail(j.gist, state.data && state.data.taint);
    }).catch(function (e) {
      // fallback: find in list
      var g = (state.data.gists || []).filter(function (x) { return x.label === label; })[0];
      if (g) renderDetail(g, state.data.taint);
      else msg(e.message, "err");
    });
  }

  function renderDetail(g, taintMap) {
    if (!g) {
      $("detail").innerHTML = '<div class="empty">Gist no encontrado.</div>';
      return;
    }
    var t = (taintMap && taintMap[g.label]) || 0;
    var tname = SMCP.taintName(t);
    var tcls = t >= 2 ? "conf" : t >= 1 ? "susp" : "clean";
    var refs = (g.refs || []).map(function (r) {
      return SMCP.esc(r.head) + " … " + SMCP.esc(r.tail);
    }).join(" | ") || "—";
    var summary = "";
    if (g.summary && g.summary.claims && g.summary.claims.length) {
      summary = g.summary.claims.map(function (c) { return "• " + c.claim; }).join("\n");
    }
    $("detail").innerHTML =
      "<h3>" + SMCP.esc(g.label) + ' <span class="badge">' + SMCP.esc(g.kind) +
      '</span> <span class="badge ' + tcls + '">' + tname + "</span></h3>" +
      '<div class="kv">' +
      '<span class="k">author</span><span class="v">' + SMCP.esc(g.author_id || "—") + "</span>" +
      '<span class="k">digest</span><span class="v">' + SMCP.esc((g.digest || "").slice(0, 24) || "—") + "</span>" +
      '<span class="k">sig</span><span class="v">' + SMCP.esc(g.sig_kind || "—") + " · " +
      SMCP.esc((g.signature || "").slice(0, 32) || "—") + "</span>" +
      '<span class="k">refs</span><span class="v">' + refs + "</span>" +
      "</div>" +
      "<strong style=\"font-size:12px;color:var(--muted)\">GIST</strong>" +
      '<pre class="block">' + SMCP.esc(g.gist || "") + "</pre>" +
      (summary
        ? "<strong style=\"font-size:12px;color:var(--muted)\">SUMMARY (S)</strong><pre class=\"block\">" +
          SMCP.esc(summary) + "</pre>"
        : "") +
      '<div class="lab-actions">' +
      '<button class="lab-btn" type="button" id="btn-unfold">Unfold G→S</button>' +
      '<button class="lab-btn primary" type="button" id="btn-deep">Deep unfold → raw</button>' +
      "</div>" +
      '<pre class="block" id="unfold-out" style="display:none"></pre>' +
      (g.raw
        ? '<div style="font-size:12px;color:var(--muted);margin-top:6px">raw inline (' +
          String(g.raw).length + " chars)</div>"
        : "");
    $("btn-unfold").addEventListener("click", function () { unfold(false); });
    $("btn-deep").addEventListener("click", function () { unfold(true); });
  }

  function unfold(deep) {
    if (!state.selected) return;
    var body = { label: state.selected, deep: !!deep };
    if (state.run) body.run = state.run;
    var el = $("unfold-out");
    el.style.display = "block";
    el.textContent = "unfold…";
    SMCP.post("/api/unfold", body).then(function (j) {
      el.textContent = SMCP.jpretty(j.unfolded);
    }).catch(function (e) {
      el.textContent = "error: " + e.message;
    });
  }

  function showRender() {
    if (!state.data) return;
    var b = $("render-block");
    if (b.style.display === "none") {
      b.textContent = state.data.render || "(empty)";
      b.style.display = "block";
    } else {
      b.style.display = "none";
    }
  }

  function init() {
    $("btn-reload").addEventListener("click", function () {
      state.run = $("run-sel").value;
      loadContext();
    });
    $("run-sel").addEventListener("change", function () {
      state.run = this.value;
      loadContext();
    });
    $("btn-render").addEventListener("click", showRender);
    loadRuns().then(loadContext);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
