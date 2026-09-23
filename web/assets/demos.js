/* SMCP — demos.js: ejecutar demos in-process y multihost subprocess. */
(function () {
  "use strict";

  function runDemo(card) {
    var name = card.getAttribute("data-demo");
    var btn = card.querySelector(".demo-btn");
    var st = card.querySelector(".demo-st");
    var term = card.querySelector("pre.term");
    var json = card.querySelector(".json-block");
    if (!btn || btn.disabled) return;
    btn.disabled = true;
    st.textContent = "corriendo…";
    st.className = "demo-st";
    if (json) json.classList.remove("visible");
    term.innerHTML = '<span class="dim">POST /api/demo/' + name + " …</span>";

    var req = name === "multihost"
      ? SMCP.post("/api/run/multihost")
      : SMCP.post("/api/demo/" + name);

    req.then(function (j) {
      st.textContent = "ok · " + (j.secs != null ? j.secs + "s" : "");
      st.className = "demo-st ok";
      var head = "OK · " + name + (j.secs != null ? " · " + j.secs + "s" : "") + "\n";
      var body;
      if (j.data && j.data.stdout) {
        body = head + j.data.stdout;
      } else if (j.stdout) {
        body = head + j.stdout;
      } else if (j.data && j.data.final_answer !== undefined) {
        body = head +
          "admitted: " + ((j.data.admitted_gists || []).length) + "\n" +
          "final: " + String(j.data.final_answer || "").slice(0, 400);
      } else if (j.data && j.data.ok === true) {
        body = head + "OK";
      } else {
        body = head + SMCP.jpretty(j.data !== undefined ? j.data : j).slice(0, 800);
      }
      term.innerHTML = SMCP.esc(body);
      if (j.data !== undefined && json) {
        json.textContent = SMCP.jpretty(j.data);
        json.classList.add("visible");
      } else if (j.stdout && json) {
        json.textContent = SMCP.jpretty({ secs: j.secs, code: j.code, stdout: j.stdout, stderr: j.stderr });
        json.classList.add("visible");
      }
    }).catch(function (e) {
      st.textContent = "error";
      st.className = "demo-st err";
      var detail = e.body && e.body.detail
        ? (typeof e.body.detail === "string" ? e.body.detail : SMCP.jpretty(e.body.detail))
        : "";
      term.innerHTML = SMCP.esc("FAIL · " + name + "\n" + e.message + (detail ? "\n" + detail : ""));
    }).finally(function () {
      btn.disabled = false;
    });
  }

  function init() {
    document.querySelectorAll(".demo[data-demo]").forEach(function (card) {
      var btn = card.querySelector(".demo-btn");
      if (btn) btn.addEventListener("click", function () { runDemo(card); });
    });
    SMCP.get("/api/health").then(function (h) {
      var m = h.model || {};
      var real = document.querySelector('.demo[data-demo="real"] .demo-st');
      if (real && m.configured && !m.reachable) {
        real.textContent = "endpoint caído";
        real.className = "demo-st err";
      }
    }).catch(function () {});
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
