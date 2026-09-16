/* SMCP — app.js: tema (dark por defecto). Fuente OpenCode vía CSS @font-face. */
(function () {
  "use strict";

  /* --- Tema --- */
  var KEY = "smcp-theme";

  function isDark() {
    return !document.body.classList.contains("light");
  }

  function apply(dark) {
    if (dark) {
      document.body.classList.remove("light");
    } else {
      document.body.classList.add("light");
    }
    var btn = document.querySelector(".theme-btn");
    if (btn) btn.textContent = dark ? "\u2600" : "\u263E";
  }

  function toggle() {
    apply(!isDark());
    try { localStorage.setItem(KEY, isDark() ? "dark" : "light"); } catch (e) {}
  }

  /* --- Init --- */
  function init() {
    try {
      var saved = localStorage.getItem(KEY);
      if (saved === "light") apply(false);
      else apply(true);
    } catch (e) {
      apply(true);
    }
    var btn = document.querySelector(".theme-btn");
    if (btn) btn.addEventListener("click", toggle);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
