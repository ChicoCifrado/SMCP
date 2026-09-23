/* SMCP — app.js: tema (dark por defecto) + recordar última página.
   Fuente OpenCode vía CSS @font-face. */
(function () {
  "use strict";

  /* --- Tema --- */
  var KEY = "smcp-theme";
  var PAGE_KEY = "smcp-last-page";
  var HOME = "index.html";

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

  /* --- Última página visitada --- */
  function savePage() {
    var path = location.pathname.split("/").pop() || HOME;
    if (!path || path === HOME) return; // el home no se "recuerda" como destino
    try { localStorage.setItem(PAGE_KEY, path); } catch (e) {}
  }

  function lastPage() {
    try { return localStorage.getItem(PAGE_KEY); } catch (e) { return null; }
  }

  /* Si entramos en la raíz / home y hay una última página guardada distinta,
     redirigimos ahí (restaurar sesión de navegación). */
  function maybeRestore() {
    var path = location.pathname.split("/").pop() || HOME;
    if (path !== HOME && path !== "") return;
    var dest = lastPage();
    if (!dest || dest === HOME) return;
    // Solo si el archivo existe (evita bucles con páginas borradas).
    // Comprobación barata: mismos dominios de nombre que las del nav.
    var known = ["nucleo.html", "seguridad.html", "demos.html",
                 "arquitectura.html", "estado.html", "console.html"];
    if (known.indexOf(dest) !== -1) {
      location.replace(dest);
    }
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

    maybeRestore();
    savePage();
    // Al navegar dentro del SPA-less site, cada load ya guarda su página.
    window.addEventListener("pagehide", savePage);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
