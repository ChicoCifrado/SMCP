/* SMCP — runs.js: cliente del motor de runs asincrono.

   El path heredado (/api/run/<fid>) bloquea la peticion hasta que la
   funcion termina. Con la suite de tests a 240 s eso significa una
   consola congelada, sin progreso y sin cancelacion. Este modulo habla
   con el motor real:

     POST /api/runs              -> crea el run, devuelve el header
     GET  /api/runs/<id>/events  -> SSE: replay + follow hasta "end"
     POST /api/runs/<id>/cancel  -> cancela en vivo
     GET  /api/runs/<id>/state   -> snapshot (para reconectar)
     DELETE /api/runs/<id>       -> borra del registro

   Uso:  Runs.start({tasks, n_workers, max_rounds}, handlers)
   handlers: onEvent(ev), onState(st), onEnd(status)
*/
(function () {
  "use strict";

  var SSE = window.EventSource;

  /** Lanza un run y devuelve un control con cancel(). */
  function start(opts, handlers) {
    var h = handlers || {};
    var ctrl = { id: null, cancelled: false, _es: null, _closed: false };

    var body = {
      backend: opts.backend || "fake",
      n_workers: opts.n_workers || 2,
      max_rounds: opts.max_rounds || 1,
      tasks: (opts.tasks || [{ body: "resolver la tarea" }]),
    };

    fetch("/api/runs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    })
      .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j }; }); })
      .then(function (res) {
        if (!res.ok) throw new Error(res.j.detail || "error al crear el run");
        ctrl.id = res.j.id;
        if (h.onCreate) h.onCreate(res.j);
        follow(ctrl, h);
      })
      .catch(function (e) { if (h.onError) h.onError(e); });

    return ctrl;
  }

  /** Sigue el stream de eventos (replay incluido) hasta el "end". */
  function follow(ctrl, h) {
    if (!SSE) { poll(ctrl, h); return; }
    var es = new SSE("/api/runs/" + ctrl.id + "/events");
    ctrl._es = es;
    es.onmessage = function (msg) {
      var ev;
      try { ev = JSON.parse(msg.data); } catch (e) { return; }
      if (ev.type === "end") {
        es.close();
        ctrl._closed = true;
        if (h.onEnd) h.onEnd(ev.status);
        return;
      }
      if (h.onEvent) h.onEvent(ev);
    };
    es.onerror = function () {
      // El server cierra la conexion al terminar; si ya cerramos, nada.
      if (ctrl._closed) return;
      es.close();
      // Reconectar por sondeo si el stream murio antes de "end".
      poll(ctrl, h);
    };
  }

  /** Sondeo de respaldo: sigue el estado hasta estado terminal. */
  function poll(ctrl, h) {
    var tick = function () {
      if (ctrl._closed) return;
      fetch("/api/runs/" + ctrl.id + "/state")
        .then(function (r) { return r.json(); })
        .then(function (st) {
          if (h.onState) h.onState(st);
          if (st.status === "done" || st.status === "error" || st.status === "cancelled") {
            ctrl._closed = true;
            if (h.onEnd) h.onEnd(st.status);
            return;
          }
          setTimeout(tick, 600);
        })
        .catch(function () { setTimeout(tick, 1500); });
    };
    tick();
  }

  /** Cancela el run en vivo. */
  function cancel(ctrl) {
    if (!ctrl.id || ctrl._closed) return Promise.resolve({ ok: false });
    ctrl.cancelled = true;
    return fetch("/api/runs/" + ctrl.id + "/cancel", { method: "POST" })
      .then(function (r) { return r.json(); })
      .catch(function () { return { ok: false }; });
  }

  /** Snapshot del estado (para reconectar a un run existente). */
  function state(id) {
    return fetch("/api/runs/" + id + "/state").then(function (r) { return r.json(); });
  }

  /** Borra el run del registro. */
  function drop(id) {
    return fetch("/api/runs/" + id, { method: "DELETE" })
      .then(function (r) { return r.json(); })
      .catch(function () { return { ok: false }; });
  }

  /** Lista de runs con el activo. */
  function list() {
    return fetch("/api/runs").then(function (r) { return r.json(); });
  }

  /**
   * Reconectar al run activo tras recargar la pagina.
   * La API lista los runs; el activo se sigue como si se hubiera
   * lanzado aqui — el stream hace replay desde el evento 0.
   * Devuelve null si no hay run activo.
   */
  function reconnect(handlers) {
    return list().then(function (j) {
      var active = j.active;
      if (!active) return null;
      var h = handlers || {};
      var ctrl = { id: active, cancelled: false, _es: null, _closed: false, reconnected: true };
      if (h.onCreate) {
        // el header completo para el reconectado
        fetch("/api/runs/" + active)
          .then(function (r) { return r.json(); })
          .then(function (hdr) { if (h.onCreate) h.onCreate(hdr); })
          .catch(function () {});
      }
      follow(ctrl, h);
      return ctrl;
    });
  }

  window.SMCPRuns = { start: start, cancel: cancel, state: state, drop: drop, list: list, reconnect: reconnect };
})();
