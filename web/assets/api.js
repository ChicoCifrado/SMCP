/* SMCP — api.js: helpers compartidos (fetch, health, escape, poll). */
(function () {
  "use strict";

  var SMCP = (window.SMCP = window.SMCP || {});

  SMCP.esc = function (s) {
    if (s == null) return "";
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  };

  SMCP.jpretty = function (obj) {
    try {
      return JSON.stringify(obj, null, 2);
    } catch (e) {
      return String(obj);
    }
  };

  SMCP.get = function (path) {
    return fetch(path).then(function (r) {
      return r.json().then(function (j) {
        if (!r.ok) {
          var msg = (j && (j.detail || j.error)) || "HTTP " + r.status;
          var err = new Error(msg);
          err.status = r.status;
          err.body = j;
          throw err;
        }
        return j;
      });
    });
  };

  SMCP.post = function (path, body) {
    var opts = { method: "POST", headers: {} };
    if (body !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    return fetch(path, opts).then(function (r) {
      return r.json().then(function (j) {
        if (!r.ok) {
          var msg = (j && (j.detail || j.error)) || "HTTP " + r.status;
          var err = new Error(typeof msg === "string" ? msg : JSON.stringify(msg));
          err.status = r.status;
          err.body = j;
          throw err;
        }
        return j;
      });
    });
  };

  SMCP.del = function (path) {
    return fetch(path, { method: "DELETE" }).then(function (r) {
      return r.json().then(function (j) {
        if (!r.ok) {
          var err = new Error((j && j.detail) || "HTTP " + r.status);
          err.status = r.status;
          throw err;
        }
        return j;
      });
    });
  };

  /* Health pip: expects elements #api-pip and #api-label (optional). */
  SMCP.setApi = function (up, label) {
    var pip = document.getElementById("api-pip");
    var lab = document.getElementById("api-label");
    if (pip) {
      pip.classList.remove("up", "down");
      pip.classList.add(up ? "up" : "down");
    }
    if (lab) lab.textContent = label;
  };

  SMCP.refreshHealth = function () {
    SMCP.setApi(false, "consultando…");
    return SMCP.get("/api/health")
      .then(function (h) {
        var m = h.model || {};
        if (m.configured && !m.reachable) {
          SMCP.setApi(true, "API arriba · modelo caído");
        } else if (m.configured && m.reachable) {
          SMCP.setApi(true, "API + endpoint OK");
        } else {
          SMCP.setApi(true, "API arriba · sin endpoint");
        }
        return h;
      })
      .catch(function (e) {
        SMCP.setApi(false, "API caída (" + e.message + ")");
        throw e;
      });
  };

  /* Poll manager: start/stop; auto-clears on pagehide. */
  SMCP.poll = function (url, ms, cb) {
    var timer = null;
    function tick() {
      SMCP.get(url)
        .then(cb)
        .catch(function (e) {
          if (cb.onError) cb.onError(e);
        });
    }
    function start() {
      stop();
      tick();
      timer = setInterval(tick, ms);
    }
    function stop() {
      if (timer) {
        clearInterval(timer);
        timer = null;
      }
    }
    window.addEventListener("pagehide", stop);
    return { start: start, stop: stop, tick: tick };
  };

  SMCP.fmtSecs = function (s) {
    if (s == null) return "—";
    if (s < 60) return s + "s";
    return Math.floor(s / 60) + "m " + Math.round(s % 60) + "s";
  };

  SMCP.taintName = function (n) {
    if (n >= 2) return "CONFIRMED";
    if (n >= 1) return "SUSPICIOUS";
    return "CLEAN";
  };
})();
