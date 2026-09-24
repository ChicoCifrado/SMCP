/* SMCP — play.js: Lab — create run, live SSE events, poll state, inspect. */
(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };
  var out = $("lab-out");
  var poller = null;
  var stream = null;
  var currentId = null;
  var lastOutcome = null;

  function show(msg, cls) {
    out.className = "visible " + (cls || "");
    out.textContent = msg;
    out.scrollTop = out.scrollHeight;
  }

  function stopStream() {
    if (stream) {
      stream.close();
      stream = null;
    }
  }

  function appendEvent(ev) {
    var feed = $("event-feed");
    if (!feed) return;
    var line = "[" + (ev.type || "?") + "] " + (ev.label || "") +
      (ev.error ? " " + ev.error : "") +
      (ev.admitted != null ? " admitted=" + ev.admitted : "");
    feed.textContent = (feed.textContent ? feed.textContent + "\n" : "") + line;
    feed.scrollTop = feed.scrollHeight;
  }

  function beginStream(id) {
    stopStream();
    stream = SMCP.streamRun(id, {
      onEvent: function (ev) {
        appendEvent(ev);
        // Refresh state on meaningful events for snappy UI.
        if (ev.type === "reason" || ev.type === "done" || ev.type === "started") {
          SMCP.get("/api/runs/" + id + "/state").then(renderState).catch(function () {});
        }
      },
      onEnd: function (status) {
        stopStream();
        SMCP.get("/api/runs/" + id + "/state").then(function (st) {
          renderState(st);
          finishRun(id, st);
        }).catch(function () {
          $("btn-start").disabled = false;
          $("btn-cancel").disabled = true;
        });
        void status;
      },
      onError: function () {
        // SSE failed — poll keeps the UI alive.
        beginPoll(id);
      }
    });
  }

  function loadConfig() {
    return SMCP.get("/api/config").then(function (c) {
      $("cfg-model").textContent = c.model || "(sin model)";
      $("cfg-base").textContent = c.base_url || "(sin base_url)";
      $("cfg-key").textContent = c.api_key_set
        ? (c.api_key_masked || "set") + " · set"
        : "(vacío — sin Authorization)";
      // Enable real only if configured
      var opt = $("in-backend").querySelector('option[value="real"]');
      if (opt) {
        opt.disabled = !(c.has_model && c.has_base_url);
        if (opt.disabled && $("in-backend").value === "real") {
          $("in-backend").value = "fake";
        }
      }
      return c;
    }).catch(function (e) {
      $("cfg-model").textContent = "error: " + e.message;
    });
  }

  function probe() {
    var el = $("probe-out");
    el.style.display = "block";
    el.textContent = "probe POST /api/config/probe …";
    return SMCP.post("/api/config/probe", { check_completion: false })
      .then(function (j) {
        el.textContent = SMCP.jpretty(j);
        var realOpt = $("in-backend").querySelector('option[value="real"]');
        if (realOpt) realOpt.disabled = !j.reachable;
        SMCP.refreshHealth().catch(function () {});
      })
      .catch(function (e) {
        el.textContent = "probe error: " + e.message;
      });
  }

  function parseTasks(text) {
    var lines = String(text || "").split(/\r?\n/);
    var tasks = [];
    for (var i = 0; i < lines.length; i++) {
      var body = lines[i].trim();
      if (!body) continue;
      var n = tasks.length + 1;
      tasks.push({ label: "t-" + (n < 100 ? ("00" + n).slice(-3) : String(n)), body: body });
    }
    return tasks;
  }

  function startRun() {
    var tasks = parseTasks($("in-tasks").value);
    if (!tasks.length) {
      show("Añade al menos una task (una por línea).", "err");
      return;
    }
    if (tasks.length > 32) {
      show("Máximo 32 tasks por run.", "err");
      return;
    }
    var body = {
      tasks: tasks,
      n_workers: parseInt($("in-workers").value, 10) || 2,
      max_rounds: parseInt($("in-rounds").value, 10) || 8,
      backend: $("in-backend").value
    };
    $("btn-start").disabled = true;
    show("POST /api/runs …\n" + SMCP.jpretty(body));
    SMCP.post("/api/runs", body)
      .then(function (h) {
        currentId = h.id;
        lastOutcome = null;
        $("btn-cancel").disabled = false;
        $("outcome-actions").style.display = "none";
        $("worker-actions").style.display = "none";
        $("worker-actions").innerHTML = "";
        show("run " + h.id + " · status=" + h.status + "\n" + SMCP.jpretty(h), "ok");
        beginStream(h.id);
        beginPoll(h.id);
      })
      .catch(function (e) {
        show("Error al crear run: " + e.message + (e.body && e.body.detail ? "\n" + SMCP.jpretty(e.body.detail) : ""), "err");
        $("btn-start").disabled = false;
      });
  }

  function finishRun(id, st) {
    stopPoll();
    stopStream();
    $("btn-start").disabled = false;
    $("btn-cancel").disabled = true;
    if (st.status === "done") {
      show("run " + id + " DONE\n" + SMCP.jpretty(st.metrics || {}), "ok");
      $("outcome-actions").style.display = "";
    } else {
      show("run " + id + " " + st.status.toUpperCase() + (st.error ? "\n" + st.error : ""), "err");
    }
  }

  function beginPoll(id) {
    stopPoll();
    poller = SMCP.poll("/api/runs/" + id + "/state", 700, function (st) {
      renderState(st);
      if (st.status === "done" || st.status === "error" || st.status === "cancelled") {
        finishRun(id, st);
      }
    });
    poller.start();
  }

  function stopPoll() {
    if (poller) {
      poller.stop();
      poller = null;
    }
  }

  function renderState(st) {
    currentId = st.id;
    var pip = $("run-pip");
    pip.classList.remove("up", "down");
    if (st.status === "running" || st.status === "starting") {
      pip.classList.add("up");
    } else if (st.status === "done") {
      pip.classList.add("up");
    } else {
      pip.classList.add("down");
    }
    $("run-status").textContent = st.status + (st.error ? " · " + st.error : "");
    $("run-meta").textContent =
      st.id + " · backend=" + st.backend + " · rounds=" + (st.rounds || 0) +
      (st.wall_s != null ? " · wall=" + st.wall_s + "s" : "") +
      (st.model && st.model.model ? " · model=" + st.model.model : "");

    var total = (st.queue || []).length;
    var done = (st.queue || []).filter(function (t) { return t.state === "done"; }).length;
    var pct = total ? Math.round((done / total) * 100) : (st.status === "done" ? 100 : 0);
    $("run-bar").style.width = pct + "%";

    $("m-rounds").textContent = st.rounds != null ? st.rounds : "—";
    $("m-gists").textContent = st.gists ? st.gists.length : (st.ctx_labels || []).length;
    $("m-pending").textContent = st.pending != null ? st.pending : "—";
    var agg = st.metrics || {};
    $("m-admit").textContent = agg.admit_rate != null ? Math.round(agg.admit_rate * 100) + "%" : "—";
    $("m-lat").textContent = agg.latency_ms ? Math.round(agg.latency_ms.p50 || 0) : "—";
    $("m-wall").textContent = st.wall_s != null ? st.wall_s + "s" : "—";

    var q = $("queue-chips");
    q.innerHTML = "";
    if (!st.queue || !st.queue.length) {
      q.innerHTML = '<span class="chip-s">vacía</span>';
    } else {
      st.queue.forEach(function (t) {
        var s = document.createElement("span");
        s.className = "chip-s " + SMCP.esc(t.state);
        s.textContent = t.label + " · " + t.state;
        q.appendChild(s);
      });
    }

    var g = $("gist-chips");
    g.innerHTML = "";
    if (!st.gists || !st.gists.length) {
      g.innerHTML = '<span class="chip-s">—</span>';
    } else {
      st.gists.forEach(function (gi) {
        var s = document.createElement("a");
        s.className = "chip-s gist";
        s.href = "context.html?label=" + encodeURIComponent(gi.label);
        s.textContent = gi.label + (gi.taint ? " · taint" : "");
        g.appendChild(s);
      });
    }

    var feed = $("event-feed");
    if (st.events && st.events.length) {
      // Prefer live SSE appends; only hydrate when feed is empty.
      if (!feed.textContent.trim()) {
        feed.textContent = st.events.map(function (e) {
          return "[" + e.type + "] " + (e.label || "") + (e.error ? " " + e.error : "") +
            (e.admitted != null ? " admitted=" + e.admitted : "");
        }).join("\n");
        feed.scrollTop = feed.scrollHeight;
      }
    }

    if (st.status === "done" && st.workers && st.workers.length) {
      $("worker-actions").style.display = "";
      $("worker-actions").innerHTML = st.workers.map(function (w) {
        return '<span class="chip-s done">w' + w.worker_id + " · adm=" + w.admitted +
          " fail=" + w.failed + "</span>";
      }).join("");
    }
  }

  function cancelRun() {
    if (!currentId) return;
    $("btn-cancel").disabled = true;
    SMCP.post("/api/runs/" + currentId + "/cancel")
      .then(function (h) {
        show("cancelado: " + h.id + " status=" + h.status, "ok");
        stopPoll();
        stopStream();
        $("btn-start").disabled = false;
      })
      .catch(function (e) {
        show("cancel error: " + e.message, "err");
        $("btn-cancel").disabled = false;
      });
  }

  function refresh() {
    SMCP.get("/api/runs").then(function (j) {
      var id = currentId || j.active || (j.runs && j.runs[0] && j.runs[0].id);
      if (!id) {
        $("run-status").textContent = "sin run";
        return;
      }
      currentId = id;
      return SMCP.get("/api/runs/" + id + "/state").then(function (st) {
        renderState(st);
        if (st.status === "running" || st.status === "starting" || st.status === "queued") {
          beginStream(id);
          beginPoll(id);
          $("btn-cancel").disabled = false;
          $("btn-start").disabled = true;
        } else {
          $("btn-start").disabled = false;
          $("btn-cancel").disabled = true;
          if (st.status === "done") $("outcome-actions").style.display = "";
        }
      });
    }).catch(function (e) {
      $("run-status").textContent = "error: " + e.message;
    });
  }

  function showOutcome() {
    if (!currentId) return;
    SMCP.get("/api/runs/" + currentId + "/outcome").then(function (o) {
      lastOutcome = o;
      show("=== outcome ===\n" + SMCP.jpretty(o), "ok");
    }).catch(function (e) {
      show("outcome: " + e.message, "err");
    });
  }

  function init() {
    loadConfig();
    SMCP.refreshHealth().catch(function () {});
    refresh();
    window.addEventListener("pagehide", function () {
      stopPoll();
      stopStream();
    });
    $("btn-probe").addEventListener("click", probe);
    $("btn-health").addEventListener("click", function () {
      SMCP.refreshHealth().then(function (h) {
        show("=== health ===\n" + SMCP.jpretty(h), "ok");
      }).catch(function (e) {
        show("health error: " + e.message, "err");
      });
    });
    $("btn-start").addEventListener("click", startRun);
    $("btn-cancel").addEventListener("click", cancelRun);
    $("btn-refresh").addEventListener("click", refresh);
    $("btn-outcome").addEventListener("click", showOutcome);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
