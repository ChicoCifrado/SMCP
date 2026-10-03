/* DeLM/SMCP — Consola de control 3D (Three.js)

   Dos modos:

   MOTOR — lanza runs contra /api/runs (asincrono, SSE en vivo).
   Cada worker del run es un cuerpo en orbita; los gists admitidos
   son puntos de luz que nacen del worker; el taint se pinta de
   ambar; las rondas avanzan el anillo. Cancelacion en vivo.

   PROYECTO — el path heredado: 5 nodos-funcion orbitando el
   nucleo; clic en uno ejecuta la funcion via /api/run/<id>
   (sincrono). Sirve para las demos del repo (tests, seguridad…).

   El estado visual sale del stream de eventos, no de un cronometro:
   lo que se ve es lo que el motor esta haciendo.
*/
(function () {
  "use strict";

  // ---------- paleta (coincidente con style.css) ----------
  var COL = {
    bg: 0x090a09, fog: 0x090a09,
    core: 0x8fbf3f, coreHi: 0xdce6cf,
    node: 0x58624b, nodeHi: 0x8fbf3f,
    worker: 0x6b7a5a, ring: 0x262b22,
    gist: 0xb8d98a, taint: 0xffc233, err: 0xff6b5b,
    text: 0xdce6cf, dim: 0x9aa68c,
    run: 0xffc233,
  };

  // ---------- estado de modo ----------
  var MODE = "motor"; // "motor" | "proy"

  // ---------- refs de UI ----------
  var el = function (id) { return document.getElementById(id); };
  var out = el("out"), dot = el("dot"), ttl = el("ttl"), st = el("st");
  var cancelBtn = el("btn-cancel"), runBtn = el("btn-run");

  // ---------- escenario ----------
  var scene, camera, renderer, clock;
  var core, coreGlow, ring, ringWire;
  var workers = [];   // { mesh, halo, label, radius, speed, phase, baseY, busy, mat }
  var gists = [];     // { mesh, mat, born, from }
  var taintPuffs = [];
  var particles, particleMat;
  var funcNodes = []; // modo PROYECTO
  var hitMeshes = [];

  var raycaster = new THREE.Raycaster();
  var cam = { theta: 0.6, phi: 1.15, radius: 26, target: new THREE.Vector3(0, 1.5, 0), dragging: false, px: 0, py: 0 };

  // ---------- motor ----------
  var run = null; // { ctrl, taskNodes }
  var T = 0;

  // ============================================================
  //  label: sprite de texto (canvas)
  // ============================================================
  function makeLabel(text, color) {
    var fs = 46, pad = 18;
    var c = document.createElement("canvas");
    var ctx = c.getContext("2d");
    ctx.font = "600 " + fs + "px 'IBM Plex Mono', ui-monospace, monospace";
    var w = Math.ceil(ctx.measureText(text).width) + pad * 2;
    c.width = w; c.height = fs + pad * 2;
    var x = c.getContext("2d");
    x.font = "600 " + fs + "px 'IBM Plex Mono', ui-monospace, monospace";
    x.textBaseline = "middle";
    x.fillStyle = "rgba(18,20,15,0.72)";
    roundRect(x, 0, 0, c.width, c.height, 14); x.fill();
    x.strokeStyle = "rgba(143,191,63,0.35)"; x.lineWidth = 2;
    roundRect(x, 1, 1, c.width - 2, c.height - 2, 14); x.stroke();
    x.fillStyle = color || "#dce6cf";
    x.fillText(text, pad, c.height / 2);
    var tex = new THREE.CanvasTexture(c);
    tex.minFilter = THREE.LinearFilter;
    var mat = new THREE.SpriteMaterial({ map: tex, transparent: true, depthTest: false });
    var sp = new THREE.Sprite(mat);
    var s = 0.016;
    sp.scale.set(c.width * s, c.height * s, 1);
    return sp;
  }
  function roundRect(x, a, b, w, h, r) {
    x.beginPath();
    x.moveTo(a + r, b);
    x.arcTo(a + w, b, a + w, b + h, r);
    x.arcTo(a + w, b + h, a, b + h, r);
    x.arcTo(a, b + h, a, b, r);
    x.arcTo(a, b, a + w, b, r);
    x.closePath();
  }

  // ============================================================
  //  escena
  // ============================================================
  function initScene() {
    scene = new THREE.Scene();
    scene.fog = new THREE.FogExp2(COL.bg, 0.016);

    camera = new THREE.PerspectiveCamera(50, innerWidth / innerHeight, 0.1, 200);
    placeCamera();

    renderer = new THREE.WebGLRenderer({ canvas: el("scene"), antialias: true });
    renderer.setPixelRatio(Math.min(devicePixelRatio, 2));
    renderer.setSize(innerWidth, innerHeight);
    renderer.setClearColor(COL.bg, 1);

    scene.add(new THREE.AmbientLight(0x40403a, 0.9));
    var key = new THREE.DirectionalLight(0xdce6cf, 0.8); key.position.set(8, 14, 6); scene.add(key);
    var rim = new THREE.PointLight(COL.core, 1.1, 60); rim.position.set(0, 4, 0); scene.add(rim);

    buildCore();
    buildRing();
    buildParticles();
    buildFloor();

    clock = new THREE.Clock();
  }

  function placeCamera() {
    var sp = Math.sin(cam.phi), cp = Math.cos(cam.phi);
    camera.position.set(
      cam.target.x + cam.radius * sp * Math.sin(cam.theta),
      cam.target.y + cam.radius * cp,
      cam.target.z + cam.radius * sp * Math.cos(cam.theta)
    );
    camera.lookAt(cam.target);
  }

  function buildCore() {
    var g = new THREE.IcosahedronGeometry(2.1, 1);
    var m = new THREE.MeshStandardMaterial({
      color: COL.core, emissive: COL.core, emissiveIntensity: 0.35,
      metalness: 0.3, roughness: 0.5, flatShading: true,
    });
    core = new THREE.Mesh(g, m); core.position.set(0, 1.5, 0);
    scene.add(core);

    var w = new THREE.Mesh(
      new THREE.IcosahedronGeometry(2.35, 1),
      new THREE.MeshBasicMaterial({ color: COL.coreHi, wireframe: true, transparent: true, opacity: 0.28 })
    );
    w.position.copy(core.position); scene.add(w);
    coreGlow = w;

    var lb = makeLabel("núcleo DeLM", "#dce6cf");
    lb.position.set(0, 4.4, 0); scene.add(lb);
  }

  function buildRing() {
    var r = 7.2;
    ring = new THREE.Mesh(
      new THREE.TorusGeometry(r, 0.05, 8, 120),
      new THREE.MeshBasicMaterial({ color: COL.core, transparent: true, opacity: 0.5 })
    );
    ring.rotation.x = Math.PI / 2; ring.position.y = 0.1; scene.add(ring);

    var r2 = 9.4;
    ringWire = new THREE.Mesh(
      new THREE.TorusGeometry(r2, 0.03, 6, 140),
      new THREE.MeshBasicMaterial({ color: COL.coreHi, wireframe: true, transparent: true, opacity: 0.18 })
    );
    ringWire.rotation.x = Math.PI / 2; ringWire.position.y = 0.05; scene.add(ringWire);
  }

  function buildParticles() {
    var N = 400, pos = new Float32Array(N * 3);
    for (var i = 0; i < N; i++) {
      var r = 12 + Math.random() * 22;
      var th = Math.random() * Math.PI * 2;
      var ph = Math.acos(2 * Math.random() - 1);
      pos[i * 3] = r * Math.sin(ph) * Math.cos(th);
      pos[i * 3 + 1] = Math.abs(r * Math.cos(ph)) * 0.5 + 0.3;
      pos[i * 3 + 2] = r * Math.sin(ph) * Math.sin(th);
    }
    var geo = new THREE.BufferGeometry();
    geo.setAttribute("position", new THREE.BufferAttribute(pos, 3));
    particleMat = new THREE.PointsMaterial({ color: 0x9aa68c, size: 0.12, transparent: true, opacity: 0.7, sizeAttenuation: true });
    particles = new THREE.Points(geo, particleMat);
    scene.add(particles);
  }

  function buildFloor() {
    var grid = new THREE.GridHelper(60, 40, 0x262b22, 0x1a1e16);
    grid.position.y = -0.02;
    grid.material.transparent = true; grid.material.opacity = 0.5;
    scene.add(grid);
  }

  // ============================================================
  //  MODO MOTOR — workers dinamicos
  // ============================================================
  function spawnWorkers(n) {
    clearWorkers();
    var baseR = 5.6;
    for (var i = 0; i < n; i++) {
      var g = new THREE.SphereGeometry(0.5, 20, 20);
      var m = new THREE.MeshStandardMaterial({
        color: COL.worker, emissive: COL.worker, emissiveIntensity: 0.4,
        metalness: 0.2, roughness: 0.6,
      });
      var mesh = new THREE.Mesh(g, m);
      var radius = baseR + (i % 2) * 1.3;
      var phase = (i / n) * Math.PI * 2 - Math.PI / 2;
      mesh.position.set(Math.cos(phase) * radius, 1.5, Math.sin(phase) * radius);
      scene.add(mesh);

      var halo = new THREE.Mesh(
        new THREE.SphereGeometry(0.85, 14, 14),
        new THREE.MeshBasicMaterial({ color: COL.worker, wireframe: true, transparent: true, opacity: 0.14 })
      );
      halo.position.copy(mesh.position); scene.add(halo);

      var lb = makeLabel("worker-" + i, "#9aa68c");
      lb.position.copy(mesh.position); scene.add(lb);

      workers.push({
        mesh: mesh, halo: halo, label: lb, mat: m,
        radius: radius, speed: 0.5 + (i % 3) * 0.14,
        phase: phase, baseY: 1.5, busy: false,
      });
    }
  }

  function clearWorkers() {
    workers.forEach(function (w) {
      scene.remove(w.mesh); scene.remove(w.halo); scene.remove(w.label);
    });
    workers = [];
  }

  function markBusy(i, busy) {
    var w = workers[i];
    if (!w) return;
    if (busy) {
      w.mat.color.setHex(COL.run); w.mat.emissive.setHex(0x554411);
      w.mat.emissiveIntensity = 0.9;
      w.halo.material.color.setHex(COL.run);
    } else {
      w.mat.color.setHex(COL.worker); w.mat.emissive.setHex(COL.worker);
      w.mat.emissiveIntensity = 0.4;
      w.halo.material.color.setHex(COL.worker);
    }
  }

  function burstGist(fromPos) {
    var g = new THREE.SphereGeometry(0.22, 12, 12);
    var m = new THREE.MeshBasicMaterial({ color: COL.gist, transparent: true, opacity: 1 });
    var mesh = new THREE.Mesh(g, m);
    mesh.position.copy(fromPos);
    scene.add(mesh);
    gists.push({ mesh: mesh, mat: m, born: T, from: fromPos.clone() });
  }

  function puffTaint(atPos) {
    var g = new THREE.SphereGeometry(0.3, 10, 10);
    var m = new THREE.MeshBasicMaterial({ color: COL.taint, transparent: true, opacity: 0.8 });
    var mesh = new THREE.Mesh(g, m);
    mesh.position.copy(atPos);
    scene.add(mesh);
    taintPuffs.push({ mesh: mesh, mat: m, born: T });
  }

  // ============================================================
  //  MODO PROYECTO — nodos-funcion heredados
  // ============================================================
  var FUNCS = [
    { id: "demo", label: "Pipeline DeLM" },
    { id: "security", label: "Seguridad" },
    { id: "taint", label: "Anti-inyección" },
    { id: "multihost", label: "Multi-host" },
    { id: "tests", label: "Tests" },
  ];

  function loadFunctions() {
    return fetch("/api/functions")
      .then(function (r) { return r.json(); })
      .then(function (list) {
        if (!Array.isArray(list) || !list.length) return;
        var ids = list.map(function (f) { return f.id; }).join(",");
        var cur = FUNCS.map(function (f) { return f.id; }).join(",");
        if (ids === cur) return;
        FUNCS = list.map(function (f) {
          return { id: f.id, label: f.label || f.id };
        });
        if (scene && funcNodes.length) {
          funcNodes.forEach(function (n) {
            scene.remove(n.mesh); scene.remove(n.halo);
            if (n.label) scene.remove(n.label);
            if (n.line) scene.remove(n.line);
          });
          funcNodes = [];
          hitMeshes = [];
          buildFuncNodes();
        }
      })
      .catch(function () {});
  }

  function buildFuncNodes() {
    var r = 7.2;
    FUNCS.forEach(function (f, i) {
      var a = (i / FUNCS.length) * Math.PI * 2 - Math.PI / 2;
      var x = Math.cos(a) * r, z = Math.sin(a) * r;

      var g = new THREE.OctahedronGeometry(0.72, 0);
      var m = new THREE.MeshStandardMaterial({
        color: COL.node, emissive: COL.node, emissiveIntensity: 0.5,
        metalness: 0.2, roughness: 0.6, flatShading: true,
      });
      var mesh = new THREE.Mesh(g, m);
      mesh.position.set(x, 1.1, z);
      scene.add(mesh);

      var halo = new THREE.Mesh(
        new THREE.SphereGeometry(1.0, 16, 16),
        new THREE.MeshBasicMaterial({ color: COL.node, transparent: true, opacity: 0.12, wireframe: true })
      );
      halo.position.copy(mesh.position); scene.add(halo);

      var lb = makeLabel(f.label, "#dce6cf");
      lb.position.set(x, 2.7, z); scene.add(lb);

      var line = makeLine(new THREE.Vector3(0, 1.5, 0), mesh.position, 0x58624b, 0.5);
      scene.add(line);

      funcNodes.push({ mesh: mesh, halo: halo, id: f.id, baseY: 1.1, phase: a, label: lb, mat: m, line: line });
      hitMeshes.push(mesh);
    });
  }

  function clearFuncNodes() {
    funcNodes.forEach(function (n) {
      scene.remove(n.mesh); scene.remove(n.halo);
      if (n.label) scene.remove(n.label);
      if (n.line) scene.remove(n.line);
    });
    funcNodes = [];
    hitMeshes = [];
  }

  function makeLine(a, b, color, opacity) {
    var geo = new THREE.BufferGeometry().setFromPoints([a, b]);
    return new THREE.Line(geo, new THREE.LineBasicMaterial({ color: color, transparent: true, opacity: opacity }));
  }

  // ============================================================
  //  interaccion
  // ============================================================
  function onDown(e) {
    var t = e.touches ? e.touches[0] : e;
    cam.px = t.clientX; cam.py = t.clientY;
    if (e.type === "touchstart" || e.target === el("scene")) cam.dragging = true;
  }
  function onMove(e) {
    if (!cam.dragging) return;
    var t = e.touches ? e.touches[0] : e;
    var dx = t.clientX - cam.px, dy = t.clientY - cam.py;
    cam.theta -= dx * 0.005;
    cam.phi = Math.max(0.35, Math.min(1.5, cam.phi - dy * 0.005));
    cam.px = t.clientX; cam.py = t.clientY;
    placeCamera();
  }
  function onUp(e) {
    cam.dragging = false;
    var t = e.changedTouches ? e.changedTouches[0] : e;
    if (Math.abs(t.clientX - cam.px) < 6 && Math.abs(t.clientY - cam.py) < 6) {
      pickAt(t.clientX, t.clientY);
    }
  }
  function onWheel(e) {
    e.preventDefault();
    cam.radius = Math.max(8, Math.min(60, cam.radius + e.deltaY * 0.02));
    placeCamera();
  }
  function pickAt(cx, cy) {
    if (MODE !== "proy") return; // en modo motor el clic no ejecuta
    var v = new THREE.Vector2((cx / innerWidth) * 2 - 1, -(cy / innerHeight) * 2 + 1);
    raycaster.setFromCamera(v, camera);
    var hits = raycaster.intersectObjects(hitMeshes, false);
    if (hits.length) {
      var mesh = hits[0].object;
      for (var i = 0; i < funcNodes.length; i++) {
        if (funcNodes[i].mesh === mesh) { runFunc(funcNodes[i].id); break; }
      }
    }
  }

  // ============================================================
  //  ejecucion de funciones del proyecto (modo PROYECTO)
  // ============================================================
  function runFunc(id) {
    if (run && run.ctrl && !run.ctrl._closed) return;
    var node = funcNodes.filter(function (n) { return n.id === id; })[0];
    if (node) { node.mat.color.setHex(0xffc233); node.mat.emissive.setHex(0x554411); node.mat.emissiveIntensity = 0.8; }
    dot.classList.add("on");
    ttl.textContent = labelOf(id);
    st.textContent = "ejecutando…"; st.className = "st";
    out.innerHTML = '<span class="dim">POST /api/run/' + id + ' …</span>';
    fetch("/api/run/" + id, { method: "POST" })
      .then(function (r) { return r.json(); })
      .then(function (res) { showResult(id, res); })
      .catch(function (e) { showResult(id, { ok: false, stderr: String(e), stdout: "" }); });
  }

  function labelOf(id) {
    var f = FUNCS.filter(function (x) { return x.id === id; })[0];
    return f ? f.label : id;
  }

  function showResult(id, res) {
    var node = funcNodes.filter(function (n) { return n.id === id; })[0];
    if (node) {
      node.mat.color.setHex(res.ok ? COL.core : COL.err);
      node.mat.emissive.setHex(res.ok ? 0x113311 : 0x331111);
      node.mat.emissiveIntensity = 0.6;
    }
    dot.classList.remove("on");
    if (res.ok) { st.textContent = "OK · " + (res.secs != null ? res.secs + "s" : ""); st.className = "st ok"; }
    else { st.textContent = "error (código " + (res.code != null ? res.code : "?") + ")"; st.className = "st err"; }
    out.innerHTML = renderBody(id, res);
    setTimeout(function () {
      if (node) { node.mat.color.setHex(COL.node); node.mat.emissive.setHex(COL.node); node.mat.emissiveIntensity = 0.5; }
    }, 1200);
  }

  function renderBody(id, res) {
    var secs = res.secs != null ? '\n<span class="dim">— ' + res.secs + 's</span>' : "";
    var sum = res.summary;
    if (id === "tests" && sum && sum.parsed) {
      var head = '<span class="' + (res.ok ? "ok" : "err") + '">' + fmt(sum.headline) + "</span>";
      var body = sum.body ? "\n" + fmt(sum.body) : "";
      var warn = "";
      if (sum.warnings_text) {
        warn = '\n\n<span class="dim">warnings (' + sum.warnings + ")</span>\n"
          + '<span class="dim">' + fmt(sum.warnings_text) + "</span>";
      }
      return head + body + warn + secs;
    }
    var raw = res.stdout || res.stderr || "(sin salida)";
    return fmt(raw) + secs;
  }

  function fmt(s) {
    return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  // ============================================================
  //  MODO MOTOR — lanzar run (SSE)
  // ============================================================
  function launchRun() {
    if (run && run.ctrl && !run.ctrl._closed) return; // ya hay uno en curso
    var taskText = el("f-task").value.trim() || "resolver la tarea";
    var backend = el("f-backend").value;
    var nw = Math.max(1, Math.min(8, parseInt(el("f-workers").value, 10) || 2));
    var rounds = Math.max(1, Math.min(10, parseInt(el("f-rounds").value, 10) || 1));

    // Preparar escena
    clearFuncNodes();
    spawnWorkers(nw);
    clearGists();
    clearTaint();
    ring.material.color.setHex(COL.core);

    dot.classList.add("on");
    ttl.textContent = "Run " + taskText.slice(0, 26);
    st.textContent = "creando…"; st.className = "st";
    runBtn.disabled = true;
    cancelBtn.classList.add("on");
    out.innerHTML = '<span class="dim">POST /api/runs — backend=' + backend +
      ", workers=" + nw + ", rounds=" + rounds + "</span>\n";

    var ctrl = SMCPRuns.start(
      { backend: backend, n_workers: nw, max_rounds: rounds, tasks: [{ body: taskText }] },
      {
        onCreate: function (hdr) {
          st.textContent = "run " + hdr.id.slice(4, 10) + " · vivo"; st.className = "st ok";
          printLine("run <span class='ok'>" + hdr.id + "</span> creado");
        },
        onEvent: function (ev) { handleEvent(ev, nw); },
        onEnd: function (status) { endRun(status); },
        onError: function (e) {
          endRun("error");
          printLine('<span class="err">error: ' + fmt(e.message || String(e)) + "</span>");
        },
      }
    );
    run = { ctrl: ctrl, nw: nw };
  }

  function handleEvent(ev, nw) {
    var i, w;
    switch (ev.type) {
      case "started":
        printLine('<span class="k">motor</span> arrancó — backend=' + ev.backend);
        break;
      case "round":
        printLine('<span class="k">ronda</span> ' + ev.round + " / " + (ev.max_rounds != null ? ev.max_rounds : "?"));
        ring.material.color.setHex(COL.run);
        setTimeout(function () { ring.material.color.setHex(COL.core); }, 600);
        break;
      case "reason":
        // worker i resuelve la tarea label
        w = workerFor(ev.label, nw);
        if (w != null) markBusy(w, true);
        printLine('<span class="k">solve</span> ' + ev.label);
        break;
      case "gist":
      case "admit":
        w = workerFor(ev.label, nw);
        if (w != null) {
          markBusy(w, false);
          burstGist(workers[w].mesh.position);
        }
        printLine('<span class="gist">gist admitido</span>' + (ev.label ? " " + ev.label : ""));
        break;
      case "taint":
        w = workerFor(ev.label, nw);
        if (w != null) puffTaint(workers[w].mesh.position);
        printLine('<span class="taint">taint</span>' + (ev.label ? " " + ev.label : "") +
          (ev.score != null ? " ·" + ev.score : ""));
        break;
      case "reject":
        w = workerFor(ev.label, nw);
        if (w != null) markBusy(w, false);
        printLine('<span class="err">rechazado</span>' + (ev.label ? " " + ev.label : ""));
        break;
      case "worker":
        break;
      case "done":
        printLine('<span class="ok">done</span> — admitted=' + (ev.admitted != null ? ev.admitted : "?") +
          ", rounds=" + (ev.rounds != null ? ev.rounds : "?"));
        break;
      case "error":
        printLine('<span class="err">error del motor</span>');
        break;
      default:
        printLine('<span class="k">' + fmt(ev.type) + "</span>");
    }
  }

  /** El label de gist tiene forma "t-001/w0" — el worker es el sufijo. */
  function workerFor(label, nw) {
    if (!label) return null;
    var m = /w(\d+)$/.exec(label);
    if (m) {
      var i = parseInt(m[1], 10);
      return i < nw ? i : null;
    }
    return null;
  }

  function endRun(status) {
    dot.classList.remove("on");
    runBtn.disabled = false;
    cancelBtn.classList.remove("on");
    workers.forEach(function (w, i) { markBusy(i, false); });
    if (status === "done") {
      st.textContent = "completado"; st.className = "st ok";
      printLine('<span class="ok">run completado</span>');
    } else if (status === "cancelled") {
      st.textContent = "cancelado"; st.className = "st err";
      printLine('<span class="err">run cancelado</span>');
    } else {
      st.textContent = "falló"; st.className = "st err";
      printLine('<span class="err">run falló: ' + fmt(String(status)) + "</span>");
    }
    if (run && run.ctrl) SMCPRuns.state(run.ctrl.id).then(applyMetrics).catch(function () {});
  }

  function applyMetrics(s) {
    el("mx-rounds").textContent = s.rounds != null ? s.rounds : 0;
    el("mx-gists").textContent = s.gists ? s.gists.length : 0;
    el("mx-pending").textContent = s.pending != null ? s.pending : 0;
    el("mx-workers").textContent = s.workers ? s.workers.length : 0;
  }

  function clearGists() {
    gists.forEach(function (g) { scene.remove(g.mesh); });
    gists = [];
  }
  function clearTaint() {
    taintPuffs.forEach(function (p) { scene.remove(p.mesh); });
    taintPuffs = [];
  }

  function printLine(html) {
    var div = document.createElement("div");
    div.className = "ev";
    div.innerHTML = html;
    out.appendChild(div);
    out.scrollTop = out.scrollHeight;
  }

  // ============================================================
  //  cambio de modo
  // ============================================================
  function setMode(m) {
    if (m === MODE) return;
    MODE = m;
    el("m-motor").classList.toggle("on", m === "motor");
    el("m-proy").classList.toggle("on", m === "proy");
    el("metrics").style.display = m === "motor" ? "flex" : "none";
    el("runform").style.display = m === "motor" ? "grid" : "none";
    el("hint").textContent = m === "motor"
      ? "arrastra para orbitar · rueda para zoom · el run se dibuja en vivo"
      : "arrastra para orbitar · rueda para zoom · clic en un nodo para ejecutar";
    if (m === "motor") {
      clearFuncNodes();
      spawnWorkers(2);
      ttl.textContent = "Motor DeLM";
      st.textContent = "en reposo"; st.className = "st";
      out.innerHTML = '<span class="dim">Pulsa «Ejecutar run» para lanzar el motor DeLM. El streaming llega en vivo por SSE; cada worker, gist y ronda se dibuja en la escena.</span>';
    } else {
      clearWorkers();
      clearGists();
      clearTaint();
      hitMeshes = [];
      buildFuncNodes();
      ttl.textContent = "Funciones";
      st.textContent = "elige una función"; st.className = "st";
      out.innerHTML = '<span class="dim">Clic en un nodo de la órbita para ejecutar una función del proyecto. La salida aparece aquí.</span>';
    }
  }

  // ============================================================
  //  bucle de animacion
  // ============================================================
  function tick() {
    requestAnimationFrame(tick);
    var dt = clock.getDelta(); T += dt;

    // nucleo: pulso + rotacion
    core.rotation.y += dt * 0.5; core.rotation.x += dt * 0.2;
    core.scale.setScalar(1 + Math.sin(T * 2.2) * 0.04);
    coreGlow.rotation.y -= dt * 0.3;

    // anillos
    ring.rotation.z += dt * 0.15;
    ringWire.rotation.z -= dt * 0.08;

    // workers del motor
    var w, a;
    for (var i = 0; i < workers.length; i++) {
      w = workers[i];
      if (w.busy) {
        // resolve: orbita mas rapida y cercana
        a = T * (w.speed + 0.7) + w.phase;
        var rr = w.radius * 0.82;
        w.mesh.position.set(Math.cos(a) * rr, w.baseY + Math.sin(T * 3 + w.phase) * 0.35, Math.sin(a) * rr);
      } else {
        a = T * w.speed + w.phase;
        w.mesh.position.set(Math.cos(a) * w.radius, w.baseY + Math.sin(T * 2 + w.phase) * 0.3, Math.sin(a) * w.radius);
      }
      w.halo.position.copy(w.mesh.position);
      w.halo.rotation.y += dt * 0.6;
      w.label.position.copy(w.mesh.position);
      w.label.position.y += 1.1;
    }

    // nodos del proyecto: flotar
    for (var j = 0; j < funcNodes.length; j++) {
      var n = funcNodes[j];
      n.mesh.position.y = n.baseY + Math.sin(T * 1.6 + n.phase) * 0.12;
      n.mesh.rotation.y += dt * 0.8;
      n.label.position.y = n.mesh.position.y + 1.5;
      n.halo.position.copy(n.mesh.position);
    }

    // gists: flotan hacia arriba y se apagan
    for (var k = gists.length - 1; k >= 0; k--) {
      var g = gists[k];
      var age = T - g.born;
      g.mesh.position.y += dt * 0.9;
      g.mat.opacity = Math.max(0, 1 - age / 3.2);
      if (age > 3.2) { scene.remove(g.mesh); gists.splice(k, 1); }
    }

    // taint: pulsa y se apaga
    for (var t2 = taintPuffs.length - 1; t2 >= 0; t2--) {
      var p = taintPuffs[t2];
      var age2 = T - p.born;
      p.mesh.scale.setScalar(1 + age2 * 1.6);
      p.mat.opacity = Math.max(0, 0.8 - age2 / 2.2);
      if (age2 > 2.2) { scene.remove(p.mesh); taintPuffs.splice(t2, 1); }
    }

    // particulas
    if (particles) particles.rotation.y += dt * 0.02;
    renderer.render(scene, camera);
  }

  // ============================================================
  //  arranque
  // ============================================================
  function start() {
    try {
      initScene();
      spawnWorkers(2);       // modo por defecto: motor
      loadFunctions();       // cache para el modo proyecto

      el("m-motor").addEventListener("click", function () { setMode("motor"); });
      el("m-proy").addEventListener("click", function () { setMode("proy"); });
      runBtn.addEventListener("click", launchRun);
      cancelBtn.addEventListener("click", function () {
        if (run && run.ctrl) {
          SMCPRuns.cancel(run.ctrl).then(function () {
            printLine('<span class="dim">cancelacion pedida…</span>');
          });
        }
      });
      el("f-task").addEventListener("keydown", function (e) {
        if (e.key === "Enter") launchRun();
      });

      var c = el("scene");
      c.addEventListener("mousedown", onDown);
      window.addEventListener("mousemove", onMove);
      window.addEventListener("mouseup", onUp);
      c.addEventListener("touchstart", onDown, { passive: true });
      window.addEventListener("touchmove", onMove, { passive: true });
      window.addEventListener("touchend", onUp);
      c.addEventListener("wheel", onWheel, { passive: false });
      window.addEventListener("resize", function () {
        camera.aspect = innerWidth / innerHeight; camera.updateProjectionMatrix();
        renderer.setSize(innerWidth, innerHeight);
      });
      tick();
      setTimeout(function () { var l = el("loading"); if (l) l.classList.add("hide"); }, 400);
      window.__delm = {
        get mode() { return MODE; },
        get nodes() { return funcNodes; },   // getter: funcNodes se reasigna al cambiar de modo
        get camera() { return camera; },
        get scene() { return scene; },
        raycastAt: function (wx, wy) {
          var v = new THREE.Vector2((wx / innerWidth) * 2 - 1, -(wy / innerHeight) * 2 + 1);
          var rc = new THREE.Raycaster(); rc.setFromCamera(v, camera);
          var hits = rc.intersectObjects(hitMeshes, false);
          return hits.length ? hits[0].object : null;
        }
      };
    } catch (e) {
      window.__initErr = (e && e.stack) || String(e);
      var l = el("loading");
      if (l) { l.textContent = "ERROR: " + (e && e.message); l.style.color = "#ff6b5b"; }
      throw e;
    }
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start);
  else start();
})();
