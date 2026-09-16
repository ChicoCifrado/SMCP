/* DeLM/SMCP — Consola de control 3D (Three.js)
   Núcleo central + 5 nodos-función orbitando + workers.
   Clic en un nodo ejecuta la función vía /api/run/<id>. */
(function () {
  "use strict";

  // ---------- paleta (coincidente con style.css) ----------
  var COL = {
    bg: 0x090a09, fog: 0x090a09,
    core: 0x8fbf3f, coreHi: 0xdce6cf,
    node: 0x58624b, nodeHi: 0x8fbf3f,
    worker: 0x3a4133, ring: 0x262b22,
    text: 0xdce6cf, dim: 0x9aa68c,
    run: 0xffc233, err: 0xff6b5b, ok: 0x8fbf3f,
  };

  // ---------- funciones (deben coincidir con /api/functions) ----------
  var FUNCS = [
    { id: "demo",        label: "Pipeline DeLM" },
    { id: "security",    label: "Seguridad" },
    { id: "taint",       label: "Anti-inyección" },
    { id: "multihost",   label: "Multi-host" },
    { id: "tests",       label: "Tests" },
  ];

  var scene, camera, renderer, clock;
  var core, coreGlow, ring, ringWire;
  var funcNodes = [];      // { mesh, label, id, baseY, phase }
  var workers = [];        // { mesh, radius, speed, phase, y }
  var particles, particleMat;
  var raycaster = new THREE.Raycaster();
  var pointer = new THREE.Vector2();
  var hitMeshes = [];      // meshes clicables

  // control de cámara manual (órbita + zoom)
  var cam = { theta: 0.6, phi: 1.15, radius: 26, target: new THREE.Vector3(0, 1.5, 0), dragging: false, px: 0, py: 0 };

  // estado de ejecución
  var running = null;      // id en curso

  // ---------- refs de UI ----------
  var el = function (id) { return document.getElementById(id); };
  var out = el("out"), dot = el("dot"), ttl = el("ttl"), st = el("st");

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

    renderer = new THREE.WebGLRenderer({ canvas: document.getElementById("scene"), antialias: true });
    renderer.setPixelRatio(Math.min(devicePixelRatio, 2));
    renderer.setSize(innerWidth, innerHeight);
    renderer.setClearColor(COL.bg, 1);

    // luces
    scene.add(new THREE.AmbientLight(0x40403a, 0.9));
    var key = new THREE.DirectionalLight(0xdce6cf, 0.8); key.position.set(8, 14, 6); scene.add(key);
    var rim = new THREE.PointLight(COL.core, 1.1, 60); rim.position.set(0, 4, 0); scene.add(rim);

    buildCore();
    buildRing();
    buildFuncNodes();
    buildWorkers();
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

    // wireframe exterior
    var w = new THREE.Mesh(
      new THREE.IcosahedronGeometry(2.35, 1),
      new THREE.MeshBasicMaterial({ color: COL.coreHi, wireframe: true, transparent: true, opacity: 0.28 })
    );
    w.position.copy(core.position); scene.add(w);
    coreGlow = w;

    // etiqueta
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

      // halo
      var halo = new THREE.Mesh(
        new THREE.SphereGeometry(1.0, 16, 16),
        new THREE.MeshBasicMaterial({ color: COL.node, transparent: true, opacity: 0.12, wireframe: true })
      );
      halo.position.copy(mesh.position); scene.add(halo);

      // etiqueta
      var lb = makeLabel(f.label, "#dce6cf");
      lb.position.set(x, 2.7, z); scene.add(lb);

      // conector al núcleo
      var line = makeLine(new THREE.Vector3(0, 1.5, 0), mesh.position, 0x58624b, 0.5);
      scene.add(line);

      funcNodes.push({ mesh: mesh, halo: halo, id: f.id, baseY: 1.1, phase: a, label: lb, mat: m });
      hitMeshes.push(mesh);
    });
  }

  function buildWorkers() {
    for (var i = 0; i < 10; i++) {
      var g = new THREE.SphereGeometry(0.16, 12, 12);
      var m = new THREE.MeshStandardMaterial({ color: 0x6b7a5a, emissive: 0x6b7a5a, emissiveIntensity: 0.4, roughness: 0.7 });
      var mesh = new THREE.Mesh(g, m); scene.add(mesh);
      workers.push({ mesh: mesh, radius: 4.2 + (i % 3) * 0.6, speed: 0.4 + (i % 4) * 0.12, phase: (i / 10) * Math.PI * 2, y: 1.5 + (i % 3) * 0.5 });
    }
  }

  function makeLine(a, b, color, opacity) {
    var geo = new THREE.BufferGeometry().setFromPoints([a, b]);
    return new THREE.Line(geo, new THREE.LineBasicMaterial({ color: color, transparent: true, opacity: opacity }));
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
  //  interacción
  // ============================================================
  function onDown(e) {
    var t = e.touches ? e.touches[0] : e;
    cam.px = t.clientX; cam.py = t.clientY;
    if (e.type === "touchstart" || e.target === document.getElementById("scene")) cam.dragging = true;
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
    // clic corto sobre un nodo -> ejecutar
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
  //  ejecución vía API
  // ============================================================
  function runFunc(id) {
    if (running) return;
    running = id;
    // feedback visual en el nodo
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
    running = null;
    var node = funcNodes.filter(function (n) { return n.id === id; })[0];
    if (node) {
      node.mat.color.setHex(res.ok ? COL.ok : COL.err);
      node.mat.emissive.setHex(res.ok ? 0x113311 : 0x331111);
      node.mat.emissiveIntensity = 0.6;
    }
    dot.classList.remove("on");
    if (res.ok) { st.textContent = "OK · " + (res.secs != null ? res.secs + "s" : ""); st.className = "st ok"; }
    else { st.textContent = "error (código " + (res.code != null ? res.code : "?") + ")"; st.className = "st err"; }
    var body = res.stdout || res.stderr || "(sin salida)";
    out.innerHTML = fmt(body) + (res.secs != null ? '\n<span class="dim">— ' + res.secs + 's</span>' : "");
    // volver al color base tras 1.2s
    setTimeout(function () {
      if (node) { node.mat.color.setHex(COL.node); node.mat.emissive.setHex(COL.node); node.mat.emissiveIntensity = 0.5; }
    }, 1200);
  }

  function fmt(s) {
    s = String(s);
    s = s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    return s;
  }

  // ============================================================
  //  bucle de animación
  // ============================================================
  var T = 0;
  function tick() {
    requestAnimationFrame(tick);
    var dt = clock.getDelta(); T += dt;
    // núcleo: pulso + rotación
    core.rotation.y += dt * 0.5; core.rotation.x += dt * 0.2;
    var pulse = 1 + Math.sin(T * 2.2) * 0.04;
    core.scale.setScalar(pulse);
    coreGlow.rotation.y -= dt * 0.3;
    // anillos
    ring.rotation.z += dt * 0.15;
    ringWire.rotation.z -= dt * 0.08;
    // nodos: flotar
    for (var i = 0; i < funcNodes.length; i++) {
      var n = funcNodes[i];
      n.mesh.position.y = n.baseY + Math.sin(T * 1.6 + n.phase) * 0.12;
      n.mesh.rotation.y += dt * 0.8;
      n.label.position.y = n.mesh.position.y + 1.5;
    }
    // workers: órbita
    for (var w = 0; w < workers.length; w++) {
      var k = workers[w];
      var a = T * k.speed + k.phase;
      k.mesh.position.set(
        Math.cos(a) * k.radius,
        k.y + Math.sin(T * 2 + k.phase) * 0.3,
        Math.sin(a) * k.radius
      );
    }
    // partículas
    if (particles) particles.rotation.y += dt * 0.02;
    renderer.render(scene, camera);
  }

  // ============================================================
  //  arranque
  // ============================================================
  function start() {
    try {
      initScene();
      var c = document.getElementById("scene");
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
      setTimeout(function () { var l = document.getElementById("loading"); if (l) l.classList.add("hide"); }, 400);
      window.__delm = {
        nodes: funcNodes,
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
      var l = document.getElementById("loading");
      if (l) { l.textContent = "ERROR: " + (e && e.message); l.style.color = "#ff6b5b"; }
      throw e;
    }
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start);
  else start();
})();
