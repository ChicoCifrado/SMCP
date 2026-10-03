/* SMCP — mesh3d.js: la malla de intercambio como escena 3D.

   Cada peer verificado es un nodo en orbita, tamaño segun VRAM
   compartida. Lo que se ve sale de /api/mesh:

     peers[].vram_shared_gb   -> radio del nodo
     peers[].alive            -> color (verde vivo / gris muerto)
     peers[].inferences_served -> halo (historial, no saldo)
     peers[].satoshis_earned  -> etiqueta
     vram_verified_gb / declared -> anillo de cuentas
     chain_ok                 -> pulso del nucleo

   GET /api/mesh          -> estado (sondeo cada 5 s)
   GET /api/mesh/reservations -> reservas por nodo (tier 2)

   Los nodos NO se mueven por un cronometro: su posicion es
   su identidad (hash del peer_id), y su tamano es su VRAM.
   Un nodo nuevo entra en orbita; uno que se apaga, se apaga.
*/
(function () {
  "use strict";

  var POLL_MS = 5000;
  var COL = {
    alive: 0x8fbf3f, dead: 0x58624b, core: 0x8fbf3f,
    ring: 0x262b22, text: 0xdce6cf, dim: 0x9aa68c,
    reserved: 0xffc233, free: 0x6b7a5a,
  };

  var scene, camera, renderer, clock, raycaster;
  var cam = { theta: 0.7, phi: 1.2, radius: 30, target: new THREE.Vector3(0, 1.5, 0), dragging: false, px: 0, py: 0 };

  var core, coreGlow, ringAcc, ringFree;
  var peers = [];   // { peer_id, mesh, halo, label, resHalo, vram, alive, reserved_gb, free_gb }
  var byId = {};    // peer_id -> indice en peers
  var hitMeshes = [];
  var selected = null;

  var T = 0;

  function el(id) { return document.getElementById(id); }
  function esc(s) { return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"); }

  // ---------- sprite de texto ----------
  function makeLabel(text, sub, color) {
    var fs = 40, pad = 16;
    var c = document.createElement("canvas");
    var ctx = c.getContext("2d");
    ctx.font = "600 " + fs + "px 'IBM Plex Mono', ui-monospace, monospace";
    var w = Math.ceil(ctx.measureText(text).width) + pad * 2;
    var h = fs + pad * 2 + (sub ? fs * 0.7 + 6 : 0);
    c.width = w; c.height = h;
    var x = c.getContext("2d");
    x.font = "600 " + fs + "px 'IBM Plex Mono', ui-monospace, monospace";
    x.textBaseline = "top";
    x.fillStyle = "rgba(18,20,15,0.78)";
    roundRect(x, 0, 0, c.width, c.height, 12); x.fill();
    x.strokeStyle = "rgba(143,191,63,0.32)"; x.lineWidth = 2;
    roundRect(x, 1, 1, c.width - 2, c.height - 2, 12); x.stroke();
    x.fillStyle = color || "#dce6cf";
    x.fillText(text, pad, pad);
    if (sub) {
      x.font = "400 " + (fs * 0.7) + "px 'IBM Plex Mono', ui-monospace, monospace";
      x.fillStyle = "#9aa68c";
      x.fillText(sub, pad, pad + fs + 6);
    }
    var tex = new THREE.CanvasTexture(c);
    tex.minFilter = THREE.LinearFilter;
    var sp = new THREE.Sprite(new THREE.SpriteMaterial({ map: tex, transparent: true, depthTest: false }));
    var s = 0.015;
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

  // ---------- posicion: identidad, no aleatorio ----------
  function peerAngle(peerId) {
    // hash estable del peer_id -> angulo fijo en la orbita
    var h = 0;
    for (var i = 0; i < peerId.length; i++) {
      h = ((h << 5) - h + peerId.charCodeAt(i)) | 0;
    }
    var u = (h >>> 0) / 4294967296;
    return u * Math.PI * 2 - Math.PI / 2;
  }

  function initScene() {
    scene = new THREE.Scene();
    scene.fog = new THREE.FogExp2(0x090a09, 0.014);

    camera = new THREE.PerspectiveCamera(50, innerWidth / innerHeight, 0.1, 300);
    placeCamera();

    renderer = new THREE.WebGLRenderer({ canvas: el("scene"), antialias: true });
    renderer.setPixelRatio(Math.min(devicePixelRatio, 2));
    renderer.setSize(innerWidth, innerHeight);
    renderer.setClearColor(0x090a09, 1);

    scene.add(new THREE.AmbientLight(0x40403a, 0.95));
    var key = new THREE.DirectionalLight(0xdce6cf, 0.85); key.position.set(10, 16, 8); scene.add(key);
    var rim = new THREE.PointLight(COL.core, 1.2, 90); rim.position.set(0, 5, 0); scene.add(rim);

    buildCore();
    buildRings();
    buildFloor();
    clock = new THREE.Clock();
    raycaster = new THREE.Raycaster();
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
    var g = new THREE.IcosahedronGeometry(2.0, 1);
    var m = new THREE.MeshStandardMaterial({
      color: COL.core, emissive: COL.core, emissiveIntensity: 0.4,
      metalness: 0.3, roughness: 0.5, flatShading: true,
    });
    core = new THREE.Mesh(g, m); core.position.set(0, 1.5, 0);
    scene.add(core);

    var w = new THREE.Mesh(
      new THREE.IcosahedronGeometry(2.3, 1),
      new THREE.MeshBasicMaterial({ color: 0xdce6cf, wireframe: true, transparent: true, opacity: 0.25 })
    );
    w.position.copy(core.position); scene.add(w);
    coreGlow = w;

    var lb = makeLabel("malla de intercambio", "VRAM verificada · cadena de evidencia", "#dce6cf");
    lb.position.set(0, 4.6, 0); scene.add(lb);
  }

  function buildRings() {
    // anillo de VRAM verificada (verde) y declarada (gris)
    ringAcc = new THREE.Mesh(
      new THREE.TorusGeometry(7.4, 0.06, 8, 120),
      new THREE.MeshBasicMaterial({ color: COL.alive, transparent: true, opacity: 0.55 })
    );
    ringAcc.rotation.x = Math.PI / 2; ringAcc.position.y = 0.1; scene.add(ringAcc);

    ringFree = new THREE.Mesh(
      new THREE.TorusGeometry(9.6, 0.03, 6, 140),
      new THREE.MeshBasicMaterial({ color: COL.ring, wireframe: true, transparent: true, opacity: 0.3 })
    );
    ringFree.rotation.x = Math.PI / 2; ringFree.position.y = 0.05; scene.add(ringFree);
  }

  function buildFloor() {
    var grid = new THREE.GridHelper(80, 40, 0x262b22, 0x1a1e16);
    grid.position.y = -0.02;
    grid.material.transparent = true; grid.material.opacity = 0.45;
    scene.add(grid);
  }

  // ---------- peers ----------
  function radiusOf(vramGb) {
    // 0 GB -> 0.35 (punto), 8 GB -> 0.9, 24 GB -> 1.5, 80 GB -> 2.6
    return 0.35 + Math.min(2.4, Math.sqrt(Math.max(0, vramGb)) * 0.32);
  }

  function syncPeers(view) {
    var list = view.peers || [];
    var seen = {};

    list.forEach(function (p) {
      seen[p.peer_id] = true;
      var ex = byId[p.peer_id];
      if (ex != null) {
        // actualizar el existente
        updatePeer(peers[ex], p);
        return;
      }
      spawnPeer(p);
    });

    // los que ya no estan: se apagan (no desaparecen de golpe)
    peers.forEach(function (peer, i) {
      if (!seen[peer.peer_id]) {
        peer.alive = false;
        peer.mat.color.setHex(COL.dead);
        peer.mat.emissive.setHex(COL.dead);
        peer.mat.emissiveIntensity = 0.15;
        peer.halo.material.color.setHex(COL.dead);
        peer.halo.material.opacity = 0.08;
      }
    });

    // cuentas globales
    el("mv-verified").textContent = (view.vram_verified_gb != null ? view.vram_verified_gb : 0).toFixed(1) + " GB";
    el("mv-declared").textContent = (view.vram_declared_gb != null ? view.vram_declared_gb : 0).toFixed(1) + " GB";
    el("mv-peers").textContent = list.length;
    el("mv-chain").textContent = view.chain_ok ? "válida" : "ROTA";
    el("mv-chain").className = "card-n" + (view.chain_ok ? "" : " bad");
    el("mv-digest").textContent = (view.state_digest || "").slice(0, 12);

    // el anillo de verificado crece con el total
    var scale = 0.7 + Math.min(1.2, (view.vram_verified_gb || 0) / 64);
    ringAcc.scale.setScalar(scale);
  }

  function spawnPeer(p) {
    var angle = peerAngle(p.peer_id);
    var radius = 7.4;
    var r = radiusOf(p.vram_shared_gb || 0);

    var mat = new THREE.MeshStandardMaterial({
      color: COL.alive, emissive: COL.alive, emissiveIntensity: 0.45,
      metalness: 0.25, roughness: 0.55, flatShading: true,
    });
    var mesh = new THREE.Mesh(new THREE.IcosahedronGeometry(r, 1), mat);
    var x = Math.cos(angle) * radius, z = Math.sin(angle) * radius;
    mesh.position.set(x, 1.5, z);
    scene.add(mesh);

    var halo = new THREE.Mesh(
      new THREE.SphereGeometry(r * 1.7, 14, 14),
      new THREE.MeshBasicMaterial({ color: COL.alive, wireframe: true, transparent: true, opacity: 0.13 })
    );
    halo.position.copy(mesh.position); scene.add(halo);

    // halo de reserva (tier 2) — se ve solo si hay VRAM reservada
    var resHalo = new THREE.Mesh(
      new THREE.TorusGeometry(r * 1.35, 0.05, 6, 40),
      new THREE.MeshBasicMaterial({ color: COL.reserved, transparent: true, opacity: 0 })
    );
    resHalo.rotation.x = Math.PI / 2;
    resHalo.position.copy(mesh.position); scene.add(resHalo);

    var sub = fmtGb(p.vram_shared_gb) + " compartidos · " + (p.inferences_served || 0) + " inf.";
    var lb = makeLabel(p.peer_id, sub, "#dce6cf");
    lb.position.set(x, 1.5 + r + 1.6, z); scene.add(lb);

    var peer = {
      peer_id: p.peer_id, mesh: mesh, halo: halo, label: lb, resHalo: resHalo,
      mat: mat, angle: angle, radius: radius, vram: r, alive: p.alive !== false,
      reserved_gb: 0, free_gb: null, data: p,
    };
    peers.push(peer);
    byId[p.peer_id] = peers.length - 1;
    hitMeshes.push(mesh);
  }

  function updatePeer(peer, p) {
    peer.alive = p.alive !== false;
    peer.data = p;
    var wantR = radiusOf(p.vram_shared_gb || 0);
    if (Math.abs(wantR - peer.vram) > 0.05) {
      // VRAM cambio: escalar el cuerpo (no recrear)
      var k = wantR / peer.vram;
      peer.mesh.scale.setScalar(k);
      peer.halo.scale.setScalar(k);
      peer.resHalo.scale.setScalar(k);
      peer.vram = wantR;
    }
    if (peer.alive) {
      peer.mat.color.setHex(COL.alive);
      peer.mat.emissive.setHex(COL.alive);
      peer.mat.emissiveIntensity = 0.45;
      peer.halo.material.color.setHex(COL.alive);
      peer.halo.material.opacity = 0.13;
    }
    // etiqueta
    var sub = fmtGb(p.vram_shared_gb) + " compartidos · " + (p.inferences_served || 0) + " inf.";
    var pos = peer.label.position;
    scene.remove(peer.label);
    peer.label = makeLabel(p.peer_id, sub, "#dce6cf");
    peer.label.position.copy(pos);
    scene.add(peer.label);
  }

  function fmtGb(g) {
    if (g == null) return "—";
    return (g >= 10 ? g.toFixed(0) : g.toFixed(1)) + " GB";
  }

  // ---------- reservas (tier 2) ----------
  function syncReservations(res) {
    var nodes = res.nodes || {};
    peers.forEach(function (peer) {
      var n = nodes[peer.peer_id];
      var reserved = n ? (n.reserved_gb || 0) : 0;
      var free = n ? (n.free_gb || 0) : null;
      peer.reserved_gb = reserved;
      peer.free_gb = free;
      var op = reserved > 0 ? 0.75 : 0;
      peer.resHalo.material.opacity = op;
      if (reserved > 0) {
        // el anillo de reserva marca cuanto del nodo esta comprometido
        var frac = peer.vram > 0 ? Math.min(1, reserved / (peer.vram * 3.1)) : 0;
        peer.resHalo.scale.setScalar(1 + frac * 0.25);
      }
    });
    var totalRes = 0;
    Object.keys(nodes).forEach(function (k) { totalRes += nodes[k].reserved_gb || 0; });
    el("mv-reserved").textContent = totalRes.toFixed(1) + " GB";
  }

  // ---------- interaccion ----------
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
    cam.radius = Math.max(10, Math.min(70, cam.radius + e.deltaY * 0.02));
    placeCamera();
  }

  function pickAt(cx, cy) {
    var v = new THREE.Vector2((cx / innerWidth) * 2 - 1, -(cy / innerHeight) * 2 + 1);
    raycaster.setFromCamera(v, camera);
    var hits = raycaster.intersectObjects(hitMeshes, false);
    if (!hits.length) { selectPeer(null); return; }
    var mesh = hits[0].object;
    for (var i = 0; i < peers.length; i++) {
      if (peers[i].mesh === mesh) { selectPeer(peers[i]); return; }
    }
  }

  function selectPeer(peer) {
    selected = peer;
    peers.forEach(function (p, i) {
      var sel = p === peer;
      p.halo.material.opacity = sel ? 0.35 : (p.alive ? 0.13 : 0.08);
      p.mat.emissiveIntensity = sel ? 0.95 : (p.alive ? 0.45 : 0.15);
    });
    var card = el("peer-card");
    if (!peer) {
      card.classList.remove("on");
      return;
    }
    fillPeerCard(peer);
    card.classList.add("on");
  }

  function fillPeerCard(peer) {
    var d = peer.data || {};
    el("pp-id").textContent = peer.peer_id;
    el("pp-alive").textContent = peer.alive ? "vivo" : "muerto";
    el("pp-alive").className = "pill " + (peer.alive ? "ok" : "bad");
    el("pp-vram").textContent = fmtGb(d.vram_shared_gb);
    el("pp-free").textContent = peer.free_gb != null ? fmtGb(peer.free_gb) : "—";
    el("pp-res").textContent = peer.reserved_gb ? peer.reserved_gb.toFixed(1) + " GB" : "—";
    el("pp-inf").textContent = d.inferences_served != null ? d.inferences_served : "—";
    el("pp-sat").textContent = d.satoshis_earned != null ? d.satoshis_earned : "—";
    el("pp-rej").textContent = d.rejections != null ? d.rejections : "—";
    el("pp-obs").textContent = d.seconds_observed != null ? Math.round(d.seconds_observed) + " s" : "—";
  }

  // ---------- sondeo ----------
  function poll() {
    fetch("/api/mesh")
      .then(function (r) { return r.json(); })
      .then(function (view) {
        syncPeers(view);
        el("mesh-status").textContent = "hace " + new Date().toLocaleTimeString();
      })
      .catch(function () {
        el("mesh-status").textContent = "error al leer la malla";
      });
    fetch("/api/mesh/reservations")
      .then(function (r) { return r.json(); })
      .then(syncReservations)
      .catch(function () {});
  }

  // ---------- animacion ----------
  function tick() {
    requestAnimationFrame(tick);
    var dt = clock.getDelta(); T += dt;

    core.rotation.y += dt * 0.4; core.rotation.x += dt * 0.15;
    core.scale.setScalar(1 + Math.sin(T * 2) * 0.03);
    coreGlow.rotation.y -= dt * 0.25;

    ringAcc.rotation.z += dt * 0.1;
    ringFree.rotation.z -= dt * 0.06;

    for (var i = 0; i < peers.length; i++) {
      var p = peers[i];
      var a = T * 0.12 + p.angle;
      // deriva lenta alrededor de su angulo de identidad
      var rr = p.radius;
      p.mesh.position.set(Math.cos(a) * rr, 1.5 + Math.sin(T * 0.8 + p.angle) * 0.25, Math.sin(a) * rr);
      p.mesh.rotation.y += dt * 0.5;
      p.halo.position.copy(p.mesh.position);
      p.halo.rotation.y += dt * 0.4;
      p.resHalo.position.copy(p.mesh.position);
      p.resHalo.rotation.z += dt * 0.8;
      p.label.position.copy(p.mesh.position);
      p.label.position.y += p.vram + 1.5;
    }

    renderer.render(scene, camera);
  }

  // ---------- arranque ----------
  function start() {
    try {
      initScene();
      poll();
      setInterval(poll, POLL_MS);

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
      window.__delmMesh = {
        get peers() { return peers; },
        get camera() { return camera; },
        get scene() { return scene; },
        refresh: poll,
        selectPeer: selectPeer,
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
