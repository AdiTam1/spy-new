// Spy game, serverless edition.
// The host's browser is the game server. Everyone talks through a public MQTT broker.
// Public room state is broadcast to all; each player's role is end-to-end encrypted
// (ECDH P-256 + AES-GCM) so nobody can read another player's role off the wire.

const $ = (id) => document.getElementById(id);
const params = new URLSearchParams(location.search);
const BROKER = params.get("broker") || "wss://broker.hivemq.com:8884/mqtt";
const NS = "spyil-v1";
const topic = (code, ...rest) => [NS, code, ...rest].join("/");

const MAX_PLAYERS = 30;
const MIN_PLAYERS = 3;
const HELLO_EVERY_MS = 8000;
const ONLINE_MS = 22000;
const JOIN_TIMEOUT_MS = 7000;

const maxSpies = (n) => Math.max(1, Math.min(8, Math.floor((n - 1) / 2)));
const recSpies = (n) => (n <= 7 ? 1 : n <= 12 ? 2 : n <= 17 ? 3 : n <= 23 ? 4 : 5);
const recMinutes = (n) => Math.min(20, 8 + Math.max(0, Math.ceil((n - 8) / 2)));
const cleanName = (s) => String(s || "").replace(/\s+/g, " ").trim().slice(0, 20);
const randInt = (n) => crypto.getRandomValues(new Uint32Array(1))[0] % n;

const store = {
  get(k) { try { return localStorage.getItem(k); } catch (e) { return null; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch (e) {} },
  del(k) { try { localStorage.removeItem(k); } catch (e) {} },
  json(k) { try { return JSON.parse(localStorage.getItem(k) || "null"); } catch (e) { return null; } },
};

// ---------- identity & crypto ----------
let playerId = store.get("spy.playerId");
if (!playerId || !/^[0-9a-f]{16}$/.test(playerId)) {
  playerId = Array.from(crypto.getRandomValues(new Uint8Array(8)), (b) => b.toString(16).padStart(2, "0")).join("");
  store.set("spy.playerId", playerId);
}
const EC = { name: "ECDH", namedCurve: "P-256" };
let myPriv = null;
let myPubJwk = null;

async function loadKeys() {
  let saved = store.json("spy.keys");
  if (!saved) {
    const kp = await crypto.subtle.generateKey(EC, true, ["deriveKey"]);
    const priv = await crypto.subtle.exportKey("jwk", kp.privateKey);
    const pub = await crypto.subtle.exportKey("jwk", kp.publicKey);
    saved = { priv, pub: { kty: pub.kty, crv: pub.crv, x: pub.x, y: pub.y } };
    store.set("spy.keys", JSON.stringify(saved));
  }
  myPriv = await crypto.subtle.importKey("jwk", saved.priv, EC, false, ["deriveKey"]);
  myPubJwk = saved.pub;
}
const keyCache = new Map();
async function sharedKey(otherPubJwk) {
  const id = otherPubJwk.x + otherPubJwk.y;
  if (keyCache.has(id)) return keyCache.get(id);
  const pub = await crypto.subtle.importKey("jwk", otherPubJwk, EC, false, []);
  const key = await crypto.subtle.deriveKey({ name: "ECDH", public: pub }, myPriv, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  keyCache.set(id, key);
  return key;
}
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
async function seal(pubJwk, obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await sharedKey(pubJwk), new TextEncoder().encode(JSON.stringify(obj)));
  return { iv: b64(iv), ct: b64(ct) };
}
async function unseal(pubJwk, box) {
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(box.iv) }, await sharedKey(pubJwk), unb64(box.ct));
  return JSON.parse(new TextDecoder().decode(pt));
}

// ---------- UI helpers ----------
let LOCS = [];
let view = null; // what render() draws, same shape for host and players
let shown = false;

function toast(text) {
  const t = $("toast");
  t.textContent = text;
  t.hidden = false;
  clearTimeout(toast.h);
  toast.h = setTimeout(() => (t.hidden = true), 2400);
}
function setConn(on) {
  $("conn-dot").classList.toggle("on", on);
  $("conn-text").textContent = on ? "מחובר" : "מתחבר…";
}
function showHomeErr(text) { $("home-err").textContent = text || ""; $("home-err").hidden = !text; }
function el(tag, cls, txt) { const e = document.createElement(tag); e.className = cls; e.textContent = txt; return e; }

// ---------- MQTT ----------
let client = null;
let connected = false;
let session = store.json("spy.session"); // {code, host: bool}

function connectBroker() {
  client = mqtt.connect(BROKER, {
    clientId: "spy_" + playerId + "_" + Math.random().toString(36).slice(2, 8),
    keepalive: 30,
    reconnectPeriod: 2000,
    connectTimeout: 10000,
    clean: true,
  });
  client.on("connect", () => { connected = true; setConn(true); resume(); });
  client.on("close", () => { connected = false; setConn(false); });
  client.on("offline", () => { connected = false; setConn(false); });
  client.on("error", () => {});
  client.on("message", (t, payload, packet) => onMessage(t, payload.toString(), packet.retain));
}
function pub(t, obj, retain = false) {
  if (!client) return;
  client.publish(t, obj === null ? "" : JSON.stringify(obj), { qos: 1, retain });
}
function sub(topics) { client.subscribe(topics, { qos: 1 }); }
function unsubAll(code) {
  if (client && code) client.unsubscribe([topic(code, "h"), topic(code, "s"), topic(code, "u", playerId), topic(code, "e", playerId)]);
}

function resume() {
  if (!session) return;
  if (session.host) {
    room = store.json("spy.room." + session.code);
    if (!room) { endSession(); return; }
    sub([topic(room.code, "h")]);
    hostPublishAll();
    hostRender();
  } else {
    playerJoin(session.code, store.get("spy.name") || "", true);
  }
}
function onMessage(t, text, retained) {
  const parts = t.split("/");
  if (parts[0] !== NS || !session || parts[1] !== session.code) return;
  let msg = null;
  if (text) { try { msg = JSON.parse(text); } catch (e) { return; } }
  const kind = parts[2];
  if (session.host && kind === "h" && msg) hostOnHello(msg);
  if (!session.host) {
    if (kind === "s") playerOnState(msg);
    else if (kind === "u" && parts[3] === playerId && msg) playerOnRole(msg);
    else if (kind === "e" && parts[3] === playerId && msg) playerOnError(msg);
  }
}
function endSession(message) {
  if (session) unsubAll(session.code);
  clearInterval(helloTimer);
  clearTimeout(joinTimer);
  session = null;
  room = null;
  pstate = null;
  prole = null;
  view = null;
  store.del("spy.session");
  render();
  if (message) toast(message);
}

// ================= HOST =================
let room = null;

function hostCreate(name) {
  const A = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const code = Array.from(crypto.getRandomValues(new Uint8Array(5)), (b) => A[b % 32]).join("");
  room = {
    code, status: "lobby", round: 0,
    spies: 1, spiesManual: false, minutes: 8, minutesManual: false,
    endsAt: null, pausedLeft: null, timerOn: true, location: null, spyIds: [],
    players: [{ id: playerId, name, pub: myPubJwk, lastSeen: Date.now(), inRound: false }],
  };
  session = { code, host: true };
  store.set("spy.session", JSON.stringify(session));
  hostAutoTune();
  sub([topic(code, "h")]);
  hostCommit();
}
function hostSave() { store.set("spy.room." + room.code, JSON.stringify(room)); }
function hostAutoTune() {
  const nn = Math.max(room.players.length, MIN_PLAYERS);
  if (!room.spiesManual) room.spies = recSpies(nn);
  room.spies = Math.min(room.spies, maxSpies(nn));
  if (!room.minutesManual) room.minutes = recMinutes(nn);
}
const isOnline = (p) => p.id === playerId || Date.now() - p.lastSeen < ONLINE_MS;
function hostPublicState() {
  const nn = Math.max(room.players.length, MIN_PLAYERS);
  return {
    code: room.code, status: room.status, round: room.round, hostId: playerId, hostPub: myPubJwk,
    players: room.players.map((p) => ({ id: p.id, name: p.name, online: isOnline(p) })),
    inRound: room.players.filter((p) => p.inRound).map((p) => p.id),
    spies: room.spies, maxSpies: maxSpies(nn), recSpies: recSpies(nn),
    minutes: room.minutes, recMinutes: recMinutes(nn),
    maxPlayers: MAX_PLAYERS, minPlayers: MIN_PLAYERS, endsAt: room.endsAt,
    timerOn: room.timerOn !== false, pausedLeft: room.pausedLeft ?? null,
    reveal: room.status === "reveal" ? { location: room.location, spyIds: room.spyIds } : null,
  };
}
function roleFor(p) {
  return room.spyIds.includes(p.id) ? { round: room.round, spy: true } : { round: room.round, spy: false, location: room.location, job: (room.jobOf || {})[p.id] || null };
}
async function hostSendRole(p) {
  if (p.id === playerId || !p.inRound || room.status !== "playing") return;
  try { pub(topic(room.code, "u", p.id), await seal(p.pub, roleFor(p)), true); } catch (e) {}
}
function hostPublishState() { pub(topic(room.code, "s"), hostPublicState(), true); }
function hostPublishAll() {
  hostPublishState();
  room.players.forEach(hostSendRole);
}
function hostCommit() { hostSave(); hostPublishState(); hostRender(); }
function hostRender() {
  const me = room.players.find((p) => p.id === playerId);
  const s = hostPublicState();
  view = { ...s, you: playerId, isHost: true, role: null };
  if (room.status === "playing") view.role = me && me.inRound ? roleFor(me) : { waiting: true };
  render();
}
function hostOnHello(m) {
  if (typeof m.id !== "string" || !/^[0-9a-f]{16}$/.test(m.id) || m.id === playerId) return;
  const err = (text, kicked) => pub(topic(room.code, "e", m.id), { text, kicked: !!kicked });
  if (m.t === "leave") {
    if (room.players.some((p) => p.id === m.id)) { hostRemove(m.id); }
    return;
  }
  if (m.t !== "hello" || !m.pub || typeof m.pub.x !== "string") return;
  const name = cleanName(m.name);
  let p = room.players.find((x) => x.id === m.id);
  if (!p) {
    if (!name) return err("כתבו שם כדי להצטרף.");
    if (room.players.length >= MAX_PLAYERS) return err("החדר מלא (" + MAX_PLAYERS + " שחקנים).");
    if (room.players.some((x) => x.name === name)) return err("השם הזה כבר תפוס בחדר. בחרו שם אחר.");
    p = { id: m.id, name, pub: { kty: "EC", crv: "P-256", x: m.pub.x, y: m.pub.y }, lastSeen: Date.now(), inRound: false };
    room.players.push(p);
    if (room.status === "lobby") hostAutoTune();
    hostCommit();
    return;
  }
  const wasOnline = isOnline(p);
  p.lastSeen = Date.now();
  let changed = !wasOnline;
  if (name && name !== p.name && !room.players.some((x) => x.id !== p.id && x.name === name)) { p.name = name; changed = true; }
  if (m.pub.x !== p.pub.x) { p.pub = { kty: "EC", crv: "P-256", x: m.pub.x, y: m.pub.y }; changed = true; }
  if (changed || m.fresh) hostCommit();
  if (m.needRole) hostSendRole(p);
}
function hostRemove(id, kicked) {
  room.players = room.players.filter((p) => p.id !== id);
  room.spyIds = room.spyIds.filter((x) => x !== id);
  pub(topic(room.code, "u", id), null, true);
  if (kicked) pub(topic(room.code, "e", id), { text: "המארח הוציא אתכם מהחדר.", kicked: true });
  if (room.status === "lobby") hostAutoTune();
  hostCommit();
}
// Watch for players going offline.
setInterval(() => {
  if (!session || !session.host || !room) return;
  const sig = room.players.map((p) => (isOnline(p) ? 1 : 0)).join("");
  if (sig !== hostTick.sig) { hostTick.sig = sig; hostPublishState(); hostRender(); }
}, 4000);
const hostTick = { sig: "" };

const host = {
  setSpies(k) {
    const nn = Math.max(room.players.length, MIN_PLAYERS);
    if (room.status !== "lobby" || k < 1 || k > maxSpies(nn)) return;
    room.spies = k; room.spiesManual = k !== recSpies(nn); hostCommit();
  },
  setMinutes(m) {
    const nn = Math.max(room.players.length, MIN_PLAYERS);
    if (room.status !== "lobby" || m < 2 || m > 30) return;
    room.minutes = m; room.minutesManual = m !== recMinutes(nn); hostCommit();
  },
  resetAuto() { room.spiesManual = false; room.minutesManual = false; hostAutoTune(); hostCommit(); },
  start() {
    const n = room.players.length;
    if (room.status !== "lobby") return;
    if (n < MIN_PLAYERS) return toast("צריך לפחות " + MIN_PLAYERS + " שחקנים.");
    room.spies = Math.min(room.spies, maxSpies(n));
    const ids = room.players.map((p) => p.id);
    for (let i = ids.length - 1; i > 0; i--) { const j = randInt(i + 1); [ids[i], ids[j]] = [ids[j], ids[i]]; }
    let loc;
    do loc = LOCS[randInt(LOCS.length)]; while (LOCS.length > 1 && loc === room.location);
    room.location = loc;
    room.spyIds = ids.slice(0, room.spies);
    // Citizens get a job at the location; jobs repeat only when there are more citizens than jobs.
    const jobs = (ROLES[loc] || []).slice();
    for (let i = jobs.length - 1; i > 0; i--) { const j = randInt(i + 1); [jobs[i], jobs[j]] = [jobs[j], jobs[i]]; }
    room.jobOf = {};
    ids.slice(room.spies).forEach((id, i) => { if (jobs.length) room.jobOf[id] = jobs[i % jobs.length]; });
    room.players.forEach((p) => (p.inRound = true));
    room.status = "playing";
    room.round += 1;
    room.timerOn = room.timerOn !== false;
    room.endsAt = room.timerOn ? Date.now() + room.minutes * 60000 : null;
    room.pausedLeft = null;
    hostCommit();
    room.players.forEach(hostSendRole);
  },
  reveal() { if (room.status !== "playing") return; room.status = "reveal"; room.endsAt = null; room.pausedLeft = null; hostCommit(); },
  toggleTimer() { if (room.status !== "lobby") return; room.timerOn = room.timerOn === false; hostCommit(); },
  pauseTimer() {
    if (room.status !== "playing" || !room.timerOn) return;
    if (room.pausedLeft != null) { room.endsAt = Date.now() + room.pausedLeft; room.pausedLeft = null; }
    else if (room.endsAt) { room.pausedLeft = Math.max(0, room.endsAt - Date.now()); room.endsAt = null; }
    hostCommit();
  },
  cancelTimer() {
    if (room.status !== "playing") return;
    room.endsAt = null; room.pausedLeft = null; room.timerOn = false;
    hostCommit();
  },
  lobby() {
    room.status = "lobby"; room.endsAt = null; room.pausedLeft = null; room.spyIds = [];
    room.players.forEach((p) => { p.inRound = false; pub(topic(room.code, "u", p.id), null, true); });
    hostAutoTune(); hostCommit();
  },
  kick(id) { if (id !== playerId) hostRemove(id, true); },
  close() {
    room.players.forEach((p) => pub(topic(room.code, "u", p.id), null, true));
    pub(topic(room.code, "s"), { closed: true }, false);
    pub(topic(room.code, "s"), null, true);
    store.del("spy.room." + room.code);
    endSession("החדר נסגר");
  },
};

// ================= PLAYER =================
let pstate = null; // public state from the host
let prole = null; // decrypted role {round, spy, location}
let rawRole = null;
let helloTimer = null;
let joinTimer = null;

function sendHello(fresh) {
  if (!session || session.host || !connected) return;
  const needRole = !!(pstate && pstate.status === "playing" && pstate.inRound.includes(playerId) && !(prole && prole.round === pstate.round));
  pub(topic(session.code, "h"), { t: "hello", id: playerId, name: store.get("spy.name") || "", pub: myPubJwk, needRole, fresh: !!fresh });
}
function playerJoin(code, name, rejoin) {
  session = { code, host: false };
  if (!rejoin) { pstate = null; prole = null; rawRole = null; }
  sub([topic(code, "s"), topic(code, "u", playerId), topic(code, "e", playerId)]);
  sendHello(true);
  clearInterval(helloTimer);
  helloTimer = setInterval(() => sendHello(false), HELLO_EVERY_MS);
  clearTimeout(joinTimer);
  if (!rejoin) {
    joinTimer = setTimeout(() => {
      if (!pstate || !pstate.players.some((p) => p.id === playerId)) {
        endSession();
        showHomeErr(pstate ? "המארח לא אישר את ההצטרפות. נסו שוב." : "לא מצאנו חדר עם הקוד הזה, או שהמארח לא מחובר כרגע.");
      }
    }, JOIN_TIMEOUT_MS);
  }
}
function playerOnState(s) {
  if (!s) return; // retained message cleared
  if (s.closed) { endSession("המארח סגר את החדר"); return; }
  if (!s.players) return;
  const wasIn = pstate && pstate.players.some((p) => p.id === playerId);
  const isIn = s.players.some((p) => p.id === playerId);
  if (wasIn && !isIn) { endSession("יצאתם מהחדר"); return; }
  pstate = s;
  if (isIn && !store.get("spy.session")) store.set("spy.session", JSON.stringify(session));
  if (isIn) { clearTimeout(joinTimer); showHomeErr(""); }
  if (rawRole) playerOnRole(rawRole);
  else playerRender();
  if (s.status === "playing" && s.inRound.includes(playerId) && !(prole && prole.round === s.round)) sendHello(false);
}
async function playerOnRole(box) {
  rawRole = box;
  if (!pstate || !pstate.hostPub) return;
  try { prole = await unseal(pstate.hostPub, box); rawRole = null; } catch (e) { /* stale role from an older host key */ }
  playerRender();
}
function playerOnError(m) {
  if (m.kicked) { endSession(m.text); return; }
  if (!pstate || !pstate.players.some((p) => p.id === playerId)) { endSession(); showHomeErr(m.text); }
  else toast(m.text);
}
function playerRender() {
  if (!pstate || !pstate.players.some((p) => p.id === playerId)) { render(); return; }
  view = { ...pstate, you: playerId, isHost: false, role: null };
  if (pstate.status === "playing") {
    if (!pstate.inRound.includes(playerId)) view.role = { waiting: true };
    else if (prole && prole.round === pstate.round) view.role = prole;
    else view.role = { loading: true };
  }
  render();
}

// ================= RENDER =================
let lastKey = "";
function render() {
  const s = view && session ? view : null;
  const key = s ? s.status + ":" + s.round : "";
  if (key !== lastKey) { shown = false; lastKey = key; }
  $("home").hidden = !!s;
  ["lobby", "host-panel", "guest-panel", "game", "timer-card", "reveal", "players-card"].forEach((id) => ($(id).hidden = true));
  if (!s) { $("join").disabled = $("create").disabled = false; renderLocs(); return; }

  $("players-card").hidden = false;
  $("leave").textContent = s.isHost ? "סגירת החדר" : "יציאה מהחדר";
  renderPlayers(s);

  if (s.status === "lobby") {
    $("lobby").hidden = false;
    $("room-code").textContent = s.code;
    const n = s.players.length;
    if (s.isHost) {
      $("host-panel").hidden = false;
      $("k-out").value = s.spies;
      $("k-minus").disabled = s.spies <= 1;
      $("k-plus").disabled = s.spies >= s.maxSpies;
      $("t-toggle").textContent = s.timerOn ? "פועל" : "כבוי";
      $("t-toggle").setAttribute("aria-pressed", s.timerOn);
      $("minutes-row").hidden = !s.timerOn;
      $("m-out").value = s.minutes;
      $("m-minus").disabled = s.minutes <= 2;
      $("m-plus").disabled = s.minutes >= 30;
      const recOk = s.spies === s.recSpies && s.minutes === s.recMinutes;
      $("rec-hint").textContent = n < s.minPlayers
        ? "צריך לפחות " + s.minPlayers + " שחקנים. כרגע בחדר: " + n + "."
        : "ל־" + n + " שחקנים מומלץ " + (s.recSpies === 1 ? "מרגל אחד" : s.recSpies + " מרגלים") + " ו־" + s.recMinutes + " דקות." + (recOk ? " ההמלצה מתעדכנת כשאנשים נכנסים." : "")
          + (s.spies >= s.maxSpies ? " עוד מרגל אפשר רק מ־" + (2 * s.maxSpies + 3) + " שחקנים, כדי שהאזרחים יהיו לפחות פי שניים מהמרגלים." : "");
      $("reset-auto").hidden = recOk;
      $("start").disabled = n < s.minPlayers;
    } else {
      $("guest-panel").hidden = false;
      $("guest-info").textContent = n + " בחדר · " + (s.spies === 1 ? "מרגל אחד" : s.spies + " מרגלים") + " · " + (s.timerOn ? s.minutes + " דקות" : "ללא טיימר");
    }
  }
  if (s.status === "playing") {
    $("game").hidden = false;
    $("timer-card").hidden = false;
    $("timer-host").hidden = !s.isHost || !s.timerOn;
    $("t-pause").textContent = s.pausedLeft != null ? "המשך" : "השהה";
    $("timer").hidden = !s.timerOn;
    $("timer-note").hidden = s.timerOn && s.pausedLeft == null;
    $("timer-note").textContent = !s.timerOn ? "משחקים בלי טיימר" : "הטיימר מושהה";
    drawTimer();
    $("reveal-btn").hidden = !s.isHost;
    drawFile(s);
  }
  if (s.status === "reveal" && s.reveal) {
    $("reveal").hidden = false;
    $("reveal-loc").textContent = s.reveal.location;
    $("reveal-spies").textContent = s.reveal.spyIds.map((id) => (s.players.find((p) => p.id === id) || { name: "שחקן שיצא" }).name).join(", ");
    $("new-round").hidden = !s.isHost;
    $("wait-new").hidden = s.isHost;
  }
  renderLocs();
}
function renderPlayers(s) {
  const ul = $("players");
  ul.textContent = "";
  $("p-count").textContent = s.players.length + "/" + s.maxPlayers;
  const spyIds = s.status === "reveal" && s.reveal ? s.reveal.spyIds : [];
  s.players.forEach((p) => {
    const li = document.createElement("li");
    if (!p.online) li.className = "off";
    const dot = el("span", "dot" + (p.online ? " on" : ""), "");
    const name = el("span", "name", p.name + (p.id === s.you ? " (את/ה)" : ""));
    li.append(dot, name);
    if (p.id === s.hostId) li.append(el("span", "badge host", "מארח"));
    if (spyIds.includes(p.id)) li.append(el("span", "badge spy", "מרגל"));
    if (s.isHost && p.id !== s.you) {
      const kick = el("button", "x", "✕");
      kick.title = "הוצא מהחדר";
      kick.setAttribute("aria-label", "הוצא את " + p.name);
      kick.onclick = () => host.kick(p.id);
      li.append(kick);
    }
    ul.append(li);
  });
}
function drawFile(s) {
  const f = $("file"), role = s.role || {};
  f.textContent = "";
  f.append(el("span", "rnd", "ROUND " + String(s.round).padStart(2, "0")));
  if (role.waiting) { f.append(el("div", "cover", "הסבב כבר התחיל"), el("div", "small", "תצטרפו בסבב הבא.")); return; }
  if (role.loading) { f.append(el("div", "cover", "מקבל תיק…"), el("div", "small", "רגע אחד")); return; }
  if (!shown) { f.append(el("div", "cover", "תיק סודי"), el("div", "small", "הקישו כדי לפתוח")); return; }
  if (role.spy) {
    const others = s.spies - 1;
    f.append(el("div", "stamp", "מרגל"), el("div", "small", others > 0 ? "יש עוד " + (others === 1 ? "מרגל אחד" : others + " מרגלים") + ". גלו את המקום בלי להיחשף." : "גלו את המקום בלי להיחשף."));
  } else {
    f.append(el("div", "small", "המקום"), el("div", "loc-name", role.location), ...(role.job ? [el("div", "job", "התפקיד שלך: " + role.job)] : []), el("div", "small", s.spies === 1 ? "יש מרגל אחד ביניכם" : "יש " + s.spies + " מרגלים ביניכם"));
  }
}
$("file").onclick = () => {
  const r = view && view.role;
  if (r && !r.waiting && !r.loading) { shown = !shown; drawFile(view); }
};
$("file").onkeydown = (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); $("file").click(); } };

function renderLocs() {
  const key = "spy.out." + (view && session ? view.code + "." + view.round : "none");
  const out = new Set(store.json(key) || []);
  const box = $("locs");
  box.textContent = "";
  LOCS.forEach((l) => {
    const b = el("button", "loc" + (out.has(l) ? " out" : ""), l);
    b.onclick = () => { out.has(l) ? out.delete(l) : out.add(l); b.classList.toggle("out"); store.set(key, JSON.stringify([...out])); };
    box.append(b);
  });
}

// ---------- home ----------
$("name").value = store.get("spy.name") || "";
function setTab(create) {
  $("tab-create").setAttribute("aria-selected", create);
  $("tab-join").setAttribute("aria-selected", !create);
  $("create-pane").hidden = !create;
  $("join-pane").hidden = create;
}
$("tab-create").onclick = () => setTab(true);
$("tab-join").onclick = () => setTab(false);
function readName() {
  const name = cleanName($("name").value);
  if (!name) { showHomeErr("כתבו שם קודם."); $("name").focus(); return null; }
  store.set("spy.name", name);
  showHomeErr("");
  return name;
}
$("create").onclick = () => {
  const name = readName(); if (!name) return;
  if (!connected) return showHomeErr("אין חיבור עדיין. נסו שוב בעוד רגע.");
  hostCreate(name);
};
$("join").onclick = () => {
  const name = readName(); if (!name) return;
  const code = $("code").value.toUpperCase().replace(/[^A-Z0-9]/g, "");
  if (code.length !== 5) return showHomeErr("הקוד צריך להיות 5 תווים.");
  if (!connected) return showHomeErr("אין חיבור עדיין. נסו שוב בעוד רגע.");
  $("join").disabled = true;
  showHomeErr("מתחבר לחדר…");
  playerJoin(code, name, false);
};
$("code").addEventListener("keydown", (e) => { if (e.key === "Enter") $("join").click(); });
const urlCode = (params.get("r") || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
if (urlCode) { setTab(false); $("code").value = urlCode; }

// ---------- room controls ----------
$("k-minus").onclick = () => host.setSpies(room.spies - 1);
$("k-plus").onclick = () => host.setSpies(room.spies + 1);
$("t-toggle").onclick = () => host.toggleTimer();
$("t-pause").onclick = () => host.pauseTimer();
$("t-cancel").onclick = () => host.cancelTimer();
$("m-minus").onclick = () => host.setMinutes(room.minutes - 1);
$("m-plus").onclick = () => host.setMinutes(room.minutes + 1);
$("reset-auto").onclick = () => host.resetAuto();
$("start").onclick = () => host.start();
$("reveal-btn").onclick = () => host.reveal();
$("new-round").onclick = () => host.lobby();
$("leave").onclick = () => {
  if (!session) return;
  if (session.host) {
    if ($("leave").dataset.armed !== "1") {
      $("leave").dataset.armed = "1";
      $("leave").textContent = "לחצו שוב כדי לסגור לכולם";
      setTimeout(() => { $("leave").dataset.armed = ""; render(); }, 3000);
      return;
    }
    $("leave").dataset.armed = "";
    host.close();
  } else {
    pub(topic(session.code, "h"), { t: "leave", id: playerId });
    endSession("יצאתם מהחדר");
  }
};
async function copy(text, okMsg) {
  try { await navigator.clipboard.writeText(text); toast(okMsg); }
  catch (e) { toast(text); }
}
const shareUrl = () => location.origin + location.pathname + "?r=" + view.code;
$("copy-link").onclick = async () => {
  if (navigator.share) { try { await navigator.share({ title: "המרגל", text: "בואו לשחק! קוד: " + view.code, url: shareUrl() }); return; } catch (e) { if (e && e.name === "AbortError") return; } }
  copy(shareUrl(), "הקישור הועתק");
};
$("copy-code").onclick = () => copy(view.code, "הקוד הועתק");

// ---------- timer ----------
let beeped = 0;
function drawTimer() {
  if (!view || view.status !== "playing" || !view.timerOn) return;
  let left;
  if (view.pausedLeft != null) left = Math.round(view.pausedLeft / 1000);
  else if (view.endsAt) left = Math.max(0, Math.round((view.endsAt - Date.now()) / 1000));
  else return;
  $("timer").textContent = String(Math.floor(left / 60)).padStart(2, "0") + ":" + String(left % 60).padStart(2, "0");
  $("timer").classList.toggle("done", left === 0);
  if (left === 0 && beeped !== view.round) { beeped = view.round; beep(); toast("הזמן נגמר. מצביעים!"); }
}
setInterval(drawTimer, 250);
function beep() {
  try {
    const a = new (window.AudioContext || window.webkitAudioContext)();
    const o = a.createOscillator(), g = a.createGain();
    o.frequency.value = 660; o.connect(g); g.connect(a.destination);
    g.gain.setValueAtTime(0.3, a.currentTime);
    g.gain.exponentialRampToValueAtTime(0.001, a.currentTime + 1.2);
    o.start(); o.stop(a.currentTime + 1.2);
  } catch (e) {}
}
let wake = null;
async function holdWake() {
  if (document.visibilityState !== "visible" || wake) return;
  try { wake = await navigator.wakeLock.request("screen"); wake.addEventListener("release", () => (wake = null)); } catch (e) {}
}
document.addEventListener("visibilitychange", () => {
  holdWake();
  if (document.visibilityState === "visible" && session) {
    if (session.host && room && connected) hostPublishAll();
    else sendHello(false);
  }
});
document.addEventListener("click", holdWake);

// ---------- boot ----------
(async function boot() {
  LOCS = LOCATIONS;
  render();
  try { await loadKeys(); }
  catch (e) { showHomeErr("הדפדפן לא תומך בהצפנה שהמשחק צריך. פתחו את הקישור ב־Chrome או Safari."); return; }
  connectBroker();
})();
