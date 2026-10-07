// Lobby / signaling service for the co-op mode.
//
// What it does: lets a host open a room with a short code and an optional password, lets up to three other
// players join that room, and relays the WebRTC handshake (session descriptions and ICE candidates) between
// the host and each of them. It also hands every player the ICE server list (STUN, optional TURN).
// What it does not do: it never sees or relays game traffic, and it knows nothing about the game's rules.
//
// It attaches to any Node http(s) server:   attachSignaling(server, { path: '/signal' })
// Deployed behind HTTPS the browser reaches it as wss://<host>/signal.
//
// Environment (all optional):
//   STUN_URLS          comma separated STUN urls            default: stun:stun.l.google.com:19302
//   TURN_URLS          comma separated TURN urls            e.g. turn:turn.example.org:3478,turns:turn.example.org:5349
//   TURN_SECRET        shared secret of a TURN server run with time-limited credentials (coturn: use-auth-secret)
//   TURN_TTL           lifetime in seconds of such credentials                       default: 3600
//   TURN_USERNAME / TURN_CREDENTIAL   static TURN credentials (used when TURN_SECRET is not set)
//   ICE_SERVERS        a complete JSON array of RTCIceServer objects (replaces everything above)
//   ALLOWED_ORIGINS    comma separated origins allowed to connect (default: any origin)
//   SIGNAL_MAX_ROOMS   upper bound on simultaneous rooms                             default: 500
//   TRUST_PROXY=1      take the client address from X-Forwarded-For (only behind a proxy you control)
import { createHash, createHmac, randomBytes, randomInt, scryptSync, timingSafeEqual } from 'node:crypto';
import { WebSocketServer } from 'ws';

export const SIGNAL_PATH = '/signal';
const MAX_PLAYERS = 4;
const MAX_MESSAGE_BYTES = 16 * 1024;
const CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no 0/O, 1/I
const CODE_LENGTH = 5;
const HOST_GRACE_MS = 60 * 1000;       // room survives this long without its host's socket
const EMPTY_ROOM_MS = 10 * 60 * 1000;  // ... and this long with nobody connected at all
const ROOM_MAX_AGE_MS = 12 * 60 * 60 * 1000;

const text = (v, max) => String(v ?? '').replace(/[\u0000-\u001f]/g, '').trim().slice(0, max);
const sha = (s) => createHash('sha256').update(s).digest();

/** Token bucket: `rate` tokens per second, at most `burst` saved up. */
class Bucket {
  constructor(rate, burst) { this.rate = rate; this.burst = burst; this.tokens = burst; this.t = Date.now(); }
  take(n = 1) {
    const now = Date.now();
    this.tokens = Math.min(this.burst, this.tokens + ((now - this.t) / 1000) * this.rate);
    this.t = now;
    if (this.tokens < n) return false;
    this.tokens -= n;
    return true;
  }
}

export function iceServers(env = process.env, identity = 'player') {
  if (env.ICE_SERVERS) {
    try { const list = JSON.parse(env.ICE_SERVERS); if (Array.isArray(list)) return list; } catch { /* fall through to the individual settings */ }
  }
  const out = [];
  const stun = (env.STUN_URLS ?? 'stun:stun.l.google.com:19302').split(',').map((s) => s.trim()).filter(Boolean);
  if (stun.length) out.push({ urls: stun });
  const turn = (env.TURN_URLS ?? '').split(',').map((s) => s.trim()).filter(Boolean);
  if (turn.length) {
    if (env.TURN_SECRET) {
      // time-limited credentials (TURN REST convention): username = "<expiry>:<id>", credential = HMAC-SHA1(secret, username)
      const ttl = Number(env.TURN_TTL) || 3600;
      const username = `${Math.floor(Date.now() / 1000) + ttl}:${identity}`;
      out.push({ urls: turn, username, credential: createHmac('sha1', env.TURN_SECRET).update(username).digest('base64') });
    } else if (env.TURN_USERNAME && env.TURN_CREDENTIAL) out.push({ urls: turn, username: env.TURN_USERNAME, credential: env.TURN_CREDENTIAL });
  }
  return out;
}

/**
 * @param {import('node:http').Server} server
 * @param {{ path?: string, env?: Record<string, string | undefined>, log?: (line: string) => void, limits?: { createPerMinute?: number, createBurst?: number, joinPerMinute?: number, joinBurst?: number } }} [options]
 */
export function attachSignaling(server, options = {}) {
  const path = options.path ?? SIGNAL_PATH;
  const env = options.env ?? process.env;
  const log = options.log ?? (() => {});
  const maxRooms = Number(env.SIGNAL_MAX_ROOMS) || 500;
  // per address: lobbies created and join / rejoin attempts (a short burst, then a steady trickle)
  const L = { createPerMinute: 10, createBurst: 6, joinPerMinute: 20, joinBurst: 12, ...(options.limits ?? {}) };
  const allowed = (env.ALLOWED_ORIGINS ?? '').split(',').map((s) => s.trim()).filter(Boolean);
  const trustProxy = env.TRUST_PROXY === '1';
  /** @type {Map<string, any>} */
  const rooms = new Map();
  /** per-address limits: connections, room creations, join attempts */
  const perIp = new Map();
  const ipState = (ip) => {
    let s = perIp.get(ip);
    if (!s) { s = { sockets: 0, create: new Bucket(L.createPerMinute / 60, L.createBurst), join: new Bucket(L.joinPerMinute / 60, L.joinBurst), seen: Date.now() }; perIp.set(ip, s); }
    s.seen = Date.now();
    return s;
  };

  const wss = new WebSocketServer({ noServer: true, maxPayload: MAX_MESSAGE_BYTES });

  const send = (ws, msg) => { if (ws && ws.readyState === 1) ws.send(JSON.stringify(msg)); };
  const fail = (ws, reason) => send(ws, { t: 'error', reason });

  function newCode() {
    for (let attempt = 0; attempt < 200; attempt++) {
      let code = '';
      for (let i = 0; i < CODE_LENGTH; i++) code += CODE_ALPHABET[randomInt(CODE_ALPHABET.length)];
      if (!rooms.has(code)) return code; // collision check against every open room
    }
    return null;
  }

  function closeRoom(room, reason) {
    if (!rooms.delete(room.code)) return;
    for (const m of room.members.values()) { send(m.ws, { t: 'closed', reason }); if (m.ws) m.ws.room = null; }
    log(`room ${room.code} closed (${reason}); ${rooms.size} open`);
  }

  function welcome(ws, room, member, rejoin) {
    ws.room = room;
    ws.pid = member.pid;
    member.ws = ws;
    member.lastSeen = Date.now();
    room.lastActive = Date.now();
    send(ws, { t: member.pid === 0 && !rejoin ? 'created' : 'joined', code: room.code, pid: member.pid, token: member.token, rejoin, ice: iceServers(env, `${room.code}-${member.pid}`), max: MAX_PLAYERS });
  }

  function onMessage(ws, raw) {
    if (!ws.bucket.take()) { fail(ws, 'rate-limited'); return; }
    let m;
    try { m = JSON.parse(raw); } catch { fail(ws, 'bad-request'); return; }
    if (!m || typeof m !== 'object' || typeof m.t !== 'string') { fail(ws, 'bad-request'); return; }
    const ip = ipState(ws.ip);

    if (m.t === 'create') {
      if (ws.room) { fail(ws, 'bad-request'); return; }
      if (!ip.create.take() || rooms.size >= maxRooms) { fail(ws, 'rate-limited'); return; }
      const code = newCode();
      if (!code) { fail(ws, 'rate-limited'); return; }
      const password = text(m.password, 64);
      // only a salted verifier of the password is kept; the password itself is never stored or sent on
      const salt = randomBytes(16);
      const room = {
        code, version: Number(m.v) || 0, started: false, created: Date.now(), lastActive: Date.now(), hostGone: 0,
        salt, verifier: password ? scryptSync(password, salt, 32) : null, members: new Map(), badPasswords: new Map(),
      };
      const member = { pid: 0, name: text(m.name, 16) || 'Host', token: randomBytes(24).toString('base64url'), ws: null, lastSeen: Date.now() };
      member.tokenHash = sha(member.token);
      room.members.set(0, member);
      rooms.set(code, room);
      welcome(ws, room, member, false);
      log(`room ${code} created${room.verifier ? ' (password)' : ''}; ${rooms.size} open`);
      return;
    }

    if (m.t === 'join') {
      if (ws.room) { fail(ws, 'bad-request'); return; }
      if (!ip.join.take()) { fail(ws, 'rate-limited'); return; }
      const room = rooms.get(text(m.code, 12).toUpperCase());
      if (!room) { fail(ws, 'not-found'); return; }
      if (room.version !== (Number(m.v) || 0)) { fail(ws, 'version'); return; }
      if (room.verifier) {
        const password = text(m.password, 64);
        if (!password) { fail(ws, 'password-required'); return; }
        // a handful of wrong guesses per address and room, then the address has to wait
        const bad = room.badPasswords.get(ws.ip) ?? { n: 0, until: 0 };
        if (bad.until > Date.now()) { fail(ws, 'rate-limited'); return; }
        const given = scryptSync(password, room.salt, 32);
        if (!timingSafeEqual(given, room.verifier)) {
          bad.n++;
          if (bad.n >= 6) { bad.n = 0; bad.until = Date.now() + 5 * 60 * 1000; }
          room.badPasswords.set(ws.ip, bad);
          fail(ws, 'wrong-password');
          return;
        }
      }
      if (room.started) { fail(ws, 'in-progress'); return; }
      let pid = -1;
      for (let i = 1; i < MAX_PLAYERS; i++) if (!room.members.has(i)) { pid = i; break; }
      if (pid < 0) { fail(ws, 'full'); return; }
      const member = { pid, name: text(m.name, 16) || `Player ${pid + 1}`, token: randomBytes(24).toString('base64url'), ws: null, lastSeen: Date.now() };
      member.tokenHash = sha(member.token);
      room.members.set(pid, member);
      welcome(ws, room, member, false);
      send(room.members.get(0)?.ws, { t: 'peer', event: 'join', pid, name: member.name });
      return;
    }

    if (m.t === 'rejoin') {
      // back into one's own slot: only the holder of the token the service issued for it gets in
      if (ws.room) { fail(ws, 'bad-request'); return; }
      if (!ip.join.take()) { fail(ws, 'rate-limited'); return; }
      const room = rooms.get(text(m.code, 12).toUpperCase());
      if (!room) { fail(ws, 'not-found'); return; }
      if (room.version !== (Number(m.v) || 0)) { fail(ws, 'version'); return; }
      const hash = sha(text(m.token, 80));
      let member = null;
      for (const x of room.members.values()) if (x.tokenHash.length === hash.length && timingSafeEqual(x.tokenHash, hash)) { member = x; break; }
      if (!member) { fail(ws, 'kicked'); return; }
      const old = member.ws;
      if (old && old !== ws) { old.room = null; try { old.close(); } catch { /* already gone */ } }
      welcome(ws, room, member, true);
      if (member.pid === 0) room.hostGone = 0;
      else send(room.members.get(0)?.ws, { t: 'peer', event: 'rejoin', pid: member.pid, name: member.name });
      return;
    }

    const room = ws.room;
    if (!room) { fail(ws, 'bad-request'); return; }
    room.lastActive = Date.now();

    if (m.t === 'signal') {
      // handshake payloads only travel between the host and one member of the same room
      const to = Number(m.to);
      const target = ws.pid === 0 ? room.members.get(to) : to === 0 ? room.members.get(0) : null;
      if (!target || target.pid === ws.pid || !m.data || typeof m.data !== 'object') { fail(ws, 'bad-request'); return; }
      send(target.ws, { t: 'signal', from: ws.pid, data: m.data });
      return;
    }
    if (m.t === 'state' && ws.pid === 0) { room.started = !!m.started; return; }
    if (m.t === 'kick' && ws.pid === 0) {
      const pid = Number(m.pid);
      const member = pid > 0 ? room.members.get(pid) : null;
      if (member) { room.members.delete(pid); send(member.ws, { t: 'closed', reason: 'kicked' }); if (member.ws) member.ws.room = null; }
      return;
    }
    if (m.t === 'leave') {
      if (ws.pid === 0) closeRoom(room, 'host-left');
      else { room.members.delete(ws.pid); ws.room = null; send(room.members.get(0)?.ws, { t: 'peer', event: 'leave', pid: ws.pid }); }
      return;
    }
    fail(ws, 'bad-request');
  }

  function onClose(ws) {
    const ip = perIp.get(ws.ip);
    if (ip) ip.sockets = Math.max(0, ip.sockets - 1);
    const room = ws.room;
    if (!room) return;
    const member = room.members.get(ws.pid);
    if (!member || member.ws !== ws) return; // replaced by a newer socket of the same player
    member.ws = null;
    member.lastSeen = Date.now();
    if (ws.pid === 0) { room.hostGone = Date.now(); for (const x of room.members.values()) send(x.ws, { t: 'peer', event: 'host-drop', pid: 0 }); }
    else send(room.members.get(0)?.ws, { t: 'peer', event: 'drop', pid: ws.pid });
  }

  wss.on('connection', (ws, req) => {
    // per-address limits use the socket address; a forwarded header is only believed behind a known proxy
    ws.ip = String((trustProxy && req.headers['x-forwarded-for']) || req.socket.remoteAddress || '').split(',')[0].trim();
    ws.bucket = new Bucket(40, 120); // ICE candidates arrive in bursts
    ws.room = null;
    ws.pid = -1;
    ws.alive = true;
    const ip = ipState(ws.ip);
    ip.sockets++;
    if (ip.sockets > 16) { fail(ws, 'rate-limited'); ws.close(); return; }
    ws.on('pong', () => { ws.alive = true; });
    ws.on('message', (data, isBinary) => { if (!isBinary) onMessage(ws, data.toString()); });
    ws.on('close', () => onClose(ws));
    ws.on('error', () => { /* the close event follows */ });
  });

  const onUpgrade = (req, socket, head) => {
    let pathname = '';
    try { pathname = new URL(req.url ?? '/', 'http://localhost').pathname; } catch { /* malformed */ }
    if (pathname !== path) return; // not ours (the dev server's own socket, for instance)
    if (allowed.length && !allowed.includes(String(req.headers.origin ?? ''))) { socket.write('HTTP/1.1 403 Forbidden\r\n\r\n'); socket.destroy(); return; }
    wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws, req));
  };
  server.on('upgrade', onUpgrade);

  // housekeeping: dead sockets, rooms without a host, idle and very old rooms, stale address records
  const timer = setInterval(() => {
    const now = Date.now();
    for (const ws of wss.clients) {
      if (!ws.alive) { ws.terminate(); continue; }
      ws.alive = false;
      try { ws.ping(); } catch { /* closing */ }
    }
    for (const room of [...rooms.values()]) {
      const anyone = [...room.members.values()].some((m) => m.ws);
      if (room.hostGone && now - room.hostGone > HOST_GRACE_MS) closeRoom(room, 'host-left');
      else if (!anyone && now - room.lastActive > EMPTY_ROOM_MS) closeRoom(room, 'closed');
      else if (now - room.created > ROOM_MAX_AGE_MS) closeRoom(room, 'closed');
    }
    for (const [ip, s] of perIp) if (s.sockets <= 0 && now - s.seen > 10 * 60 * 1000) perIp.delete(ip);
  }, 15000);
  timer.unref?.();

  return {
    path,
    /** number of open rooms (health checks) */
    get rooms() { return rooms.size; },
    /** small JSON status for GET <path>/health */
    health() { return { ok: true, rooms: rooms.size, sockets: wss.clients.size, turn: iceServers(env).some((s) => [].concat(s.urls).some((u) => String(u).startsWith('turn'))) }; },
    close() { clearInterval(timer); server.off('upgrade', onUpgrade); for (const ws of wss.clients) ws.terminate(); wss.close(); rooms.clear(); },
  };
}
