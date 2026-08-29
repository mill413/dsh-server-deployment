'use strict';
const http = require('http');
const https = require('https');
const net = require('net');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const url = require('url');
const { spawn, execFileSync } = require('child_process');
const zlib = require('zlib');
const { verifyPassword, timingSafeStr } = require('./auth.js');
const { ClusterStore } = require('../cluster/store.js');
const { withFileLock } = require('../cluster/file-lock.js');

const HOST = process.env.HOST || '127.0.0.1';
const PORT = parseInt(process.env.PORT || '3081', 10);
const USERS_FILE = process.env.USERS_FILE || '/opt/deepseek-harness/gateway/users.json';
const CONTROL_SOCKET = process.env.DSH_CONTROL_SOCKET || '/run/dsh/control.sock';
const SECRET_FILE = process.env.SECRET_FILE || '/opt/deepseek-harness/gateway/secret';
const USERS_DIR = process.env.USERS_DIR || '/opt/deepseek-harness/users';
const SESSION_TTL = Math.max(1, parseInt(process.env.SESSION_TTL || '43200', 10) || 43200);
// Sliding renewal is opt-in. While a DSH page is alive its authenticated
// presence heartbeat refreshes the cookie after this many seconds from the
// previous issuance. Zero preserves fixed-expiry sessions.
const SESSION_REFRESH_INTERVAL = Math.max(0, parseInt(process.env.SESSION_REFRESH_INTERVAL || '0', 10) || 0);
if (SESSION_REFRESH_INTERVAL >= SESSION_TTL && SESSION_REFRESH_INTERVAL > 0) {
  throw new Error('SESSION_REFRESH_INTERVAL must be less than SESSION_TTL');
}
const COOKIE_SECURE = (process.env.COOKIE_SECURE || '1') !== '0';
const DEEPSEEK_BASE_URL = process.env.DEEPSEEK_BASE_URL || 'https://api.deepseek.com';
const MAX_IP_ATTEMPTS = parseInt(process.env.MAX_IP_ATTEMPTS || '20', 10);
const MAX_USER_ATTEMPTS = parseInt(process.env.MAX_USER_ATTEMPTS || '5', 10);
const WINDOW_MS = parseInt(process.env.WINDOW_MS || '900000', 10);
const LOCK_MS = parseInt(process.env.LOCK_MS || '900000', 10);
const COOKIE_NAME = 'dsh_session';
const CSRF_COOKIE = 'dsh_csrf';

// ---------- admin / online-users tracking ----------
// Sessions are stateless HMAC cookies, so "logged in" is approximated by the
// last authenticated request: users with an entry here have a valid session
// and were seen recently. `online` = active within ACTIVE_WINDOW_MS; entries
// are retained while their session could still be valid (SESSION_TTL).
const ACTIVE_WINDOW_MS = 15 * 60 * 1000;
const ACTIVE_RETAIN_MS = (SESSION_TTL || 43200) * 1000;
const activeUsers = new Map(); // username -> { at, ip }
function markActive(user, req) {
  const now = Date.now();
  if (activeUsers.size > 5000) {
    for (const [k, v] of activeUsers) if (now - v.at > ACTIVE_RETAIN_MS) activeUsers.delete(k);
  }
  const previous = activeUsers.get(user);
  const ip = clientIp(req);
  activeUsers.set(user, { at: now, ip });
  if (CLUSTER_ENABLED && (!previous || previous.loggedOut || now - previous.at >= 30000)) {
    clusterStore.markUserActive(user, ip, false).catch((error) => {
      console.error(`cluster activity update failed for ${user}: ${error.message}`);
    });
  }
}

// ---------- self-service registration (Docker deployment) ----------
// The gateway cannot provision users itself (OS account / port / instance /
// firewall need root); it forwards the request through a fixed-path sudo
// helper (dsh-register) to the entrypoint supervisor's control socket. The
// feature is enabled automatically when the helper is installed (Docker
// image) and can be forced off/on with DSH_ENABLE_REGISTER=0/1.
const REGISTER_HELPER = process.env.DSH_REGISTER_HELPER || '/usr/local/libexec/dsh/dsh-register';
const REGISTER_ENABLED = process.env.DSH_ENABLE_REGISTER
  ? process.env.DSH_ENABLE_REGISTER === '1'
  : fs.existsSync(REGISTER_HELPER);
const MAX_REGISTER_ATTEMPTS = parseInt(process.env.MAX_REGISTER_ATTEMPTS || '10', 10);
const registerFails = new Map();

// ---------- external registration / provider API ----------
// Machine-to-machine endpoints, enabled only when DSH_REGISTER_API_KEY is set.
//   POST /api/register                {username,password}  -> create the user
//   POST /api/users/<name>/provider   {provider:{name,baseURL,model},apiKey}
//                                     -> register/replace the user's custom
//                                        provider and write its API key
//   POST /api/users/<name>/message    {message,sessionId?,mode?}
//                                     -> send a prompt to the user's DSH
//   GET  /api/users/<name>/messages   ?sessionId=... -> read message history
//   POST /api/users/<name>/files      ?name=...&dir=... -> upload raw bytes
// All calls require: Authorization: Bearer <DSH_REGISTER_API_KEY>.
const REGISTER_API_TOKEN = process.env.DSH_REGISTER_API_KEY || '';
const REGISTER_API_ENABLED = REGISTER_API_TOKEN.length > 0;
// External SSO bridge. A trusted backend authenticates with this dedicated
// key, asks for a short-lived one-time ticket, then redirects the browser to
// the returned same-origin URL. Never put this long-lived key in browser code.
const LOGIN_API_TOKEN = process.env.DSH_LOGIN_API_KEY || '';
const LOGIN_API_ENABLED = LOGIN_API_TOKEN.length > 0;
const LOGIN_TICKET_TTL = Math.min(300, Math.max(10, parseInt(process.env.LOGIN_TICKET_TTL || '60', 10) || 60));
const LOGIN_TICKET_MAX = 10000;
const loginTickets = new Map(); // sha256(ticket) -> { user, returnTo, expiresAt }
const PROVIDER_HELPER = process.env.DSH_PROVIDER_HELPER || '/usr/local/libexec/dsh/dsh-provider';
function bearerAuthorized(req, token) {
  if (!token) return false;
  const h = req.headers['authorization'] || '';
  const m = /^Bearer\s+(.+)$/i.exec(h);
  return !!(m && m[1] && timingSafeStr(m[1], token));
}
function apiAuthorized(req) {
  return REGISTER_API_ENABLED && bearerAuthorized(req, REGISTER_API_TOKEN);
}
function loginApiAuthorized(req) {
  return LOGIN_API_ENABLED && bearerAuthorized(req, LOGIN_API_TOKEN);
}
function readJsonBody(req, limit) {
  return readBody(req, limit).then((body) => {
    try { return JSON.parse(body); } catch (e) { throw new Error('invalid JSON body'); }
  });
}

// Ask an OpenAI-compatible provider for its model list (GET <baseURL>/models
// with the API key). Used by the model registration API so callers do not have
// to know the models ahead of time. Returns up to 100 model ids.
async function fetchProviderModels(baseURL, apiKey) {
  const url = String(baseURL).replace(/\/+$/, '') + '/models';
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 15000);
  try {
    const res = await fetch(url, {
      method: 'GET',
      headers: { 'Authorization': 'Bearer ' + apiKey, 'Accept': 'application/json' },
      signal: controller.signal,
    });
    if (!res.ok) throw new Error('HTTP ' + res.status + (res.statusText ? ' ' + res.statusText : ''));
    const j = await res.json();
    if (!j || !Array.isArray(j.data)) throw new Error('provider response has no data array');
    const ids = j.data.map((m) => (m && typeof m.id === 'string') ? m.id.trim() : '').filter(Boolean);
    if (ids.length === 0) throw new Error('provider returned no models');
    return [...new Set(ids)].slice(0, 100);
  } finally {
    clearTimeout(timer);
  }
}
const UPLOAD_HELPER = process.env.UPLOAD_HELPER || '/opt/deepseek-harness/bin/dsh-file-put';
const FILE_STAT_HELPER = process.env.FILE_STAT_HELPER || '/opt/deepseek-harness/bin/dsh-file-stat';
const FILE_READ_HELPER = process.env.FILE_READ_HELPER || '/opt/deepseek-harness/bin/dsh-file-read';
const FILE_LIST_HELPER = process.env.FILE_LIST_HELPER || '/opt/deepseek-harness/bin/dsh-file-list';
const FILE_DELETE_HELPER = process.env.FILE_DELETE_HELPER || '/opt/deepseek-harness/bin/dsh-file-delete';
const FILE_MKDIR_HELPER = process.env.FILE_MKDIR_HELPER || '/opt/deepseek-harness/bin/dsh-file-mkdir';
const UPLOAD_MAX_MB = parseInt(process.env.UPLOAD_MAX_MB || '100', 10);
const MESSAGE_STREAM_TIMEOUT_MS = Math.max(30000, parseInt(process.env.DSH_MESSAGE_STREAM_TIMEOUT_MS || '900000', 10) || 900000);
const PLUGIN_TARBALL_DIR = process.env.DSH_PLUGIN_TARBALL_DIR
  || path.join(path.dirname(USERS_FILE), 'plugin-tarballs');
const PLUGIN_TARBALL_MAX_MB = Math.min(1024, Math.max(1, parseInt(process.env.PLUGIN_TARBALL_MAX_MB || '100', 10) || 100));
const clusterStore = new ClusterStore({ gatewayPort: PORT });
const CLUSTER_ENABLED = clusterStore.enabled;
const CLUSTER_TOKEN = process.env.DSH_CLUSTER_TOKEN || '';
if (CLUSTER_ENABLED && CLUSTER_TOKEN.length < 32) throw new Error('DSH_CLUSTER_TOKEN must contain at least 32 characters in cluster mode');

// ---------- history page trimming + JSON gzip tuning ----------
// Huge agent sessions accumulate tens of thousands of streaming chunk events
// per page: the DSH host pages by *messages* (user/message, assistant/message)
// while keeping every tool/chunk event of the page, and it never compresses.
// The web client asks for the last 50 messages, parses/renders every returned
// event and aborts its own fetch after 30s ("The user aborted a request."),
// so a multi-MB page over a slow link fails. The gateway therefore trims
// oversized history pages to the last few messages at message boundaries (the
// same boundary rule the host applies) and gzips JSON responses the host
// leaves raw. Trimming never drops data: the page tail is kept, hasMore is
// forced true, and the client's beforeSeq paging walks the skipped range.
const HISTORY_TRIM_MESSAGES = parseInt(process.env.HISTORY_TRIM_MESSAGES || '6', 10);
const HISTORY_TRIM_MIN_EVENTS = parseInt(process.env.HISTORY_TRIM_MIN_EVENTS || '2000', 10);
const GZIP_MIN_BYTES = parseInt(process.env.GZIP_MIN_BYTES || '256', 10);
const HISTORY_BUF_MAX = 64 * 1024 * 1024;

function loadSecret() {
  const configured = String(process.env.DSH_SESSION_SECRET || '').trim();
  if (configured) {
    if (configured.length < 32) throw new Error('DSH_SESSION_SECRET must contain at least 32 characters');
    return configured;
  }
  try {
    const s = fs.readFileSync(SECRET_FILE, 'utf8').trim();
    if (s.length >= 32) return s;
    console.error(`session secret is too short, replacing it: ${SECRET_FILE}`);
  } catch (e) {
    if (!e || e.code !== 'ENOENT') console.error(`cannot read session secret ${SECRET_FILE}: ${e.message}`);
  }
  const s = crypto.randomBytes(32).toString('hex');
  try {
    fs.mkdirSync(path.dirname(SECRET_FILE), { recursive: true, mode: 0o700 });
    fs.writeFileSync(SECRET_FILE, s + '\n', { mode: 0o600 });
  } catch (e) { console.error('cannot persist session secret:', e.message); }
  return s;
}
const SECRET = loadSecret();
const SECRET_ID = crypto.createHash('sha256').update(SECRET).digest('hex').slice(0, 12);

function hmac(data) {
  return crypto.createHmac('sha256', SECRET).update(data).digest('base64url');
}

// ---------- users store (small JSON, cached) ----------
let usersCache = { version: 1, users: {} };
let usersCacheAt = 0;
let usersCacheSignature = '';
function loadUsers() {
  const now = Date.now();
  if (!CLUSTER_ENABLED && now - usersCacheAt < 2000) return usersCache;
  if (CLUSTER_ENABLED && usersCacheAt > 0) {
    try {
      const stat = fs.statSync(USERS_FILE);
      const signature = `${stat.dev}:${stat.ino}:${stat.size}:${stat.mtimeMs}`;
      if (signature === usersCacheSignature) return usersCache;
    } catch (error) {}
  }
  try {
    usersCache = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
    try {
      const stat = fs.statSync(USERS_FILE);
      usersCacheSignature = `${stat.dev}:${stat.ino}:${stat.size}:${stat.mtimeMs}`;
    } catch (error) { usersCacheSignature = ''; }
  } catch (e) {
    // A corrupt store must be loud, not silently "no users" (lockout for
    // everyone + impossible to debug from the outside).
    console.error('users.json parse failed, keeping last known cache:', e.message);
  }
  usersCacheAt = now;
  return usersCache;
}
function getUser(name) {
  const u = loadUsers().users;
  return (u && u[name]) || null;
}
// Password generation: bumped by userctl on every password change so all
// outstanding session tokens (which embed pwdVer) become invalid - otherwise
// a stolen 12h token would survive a password reset.
function pwdVersion(user) {
  const u = getUser(user);
  return (u && typeof u.pwdVer === 'number') ? u.pwdVer : 0;
}

// Whether the user already configured an API key (flag lives in users.json,
// maintained by the gateway and by host-side userctl).
function hasKey(user) {
  const u = getUser(user);
  return !!(u && u.keyConfigured);
}

// Atomically update one user record inside users.json (read-modify-write via
// temp file + rename) so a crash never leaves a truncated store and the
// in-memory cache is refreshed immediately.
async function mutateUserStore(user, fn) {
  return withFileLock(USERS_FILE, async () => {
    let db;
    try { db = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); } catch (e) {
      // Never turn a permission/read failure into an empty database write: that
      // would erase every user while trying to update one keyConfigured flag.
      if (!e || e.code !== 'ENOENT') console.error('users.json update read failed:', e.message);
      return false;
    }
    if (!db.users || !db.users[user]) return false;
    fn(db.users[user]);
    try {
      const tmp = USERS_FILE + '.tmp-' + process.pid + '-' + Date.now().toString(36);
      fs.writeFileSync(tmp, JSON.stringify(db, null, 2) + '\n', { mode: 0o640 });
      fs.renameSync(tmp, USERS_FILE);
    } catch (e) { console.error('users.json write failed:', e.message); return false; }
    usersCache = db;
    usersCacheAt = Date.now();
    try {
      const stat = fs.statSync(USERS_FILE);
      usersCacheSignature = `${stat.dev}:${stat.ino}:${stat.size}:${stat.mtimeMs}`;
    } catch (error) { usersCacheSignature = ''; }
    return true;
  });
}

// Persist the flag and refresh the in-memory cache so the very next request
// sees it (no 2s staleness on the /setup -> / redirect).
function setUserKeyFlag(user, val) {
  return mutateUserStore(user, (rec) => { rec.keyConfigured = !!val; });
}

// Ask the user's own DSH instance to persist the key. The instance's credentials
// store is 0600 and owned by that user's OS account, so the gateway must not
// write it directly; this loopback RPC is the only write path.
function rpcCredentialSet(port, ref, value) {
  return new Promise((resolve) => {
    const rpcId = 'gw-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 10);
    const body = JSON.stringify({ type: 'client-request', rpcId: rpcId, method: 'credentials.set', payload: { ref: ref, value: value } });
    const req = http.request({
      host: '127.0.0.1', port: port, method: 'POST', path: '/api/credentials.set',
      headers: { 'content-type': 'application/json', 'host': '127.0.0.1:' + port, 'content-length': Buffer.byteLength(body) },
    }, (res) => {
      let data = '';
      res.on('data', (c) => data += c);
      res.on('end', () => {
        try {
          const j = JSON.parse(data);
          if (j && j.result && j.result.ok) resolve({ ok: true });
          else resolve({ ok: false, detail: (j && j.result && j.result.error && j.result.error.message) || '后端返回错误' });
        } catch (e) {
          resolve({ ok: false, detail: '后端响应解析失败: ' + String(data || '(空响应)').slice(0, 120) });
        }
      });
    });
    req.on('error', (e) => resolve({ ok: false, detail: '后端服务不可用: ' + e.message }));
    req.setTimeout(10000, () => { req.destroy(); resolve({ ok: false, detail: '写入超时' }); });
    req.write(body);
    req.end();
  });
}

// Retry a loopback RPC with backoff: right after the supervisor restarts the
// user's instance the HTTP port answers before every plugin route is ready, so
// the first attempt can fail spuriously. Returns { ok, detail }.
async function rpcCredentialSetRetry(port, ref, value, attempts = 3, delayMs = 2500) {
  let last = { ok: false, detail: '未尝试' };
  for (let i = 0; i < attempts; i++) {
    last = await rpcCredentialSet(port, ref, value);
    if (last.ok) return last;
    if (i < attempts - 1) await new Promise((r) => setTimeout(r, delayMs));
  }
  return last;
}

function rpcCredentialsSet(port, key) {
  return rpcCredentialSet(port, 'DEEPSEEK_API_KEY', key);
}

// Call one unary DSH Host RPC directly over the tenant's loopback port. This
// is intentionally narrower than the browser reverse proxy: machine callers
// can only reach the explicit methods used by gateway-owned API endpoints.
function tenantRpcEnvelope(port, method, payload, timeoutMs = 30000) {
  return new Promise((resolve, reject) => {
    const rpcId = 'gw-api-' + Date.now().toString(36) + '-' + crypto.randomBytes(6).toString('hex');
    const body = JSON.stringify({ type: 'client-request', rpcId, method, payload });
    let settled = false;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      if (error) reject(error); else resolve(value);
    };
    const request = http.request({
      host: '127.0.0.1',
      port,
      method: 'POST',
      path: '/api/' + method,
      headers: {
        'content-type': 'application/json',
        'host': '127.0.0.1:' + port,
        'content-length': Buffer.byteLength(body),
      },
    }, (response) => {
      const chunks = [];
      let bytes = 0;
      response.on('data', (chunk) => {
        bytes += chunk.length;
        if (bytes <= 1024 * 1024) chunks.push(chunk);
        else request.destroy(new Error('DSH RPC response is too large'));
      });
      response.on('end', () => {
        const raw = Buffer.concat(chunks).toString('utf8');
        if ((response.statusCode || 500) < 200 || (response.statusCode || 500) >= 300) {
          return finish(new Error('DSH RPC HTTP ' + response.statusCode + ': ' + raw.slice(0, 200)));
        }
        let reply;
        try { reply = JSON.parse(raw); } catch (error) {
          return finish(new Error('invalid DSH RPC response'));
        }
        if (!reply || reply.rpcId !== rpcId || !reply.result || typeof reply.result.ok !== 'boolean') {
          return finish(new Error('invalid DSH RPC envelope'));
        }
        finish(null, { rpcId, result: reply.result });
      });
      response.on('error', (error) => finish(error));
    });
    request.on('error', (error) => finish(error));
    request.setTimeout(timeoutMs, () => request.destroy(new Error('DSH RPC timeout')));
    request.end(body);
  });
}

function tenantRpc(port, method, payload, timeoutMs = 30000) {
  return tenantRpcEnvelope(port, method, payload, timeoutMs).then((reply) => reply.result);
}

function openTenantMux(port, onFrame) {
  if (typeof WebSocket !== 'function') return Promise.reject(new Error('WebSocket client is unavailable in this Node runtime'));
  return new Promise((resolve, reject) => {
    const socket = new WebSocket('ws://127.0.0.1:' + port + '/api/events.mux');
    let opened = false;
    const timer = setTimeout(() => {
      if (opened) return;
      try { socket.close(); } catch (error) {}
      reject(new Error('timed out opening DSH event stream'));
    }, 10000);
    const failOpen = (event) => {
      if (!opened) {
        clearTimeout(timer);
        reject(new Error('failed to open DSH event stream' + (event && event.message ? ': ' + event.message : '')));
      }
    };
    socket.addEventListener('message', (event) => {
      try {
        if (typeof event.data !== 'string') return;
        const message = JSON.parse(event.data);
        if (message && message.type === 'server-request' && message.payload) onFrame(message.payload);
      } catch (error) {}
    });
    socket.addEventListener('open', () => { opened = true; clearTimeout(timer); resolve(socket); }, { once: true });
    socket.addEventListener('error', failOpen);
    socket.addEventListener('close', failOpen);
  });
}

function sseWrite(res, event, value) {
  if (res.destroyed || res.writableEnded) return false;
  return res.write('event: ' + event + '\ndata: ' + JSON.stringify(value) + '\n\n');
}

function streamAcceptedMessage(req, res, socket, details, promptRpcId, bufferedFrames, activateConsumer) {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream; charset=utf-8',
    'Cache-Control': 'no-store',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  sseWrite(res, 'accepted', details);
  return new Promise((resolve) => {
    let finished = false;
    let matchedPrompt = false;
    let targetTurn = null;
    let heartbeat = null;
    let timeout = null;
    const finish = (event, value) => {
      if (finished) return;
      finished = true;
      if (heartbeat) clearInterval(heartbeat);
      if (timeout) clearTimeout(timeout);
      if (event) sseWrite(res, event, value);
      try { socket.close(); } catch (error) {}
      if (!res.writableEnded) res.end();
      resolve();
    };
    const consume = (frame) => {
      if (finished || !frame || frame.sessionId !== details.sessionId) return;
      if (frame.type !== 'session/event') {
        if (matchedPrompt && (frame.type === 'approval/requested' || frame.type === 'question/requested')) {
          sseWrite(res, 'interaction', frame);
        }
        return;
      }
      const event = frame.event || {};
      if (!matchedPrompt) {
        const source = event.type === 'user/message' && event.data && event.data.source;
        if (!source || source.rpcId !== promptRpcId) return;
        matchedPrompt = true;
      }
      const eventTurn = event.data && Number.isInteger(event.data.turn) ? event.data.turn : null;
      if (targetTurn === null && eventTurn !== null) targetTurn = eventTurn;
      if (targetTurn !== null && eventTurn !== null && eventTurn !== targetTurn) return;
      sseWrite(res, event.type === 'assistant/chunk' ? 'assistant.chunk'
        : event.type === 'assistant/message' ? 'assistant.message' : 'session.event', frame);
      if (event.type === 'turn/end') finish('done', { sessionId: details.sessionId, reason: event.data && event.data.reason, event });
    };
    activateConsumer(consume);
    socket.addEventListener('error', () => finish('error', { code: 'stream-error', error: 'DSH event stream failed' }), { once: true });
    socket.addEventListener('close', () => {
      if (!finished) finish('error', { code: 'stream-closed', error: 'DSH event stream closed before the turn completed' });
    }, { once: true });
    heartbeat = setInterval(() => { if (!res.destroyed && !res.writableEnded) res.write(': keepalive\n\n'); }, 15000);
    heartbeat.unref();
    timeout = setTimeout(() => finish('error', { code: 'stream-timeout', error: 'timed out waiting for the DSH response' }), MESSAGE_STREAM_TIMEOUT_MS);
    timeout.unref();
    req.on('close', () => {
      if (!req.complete || res.destroyed) finish(null, null);
    });
    res.on('close', () => { if (!res.writableEnded) finish(null, null); });
    for (const frame of bufferedFrames) consume(frame);
    if (details.command) finish('done', { sessionId: details.sessionId, command: details.command });
  });
}

function messageViewsFromHistory(entries) {
  const messages = [];
  for (const entry of Array.isArray(entries) ? entries : []) {
    const event = entry && entry.event;
    if (!event || (event.type !== 'user/message' && event.type !== 'assistant/message')) continue;
    if (event.surfaceOp !== undefined && event.surfaceOp !== 'append') continue;
    const data = event.data || {};
    const message = event.type === 'assistant/message' ? data.message : data;
    messages.push({
      seq: event.seq,
      time: event.time,
      role: event.type === 'assistant/message' ? 'assistant' : 'user',
      message,
      ...(Number.isInteger(data.turn) ? { turn: data.turn } : {}),
      ...(Number.isInteger(data.step) ? { step: data.step } : {}),
      ...(data.usage === undefined ? {} : { usage: data.usage }),
      ...(data.interrupted === true ? { interrupted: true } : {}),
    });
  }
  return messages;
}

// ---------- rate limiting ----------
const ipFails = new Map();
const userFails = new Map();
const DUMMY_SALT = crypto.randomBytes(16); // timing-equalizer for unknown users
function clientIp(req) {
  // The gateway sits behind exactly one trusted TLS proxy (OpenResty) that we
  // control and that OVERWRITES X-Forwarded-For with $remote_addr, so the
  // header - when present - carries only the real client address. If anything
  // else reaches us without that header (direct loopback access, a mis-set
  // proxy), fall back to the socket address. Never trust a comma-separated
  // list here: an attacker-supplied XFF would otherwise spoof the rate limiter.
  const xff = req.headers['x-forwarded-for'];
  if (xff) {
    const first = String(xff).split(',')[0].trim();
    if (first) return first;
  }
  return req.socket.remoteAddress || 'unknown';
}
function lockedUntil(map, key) {
  const e = map.get(key);
  if (!e) return 0;
  if (e.lockedUntil && Date.now() < e.lockedUntil) return e.lockedUntil;
  return 0;
}
function registerFailure(map, key, max) {
  const now = Date.now();
  let e = map.get(key);
  if (!e || now - e.windowStart > WINDOW_MS) { e = { count: 0, windowStart: now, lockedUntil: 0 }; map.set(key, e); }
  e.count += 1;
  if (e.count >= max) e.lockedUntil = now + LOCK_MS;
}
async function checkAttempts(req, username) {
  const ip = clientIp(req);
  if (CLUSTER_ENABLED) {
    const [a, b] = await Promise.all([
      clusterStore.rateLimitStatus('login-ip', ip),
      clusterStore.rateLimitStatus('login-user', username),
    ]);
    return (a || b)
      ? { allowed: false, retryAfter: Math.ceil((Math.max(a, b) - Date.now()) / 1000) }
      : { allowed: true, retryAfter: 0 };
  }
  const a = lockedUntil(ipFails, ip);
  const b = lockedUntil(userFails, username);
  if (a || b) return { allowed: false, retryAfter: Math.ceil((Math.max(a, b) - Date.now()) / 1000) };
  return { allowed: true, retryAfter: 0 };
}
async function recordFailure(req, username) {
  if (CLUSTER_ENABLED) {
    await Promise.all([
      clusterStore.recordRateLimitFailure('login-ip', clientIp(req), MAX_IP_ATTEMPTS, WINDOW_MS, LOCK_MS),
      clusterStore.recordRateLimitFailure('login-user', username, MAX_USER_ATTEMPTS, WINDOW_MS, LOCK_MS),
    ]);
    return;
  }
  registerFailure(ipFails, clientIp(req), MAX_IP_ATTEMPTS);
  registerFailure(userFails, username, MAX_USER_ATTEMPTS);
  if (ipFails.size > 10000 || userFails.size > 10000) {
    const now = Date.now();
    for (const m of [ipFails, userFails]) for (const [k, v] of m) if (now - v.windowStart > WINDOW_MS + LOCK_MS) m.delete(k);
  }
}
async function recordSuccess(req, username) {
  if (CLUSTER_ENABLED) {
    await Promise.all([
      clusterStore.clearRateLimit('login-ip', clientIp(req)),
      clusterStore.clearRateLimit('login-user', username),
    ]);
    return;
  }
  ipFails.delete(clientIp(req));
  userFails.delete(username);
}

// ---------- session ----------
function makeToken(user, previous) {
  const now = Math.floor(Date.now() / 1000);
  const nonce = previous && typeof previous.n === 'string' && previous.n
    ? previous.n
    : crypto.randomBytes(8).toString('hex');
  const payload = { u: user, v: pwdVersion(user), iat: now, exp: now + SESSION_TTL, n: nonce };
  const b = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return b + '.' + hmac(b);
}
function verifyToken(tok, diagnostic) {
  const fail = (reason) => { if (diagnostic) diagnostic.reason = reason; return null; };
  if (!tok || typeof tok !== 'string') return fail('missing-cookie');
  const i = tok.lastIndexOf('.');
  if (i <= 0) return fail('invalid-format');
  const b = tok.slice(0, i);
  const sig = tok.slice(i + 1);
  if (!timingSafeStr(hmac(b), sig)) return fail('invalid-signature');
  let p;
  try { p = JSON.parse(Buffer.from(b, 'base64url').toString('utf8')); } catch (e) { return fail('invalid-payload'); }
  if (!p || typeof p.exp !== 'number') return fail('invalid-payload');
  if (diagnostic && typeof p.u === 'string') diagnostic.user = p.u;
  if (Date.now() / 1000 > p.exp) return fail('expired');
  if (diagnostic) diagnostic.reason = 'verified';
  return p;
}
function parseCookies(req) {
  const h = req.headers.cookie;
  const out = {};
  if (!h) return out;
  for (const part of String(h).split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    const k = part.slice(0, eq).trim();
    const v = part.slice(eq + 1).trim();
    if (k) { try { out[k] = decodeURIComponent(v); } catch (e) { out[k] = v; } }
  }
  return out;
}
function getSession(req) {
  const diagnostic = { reason: 'missing-cookie', user: null };
  req.__dshSessionDiagnostic = diagnostic;
  const c = parseCookies(req);
  const tok = c[COOKIE_NAME];
  if (!tok) return null;
  diagnostic.fingerprint = crypto.createHash('sha256').update(tok).digest('hex').slice(0, 12);
  const p = verifyToken(tok, diagnostic);
  if (!p || !p.u) return null;
  if (p.n && revokedSessionNonces.has(p.n)) { diagnostic.reason = 'revoked-nonce'; return null; }
  if (!getUser(p.u)) { diagnostic.reason = 'unknown-user'; return null; }
  // Reject tokens minted before the current password generation. Tokens
  // without a generation number are pre-migration relics: they must not
  // outlive a password reset either.
  const currentVersion = pwdVersion(p.u);
  if ((p.v || 0) !== currentVersion) {
    diagnostic.reason = 'password-version';
    diagnostic.tokenVersion = p.v || 0;
    diagnostic.currentVersion = currentVersion;
    return null;
  }
  diagnostic.reason = 'valid';
  return p;
}

const rejectedSessionLogs = new Map();
function logRejectedSession(req) {
  const diagnostic = req.__dshSessionDiagnostic;
  if (!diagnostic || diagnostic.reason === 'missing-cookie' || diagnostic.reason === 'valid') return;
  const now = Date.now();
  const key = `${diagnostic.fingerprint || 'none'}:${diagnostic.reason}`;
  if (now - (rejectedSessionLogs.get(key) || 0) < 60000) return;
  rejectedSessionLogs.set(key, now);
  if (rejectedSessionLogs.size > 5000) {
    for (const [entry, at] of rejectedSessionLogs) if (now - at > 3600000) rejectedSessionLogs.delete(entry);
  }
  const versions = diagnostic.reason === 'password-version'
    ? ` tokenVersion=${diagnostic.tokenVersion} currentVersion=${diagnostic.currentVersion}` : '';
  console.warn(`${new Date().toISOString()} ${clientIp(req)} session-rejected reason=${diagnostic.reason}`
    + ` user=${diagnostic.user || '-'} token=${diagnostic.fingerprint || '-'}${versions}`);
}
function cookieHeader(name, value, opts) {
  let s = name + '=' + value;
  if (opts.maxAge !== undefined) s += '; Max-Age=' + opts.maxAge;
  if (opts.path) s += '; Path=' + opts.path;
  s += '; HttpOnly';
  if (COOKIE_SECURE) s += '; Secure';
  s += '; SameSite=' + (opts.sameSite || 'Lax');
  return s;
}
function sessionNeedsRefresh(session) {
  if (SESSION_REFRESH_INTERVAL <= 0) return false;
  // Tokens issued before sliding renewal carried no iat. Refresh a still-valid
  // legacy token on its first successful presence heartbeat.
  if (typeof session.iat !== 'number') return true;
  return Math.floor(Date.now() / 1000) - session.iat >= SESSION_REFRESH_INTERVAL;
}
function setSession(res, user, previous) {
  res.setHeader('Set-Cookie', cookieHeader(COOKIE_NAME, makeToken(user, previous), { maxAge: SESSION_TTL, path: '/' }));
}
function clearSession(res) {
  res.setHeader('Set-Cookie', cookieHeader(COOKIE_NAME, '', { maxAge: 0, path: '/' }));
}

function ticketKey(ticket) {
  return crypto.createHash('sha256').update(ticket).digest('base64url');
}
function cleanLoginTickets(now) {
  for (const [key, value] of loginTickets) {
    if (!value || value.expiresAt <= now) loginTickets.delete(key);
  }
}
async function issueLoginTicket(user, returnTo) {
  if (CLUSTER_ENABLED) {
    const result = await clusterStore.issueLoginTicket(user, returnTo, LOGIN_TICKET_TTL, LOGIN_TICKET_MAX);
    return result.ticket;
  }
  const now = Date.now();
  cleanLoginTickets(now);
  if (loginTickets.size >= LOGIN_TICKET_MAX) return null;
  const ticket = crypto.randomBytes(32).toString('base64url');
  loginTickets.set(ticketKey(ticket), {
    user: user,
    returnTo: returnTo,
    expiresAt: now + LOGIN_TICKET_TTL * 1000,
  });
  return ticket;
}
async function consumeLoginTicket(ticket) {
  if (!ticket || typeof ticket !== 'string' || ticket.length > 256) return null;
  if (CLUSTER_ENABLED) return clusterStore.consumeLoginTicket(ticket);
  const key = ticketKey(ticket);
  const value = loginTickets.get(key);
  // Delete before checking/using it, so concurrent requests cannot replay it.
  loginTickets.delete(key);
  if (!value || value.expiresAt <= Date.now()) return null;
  return value;
}
function safeReturnTo(value) {
  if (value === undefined || value === null || value === '') return '/';
  if (typeof value !== 'string' || value.length > 2048) return null;
  try {
    const base = new URL('http://dsh.invalid/');
    const parsed = new URL(value, base);
    if (parsed.origin !== base.origin || value[0] !== '/' || value.startsWith('//')) return null;
    return parsed.pathname + parsed.search + parsed.hash;
  } catch (e) {
    return null;
  }
}
function loginDestination(user, requested) {
  if (!hasKey(user)) return '/setup';
  return requested || '/';
}

// ---------- security headers (gateway-origin pages) ----------
function secHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Content-Security-Policy', "default-src 'none'; connect-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; form-action 'self'; base-uri 'none'");
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
}

// ---------- body reader ----------
function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) { reject(new Error('payload too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}
// Raw binary body reader (uploads); rejects past the limit.
function readBodyBuf(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) { reject(new Error('payload too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}
function parseForm(body) {
  const out = {};
  for (const pair of body.split('&')) {
    if (!pair) continue;
    const eq = pair.indexOf('=');
    const k = eq < 0 ? pair : pair.slice(0, eq);
    const v = eq < 0 ? '' : pair.slice(eq + 1);
    try { out[decodeURIComponent(k.replace(/\+/g, ' '))] = decodeURIComponent(v.replace(/\+/g, ' ')); }
    catch (e) {}
  }
  return out;
}

// ---------- key validation against DeepSeek ----------
function validateKey(key, timeoutMs) {
  return new Promise((resolve) => {
    let u;
    try { u = new url.URL(DEEPSEEK_BASE_URL); } catch (e) { return resolve({ ok: true, warning: '基础 URL 无效，已跳过校验' }); }
    const opts = {
      hostname: u.hostname,
      port: u.port || 443,
      path: '/models',
      method: 'GET',
      headers: { 'Authorization': 'Bearer ' + key, 'Accept': 'application/json' },
      timeout: timeoutMs,
    };
    const req = https.request(opts, (res) => {
      res.resume();
      res.on('end', () => {
        if (res.statusCode === 200) resolve({ ok: true });
        else if (res.statusCode === 401 || res.statusCode === 403) resolve({ ok: false, detail: 'DeepSeek 拒绝了该 Key（' + res.statusCode + '）' });
        else resolve({ ok: true, warning: '验证接口返回 ' + res.statusCode + '，已保存但请确认 Key 有效' });
      });
    });
    req.on('timeout', () => { req.destroy(); resolve({ ok: true, warning: '验证超时，已保存；请稍后在应用中确认' }); });
    req.on('error', () => resolve({ ok: true, warning: '无法连接验证接口，已保存；请稍后在应用中确认' }));
  });
}

// ---------- HTML pages ----------
function htmlShell(title, bodyHtml) {
  return [
    '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    '<title>', title, ' · DeepSeek Harness</title>',
    '<style>',
    ':root{--bg:#0b0f17;--panel:#111726;--panel2:#161d2e;--text:#e6e9f0;--muted:#8a93a6;--accent:#3b82f6;--err:#f87171;--ok:#34d399;--border:#232b3d}',
    '*{box-sizing:border-box}body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"PingFang SC","Microsoft YaHei",sans-serif;background:radial-gradient(1200px 800px at 50% -10%,#16233b 0%,var(--bg) 55%);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}',
    '.card{width:100%;max-width:400px;background:var(--panel);border:1px solid var(--border);border-radius:16px;padding:36px 32px;box-shadow:0 20px 60px rgba(0,0,0,.45)}',
    '.brand{display:flex;align-items:center;gap:12px;margin-bottom:6px}.logo{width:38px;height:38px;border-radius:10px;background:linear-gradient(135deg,#2563eb,#7c3aed);display:flex;align-items:center;justify-content:center;font-weight:800;color:#fff;font-size:20px}',
    '.brand h1{font-size:20px;margin:0;font-weight:700}.brand .sub{font-size:12px;color:var(--muted)}',
    'p.lead{color:var(--muted);font-size:13.5px;margin:6px 0 22px;line-height:1.6}',
    'label{display:block;font-size:13px;color:var(--muted);margin:14px 0 6px}',
    'input{width:100%;background:var(--panel2);border:1px solid var(--border);border-radius:10px;color:var(--text);padding:12px 14px;font-size:15px;outline:none}input:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(59,130,246,.18)}',
    'button{margin-top:22px;width:100%;background:linear-gradient(135deg,#2563eb,#7c3aed);border:0;border-radius:10px;color:#fff;font-size:15px;font-weight:600;padding:12px;cursor:pointer}button:hover{filter:brightness(1.08)}button:disabled{opacity:.6;cursor:not-allowed}',
    '.msg{display:none;margin-top:16px;padding:11px 13px;border-radius:9px;font-size:13.5px;line-height:1.5}.msg.err{display:block;background:rgba(248,113,113,.12);color:var(--err);border:1px solid rgba(248,113,113,.25)}.msg.ok{display:block;background:rgba(52,211,153,.12);color:var(--ok);border:1px solid rgba(52,211,153,.25)}',
    '.hint{font-size:12.5px;color:var(--muted);margin-top:14px;line-height:1.6}',
    'code{background:var(--panel2);padding:2px 6px;border-radius:6px;font-size:12px}',
    '</style></head><body>',
    bodyHtml,
    '</body></html>',
  ].join('');
}

// Auth shell styled after the impeccable design reference: dark warm-black
// lacquer ground, kinpaku-gold accent, hairline gold rules, editorial type.
// Purposeful restraint: no gradients, no glassmorphism; visible focus rings
// and WCAG AA contrast throughout.
function impeccableShell(title, bodyHtml) {
  return [
    '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    '<title>', title, ' · DeepSeek Harness</title>',
    '<style>',
    ':root{--lacquer:#0b0a08;--panel:#131110;--panel2:#1a1714;--gold:#e2b961;--gold-hover:#ecc87c;--ink:#ece6da;--muted:#9b9184;--faint:#6f675c;--hairline:rgba(226,185,97,.16);--err:#e0877a;--errbg:rgba(224,135,122,.10);--ok:#9cc9ab;--okbg:rgba(156,201,171,.10)}',
    '*{box-sizing:border-box}',
    'body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"PingFang SC","Microsoft YaHei",sans-serif;background:radial-gradient(1100px 700px at 50% -8%,#181410 0%,var(--lacquer) 58%);color:var(--ink);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}',
    '.card{width:100%;max-width:400px;background:var(--panel);border:1px solid var(--hairline);border-radius:16px;padding:40px 34px;box-shadow:0 24px 80px rgba(0,0,0,.55)}',
    '.brand{display:flex;align-items:center;gap:13px;margin-bottom:8px}',
    '.logo{width:40px;height:40px;border-radius:11px;background:var(--gold);color:#171310;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:21px}',
    '.brand h1{font-size:20px;margin:0;font-weight:650;letter-spacing:.2px}',
    '.brand .sub{font-size:12px;color:var(--muted);margin-top:2px;letter-spacing:.4px}',
    'p.lead{color:var(--muted);font-size:13px;margin:10px 0 24px;line-height:1.65}',
    'label{display:block;font-size:12.5px;color:var(--muted);margin:16px 0 7px;letter-spacing:.3px}',
    'input{width:100%;background:var(--panel2);border:1px solid var(--hairline);border-radius:10px;color:var(--ink);padding:12px 14px;font-size:14.5px;outline:none}',
    'input:focus{border-color:var(--gold);box-shadow:0 0 0 3px rgba(226,185,97,.18)}',
    'button{margin-top:26px;width:100%;background:var(--gold);border:0;border-radius:10px;color:#171310;font-size:14.5px;font-weight:650;padding:12px;cursor:pointer;letter-spacing:.3px}',
    'button:hover{background:var(--gold-hover)}',
    'button:disabled{opacity:.55;cursor:not-allowed}',
    'button:focus-visible{outline:2px solid var(--gold);outline-offset:2px}',
    '.msg{display:none;margin-top:18px;padding:11px 13px;border-radius:9px;font-size:13px;line-height:1.5}',
    '.msg.err{display:block;background:var(--errbg);color:var(--err);border:1px solid rgba(224,135,122,.28)}',
    '.msg.ok{display:block;background:var(--okbg);color:var(--ok);border:1px solid rgba(156,201,171,.28)}',
    '.rule{height:1px;background:var(--hairline);margin:22px 0 14px}',
    '.hint{font-size:12.5px;color:var(--faint);line-height:1.7}',
    'code{background:var(--panel2);border:1px solid var(--hairline);padding:2px 6px;border-radius:6px;font-size:12px;color:var(--gold)}',
    '</style></head><body>',
    bodyHtml,
    '</body></html>',
  ].join('');
}

function loginPage(csrf, error, ok) {
  const errDiv = error ? '<div class="msg err" id="msg"></div>' : '<div class="msg" id="msg"></div>';
  const regLink = REGISTER_ENABLED
    ? '<div class="rule"></div><div class="hint">没有账号？<a href="/register" style="color:var(--gold);text-decoration:none">注册新账号</a></div>'
    : '';
  const body = [
    '<div class="card"><div class="brand"><div class="logo">D</div><div><h1>DeepSeek Harness</h1><div class="sub">登录控制台</div></div></div>',
    '<p class="lead">请输入你的账号与密码以继续。账号由服务器管理员创建。</p>',
    '<form id="f" method="post" action="/login" autocomplete="on">',
    '<input type="hidden" name="csrf" value="' + csrf + '">',
    '<label for="u">用户名</label><input id="u" name="username" type="text" autocomplete="username" required autofocus>',
    '<label for="p">密码</label><input id="p" name="password" type="password" autocomplete="current-password" required>',
    '<button type="submit" id="btn">登录</button>',
    '</form>', errDiv,
    '<div class="rule"></div>',
    '<div class="hint">忘记密码？请联系服务器管理员重置。</div>',
    regLink,
    '</div>',
    '<script>',
    'var m=document.getElementById("msg");',
    error ? 'm.className="msg err";m.textContent=' + JSON.stringify(error) + ';' : '',
    ok ? 'm.className="msg ok";m.textContent=' + JSON.stringify(ok) + ';' : '',
    'document.getElementById("f").addEventListener("submit",function(){var b=document.getElementById("btn");if(b){b.disabled=true;b.textContent="登录中…";}});',
    '</scr' + 'ipt>',
  ].join('');
  return impeccableShell('登录', body);
}

function registerPage(csrf, error) {
  const errDiv = error ? '<div class="msg err" id="msg"></div>' : '<div class="msg" id="msg"></div>';
  const body = [
    '<div class="card"><div class="brand"><div class="logo">D</div><div><h1>DeepSeek Harness</h1><div class="sub">注册新账号</div></div></div>',
    '<p class="lead">创建你的账号以使用 DeepSeek Harness。注册后即可登录并配置 API Key。</p>',
    '<form id="f" method="post" action="/register" autocomplete="on">',
    '<input type="hidden" name="csrf" value="' + csrf + '">',
    '<label for="u">用户名</label><input id="u" name="username" type="text" autocomplete="username" required autofocus>',
    '<label for="p">密码</label><input id="p" name="password" type="password" autocomplete="new-password" required>',
    '<label for="c">确认密码</label><input id="c" name="confirm" type="password" autocomplete="new-password" required>',
    '<button type="submit" id="btn">注册</button>',
    '</form>', errDiv,
    '<div class="rule"></div>',
    '<div class="hint">已有账号？<a href="/login" style="color:var(--gold);text-decoration:none">返回登录</a> · 密码至少 8 位。</div>',
    '</div>',
    '<script>',
    'var m=document.getElementById("msg");',
    error ? 'm.className="msg err";m.textContent=' + JSON.stringify(error) + ';' : '',
    'document.getElementById("f").addEventListener("submit",function(){var b=document.getElementById("btn");if(b){b.disabled=true;b.textContent="注册中…";}});',
    '</scr' + 'ipt>',
  ].join('');
  return impeccableShell('注册', body);
}

// Admin panel data. "online" is LIVE browser presence: at least one tab whose
// presence heartbeat is fresh (within PRESENCE_TTL_MS). Closing the tab sends
// a presence-close that removes it, so the panel flips to offline immediately
// instead of lingering on the coarse ACTIVE_WINDOW_MS last-request window.
// `lastActiveAt` keeps the last authenticated-request time for the offline
// display; users with no entry at all have never logged in.
function adminUsersPayload(processStats, statsError, realKeys, diskUsage, clusterState) {
  const db = loadUsers();
  const now = Date.now();
  const users = Object.keys(db.users || {}).sort().map((name) => {
    const u = db.users[name];
    const act = (clusterState && clusterState.activity.get(name)) || activeUsers.get(name);
    const process = processStats[name] || {};
    const tabs = tenantTabs.get(name);
    let liveTab = !!(clusterState && clusterState.online.has(name));
    if (!clusterState && tabs) {
      for (const value of tabs.values()) {
        if (value && now - value.at <= PRESENCE_TTL_MS) { liveTab = true; break; }
      }
    }
    return {
      name: name,
      admin: u.admin === true,
      online: liveTab,
      lastActiveAt: act ? act.at : null,
      port: u.port || null,
      // Real on-disk key status from the supervisor when available; the stored
      // flag is only a render fallback (e.g. control socket temporarily down).
      keyConfigured: realKeys && realKeys[name] !== undefined ? realKeys[name] : !!u.keyConfigured,
      created: u.created || null,
      dshRunning: process.running === true,
      processCount: Number(process.processCount || 0),
      rssBytes: Number(process.rssBytes || 0),
      diskBytes: diskUsage && diskUsage[name] !== undefined ? diskUsage[name] : null,
    };
  });
  return {
    ok: true,
    now: now,
    onlineCount: users.filter((x) => x.online).length,
    runningCount: users.filter((x) => x.dshRunning).length,
    totalRssBytes: users.reduce((sum, x) => sum + x.rssBytes, 0),
    statsError: statsError || null,
    users: users,
  };
}

function adminPage(csrf) {
  const body = [
    '<div class="card" style="max-width:1120px"><div class="brand"><div class="logo">A</div><div><h1>管理控制台</h1><div class="sub">DeepSeek Harness · 用户与资源</div></div></div>',
    '<section class="users"><div class="section-head"><div><h2>用户列表</h2><p class="last-updated" id="last-updated">上次更新：—</p></div><div class="section-actions"><button type="button" class="ghost" id="refresh">刷新用户</button><button type="button" class="ghost" id="toggle-users">折叠用户</button></div></div>',
    '<p class="lead" id="stat">尚未查询，请点击“刷新用户”。</p>',
    // Live DSH/process/RSS/disk columns are intentionally disabled: collecting
    // them used the login-critical control socket and synchronous `du` scans.
    // '<table id="tbl"><thead><tr><th>用户</th><th>登录状态</th><th>DSH</th><th>内存（RSS）</th><th>进程</th><th>存储</th><th>端口</th><th>最近活跃</th><th>API Key</th><th>创建时间</th><th>操作</th></tr></thead><tbody></tbody></table></section>',
    '<table id="tbl"><thead><tr><th>用户</th><th>登录状态</th><th>端口</th><th>最近活跃</th><th>API Key</th><th>创建时间</th><th>操作</th></tr></thead><tbody></tbody></table></section>',
    '<div class="rule"></div>',
    '<section class="plugins"><div class="section-head"><div><h2>共享插件</h2><p>安装一次并同步到所有现有及后续新增用户。</p></div><div class="section-actions"><button type="button" class="ghost" id="plugin-refresh">刷新插件</button><button type="button" class="ghost" id="toggle-plugins">折叠插件</button></div></div>',
    '<div class="plugin-form"><input id="plugin-spec" placeholder="插件 spec，例如 package@1.2.3"><input id="plugin-name" placeholder="package name（Git/file spec 时填写）"><button type="button" id="plugin-add">安装 / 升级</button></div>',
    '<div class="plugin-upload"><input id="plugin-tarball" type="file" accept=".tgz,application/gzip,application/x-gzip"><button type="button" id="plugin-upload">上传离线包并安装</button><span>仅接受 npm pack / pnpm pack 生成的 .tgz，上限 ' + PLUGIN_TARBALL_MAX_MB + ' MB</span></div>',
    '<div class="plugin-msg" id="plugin-msg"></div>',
    '<table id="plugin-table"><thead><tr><th>插件</th><th>版本</th><th>来源</th><th>路径</th><th>操作</th></tr></thead><tbody></tbody></table>',
    '<pre id="plugin-log" hidden></pre></section>',
    '<div class="rule"></div>',
    '<a href="/" class="ghost" style="display:inline-block;text-decoration:none;margin-left:0">返回工作区</a>',
    '<form method="post" action="/logout" style="display:inline;margin-left:10px"><input type="hidden" name="csrf" value="' + csrf + '"><button type="submit" class="ghost">退出登录</button></form>',
    '</div>',
    '<script>',
    'function esc(s){return String(s==null?"":s).replace(/[&<>"]/g,function(c){return{"&":"&amp;","<":"&lt;",">":"&gt;",\'"\':"&quot;"}[c];});}',
    'function fmt(ts){if(!ts)return "-";try{return new Date(ts).toLocaleString();}catch(e){return "-";}}',
    'function mem(n){n=Number(n||0);if(n<=0)return "—";if(n<1048576)return Math.round(n/1024)+" KB";if(n<1073741824)return (n/1048576).toFixed(1)+" MB";return (n/1073741824).toFixed(2)+" GB";}',
    'var USERS_CACHE_KEY="dsh-admin-users-v1",usersLoading=false;',
    'function markUsersStale(){var e=document.getElementById("last-updated");if(e&&e.textContent.indexOf("数据可能已变化")<0)e.textContent+=" · 数据可能已变化，请手动刷新";}',
    'function renderUsers(j,updatedAt,cached){',
    // Former live-resource summary (kept for easy restoration once metrics
    // move off the supervisor control socket):
    // 'document.getElementById("stat").textContent="在线用户："+j.onlineCount+" · 运行实例："+j.runningCount+" · 总内存："+mem(j.totalRssBytes)+" · 用户总数："+j.users.length+(j.statsError?" · 内存统计失败":"");',
    'document.getElementById("stat").textContent="在线用户："+j.onlineCount+" · 用户总数："+j.users.length;',
    'document.getElementById("last-updated").textContent="上次更新："+fmt(updatedAt)+(cached?"（本地缓存）":"");',
    'var tb=document.querySelector("#tbl tbody");tb.innerHTML="";',
    'j.users.forEach(function(u){var tr=document.createElement("tr");',
    'var st=u.online?"<span class=on>● 在线</span>":(u.lastActiveAt?"<span class=off>○ 离线</span>":"<span class=off>○ 从未活跃</span>");',
    // Former row with live resource fields:
    // 'tr.innerHTML="<td>"+esc(u.name)+(u.admin?" <span class=adm>管理员</span>":"")+"</td>"+"<td>"+st+"</td>"+"<td>"+(u.dshRunning?"<span class=on>运行中</span>":"<span class=off>休眠</span>")+"</td>"+"<td>"+mem(u.rssBytes)+"</td>"+"<td>"+u.processCount+"</td>"+"<td>"+mem(u.diskBytes)+"</td>"+"<td>"+(u.port!=null?u.port:"—")+"</td>"+"<td>"+fmt(u.lastActiveAt)+"</td>"+"<td>"+(u.keyConfigured?"已配置":"—")+"</td>"+"<td>"+fmt(u.created)+"</td>"+"<td><button type=\'button\' class=\'small danger\' data-kick=\'"+esc(u.name)+"\'>强制退出</button></td>";',
    'tr.innerHTML="<td>"+esc(u.name)+(u.admin?" <span class=adm>管理员</span>":"")+"</td>"+"<td>"+st+"</td>"+"<td>"+(u.port!=null?u.port:"—")+"</td>"+"<td>"+fmt(u.lastActiveAt)+"</td>"+"<td>"+(u.keyConfigured?"已配置":"—")+"</td>"+"<td>"+fmt(u.created)+"</td>"+"<td><button type=\'button\' class=\'small danger\' data-kick=\'"+esc(u.name)+"\'>强制退出</button></td>";',
    'tb.appendChild(tr);var kb=tr.querySelector("[data-kick]");if(kb)kb.addEventListener("click",function(){var n=this.getAttribute("data-kick");if(!window.confirm("强制退出用户 "+n+"？将杀掉该用户全部进程并使其会话立即失效。"))return;fetch("/__gw/admin/kick",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-DSH-Gateway-Action":"admin-kick"},body:JSON.stringify({name:n})}).then(function(r){return r.json().then(function(j){if(!r.ok||!j.ok)throw new Error(j.error||("HTTP "+r.status));});}).then(markUsersStale).catch(function(e){window.alert("强制退出失败："+e.message);});});});}',
    'function saveUsersCache(j,updatedAt){try{localStorage.setItem(USERS_CACHE_KEY,JSON.stringify({updatedAt:updatedAt,data:j}));}catch(e){}}',
    'function restoreUsersCache(){try{var raw=localStorage.getItem(USERS_CACHE_KEY);if(!raw)return;var cached=JSON.parse(raw);if(!cached||!cached.data||cached.data.ok!==true||!Array.isArray(cached.data.users))return;renderUsers(cached.data,Number(cached.updatedAt)||cached.data.now,true);}catch(e){}}',
    'function load(){if(usersLoading)return;usersLoading=true;var b=document.getElementById("refresh");b.disabled=true;b.textContent="查询中…";fetch("/__gw/admin/users",{credentials:"same-origin"}).then(function(r){return r.json().then(function(j){if(!r.ok||!j.ok)throw new Error(j.error||("HTTP "+r.status));return j;});}).then(function(j){var updatedAt=Number(j.now)||Date.now();renderUsers(j,updatedAt,false);saveUsersCache(j,updatedAt);}).catch(function(){document.getElementById("stat").textContent="查询失败，已保留上次加载的数据";}).then(function(){usersLoading=false;b.disabled=false;b.textContent="刷新用户";});}',
    'document.getElementById("refresh").addEventListener("click",load);',
    'document.getElementById("toggle-users").addEventListener("click",function(){var tb=document.getElementById("tbl"),hidden=tb.style.display==="none";tb.style.display=hidden?"":"none";this.textContent=hidden?"折叠用户":"展开用户";});',
    'var watchedJob=null,jobTimer=null;',
    'function pluginMessage(text,bad){var m=document.getElementById("plugin-msg");m.textContent=text||"";m.className="plugin-msg"+(bad?" bad":"");}',
    'function showCancelButton(){var c=document.getElementById("plugin-cancel");if(!c){c=document.createElement("button");c.type="button";c.id="plugin-cancel";c.className="small danger";c.textContent="取消操作";c.style.marginLeft="8px";var m=document.getElementById("plugin-msg");m.parentNode.insertBefore(c,m.nextSibling);c.addEventListener("click",function(){if(c.disabled)return;c.disabled=true;c.textContent="正在取消…";fetch("/__gw/admin/plugins/cancel",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-DSH-Gateway-Action":"admin-plugin"},body:"{}"}).then(function(r){return r.json().then(function(j){if(!r.ok||!j.ok)throw new Error(j.error||("HTTP "+r.status));});}).catch(function(e){c.disabled=false;c.textContent="取消操作";pluginMessage("取消失败："+e.message,true);});});}c.hidden=false;}',
    'function hideCancelButton(){var c=document.getElementById("plugin-cancel");if(c)c.hidden=true;}',
    'function watchJob(id){watchedJob=id;if(jobTimer)clearTimeout(jobTimer);fetch("/__gw/admin/plugin-job?id="+encodeURIComponent(id),{credentials:"same-origin"}).then(function(r){return r.json();}).then(function(j){if(!j.ok)throw new Error(j.error||"任务不存在");var job=j.job,log=document.getElementById("plugin-log");log.hidden=false;log.textContent=job.log||"等待输出…";log.scrollTop=log.scrollHeight;pluginMessage(job.status==="running"?"插件操作进行中…":(job.status==="success"?"操作完成":"操作失败："+(job.error||"未知错误")),job.status==="error");if(job.status==="running"){showCancelButton();jobTimer=setTimeout(function(){watchJob(id);},1000);}else{hideCancelButton();watchedJob=null;pluginLoad();markUsersStale();}}).catch(function(e){pluginMessage("任务查询失败："+e.message,true);});}',
    'function pluginRun(path,body){pluginMessage("正在提交操作…",false);fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-DSH-Gateway-Action":"admin-plugin"},body:JSON.stringify(body)}).then(function(r){return r.json().then(function(j){if(!r.ok||!j.ok)throw new Error(j.error||("HTTP "+r.status));return j;});}).then(function(j){watchJob(j.job.id);}).catch(function(e){pluginMessage(e.message,true);});}',
    'function pluginUpload(){var input=document.getElementById("plugin-tarball"),file=input.files&&input.files[0],button=document.getElementById("plugin-upload");if(!file){pluginMessage("请选择 .tgz 离线包",true);return;}button.disabled=true;button.textContent="上传中…";pluginMessage("正在上传 "+file.name+"…",false);fetch("/__gw/admin/plugins/upload",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/octet-stream","X-DSH-Gateway-Action":"admin-plugin"},body:file}).then(function(r){return r.json().then(function(j){if(!r.ok||!j.ok)throw new Error(j.error||("HTTP "+r.status));return j;});}).then(function(j){document.getElementById("plugin-spec").value=j.tarball.spec;document.getElementById("plugin-name").value=j.tarball.name;pluginMessage("上传完成，正在安装 "+j.tarball.name+"…",false);pluginRun("/__gw/admin/plugins/add",{spec:j.tarball.spec,name:j.tarball.name});input.value="";}).catch(function(e){pluginMessage("离线包上传失败："+e.message,true);}).then(function(){button.disabled=false;button.textContent="上传离线包并安装";});}',
    'function pluginLoad(){fetch("/__gw/admin/plugins",{credentials:"same-origin"}).then(function(r){return r.json();}).then(function(j){if(!j.ok)throw new Error(j.error||"加载失败");var tb=document.querySelector("#plugin-table tbody");tb.innerHTML="";j.plugins.forEach(function(p){var tr=document.createElement("tr"),name=document.createElement("td"),ver=document.createElement("td"),src=document.createElement("td"),dir=document.createElement("td"),act=document.createElement("td");name.textContent=p.name;ver.textContent=p.version||"—";src.textContent=p.source==="image"?"镜像内置":"运行时共享";dir.textContent=p.dir||"—";dir.title=p.dir||"";if(p.source==="image"){act.textContent="不可移除";}else{var b=document.createElement("button");b.type="button";b.className="small danger";b.textContent="移除";b.addEventListener("click",function(){if(window.confirm("从所有用户移除插件 "+p.name+"？"))pluginRun("/__gw/admin/plugins/remove",{name:p.name});});act.appendChild(b);}tr.append(name,ver,src,dir,act);tb.appendChild(tr);});if(j.activeJob&&j.activeJob.status==="running"&&!watchedJob)watchJob(j.activeJob.id);}).catch(function(e){pluginMessage("插件列表加载失败："+e.message,true);});}',
    'document.getElementById("plugin-add").addEventListener("click",function(){var spec=document.getElementById("plugin-spec").value.trim(),name=document.getElementById("plugin-name").value.trim();if(!spec){pluginMessage("请输入插件 spec",true);return;}pluginRun("/__gw/admin/plugins/add",{spec:spec,name:name});});',
    'document.getElementById("plugin-upload").addEventListener("click",pluginUpload);',
    'document.getElementById("plugin-refresh").addEventListener("click",pluginLoad);',
    'document.getElementById("toggle-plugins").addEventListener("click",function(){var tb=document.getElementById("plugin-table"),hidden=tb.style.display==="none";tb.style.display=hidden?"":"none";this.textContent=hidden?"折叠插件":"展开插件";});',
    'restoreUsersCache();',
    'pluginLoad();',
    '</scr' + 'ipt>',
    '<style>',
    'table{width:100%;border-collapse:collapse;font-size:13px}',
    'th,td{text-align:left;padding:10px;border-bottom:1px solid var(--hairline);color:var(--ink)}',
    'th{color:var(--muted);font-weight:600;letter-spacing:.3px;font-size:12px}',
    '.on{color:var(--ok)}.off{color:var(--faint)}',
    '.adm{color:var(--gold);font-size:11px;border:1px solid var(--hairline);padding:1px 6px;border-radius:6px;margin-left:6px}',
    '.ghost{background:transparent;border:1px solid var(--hairline);border-radius:9px;color:var(--gold);padding:9px 18px;font-size:13px;font-weight:600;cursor:pointer;width:auto;margin-top:0}',
    '.ghost:hover{background:rgba(226,185,97,.08)}',
    '.users h2,.plugins h2{font-size:16px;margin:0;color:var(--ink)}.plugins p,.last-updated{font-size:12.5px;color:var(--faint);margin:4px 0 0}',
    '.section-head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:12px}',
    '.section-actions{display:flex;align-items:center;gap:10px}',
    '.plugin-form{display:grid;grid-template-columns:minmax(260px,2fr) minmax(200px,1fr) auto;gap:8px;align-items:center}',
    '.plugin-form input{margin:0;padding:9px 11px;font-size:13px}.plugin-form button{width:auto;margin:0;padding:9px 16px}',
    '.plugin-upload{display:flex;align-items:center;gap:8px;margin-top:10px}.plugin-upload input{flex:1;margin:0;padding:8px 10px;font-size:12px}.plugin-upload button{width:auto;margin:0;padding:9px 16px}.plugin-upload span{color:var(--faint);font-size:11.5px}',
    '.plugin-msg{min-height:20px;margin:8px 0;color:var(--ok);font-size:12.5px}.plugin-msg.bad{color:var(--err)}',
    '#plugin-table td:nth-child(4){max-width:310px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}',
    '.small{width:auto;margin:0;padding:5px 11px;border-radius:8px;font-size:12px}.small.danger{background:transparent;color:var(--err);border:1px solid rgba(224,135,122,.4)}',
    '#plugin-log{max-height:260px;overflow:auto;background:#111827;color:#d1fae5;border-radius:10px;padding:12px;font:12px/1.55 var(--ds-font-family-code,monospace);white-space:pre-wrap;margin:10px 0 0}',
    '@media(max-width:800px){.plugin-form{grid-template-columns:1fr}.card{overflow-x:auto}}',
    '</style>',
    TENANT_LIFECYCLE_SCRIPT,
  ].join('');
  return impeccableShell('管理控制台', body);
}

function setupPage(csrf, error, warning) {
  const msgDiv = error ? '<div class="msg err" id="msg"></div>' : '<div class="msg" id="msg"></div>';
  const body = [
    '<div class="card"><div class="brand"><div class="logo">D</div><div><h1>DeepSeek Harness</h1><div class="sub">API Key 配置</div></div></div>',
    '<p class="lead">你的账户尚未配置 DeepSeek API Key。请粘贴你的 Key 以启用 AI 功能。</p>',
    '<form id="f" method="post" action="/setup" autocomplete="off">',
    '<input type="hidden" name="csrf" value="' + csrf + '">',
    '<label for="k">DeepSeek API Key</label><input id="k" name="key" type="password" autocomplete="off" placeholder="sk-..." required>',
    '<button type="submit" id="btn">保存并继续</button>',
    '</form>', msgDiv,
    '<div class="rule"></div>',
    '<div class="hint">可在 <code>platform.deepseek.com</code> → API Keys 创建 Key。Key 仅保存在你的私有目录中，仅你本人可用。</div>',
    '<button type="button" id="logout" style="background:transparent;border:1px solid var(--hairline);color:var(--faint)">退出登录</button>',
    '</div>',
    '<script>',
    'var m=document.getElementById("msg");',
    error ? 'm.className="msg err";m.textContent=' + JSON.stringify(error) + ';' : '',
    warning ? 'm.className="msg ok";m.textContent=' + JSON.stringify(warning) + ';' : '',
    'document.getElementById("f").addEventListener("submit",function(){var b=document.getElementById("btn");if(b){b.disabled=true;b.textContent="保存中…";}});',
    'document.getElementById("logout").addEventListener("click",function(){window.__DSH_GATEWAY_LOGOUT__(this);});',
    '</scr' + 'ipt>', TENANT_LIFECYCLE_SCRIPT,
  ].join('');
  return impeccableShell('配置 API Key', body);
}

function json(res, code, obj) {
  secHeaders(res);
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(obj));
}
function redirect(res, loc) {
  res.writeHead(302, { Location: loc, 'Cache-Control': 'no-store' });
  res.end();
}

// ---------- async sudo helper wrappers ----------
// All helper invocations use async spawn so a slow runuser call can never
// block the event loop (the old execFileSync stalled EVERY user's traffic
// for the duration of a listing/upload).
function runHelper(args, opts) {
  return new Promise((resolve) => {
    const o = Object.assign({ timeoutMs: 15000, maxStdout: 8 * 1024 * 1024, maxStderr: 8 * 1024 * 1024 }, opts || {});
    let child;
    try {
      const direct = process.env.DSH_HELPER_DIRECT === '1';
      child = spawn(direct ? args[0] : 'sudo', direct ? args.slice(1) : ['-n'].concat(args), {
        stdio: o.input !== undefined ? ['pipe', 'pipe', 'pipe'] : ['ignore', 'pipe', 'pipe'],
      });
    } catch (e) { return resolve({ code: null, stdout: '', stderr: String(e && e.message || e) }); }
    if (typeof o.onSpawn === 'function') o.onSpawn(child);
    let out = [];
    let outLen = 0;
    let err = [];
    let errLen = 0;
    let done = false;
    const timer = setTimeout(() => { try { child.kill('SIGKILL'); } catch (e) {} }, o.timeoutMs);
    const finish = (code) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      resolve({ code: code, stdout: Buffer.concat(out).toString('utf8'), stderr: Buffer.concat(err).toString('utf8') });
    };
    child.stdout.on('data', (c) => {
      outLen += c.length;
      if (outLen <= o.maxStdout) out.push(c);
      if (typeof o.onStdout === 'function') o.onStdout(c.toString('utf8'));
    });
    child.stderr.on('data', (c) => {
      errLen += c.length;
      if (errLen <= o.maxStderr) err.push(c);
      if (typeof o.onStderr === 'function') o.onStderr(c.toString('utf8'));
    });
    child.on('error', () => finish(null));
    child.on('close', (code) => finish(code));
    if (o.input !== undefined) {
      child.stdin.on('error', () => {});
      child.stdin.end(o.input);
    }
  });
}

function validUploadName(name) {
  return !!name && name.length <= 200 && name.indexOf('\0') < 0
    && !/[\/\\]/.test(name) && name !== '.' && name !== '..' && !name.startsWith('.')
    && !/[\x00-\x1f\x7f]/.test(name);
}

// Stream one raw HTTP request body through the privilege-dropping upload
// helper. Both browser and machine APIs use this exact path so size,
// completeness and workspace-containment guarantees cannot drift apart.
function saveUploadRequest(req, home, dirAbs, name) {
  const limit = UPLOAD_MAX_MB * 1024 * 1024;
  const contentLength = parseInt(req.headers['content-length'] || '', 10);
  if (!Number.isFinite(contentLength) || contentLength < 0) {
    return Promise.resolve({ ok: false, status: 411, detail: '缺少 Content-Length' });
  }
  if (contentLength > limit) {
    return Promise.resolve({ ok: false, status: 413, detail: '文件过大（上限 ' + UPLOAD_MAX_MB + ' MB）' });
  }
  return new Promise((resolve) => {
    let child;
    try {
      const direct = process.env.DSH_HELPER_DIRECT === '1';
      child = spawn(direct ? UPLOAD_HELPER : 'sudo', direct ? [home, dirAbs, name] : ['-n', UPLOAD_HELPER, home, dirAbs, name], { stdio: ['pipe', 'ignore', 'pipe'] });
    } catch (error) {
      return resolve({ ok: false, status: 500, detail: '写入失败：' + String(error && error.message || error) });
    }
    let stderr = '';
    let done = false;
    let over = false;
    let timedOut = false;
    let aborted = false;
    let reqEnded = false;
    let paused = false;
    let size = 0;
    const finish = (code) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try { child.stdin.destroy(); } catch (error) {}
      if (over) return resolve({ ok: false, status: 413, detail: '文件过大（上限 ' + UPLOAD_MAX_MB + ' MB）' });
      if (timedOut) return resolve({ ok: false, status: 504, detail: '上传超时' });
      if (aborted) return resolve({ ok: false, status: 400, detail: '上传中断' });
      if (code === 0) return resolve({ ok: true, status: 201, detail: '' });
      if (code === 2) return resolve({ ok: false, status: 400, detail: '文件名不合法' });
      if (code === 3) return resolve({ ok: false, status: 403, detail: '目标目录超出用户工作区' });
      if (code === 4) return resolve({ ok: false, status: 404, detail: '目标目录不存在' });
      if (code === 5) return resolve({ ok: false, status: 413, detail: '文件过大' });
      if (code === 6) return resolve({ ok: false, status: 400, detail: '上传中断（数据不完整）' });
      const firstError = stderr && stderr.split('\n')[0];
      return resolve({ ok: false, status: 500, detail: '写入失败：' + (firstError || '未知错误') });
    };
    const timer = setTimeout(() => { timedOut = true; try { child.kill('SIGKILL'); } catch (error) {} }, 600000);
    child.stderr.on('data', (chunk) => { stderr += chunk.toString('utf8'); });
    child.on('error', () => finish(null));
    child.on('close', (code) => finish(code));
    child.stdin.on('error', () => {});
    try { child.stdin.write('BYTES ' + contentLength + '\n'); } catch (error) {}
    req.on('data', (chunk) => {
      if (done || over) return;
      size += chunk.length;
      if (size > limit) {
        over = true;
        try { child.kill('SIGKILL'); } catch (error) {}
        finish(null);
        req.resume();
        return;
      }
      let writable = true;
      try { writable = child.stdin.write(chunk); } catch (error) { writable = false; }
      if (!writable && !paused) { paused = true; req.pause(); }
    });
    child.stdin.on('drain', () => { if (paused && !done && !over) { paused = false; req.resume(); } });
    req.on('end', () => { reqEnded = true; if (!done && !over) { try { child.stdin.end(); } catch (error) {} } });
    req.on('error', () => { if (!done) { aborted = true; try { child.kill('SIGKILL'); } catch (error) {} finish(null); } });
    req.on('close', () => { if (!done && !reqEnded) { aborted = true; try { child.kill('SIGKILL'); } catch (error) {} finish(null); } });
  });
}

async function fetchTenantProcessStats() {
  const r = await runHelper([REGISTER_HELPER, '--stats', CONTROL_SOCKET], {
    timeoutMs: 15000,
    maxStdout: 1024 * 1024,
  });
  let reply = null;
  try { reply = JSON.parse(r.stdout); } catch (e) {}
  if (r.code !== 0 || !reply || reply.ok !== true || !reply.result) {
    throw new Error((reply && reply.error) || String(r.stderr || '').trim() || 'process stats failed');
  }
  return reply.result;
}

// Real per-user API-key status straight from the supervisor's on-disk check
// (the gateway service account has no access into the 0700 user homes). The
// supervisor reads each user's .credentials.yaml for a non-empty *_API_KEY
// entry, so the panel never trusts the possibly SKIP_KEY_SETUP-stamped
// users.json flag. Returns null when the control socket is unavailable, in
// which case the caller falls back to the stored flag.
async function fetchRealKeyStatus() {
  try {
    const r = await runHelper([REGISTER_HELPER, '--key-status-all', CONTROL_SOCKET], {
      timeoutMs: 20000,
      maxStdout: 256 * 1024,
    });
    let reply = null;
    try { reply = JSON.parse(r.stdout); } catch (e) {}
    if (r.code !== 0 || !reply || reply.ok !== true || !reply.result) return null;
    return reply.result;
  } catch (e) { return null; }
}

// Per-user home disk usage from the supervisor's cached `du` scan (the gateway
// service account cannot read the 0700 user homes). Null when unavailable.
async function fetchDiskUsage() {
  try {
    const r = await runHelper([REGISTER_HELPER, '--du', CONTROL_SOCKET], {
      timeoutMs: 30000,
      maxStdout: 256 * 1024,
    });
    let reply = null;
    try { reply = JSON.parse(r.stdout); } catch (e) {}
    if (r.code !== 0 || !reply || reply.ok !== true || !reply.result) return null;
    return reply.result;
  } catch (e) { return null; }
}

function validPluginPackageName(value) {
  return typeof value === 'string' && /^(?:@[A-Za-z0-9._-]+\/)?[A-Za-z0-9._-]+$/.test(value);
}

function inferPluginPackageName(spec) {
  if (typeof spec !== 'string' || !spec) return null;
  if (spec.startsWith('@')) {
    const slash = spec.indexOf('/');
    if (slash < 2) return null;
    const versionAt = spec.indexOf('@', slash);
    const name = versionAt < 0 ? spec : spec.slice(0, versionAt);
    return validPluginPackageName(name) ? name : null;
  }
  const versionAt = spec.indexOf('@');
  const name = versionAt < 0 ? spec : spec.slice(0, versionAt);
  return validPluginPackageName(name) ? name : null;
}

function readPluginTarballManifest(file) {
  return new Promise((resolve, reject) => {
    const child = spawn('/usr/bin/tar', ['-xOzf', file, 'package/package.json'], {
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const stdout = [];
    const stderr = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let settled = false;
    const timer = setTimeout(() => { try { child.kill('SIGKILL'); } catch (e) {} }, 10000);
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) reject(error); else resolve(value);
    };
    child.stdout.on('data', (chunk) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes <= 256 * 1024) stdout.push(chunk);
      else { try { child.kill('SIGKILL'); } catch (e) {} }
    });
    child.stderr.on('data', (chunk) => {
      stderrBytes += chunk.length;
      if (stderrBytes <= 64 * 1024) stderr.push(chunk);
    });
    child.once('error', (error) => finish(error));
    child.once('close', (code, signal) => {
      if (stdoutBytes > 256 * 1024) return finish(new Error('plugin package.json is too large'));
      if (code !== 0) {
        const detail = Buffer.concat(stderr).toString('utf8').trim();
        return finish(new Error(detail || `invalid plugin tarball (code=${code}, signal=${signal || 'none'})`));
      }
      let manifest;
      try { manifest = JSON.parse(Buffer.concat(stdout).toString('utf8')); } catch (error) {
        return finish(new Error('plugin tarball has an invalid package.json'));
      }
      const name = manifest && manifest.name;
      if (!validPluginPackageName(name)) return finish(new Error('plugin tarball has an invalid package name'));
      if (!manifest.dsh || !manifest.dsh.bundle || typeof manifest.dsh.bundle.patch !== 'string') {
        return finish(new Error(`${name} does not declare dsh.bundle.patch`));
      }
      return finish(null, {
        name,
        version: typeof manifest.version === 'string' ? manifest.version : null,
      });
    });
  });
}

async function storePluginTarball(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 2 || buffer[0] !== 0x1f || buffer[1] !== 0x8b) {
    throw new Error('只接受 npm pack / pnpm pack 生成的 .tgz 文件');
  }
  await fs.promises.mkdir(PLUGIN_TARBALL_DIR, { recursive: true, mode: 0o700 });
  await fs.promises.chmod(PLUGIN_TARBALL_DIR, 0o700);
  const digest = crypto.createHash('sha256').update(buffer).digest('hex');
  const finalFile = path.join(PLUGIN_TARBALL_DIR, `${digest}.tgz`);
  const temporary = path.join(PLUGIN_TARBALL_DIR, `.upload-${process.pid}-${crypto.randomBytes(8).toString('hex')}`);
  try {
    await fs.promises.writeFile(temporary, buffer, { mode: 0o600, flag: 'wx' });
    const manifest = await readPluginTarballManifest(temporary);
    await fs.promises.rename(temporary, finalFile);
    await fs.promises.chmod(finalFile, 0o600);
    return {
      ...manifest,
      bytes: buffer.length,
      sha256: digest,
      spec: `file:${finalFile}`,
    };
  } catch (error) {
    try { await fs.promises.unlink(temporary); } catch (cleanupError) {}
    throw error;
  }
}

async function fetchSharedPluginList() {
  const r = await runHelper([REGISTER_HELPER, '--plugin-list', CONTROL_SOCKET], {
    timeoutMs: 15000,
    maxStdout: 1024 * 1024,
  });
  let reply = null;
  try { reply = JSON.parse(r.stdout); } catch (e) {}
  if (r.code !== 0 || !reply || reply.ok !== true || !Array.isArray(reply.result)) {
    throw new Error((reply && reply.error) || String(r.stderr || '').trim() || 'plugin list failed');
  }
  return reply.result;
}

const pluginJobs = new Map();
let activePluginJobId = null;
function appendPluginJobLog(job, text) {
  job.log = (job.log + String(text || '')).slice(-256 * 1024);
}

function startPluginJob(action, name, spec) {
  if (activePluginJobId) {
    const active = pluginJobs.get(activePluginJobId);
    if (active && active.status === 'running') throw new Error('另一个插件操作仍在运行');
  }
  const id = crypto.randomBytes(12).toString('hex');
  const job = {
    id,
    action,
    name,
    spec: spec || null,
    status: 'running',
    startedAt: Date.now(),
    finishedAt: null,
    log: '',
    result: null,
    error: null,
    _child: null, // runHelper child, kept so the admin cancel can kill it
  };
  pluginJobs.set(id, job);
  activePluginJobId = id;
  while (pluginJobs.size > 20) pluginJobs.delete(pluginJobs.keys().next().value);
  const args = action === 'add'
    ? [REGISTER_HELPER, '--plugin-add', name, spec, CONTROL_SOCKET]
    : [REGISTER_HELPER, '--plugin-remove', name, CONTROL_SOCKET];
  appendPluginJobLog(job, `${action === 'add' ? '安装' : '移除'} ${spec || name}\n`);
  runHelper(args, {
    timeoutMs: 1800000,
    maxStdout: 1024 * 1024,
    maxStderr: 1024 * 1024,
    onStderr: (chunk) => { appendPluginJobLog(job, chunk); },
    onSpawn: (child) => { job._child = child; },
  }).then((r) => {
    let reply = null;
    try { reply = JSON.parse(r.stdout); } catch (e) {}
    if (r.code !== 0 || !reply || reply.ok !== true) {
      throw new Error((reply && reply.error) || String(r.stderr || '').trim() || 'plugin operation failed');
    }
    job.status = 'success';
    job.result = reply.result;
    appendPluginJobLog(job, '\n操作完成。\n');
  }).catch((error) => {
    job.status = 'error';
    job.error = error.message;
    appendPluginJobLog(job, `\n错误：${error.message}\n`);
  }).finally(() => {
    job.finishedAt = Date.now();
    if (activePluginJobId === id) activePluginJobId = null;
  });
  return job;
}

function publicPluginJob(job) {
  return job && {
    id: job.id,
    action: job.action,
    name: job.name,
    spec: job.spec,
    status: job.status,
    startedAt: job.startedAt,
    finishedAt: job.finishedAt,
    log: job.log,
    result: job.result,
    error: job.error,
  };
}

// Tenant DSH processes are lazy: successful authentication wakes the user's
// instance through the root-only supervisor. Cache readiness for this gateway
// lifetime and coalesce concurrent browser/API/WebSocket requests so one user
// can never spawn duplicate processes.
const readyTenants = new Map(); // username -> { marker, owner, checkedAt }
const wakingTenants = new Map();
const stoppingTenants = new Map();
function ensureTenantInstance(name) {
  const record = getUser(name);
  if (!record || !record.port) return Promise.reject(new Error('user has no tenant instance'));
  const marker = String(record.port) + ':' + String(record.created || '');
  const cached = readyTenants.get(name);
  if (cached && cached.marker === marker && (!CLUSTER_ENABLED || Date.now() - cached.checkedAt < 2000)) {
    return Promise.resolve(cached.owner);
  }
  if (wakingTenants.has(name)) return wakingTenants.get(name);
  const wake = (async () => {
    const r = await runHelper([REGISTER_HELPER, '--wake', name, CONTROL_SOCKET], {
      timeoutMs: 130000,
      maxStdout: 64 * 1024,
    });
    let reply = null;
    try { reply = JSON.parse(r.stdout); } catch (e) {}
    if (r.code !== 0 || !reply || reply.ok !== true) {
      throw new Error((reply && reply.error) || String(r.stderr || '').trim() || 'tenant startup failed');
    }
    const raw = reply.result || {};
    const owner = raw.owner ? {
      local: raw.local !== false,
      nodeId: raw.owner.nodeId,
      address: raw.owner.address,
      gatewayPort: Number(raw.owner.gatewayPort || PORT),
      generation: Number(raw.owner.generation || 0),
      tenantPort: Number(raw.port || record.port),
    } : {
      local: true,
      nodeId: clusterStore.nodeId,
      address: clusterStore.nodeAddress,
      gatewayPort: PORT,
      generation: 0,
      tenantPort: record.port,
    };
    readyTenants.set(name, { marker, owner, checkedAt: Date.now() });
    return owner;
  })();
  wakingTenants.set(name, wake);
  return wake.finally(() => wakingTenants.delete(name));
}

function stopTenantInstance(name, reason, revokeSessions = false) {
  const existing = stoppingTenants.get(name);
  if (existing) {
    // A manual logout/admin action must be allowed to strengthen an already
    // running automatic sleep into a session-revoking stop.
    if (revokeSessions && !existing.revokeSessions) {
      return existing.promise.then(() => stopTenantInstance(name, reason, true));
    }
    return existing.promise;
  }
  const operation = (async () => {
    let reply;
    const owner = CLUSTER_ENABLED ? await clusterStore.getTenantOwner(name) : null;
    if (owner && !owner.local) {
      reply = await peerTenantControl(owner, {
        action: 'sleep',
        name,
        reason: reason || 'browser-idle',
        revokeSessions,
      });
    } else {
      const r = await runHelper([
        REGISTER_HELPER,
        '--sleep',
        name,
        CONTROL_SOCKET,
        reason || 'browser-idle',
        revokeSessions ? '1' : '0',
      ], {
        timeoutMs: 150000,
        maxStdout: 64 * 1024,
      });
      try { reply = JSON.parse(r.stdout); } catch (e) {}
      if (r.code !== 0 || !reply || reply.ok !== true) {
        throw new Error((reply && reply.error) || String(r.stderr || '').trim() || 'tenant stop failed');
      }
    }
    readyTenants.delete(name);
    usersCacheAt = 0;
    return reply.result;
  })();
  const entry = { revokeSessions, promise: null };
  entry.promise = operation.finally(() => {
    if (stoppingTenants.get(name) === entry) stoppingTenants.delete(name);
  });
  stoppingTenants.set(name, entry);
  return entry.promise;
}

function peerTenantControl(owner, payload) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify(payload);
    const request = http.request({
      host: owner.nodeAddress,
      port: owner.gatewayPort,
      method: 'POST',
      path: '/__gw/internal/tenant-control',
      headers: {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(body),
        'x-dsh-cluster-token': CLUSTER_TOKEN,
      },
    }, (response) => {
      let raw = '';
      response.setEncoding('utf8');
      response.on('data', (chunk) => { if (raw.length < 65536) raw += chunk; });
      response.on('end', () => {
        let reply;
        try { reply = JSON.parse(raw); } catch (error) {}
        if ((response.statusCode || 500) >= 200 && (response.statusCode || 500) < 300 && reply && reply.ok === true) resolve(reply);
        else reject(new Error((reply && reply.error) || `cluster owner returned HTTP ${response.statusCode}`));
      });
    });
    request.setTimeout(150000, () => request.destroy(new Error('cluster owner control timeout')));
    request.once('error', reject);
    request.end(body);
  });
}

// Browser presence drives automatic process recycling. pagehide/sendBeacon
// handles normal tab closes quickly; heartbeat expiry handles crashes, force
// quits and lost networks. A short zero-tab grace avoids stopping/restarting
// DSH during reloads. Multiple tabs and devices are coalesced per user.
const PRESENCE_HEARTBEAT_MS = 10000;
const PRESENCE_TTL_MS = Math.max(30000, Number(process.env.DSH_BROWSER_PRESENCE_TTL_MS || '86400000'));
const PRESENCE_STOP_GRACE_MS = Math.max(1000, Number(process.env.DSH_BROWSER_STOP_GRACE_MS || '5000'));
const tenantTabs = new Map();       // user -> Map(tabId -> { at, nonce })
const presenceNonces = new Map();   // user -> Set(session nonce)
const pendingPresenceStops = new Map();
const revokedSessionNonces = new Map(); // nonce -> token expiry epoch ms

function revokePresenceSessions(user) {
  const nonces = presenceNonces.get(user);
  if (!nonces) return;
  const expiresAt = Date.now() + SESSION_TTL * 1000;
  for (const nonce of nonces) revokedSessionNonces.set(nonce, expiresAt);
  presenceNonces.delete(user);
}

function cancelPresenceStop(user) {
  const timer = pendingPresenceStops.get(user);
  if (timer) clearTimeout(timer);
  pendingPresenceStops.delete(user);
}

function schedulePresenceStop(user, reason) {
  if (pendingPresenceStops.has(user)) return;
  const timer = setTimeout(async () => {
    pendingPresenceStops.delete(user);
    const tabs = tenantTabs.get(user);
    if (tabs && tabs.size > 0) return;
    tenantTabs.delete(user);
    // Keep the activity entry: the session cookie may still be valid, and the
    // entry decays to "offline" on its own after ACTIVE_WINDOW_MS. Deleting it
    // would mislabel a previously active user as "从未活跃".
    try {
      // Browser presence owns only tenant process lifetime. It must not own
      // authentication lifetime: background timer throttling, suspend/resume,
      // reloads and temporary network loss can all make a healthy tab miss
      // heartbeats. Preserve the signed session so the next request can wake
      // the tenant again without forcing the user through login.
      await stopTenantInstance(user, reason || 'browser-close', false);
      console.log(`tenant-presence stopped ${user} (${reason || 'browser-close'})`);
    } catch (error) {
      console.error(`tenant-presence stop failed ${user}: ${error.message}`);
    }
  }, PRESENCE_STOP_GRACE_MS);
  timer.unref();
  pendingPresenceStops.set(user, timer);
}

function updateTenantPresence(session, tabId, event) {
  const user = session.u;
  if (CLUSTER_ENABLED) {
    clusterStore.updatePresence(user, tabId, String(session.n || ''), event).catch((error) => {
      console.error(`cluster presence update failed for ${user}: ${error.message}`);
    });
  }
  let tabs = tenantTabs.get(user);
  if (!tabs) { tabs = new Map(); tenantTabs.set(user, tabs); }
  let nonces = presenceNonces.get(user);
  if (!nonces) { nonces = new Set(); presenceNonces.set(user, nonces); }
  nonces.add(String(session.n || ''));
  if (event === 'close') {
    const existing = tabs.get(tabId);
    if (!existing || existing.nonce === session.n) tabs.delete(tabId);
    if (tabs.size === 0) schedulePresenceStop(user, 'browser-close');
    return;
  }
  tabs.set(tabId, { at: Date.now(), nonce: session.n });
  cancelPresenceStop(user);
}

const presenceSweep = setInterval(() => {
  const now = Date.now();
  for (const [user, tabs] of tenantTabs) {
    for (const [tabId, value] of tabs) {
      if (!value || now - value.at > PRESENCE_TTL_MS) tabs.delete(tabId);
    }
    if (tabs.size === 0) schedulePresenceStop(user, 'browser-heartbeat-timeout');
  }
  for (const [nonce, expiresAt] of revokedSessionNonces) {
    if (expiresAt <= now) revokedSessionNonces.delete(nonce);
  }
}, Math.min(10000, Math.max(2000, Math.floor(PRESENCE_TTL_MS / 3))));
presenceSweep.unref();

// ---------- user file browser & download (deliverables) ----------
// User homes are 0700 owned by their dsh-<name> account; userctl grants the
// gateway service account an ACL (u:ubuntu:rX + default) so this authenticated
// web layer can list and download the files agents produce.
const DL_MIME = {
  '.txt': 'text/plain; charset=utf-8', '.md': 'text/plain; charset=utf-8',
  '.json': 'application/json; charset=utf-8', '.csv': 'text/csv; charset=utf-8',
  '.log': 'text/plain; charset=utf-8', '.html': 'text/plain; charset=utf-8',
  '.js': 'text/plain; charset=utf-8', '.css': 'text/plain; charset=utf-8',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg', '.gif': 'image/gif', '.webp': 'image/webp',
  '.pdf': 'application/pdf', '.zip': 'application/zip',
  '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
};
function dlContentType(name) { return DL_MIME[path.extname(String(name)).toLowerCase()] || 'application/octet-stream'; }
function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}
function fmtSize(n) {
  if (!Number.isFinite(n) || n < 0) return '';
  if (n < 1024) return n + ' B';
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
  if (n < 1024 * 1024 * 1024) return (n / 1024 / 1024).toFixed(1) + ' MB';
  return (n / 1024 / 1024 / 1024).toFixed(2) + ' GB';
}
function userHome(user) {
  const u = getUser(user);
  return (u && u.home) || path.join(USERS_DIR, user);
}

// In-page file-management widget injected into the SPA shell. Its trigger is
// cloned from the composer permission selector and placed immediately to its
// right, so it follows the native chip and narrow-composer behavior exactly.
// The restrained white drawer embeds /__gw/files?embed=1 for browsing,
// downloads and uploads; no page navigation, and ESC/backdrop/postMessage all
// close it. No backdrop blur or gradient chrome.

// Trusted-gateway marker + crypto.randomUUID shim injected into every proxied
// HTML page, BEFORE the
// SPA bundle: browsers only expose Crypto.randomUUID() in secure contexts
// (HTTPS or localhost), so plain-HTTP LAN access (http://192.168.x.x) leaves
// it undefined and the DSH web client throws "crypto.randomUUID is not a
// function" when creating messages / the events.mux RPC downlink. This
// runtime fallback (getRandomValues-based UUID v4) restores it for insecure
// origins. The marker tells the patched DSH client that this authenticated
// gateway owns the privileged Host RPC boundary, so LAN/domain browsers use
// the Host settings mirror instead of the intentionally unavailable in-memory
// fallback. Server-side session, Host and Origin checks remain authoritative.
const BROWSER_BOOTSTRAP = '<script>(function(){window.__DSH_TRUSTED_GATEWAY__=true;if(!window.crypto||typeof window.crypto.randomUUID==="function")return;function u(){var b=window.crypto.getRandomValues(new Uint8Array(16));b[6]=(b[6]&15)|64;b[8]=(b[8]&63)|128;var h="";for(var i=0;i<16;i++){if(i===4||i===6||i===8||i===10)h+="-";h+=(b[i]<16?"0":"")+b[i].toString(16);}return h;}try{Object.defineProperty(window.crypto,"randomUUID",{value:u,configurable:true,writable:true});}catch(e){window.crypto.randomUUID=u;}})();</script>';
const ADMIN_BROWSER_BOOTSTRAP = '<script>window.__DSH_GATEWAY_ADMIN__=true;</script>';

const TENANT_LIFECYCLE_SCRIPT = [
  '<script>(function(){',
  'if(window.__DSH_GATEWAY_LIFECYCLE__)return;window.__DSH_GATEWAY_LIFECYCLE__=true;',
  'var tabId=(window.crypto&&typeof window.crypto.randomUUID==="function")?window.crypto.randomUUID():(Date.now().toString(36)+Math.random().toString(36).slice(2));',
  'var presenceTimer=null,loggingOut=false;',
  'function presence(event,closing){var body="tab="+encodeURIComponent(tabId)+"&event="+encodeURIComponent(event);if(closing&&navigator.sendBeacon){try{return navigator.sendBeacon("/__gw/presence",body);}catch(e){}}fetch("/__gw/presence",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:body,keepalive:!!closing}).catch(function(){});}',
  'function startPresence(){presence("open",false);if(presenceTimer)clearInterval(presenceTimer);presenceTimer=setInterval(function(){presence("heartbeat",false);},' + PRESENCE_HEARTBEAT_MS + ');}',
  'startPresence();',
  'window.addEventListener("pageshow",function(e){if(e.persisted)startPresence();});',
  'window.addEventListener("pagehide",function(e){if(loggingOut||e.persisted)return;if(presenceTimer)clearInterval(presenceTimer);presence("close",true);});',
  'document.addEventListener("visibilitychange",function(){if(!document.hidden)presence("heartbeat",false);});',
  'window.__DSH_GATEWAY_LOGOUT__=function(button){if(loggingOut)return;if(!window.confirm("退出登录并停止当前用户的全部运行进程？用户文件不会删除。"))return;loggingOut=true;if(button){button.disabled=true;button.textContent="正在退出…";}if(presenceTimer)clearInterval(presenceTimer);fetch("/logout",{method:"POST",credentials:"same-origin",headers:{"X-DSH-Gateway-Action":"logout"}}).then(function(r){if(!r.ok)throw new Error("HTTP "+r.status);window.location.replace("/login");}).catch(function(e){loggingOut=false;if(button){button.disabled=false;button.textContent="⏻ 退出登录";}window.alert("退出失败："+e.message);});};',
  '})();</scr' + 'ipt>',
].join('');

const FILES_LINK_HTML = [
  '<style>',
  '.dshgw-ov{display:none;position:fixed;inset:0;z-index:2147483100;background:rgba(16,24,40,.45);align-items:center;justify-content:center;padding:24px}',
  '.dshgw-ov.open{display:flex}',
  '.dshgw-panel{position:relative;width:min(900px,100%);height:min(82vh,760px);background:#fcfcfd;border:1px solid #e2e8f0;border-radius:16px;box-shadow:0 1px 2px rgba(16,24,40,.06),0 8px 24px rgba(16,24,40,.12),0 32px 80px rgba(16,24,40,.18);overflow:hidden;display:flex;flex-direction:column;opacity:0;transform:translateY(10px) scale(.985);transition:opacity .18s ease,transform .18s ease}',
  '.dshgw-ov.open .dshgw-panel{opacity:1;transform:none}',
  '.dshgw-x{position:absolute;top:10px;right:10px;z-index:2;width:32px;height:32px;border-radius:10px;border:0;background:#f1f5f9;color:#475569;font:500 18px/1 -apple-system,"Segoe UI",sans-serif;cursor:pointer;display:flex;align-items:center;justify-content:center}',
  '.dshgw-x:hover{background:#e2e8f0;color:#0f172a}',
  '.dshgw-x:focus-visible{outline:2px solid #2563eb;outline-offset:2px}',
  '.dshgw-frame{flex:1;width:100%;border:0;background:#fcfcfd}',
  '@media (prefers-reduced-motion: reduce){.dshgw-panel{transition:none}}',
  '</style>',
  '<div class="dshgw-ov" id="dshgw-ov-files" role="dialog" aria-modal="true" aria-label="文件管理">',
  '  <div class="dshgw-panel">',
  '    <button class="dshgw-x" type="button" aria-label="关闭">&#215;</button>',
  '    <iframe class="dshgw-frame" title="文件管理" src="about:blank"></iframe>',
  '  </div>',
  '</div>',
  '<script>',
  '(function(){',
  'var ov=document.getElementById("dshgw-ov-files");',
  'var frame=ov.querySelector("iframe");',
  'var loaded=false;',
  'function open(){if(!loaded){frame.src="/__gw/files?embed=1";loaded=true;}ov.classList.add("open");ov.querySelector(".dshgw-x").focus();}',
  'function shutAll(){ov.classList.remove("open");}',
  'var x=ov.querySelector(".dshgw-x");x.addEventListener("click",shutAll);ov.addEventListener("click",function(e){if(e.target===ov)shutAll();});',
  'document.addEventListener("keydown",function(e){if(e.key==="Escape")shutAll();});',
  'window.addEventListener("message",function(e){if(e.data==="dshgw-close")shutAll();if(e.data==="dshgw-open-files")open();});',
  'var folderIcon="<path d=\\"M1.75 4.25h4l1.25 1.5h7.25v6.5H1.75z\\" stroke=\\"currentColor\\" stroke-width=\\"1.3\\" stroke-linejoin=\\"round\\"/><path d=\\"M1.75 4.25V3h3.5l1 1.25\\" stroke=\\"currentColor\\" stroke-width=\\"1.3\\" stroke-linejoin=\\"round\\"/>";',
  'function cloneSidebarAction(settings,id,label,title,iconMarkup,onClick,popup){var button=settings.cloneNode(true);button.id=id;button.setAttribute("aria-label",label);button.setAttribute("title",title);button.removeAttribute("aria-expanded");if(popup)button.setAttribute("aria-haspopup","dialog");else button.removeAttribute("aria-haspopup");button.querySelectorAll("[data-slot]").forEach(function(node){node.removeAttribute("data-slot");});var icon=button.querySelector("svg");if(icon){while(icon.firstChild)icon.removeChild(icon.firstChild);icon.setAttribute("viewBox","0 0 16 16");icon.setAttribute("fill","none");icon.setAttribute("aria-hidden","true");icon.innerHTML=iconMarkup;}var labels=button.querySelectorAll("span");if(labels.length)labels[labels.length-1].textContent=label;button.addEventListener("click",function(){onClick(button);});return button;}',
  'function syncSidebarActions(){',
  'var slot=document.querySelector("[data-slot=\\"sidebar.settings\\"]"),settings=slot&&slot.querySelector("button"),area=slot&&slot.parentElement,foot=area&&area.parentElement;if(!settings||!area||!foot)return;',
  'var wide=!!settings.querySelector("span"),signature=String(settings.className)+"|"+(wide?"wide":"rail"),adminRequired=window.__DSH_GATEWAY_ADMIN__===true;',
  'var staleFiles=document.getElementById("dshgw-sidebar-files"),admin=document.getElementById("dshgw-sidebar-admin"),logout=document.getElementById("dshgw-sidebar-logout");if(staleFiles)staleFiles.remove();',
  'var ordered=logout&&logout.parentElement===foot&&logout.nextElementSibling===area;',
  'if(adminRequired)ordered=ordered&&admin&&admin.parentElement===foot&&admin.nextElementSibling===logout;else ordered=ordered&&!admin;',
  'if(ordered&&logout.getAttribute("data-signature")===signature&&(!adminRequired||admin.getAttribute("data-signature")===signature))return;',
  'if(admin)admin.remove();if(logout)logout.remove();',
  'var adminIcon="<path d=\\"M2 13.5h12M3.25 13.5V6.25h9.5v7.25M5.5 6.25V3.5h5v2.75M6 9h1.25M8.75 9H10M6 11.25h1.25M8.75 11.25H10\\" stroke=\\"currentColor\\" stroke-width=\\"1.2\\" stroke-linecap=\\"round\\" stroke-linejoin=\\"round\\"/>";',
  'var powerIcon="<path d=\\"M8 1.5v6\\" stroke=\\"currentColor\\" stroke-width=\\"1.4\\" stroke-linecap=\\"round\\"/><path d=\\"M4.25 3.5a5.25 5.25 0 1 0 7.5 0\\" stroke=\\"currentColor\\" stroke-width=\\"1.4\\" stroke-linecap=\\"round\\"/>";',
  'if(adminRequired){admin=cloneSidebarAction(settings,"dshgw-sidebar-admin","管理后台","打开用户与资源管理后台",adminIcon,function(){window.location.href="/__gw/admin";},false);admin.setAttribute("data-signature",signature);foot.insertBefore(admin,area);}',
  'logout=cloneSidebarAction(settings,"dshgw-sidebar-logout","退出登录","退出登录并停止当前用户的全部进程",powerIcon,function(button){window.__DSH_GATEWAY_LOGOUT__(button);},false);logout.setAttribute("data-signature",signature);foot.insertBefore(logout,area);',
  '}',
  'function findPermissionButton(){var direct=document.querySelector("button[aria-label^=\\"访问模式\\"],button[aria-label^=\\"Access mode\\"]");if(direct)return direct;var launchers=document.querySelectorAll("button[aria-haspopup=\\"listbox\\"]");for(var i=0;i<launchers.length;i++){var modes=launchers[i].nextElementSibling;if(!modes)continue;var candidate=modes.querySelector("button");if(candidate)return candidate;}return null;}',
  'function syncComposerFileAction(){',
  'var existing=document.getElementById("dshgw-composer-files"),permission=findPermissionButton();if(!permission){if(existing)existing.remove();return;}var anchor=permission.parentElement,target=anchor&&anchor.parentElement;if(!anchor||!target)return;var signature=String(permission.className)+"|"+String(anchor.className);if(existing&&existing.parentElement===target&&anchor.nextElementSibling===existing&&existing.getAttribute("data-signature")===signature)return;if(existing)existing.remove();var wrapper=anchor.cloneNode(false),button=permission.cloneNode(true);wrapper.id="dshgw-composer-files";wrapper.setAttribute("data-signature",signature);button.removeAttribute("disabled");button.removeAttribute("aria-expanded");button.removeAttribute("aria-controls");button.setAttribute("aria-haspopup","dialog");button.setAttribute("aria-label","文件管理");button.setAttribute("title","浏览、上传、下载和管理当前工作区文件");var labels=Array.prototype.filter.call(button.querySelectorAll("span"),function(node){return !node.hasAttribute("aria-hidden");});if(labels.length)labels[0].textContent="文件管理";var hidden=button.querySelectorAll("span[aria-hidden=\\"true\\"]");if(hidden.length){var icon=hidden[0].querySelector("svg");if(icon){while(icon.firstChild)icon.removeChild(icon.firstChild);icon.setAttribute("viewBox","0 0 16 16");icon.setAttribute("fill","none");icon.innerHTML=folderIcon;}for(var i=1;i<hidden.length;i++)hidden[i].remove();}button.addEventListener("click",open);wrapper.appendChild(button);target.insertBefore(wrapper,anchor.nextSibling);',
  '}',
  'syncSidebarActions();syncComposerFileAction();',
  'var mo=new MutationObserver(function(){syncSidebarActions();syncComposerFileAction();});',
  'mo.observe(document.documentElement,{subtree:true,childList:true,attributes:true,attributeFilter:["class","style"]});',
  '})();',
  '</scr' + 'ipt>',
].join('');

// Recoverable error page for the /__gw/files embed: a bare JSON 403/404 would
// leave the popup iframe on a dead page with no way back until the whole app
// refreshes. This page offers 回到工作区 (re-list the helper default, which is
// the workspace root) and 关闭 (close the drawer through the FAB's dshgw-close
// message).
function filesErrorPage(reason) {
  const back = '/__gw/files?embed=1';
  return [
    '<!doctype html><html lang="zh"><head><meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width,initial-scale=1">',
    '<title>文件管理</title>',
    '<style>',
    'body{background:#f6f8fa;color:#0f172a;font:14px/1.6 -apple-system,"Segoe UI",Roboto,"PingFang SC","Microsoft YaHei",sans-serif;margin:0;display:flex;align-items:center;justify-content:center;min-height:100vh}',
    '.card{max-width:440px;background:#fff;border:1px solid #e2e8f0;border-radius:14px;padding:26px 28px;box-shadow:0 1px 2px rgba(16,24,40,.05)}',
    'h1{font-size:16px;margin:0 0 10px}',
    'p{color:#475569;margin:0 0 18px}',
    '.row{display:flex;gap:10px;align-items:center}',
    'a.ghost{color:#2563eb;background:#fff;border:1px solid #bfdbfe;border-radius:10px;padding:8px 16px;text-decoration:none;font-weight:600}',
    'button{color:#64748b;background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:8px 16px;cursor:pointer;font:600 13px inherit}',
    '</style></head><body><div class="card">',
    '<h1>&#128193; 文件管理</h1>',
    '<p>' + esc(reason) + '</p>',
    '<div class="row"><a class="ghost" href="' + back + '">回到工作区</a>',
    '<button type="button" id="close">关闭</button></div>',
    '<scr' + 'ipt>document.getElementById("close").addEventListener("click",function(){if(window.parent!==window){try{parent.postMessage("dshgw-close","*");}catch(e){}}})</scr' + 'ipt>',
    '</div></body></html>',
  ].join('');
}

// ---------- reverse proxy ----------
const HOP = new Set(['connection', 'proxy-connection', 'keep-alive', 'transfer-encoding', 'te', 'trailer', 'upgrade', 'proxy-authorization', 'proxy-authenticate', 'content-length']);
function cleanHeaders(h) {
  const out = {};
  for (const k in h) {
    if (HOP.has(String(k).toLowerCase())) continue;
    out[k] = h[k];
  }
  return out;
}
// Rewrite the request so the per-user backend sees a loopback client. DSH pins
// privileged methods (settings/credentials/agentPreset/llm.discoverModels) to
// loopback-only; the gateway is the authenticated front door on the same host,
// so present Host=127.0.0.1:<port> and drop browser-trust markers.
function backendHeaders(req, port) {
  const headers = cleanHeaders(req.headers);
  delete headers['cookie'];
  delete headers['x-forwarded-for'];
  delete headers['x-forwarded-proto'];
  delete headers['x-forwarded-host'];
  headers['host'] = '127.0.0.1:' + port;
  delete headers['origin'];
  delete headers['referer'];
  delete headers['sec-fetch-site'];
  delete headers['sec-fetch-mode'];
  delete headers['sec-fetch-dest'];
  delete headers['sec-fetch-user'];
  headers['x-forwarded-for'] = clientIp(req);
  headers['x-forwarded-proto'] = 'https';
  return headers;
}
// ---------- current-workspace tracking ----------
// The SPA reports the active conversation through proxied RPCs: the gateway
// watches `sessions.history` (open) requests and `sessions.list` responses to
// remember each user's current cwd, so the deliverables drawers open there.
const CWD_STATE_FILE = process.env.CWD_STATE_FILE || '/opt/deepseek-harness/gateway/state-cwd.json';
const cwdTrack = new Map(); // user -> { currentId, idToCwd: Map, cwd, at }
try {
  const loaded = JSON.parse(fs.readFileSync(CWD_STATE_FILE, 'utf8'));
  for (const u of Object.keys(loaded || {})) {
    const e = loaded[u];
    if (e && typeof e.cwd === 'string') cwdTrack.set(u, { currentId: null, idToCwd: new Map(), cwd: e.cwd, at: e.at || 0 });
  }
} catch (e) {}
let cwdSaveTimer = null;
function scheduleCwdPersist() {
  if (cwdSaveTimer) return;
  cwdSaveTimer = setTimeout(() => {
    cwdSaveTimer = null;
    const out = {};
    for (const [u, e] of cwdTrack) if (e.cwd) out[u] = { cwd: e.cwd, at: e.at };
    try { fs.writeFileSync(CWD_STATE_FILE, JSON.stringify(out) + '\n', { mode: 0o600 }); } catch (e) {}
  }, 5000);
}
function rememberCurrentSession(user, sessionId) {
  let e = cwdTrack.get(user);
  if (!e) { e = { currentId: null, idToCwd: new Map(), cwd: null, at: 0 }; cwdTrack.set(user, e); }
  e.currentId = sessionId;
  const cwd = e.idToCwd.get(sessionId);
  if (cwd) { e.cwd = cwd; e.at = Date.now(); scheduleCwdPersist(); }
}
function feedSessionList(user, items) {
  if (!Array.isArray(items) || !user) return;
  let e = cwdTrack.get(user);
  if (!e) { e = { currentId: null, idToCwd: new Map(), cwd: null, at: 0 }; cwdTrack.set(user, e); }
  let newest = null;
  for (const it of items) {
    if (!it || typeof it.sessionId !== 'string') continue;
    if (typeof it.cwd === 'string' && it.cwd) e.idToCwd.set(it.sessionId, it.cwd);
    if (!newest || (typeof it.updatedAt === 'number' && (typeof newest.updatedAt !== 'number' || it.updatedAt > newest.updatedAt))) newest = it;
  }
  let resolved = null;
  if (e.currentId && e.idToCwd.has(e.currentId)) resolved = e.idToCwd.get(e.currentId);
  if (!resolved && newest && typeof newest.cwd === 'string' && newest.cwd) resolved = newest.cwd;
  if (resolved && resolved !== e.cwd) {
    e.cwd = resolved;
    e.at = Date.now();
    scheduleCwdPersist();
    console.log('cwd-track ' + user + ' -> ' + resolved);
  }
}
function currentCwd(user) {
  const e = cwdTrack.get(user);
  return (e && e.cwd) || null;
}

const HISTORY_MESSAGE_TYPES = new Set(['user/message', 'assistant/message']);
// Returns { events, hasMore } when the page was trimmed, otherwise null.
function trimHistoryValue(value) {
  if (!value || !Array.isArray(value.events) || value.events.length <= HISTORY_TRIM_MIN_EVENTS) return null;
  const events = value.events;
  for (const item of events) {
    if (!item || !item.event || typeof item.event.seq !== 'number') return null;
  }
  const kept = [];
  let count = 0;
  let trimmed = false;
  for (let i = events.length - 1; i >= 0; i--) {
    const ev = events[i].event;
    if (HISTORY_MESSAGE_TYPES.has(ev.type) && ev.surfaceOp === 'append') count++;
    if (count >= HISTORY_TRIM_MESSAGES) {
      const sources = (Array.isArray(ev.sourceEventSeqs) ? ev.sourceEventSeqs : []).filter((s) => typeof s === 'number');
      const groupStart = Math.min(ev.seq, ...sources);
      for (let j = i; j >= 0 && events[j].event.seq >= groupStart; j--) kept.push(events[j]);
      trimmed = true;
      break;
    }
    kept.push(events[i]);
  }
  if (!trimmed) return null;
  kept.reverse();
  return { events: kept, hasMore: true };
}
function gzipBodyIfWanted(req, upstreamHeaders, body) {
  const ae = String(req.headers['accept-encoding'] || '');
  if (/\bgzip\b/.test(ae) && !upstreamHeaders['content-encoding'] && body.length >= GZIP_MIN_BYTES) {
    try { return zlib.gzipSync(body, { level: 4 }); } catch (e) {}
  }
  return null;
}
function setGzipHeaders(h) {
  const out = Object.assign({}, h);
  delete out['content-length'];
  out['content-encoding'] = 'gzip';
  const v = String(out['vary'] || '');
  out['vary'] = v.indexOf('Accept-Encoding') >= 0 ? v : (v ? v + ', ' : '') + 'Accept-Encoding';
  return out;
}

function proxyRequest(req, res, port, user) {
  const headers = backendHeaders(req, port);
  const qIdx = req.url.indexOf('?');
  const reqPath = qIdx < 0 ? req.url : req.url.slice(0, qIdx);
  // DSH client RPC paths are singular: /api/session.list, /api/session.history.
  const sniffHistoryReq = req.method === 'POST' && reqPath === '/api/session.history' && !!user;
  const sniffHistoryRes = sniffHistoryReq;
  const sniffListRes = req.method === 'POST' && reqPath === '/api/session.list' && !!user;
  const upstreamReq = http.request({
    host: '127.0.0.1',
    port: port,
    method: req.method,
    path: req.url,
    headers: headers,
  }, (upstreamRes) => {
    const rh = cleanHeaders(upstreamRes.headers);
    const ct = String(upstreamRes.headers['content-type'] || '');
    // DEPLOYMENT PATCH (dsh-server-deployment): HTML must never be cached by
    // the browser — the SPA boot manifest (plugin revs) is regenerated on
    // instance restart, and a cached index.html would pin the browser to old
    // plugin bundles (stale UI after deployments). Force no-store on every
    // text/html response, overriding whatever the upstream set.
    if (ct.indexOf('text/html') === 0) rh['cache-control'] = 'no-store';
    const canInject = req.method === 'GET' && ct.indexOf('text/html') === 0 && !upstreamRes.headers['content-encoding'];
    const wantJsonGzip = /\bgzip\b/.test(String(req.headers['accept-encoding'] || '')) && !upstreamRes.headers['content-encoding'] && ct.indexOf('application/json') === 0;
    const needBuffer = canInject || sniffListRes || sniffHistoryRes;
    if (!needBuffer) {
      upstreamRes.on('error', () => {
        if (user) readyTenants.delete(user);
        try { res.destroy(); } catch (e) {}
      });
      if (wantJsonGzip) {
        const gz = zlib.createGzip({ level: 4 });
        gz.on('error', () => { try { res.destroy(); } catch (e) {} });
        res.writeHead(upstreamRes.statusCode || 502, setGzipHeaders(rh));
        upstreamRes.pipe(gz).pipe(res);
      } else {
        res.writeHead(upstreamRes.statusCode || 502, rh);
        upstreamRes.pipe(res);
      }
      return;
    }
    // Buffer small bodies: SPA HTML for injection, session lists for cwd
    // tracking, session history for page trimming. Oversized bodies fall
    // back to a plain untouched stream.
    const MAX_BUF = sniffHistoryRes ? HISTORY_BUF_MAX : 8 * 1024 * 1024;
    let buf = [];
    let size = 0;
    let settled = false;
    upstreamRes.on('data', (c) => {
      if (settled) return;
      size += c.length;
      if (size > MAX_BUF) {
        settled = true;
        res.writeHead(upstreamRes.statusCode || 502, rh);
        for (const b of buf) res.write(b);
        buf = [];
        upstreamRes.pipe(res);
      } else {
        buf.push(c);
      }
    });
    upstreamRes.on('end', () => {
      if (settled) return;
      settled = true;
      let body = Buffer.concat(buf);
      let outHeaders = rh;
      if (sniffListRes) {
        try {
          const j = JSON.parse(body.toString('utf8'));
          feedSessionList(user, j && j.result && j.result.value && j.result.value.items);
        } catch (e) {}
      } else if (sniffHistoryRes) {
        try {
          const j = JSON.parse(body.toString('utf8'));
          const v = j && j.result && j.result.value;
          const t = trimHistoryValue(v);
          if (t) {
            v.events = t.events;
            v.hasMore = t.hasMore;
            body = Buffer.from(JSON.stringify(j), 'utf8');
            console.log('history-trim ' + user + ' kept ' + t.events.length + ' events');
          }
        } catch (e) {}
      } else {
        let html = body.toString('utf8');
        const roleBootstrap = getUser(user)?.admin === true ? ADMIN_BROWSER_BOOTSTRAP : '';
        // UUID shim must run before the SPA bundle: inject right after the
        // opening <head> tag (the DSH client scripts are deferred modules),
        // falling back to the very top of the document when there is no head.
        const headAt = html.toLowerCase().indexOf('<head');
        if (headAt >= 0) {
          const headEnd = html.indexOf('>', headAt);
          html = html.slice(0, headEnd + 1) + BROWSER_BOOTSTRAP + roleBootstrap + TENANT_LIFECYCLE_SCRIPT + html.slice(headEnd + 1);
        } else {
          html = BROWSER_BOOTSTRAP + roleBootstrap + TENANT_LIFECYCLE_SCRIPT + html;
        }
        const at = html.toLowerCase().lastIndexOf('</body>');
        html = at >= 0 ? html.slice(0, at) + FILES_LINK_HTML + html.slice(at) : html + FILES_LINK_HTML;
        body = Buffer.from(html, 'utf8');
      }
      if (wantJsonGzip) {
        const gz = gzipBodyIfWanted(req, upstreamRes.headers, body);
        if (gz) { body = gz; outHeaders = setGzipHeaders(outHeaders); }
      }
      res.writeHead(upstreamRes.statusCode || 502, outHeaders);
      res.end(body);
    });
    upstreamRes.on('error', () => {
      if (user) readyTenants.delete(user);
      if (!settled) { settled = true; if (!res.headersSent) { try { res.writeHead(502, { 'Content-Type': 'text/plain; charset=utf-8' }); } catch (e) {} } }
      try { res.destroy(); } catch (e) {}
    });
    upstreamRes.on('aborted', () => { try { res.destroy(); } catch (e) {} });
  });
  upstreamReq.on('error', (e) => {
    if (user) readyTenants.delete(user);
    console.error('proxy error ->', port, e.message);
    if (!res.headersSent) res.writeHead(502, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Bad Gateway: 后端服务不可用');
  });
  req.on('error', () => upstreamReq.destroy());
  res.on('error', () => upstreamReq.destroy());
  res.on('close', () => { try { upstreamReq.destroy(); } catch (e) {} });
  if (sniffHistoryReq) {
    readBodyBuf(req, 256 * 1024).then((body) => {
      try {
        const j = JSON.parse(body.toString('utf8'));
        const sid = j && j.payload && j.payload.sessionId;
        if (typeof sid === 'string' && sid) rememberCurrentSession(user, sid);
      } catch (e) {}
      upstreamReq.write(body);
      upstreamReq.end();
    }).catch(() => { try { upstreamReq.destroy(); } catch (e) {} });
    return;
  }
  req.pipe(upstreamReq);
}
function proxyUpgrade(req, socket, head, port, user) {
  const headers = backendHeaders(req, port);
  const lines = [req.method + ' ' + req.url + ' HTTP/1.1'];
  for (const k in headers) {
    const v = headers[k];
    if (Array.isArray(v)) lines.push(k + ': ' + v.join(', '));
    else lines.push(k + ': ' + v);
  }
  lines.push('Connection: Upgrade');
  lines.push('Upgrade: websocket');
  lines.push('', '');
  const raw = lines.join('\r\n');
  const upstream = net.connect(port, '127.0.0.1', () => {
    upstream.write(raw);
    if (head && head.length) upstream.write(head);
    socket.pipe(upstream);
    upstream.pipe(socket);
  });
  upstream.on('error', () => {
    if (user) readyTenants.delete(user);
    socket.destroy();
  });
  socket.on('error', () => upstream.destroy());
  socket.on('close', () => upstream.destroy());
  upstream.on('close', () => socket.destroy());
}

function peerHeaders(req) {
  const headers = cleanHeaders(req.headers);
  delete headers['x-dsh-cluster-token'];
  delete headers['x-dsh-cluster-hop'];
  headers['x-dsh-cluster-token'] = CLUSTER_TOKEN;
  headers['x-dsh-cluster-hop'] = '1';
  headers['x-forwarded-for'] = clientIp(req);
  return headers;
}

function proxyPeerRequest(req, res, owner, user) {
  const upstreamReq = http.request({
    host: owner.address,
    port: owner.gatewayPort,
    method: req.method,
    path: req.url,
    headers: peerHeaders(req),
  }, (upstreamRes) => {
    upstreamRes.on('error', () => { try { res.destroy(); } catch (error) {} });
    res.writeHead(upstreamRes.statusCode || 502, cleanHeaders(upstreamRes.headers));
    upstreamRes.pipe(res);
  });
  upstreamReq.on('error', (error) => {
    readyTenants.delete(user);
    console.error(`cluster proxy error -> ${owner.nodeId}@${owner.address}:${owner.gatewayPort}: ${error.message}`);
    if (!res.headersSent) res.writeHead(503, { 'Content-Type': 'application/json; charset=utf-8', 'Retry-After': '2' });
    if (!res.writableEnded) res.end(JSON.stringify({ ok: false, error: '用户实例正在故障转移，请稍后重试' }));
  });
  req.on('error', () => upstreamReq.destroy());
  res.on('close', () => { try { upstreamReq.destroy(); } catch (error) {} });
  req.pipe(upstreamReq);
}

function proxyPeerUpgrade(req, socket, head, owner, user) {
  const headers = peerHeaders(req);
  const lines = [req.method + ' ' + req.url + ' HTTP/1.1'];
  for (const [key, value] of Object.entries(headers)) {
    if (Array.isArray(value)) lines.push(key + ': ' + value.join(', '));
    else if (value !== undefined) lines.push(key + ': ' + value);
  }
  lines.push('Connection: Upgrade', 'Upgrade: websocket', '', '');
  const upstream = net.connect(owner.gatewayPort, owner.address, () => {
    upstream.write(lines.join('\r\n'));
    if (head && head.length) upstream.write(head);
    socket.pipe(upstream);
    upstream.pipe(socket);
  });
  upstream.on('error', () => {
    readyTenants.delete(user);
    try { socket.write('HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n'); } catch (error) {}
    socket.destroy();
  });
  socket.on('error', () => upstream.destroy());
  socket.on('close', () => upstream.destroy());
  upstream.on('close', () => socket.destroy());
}

// ---------- request logging ----------
function logLine(req, status, extra) {
  // Login tickets are bearer credentials. Redact them even from local logs.
  const safeUrl = String(req.url || '').replace(/([?&]ticket=)[^&#]*/gi, '$1[redacted]');
  console.log(new Date().toISOString() + ' ' + clientIp(req) + ' ' + req.method + ' ' + safeUrl + ' ' + status + (extra ? ' ' + extra : ''));
}

// ---------- server ----------
// App-level static assets served without auth (identical across instances).
const STATIC_ASSETS = {
  '/manifest.webmanifest': { file: path.join(__dirname, 'static', 'manifest.webmanifest'), type: 'application/manifest+json' },
  '/favicon.svg': { file: path.join(__dirname, 'static', 'favicon.svg'), type: 'image/svg+xml' },
};

const server = http.createServer(async (req, res) => {
  const q = req.url.indexOf('?');
  const pathname = q < 0 ? req.url : req.url.slice(0, q);
  const session = getSession(req);
  if (!session) logRejectedSession(req);
  if (session) markActive(session.u, req);

  if (req.method === 'GET' && STATIC_ASSETS[pathname]) {
    const asset = STATIC_ASSETS[pathname];
    try {
      const data = fs.readFileSync(asset.file);
      res.writeHead(200, { 'Content-Type': asset.type, 'Cache-Control': 'no-cache' });
      return res.end(data);
    } catch (e) { /* fall through to normal handling */ }
  }

  if (pathname === '/__gw/health') {
    try {
      const users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
      if (!users || typeof users !== 'object' || !users.users || typeof users.users !== 'object') {
        throw new Error('invalid users store');
      }
      const cluster = await clusterStore.health();
      return json(res, 200, { ok: true, now: Date.now(), users: Object.keys(users.users).length, ...cluster });
    } catch (error) {
      return json(res, 503, { ok: false, error: 'gateway state unavailable' });
    }
  }

  if (pathname === '/__gw/internal/tenant-control') {
    if (!CLUSTER_ENABLED || req.method !== 'POST'
        || !timingSafeStr(String(req.headers['x-dsh-cluster-token'] || ''), CLUSTER_TOKEN)) {
      return json(res, 403, { ok: false, error: 'forbidden' });
    }
    let payload;
    try { payload = await readJsonBody(req, 8192); } catch (error) {
      return json(res, 400, { ok: false, error: 'invalid cluster control payload' });
    }
    if (!payload || payload.action !== 'sleep' || !/^[A-Za-z0-9_-]{1,64}$/.test(String(payload.name || ''))) {
      return json(res, 400, { ok: false, error: 'invalid cluster control operation' });
    }
    const r = await runHelper([
      REGISTER_HELPER,
      '--sleep',
      payload.name,
      CONTROL_SOCKET,
      String(payload.reason || 'cluster-control').slice(0, 64),
      payload.revokeSessions === true ? '1' : '0',
    ], { timeoutMs: 150000, maxStdout: 64 * 1024 });
    let reply;
    try { reply = JSON.parse(r.stdout); } catch (error) {}
    if (r.code !== 0 || !reply || reply.ok !== true) {
      return json(res, 500, { ok: false, error: (reply && reply.error) || String(r.stderr || '').trim() || 'tenant control failed' });
    }
    return json(res, 200, reply);
  }

  if (CLUSTER_ENABLED) {
    const peerHop = req.headers['x-dsh-cluster-hop'] === '1';
    if (req.headers['x-dsh-cluster-hop'] && (!peerHop || !timingSafeStr(String(req.headers['x-dsh-cluster-token'] || ''), CLUSTER_TOKEN))) {
      return json(res, 403, { ok: false, error: 'invalid cluster peer request' });
    }
    let routeUser = session && session.u;
    if (!routeUser && apiAuthorized(req)) {
      const match = /^\/api\/users\/([A-Za-z0-9_-]{1,64})(?:\/|$)/.exec(pathname);
      if (match) routeUser = match[1];
    }
    if (routeUser && pathname !== '/__gw/status') {
      try {
        const owner = await ensureTenantInstance(routeUser);
        if (owner && !owner.local) {
          if (peerHop) {
            readyTenants.delete(routeUser);
            return json(res, 503, { ok: false, error: 'tenant ownership changed during cluster routing' });
          }
          return proxyPeerRequest(req, res, owner, routeUser);
        }
      } catch (error) {
        logLine(req, 503, 'cluster-route-fail ' + routeUser + ' ' + String(error.message).slice(0, 160));
        return json(res, 503, { ok: false, error: '实例路由失败，请稍后重试：' + error.message });
      }
    }
  }

  if (pathname === '/__gw/status') {
    if (!session) return json(res, 401, {
      ok: false,
      user: null,
      reason: (req.__dshSessionDiagnostic && req.__dshSessionDiagnostic.reason) || 'unknown',
    });
    return json(res, 200, { ok: true, user: session.u, keyConfigured: hasKey(session.u) });
  }

  // ---------- admin panel (admin account only) ----------
  if (pathname === '/__gw/admin' || pathname === '/__gw/admin/users'
      || pathname === '/__gw/admin/plugins' || pathname === '/__gw/admin/plugin-job'
      || pathname === '/__gw/admin/plugins/add' || pathname === '/__gw/admin/plugins/remove'
      || pathname === '/__gw/admin/plugins/cancel' || pathname === '/__gw/admin/plugins/upload'
      || pathname === '/__gw/admin/kick') {
    const au = session && getUser(session.u);
    if (!session || !au || au.admin !== true) {
      if (req.method === 'GET') return redirect(res, '/login');
      return json(res, 403, { ok: false, error: '需要管理员权限' });
    }
    if (pathname === '/__gw/admin/users') {
      // Live user metrics are disabled because all three helpers share the
      // supervisor socket with login wake/sleep. In particular, synchronous
      // per-home `du` can prevent the supervisor from accepting connections
      // long enough for login to fail with connect EAGAIN/socket timeout.
      //
      // Kept for future restoration after metrics move to an async collector:
      // let stats = {};
      // let statsError = null;
      // try { stats = await fetchTenantProcessStats(); } catch (error) { statsError = error.message; }
      // const realKeys = await fetchRealKeyStatus();
      // const diskUsage = await fetchDiskUsage();
      const stats = {};
      const statsError = null;
      const realKeys = null; // adminUsersPayload falls back to users.json.keyConfigured
      const diskUsage = null;
      let clusterState = null;
      if (CLUSTER_ENABLED) {
        try { clusterState = await clusterStore.clusterUserState(PRESENCE_TTL_MS); } catch (error) { return json(res, 503, { ok: false, error: error.message }); }
      }
      return json(res, 200, adminUsersPayload(stats, statsError, realKeys, diskUsage, clusterState));
    }
    if (pathname === '/__gw/admin/plugins' && req.method === 'GET') {
      try {
        return json(res, 200, {
          ok: true,
          plugins: await fetchSharedPluginList(),
          activeJob: publicPluginJob(activePluginJobId && pluginJobs.get(activePluginJobId)),
        });
      } catch (error) {
        return json(res, 503, { ok: false, error: error.message });
      }
    }
    if (pathname === '/__gw/admin/plugin-job' && req.method === 'GET') {
      let id = '';
      try { id = new URL(req.url, 'http://gw').searchParams.get('id') || ''; } catch (e) {}
      const job = pluginJobs.get(id);
      if (!job) return json(res, 404, { ok: false, error: 'job not found' });
      return json(res, 200, { ok: true, job: publicPluginJob(job) });
    }
    if (pathname === '/__gw/admin/plugins/upload' && req.method === 'POST') {
      if (req.headers['x-dsh-gateway-action'] !== 'admin-plugin') {
        return json(res, 403, { ok: false, error: 'CSRF 校验失败' });
      }
      const limit = PLUGIN_TARBALL_MAX_MB * 1024 * 1024;
      const contentLength = Number(req.headers['content-length'] || 0);
      if (contentLength > limit) {
        return json(res, 413, { ok: false, error: `插件离线包过大（上限 ${PLUGIN_TARBALL_MAX_MB} MB）` });
      }
      let body;
      try { body = await readBodyBuf(req, limit); } catch (error) {
        return json(res, 413, { ok: false, error: `插件离线包过大（上限 ${PLUGIN_TARBALL_MAX_MB} MB）` });
      }
      try {
        const tarball = await storePluginTarball(body);
        logLine(req, 201, `admin-plugin-upload ${tarball.name} bytes=${tarball.bytes} sha256=${tarball.sha256}`);
        return json(res, 201, { ok: true, tarball });
      } catch (error) {
        return json(res, 400, { ok: false, error: error.message });
      }
    }
    if ((pathname === '/__gw/admin/plugins/add' || pathname === '/__gw/admin/plugins/remove') && req.method === 'POST') {
      if (req.headers['x-dsh-gateway-action'] !== 'admin-plugin') {
        return json(res, 403, { ok: false, error: 'CSRF 校验失败' });
      }
      let body;
      try { body = await readJsonBody(req, 4096); } catch (e) { return json(res, 400, { ok: false, error: 'invalid JSON' }); }
      try {
        let job;
        if (pathname.endsWith('/add')) {
          const spec = String(body.spec || '').trim();
          if (!spec || spec.length > 512 || spec.startsWith('-') || /[\r\n\0]/.test(spec)) {
            return json(res, 400, { ok: false, error: '插件 spec 无效' });
          }
          const name = String(body.name || '').trim() || inferPluginPackageName(spec);
          if (!validPluginPackageName(name)) {
            return json(res, 400, { ok: false, error: '无法推断包名，请填写 package name' });
          }
          job = startPluginJob('add', name, spec);
        } else {
          const name = String(body.name || '').trim();
          if (!validPluginPackageName(name)) return json(res, 400, { ok: false, error: '插件包名无效' });
          job = startPluginJob('remove', name, null);
        }
        return json(res, 202, { ok: true, job: publicPluginJob(job) });
      } catch (error) {
        return json(res, 409, { ok: false, error: error.message });
      }
    }
    if (pathname === '/__gw/admin/plugins/cancel' && req.method === 'POST') {
      if (req.headers['x-dsh-gateway-action'] !== 'admin-plugin') {
        return json(res, 403, { ok: false, error: 'CSRF 校验失败' });
      }
      try {
        // Tell the supervisor to kill the running shared-plugin command (its
        // pnpm tree), then force-kill this gateway's own helper child as a
        // fallback when the supervisor is unreachable. The job settles as an
        // error ("plugin operation canceled") on the next watchJob poll.
        const r = await runHelper([REGISTER_HELPER, '--plugin-cancel', CONTROL_SOCKET], {
          timeoutMs: 20000,
          maxStdout: 64 * 1024,
        });
        let reply = null;
        try { reply = JSON.parse(r.stdout); } catch (e) {}
        if (r.code !== 0 || !reply || reply.ok !== true) {
          throw new Error((reply && reply.error) || String(r.stderr || '').trim() || 'plugin cancel failed');
        }
        const job = activePluginJobId && pluginJobs.get(activePluginJobId);
        if (job && job.status === 'running' && job._child) {
          try { job._child.kill('SIGKILL'); } catch (e) {}
        }
        logLine(req, 200, 'admin-plugin-cancel');
        return json(res, 200, { ok: true, canceled: !!(reply.result && reply.result.canceled) });
      } catch (error) {
        logLine(req, 500, 'admin-plugin-cancel-fail ' + String(error.message).slice(0, 160));
        return json(res, 500, { ok: false, error: error.message });
      }
    }
    if (pathname === '/__gw/admin/kick' && req.method === 'POST') {
      if (req.headers['x-dsh-gateway-action'] !== 'admin-kick') {
        return json(res, 403, { ok: false, error: 'CSRF 校验失败' });
      }
      let body;
      try { body = await readJsonBody(req, 4096); } catch (e) { return json(res, 400, { ok: false, error: 'invalid JSON' }); }
      const name = String(body.name || '').trim();
      if (!getUser(name)) return json(res, 404, { ok: false, error: '用户不存在' });
      try {
        // The supervisor's sleep command stops the tenant, sweeps every process
        // of the user's OS account (killAllProcessesForOsUser) and bumps pwdVer
        // (revokeSessions), which invalidates all of the user's session tokens
        // - a hard logout plus process kill in one call.
        await stopTenantInstance(name, 'admin-force', true);
        // Clear gateway-side presence state so the kicked user reads offline
        // immediately; the pwdVer bump already kills their sessions server-side.
        cancelPresenceStop(name);
        tenantTabs.delete(name);
        presenceNonces.delete(name);
        readyTenants.delete(name);
        if (CLUSTER_ENABLED) {
          await Promise.all([
            clusterStore.clearUserPresence(name),
            clusterStore.markUserActive(name, null, true),
          ]).catch((error) => console.error(`cluster logout state update failed for ${name}: ${error.message}`));
        }
        logLine(req, 200, 'admin-kick ' + name);
        return json(res, 200, { ok: true });
      } catch (error) {
        logLine(req, 500, 'admin-kick-fail ' + name + ' ' + String(error.message).slice(0, 160));
        return json(res, 500, { ok: false, error: error.message });
      }
    }
    const csrf = crypto.randomBytes(16).toString('hex');
    res.setHeader('Set-Cookie', cookieHeader(CSRF_COOKIE, csrf, { maxAge: 600, path: '/', sameSite: 'Lax' }));
    secHeaders(res);
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    return res.end(adminPage(csrf));
  }

  if (pathname === '/login') {
    if (req.method === 'GET') {
      if (session) {
        const su = getUser(session.u);
        return redirect(res, loginDestination(session.u, '/'));
      }
      const query = q < 0 ? '' : req.url.slice(q + 1);
      const okMsg = /(^|&)ok=1(&|$)/.test(query)
        ? '注册成功！首次登录时将自动启动你的实例。'
        : null;
      const csrf = crypto.randomBytes(16).toString('hex');
      res.setHeader('Set-Cookie', cookieHeader(CSRF_COOKIE, csrf, { maxAge: 600, path: '/', sameSite: 'Lax' }));
      secHeaders(res);
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      return res.end(loginPage(csrf, null, okMsg));
    }
    if (req.method === 'POST') {
      let body;
      try { body = await readBody(req, 10000); } catch (e) { return json(res, 413, { ok: false, error: '请求过大' }); }
      const form = parseForm(body);
      const cookies = parseCookies(req);
      if (!form.csrf || !cookies[CSRF_COOKIE] || !timingSafeStr(form.csrf, cookies[CSRF_COOKIE])) {
        logLine(req, 403, 'csrf');
        const csrf2 = crypto.randomBytes(16).toString('hex');
        res.setHeader('Set-Cookie', cookieHeader(CSRF_COOKIE, csrf2, { maxAge: 600, path: '/', sameSite: 'Lax' }));
        secHeaders(res);
        res.writeHead(403, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
        return res.end(loginPage(csrf2, 'CSRF 校验失败，请刷新页面重试'));
      }
      const username = (form.username || '').trim();
      const password = form.password || '';
      const attempt = await checkAttempts(req, username);
      if (!attempt.allowed) {
        res.setHeader('Retry-After', String(attempt.retryAfter));
        logLine(req, 429, 'locked ' + username);
        const csrf2 = crypto.randomBytes(16).toString('hex');
        res.setHeader('Set-Cookie', cookieHeader(CSRF_COOKIE, csrf2, { maxAge: 600, path: '/', sameSite: 'Lax' }));
        secHeaders(res);
        res.writeHead(429, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
        return res.end(loginPage(csrf2, '尝试次数过多，请 ' + attempt.retryAfter + ' 秒后重试'));
      }
      const u = getUser(username);
      // Always run a scrypt pass, even for unknown users, so response timing
      // does not reveal which usernames exist (only the per-user lockout map
      // would otherwise distinguish them).
      let ok = false;
      if (u && u.pwd) ok = verifyPassword(password, u.pwd);
      else crypto.scryptSync(password, DUMMY_SALT, 64);
      if (!ok) {
        await recordFailure(req, username);
        logLine(req, 401, 'bad-creds ' + username);
        const csrf2 = crypto.randomBytes(16).toString('hex');
        res.setHeader('Set-Cookie', cookieHeader(CSRF_COOKIE, csrf2, { maxAge: 600, path: '/', sameSite: 'Lax' }));
        secHeaders(res);
        res.writeHead(401, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
        return res.end(loginPage(csrf2, '用户名或密码错误'));
      }
      await recordSuccess(req, username);
      if (u.port) {
        try {
          await ensureTenantInstance(username);
        } catch (error) {
          logLine(req, 503, 'tenant-start-fail ' + username + ' ' + String(error.message).slice(0, 160));
          const csrf2 = crypto.randomBytes(16).toString('hex');
          res.setHeader('Set-Cookie', cookieHeader(CSRF_COOKIE, csrf2, { maxAge: 600, path: '/', sameSite: 'Lax' }));
          secHeaders(res);
          res.writeHead(503, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
          return res.end(loginPage(csrf2, '账号验证成功，但实例启动失败，请稍后重试：' + error.message));
        }
      }
      setSession(res, username);
      logLine(req, 302, 'login ' + username);
      return redirect(res, loginDestination(username, '/'));
    }
    return json(res, 405, { ok: false, error: '方法不允许' });
  }

  if (pathname === '/register') {
    if (!REGISTER_ENABLED) return redirect(res, '/login');
    if (session) return redirect(res, hasKey(session.u) ? '/' : '/setup');
    if (req.method === 'GET') {
      const csrf = crypto.randomBytes(16).toString('hex');
      res.setHeader('Set-Cookie', cookieHeader(CSRF_COOKIE, csrf, { maxAge: 600, path: '/', sameSite: 'Lax' }));
      secHeaders(res);
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      return res.end(registerPage(csrf, null));
    }
    if (req.method === 'POST') {
      let body;
      try { body = await readBody(req, 10000); } catch (e) { return json(res, 413, { ok: false, error: '请求过大' }); }
      const form = parseForm(body);
      const cookies = parseCookies(req);
      const renderErr = (msg, code) => {
        const csrf2 = crypto.randomBytes(16).toString('hex');
        res.setHeader('Set-Cookie', cookieHeader(CSRF_COOKIE, csrf2, { maxAge: 600, path: '/', sameSite: 'Lax' }));
        secHeaders(res);
        res.writeHead(code || 200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
        return res.end(registerPage(csrf2, msg));
      };
      if (!form.csrf || !cookies[CSRF_COOKIE] || !timingSafeStr(form.csrf, cookies[CSRF_COOKIE])) {
        logLine(req, 403, 'csrf-register');
        return renderErr('CSRF 校验失败，请刷新页面重试', 403);
      }
      const ip = clientIp(req);
      const locked = CLUSTER_ENABLED
        ? await clusterStore.rateLimitStatus('register-ip', ip)
        : lockedUntil(registerFails, ip);
      if (locked) {
        res.setHeader('Retry-After', String(Math.ceil((locked - Date.now()) / 1000)));
        logLine(req, 429, 'register-locked ' + ip);
        return renderErr('注册尝试过多，请稍后再试', 429);
      }
      const username = (form.username || '').trim();
      const password = form.password || '';
      const confirm = form.confirm || '';
      if (!/^[A-Za-z0-9_-]{1,64}$/.test(username)) return renderErr('用户名仅限字母、数字、下划线、连字符');
      if (password.length < 8) return renderErr('密码至少 8 位');
      if (password !== confirm) return renderErr('两次输入的密码不一致');
      // Pass the control socket path explicitly: the helper runs under sudo,
      // which strips custom env vars (env_reset), so it cannot rely on the
      // gateway process environment.
      const r = await runHelper([REGISTER_HELPER, username, CONTROL_SOCKET], { input: password, timeoutMs: 130000, maxStdout: 64 * 1024 });
      let reply = null;
      try { reply = JSON.parse(r.stdout); } catch (e) {}
      if (r.code !== 0 || !reply || reply.ok !== true) {
        if (CLUSTER_ENABLED) {
          await clusterStore.recordRateLimitFailure('register-ip', ip, MAX_REGISTER_ATTEMPTS, WINDOW_MS, LOCK_MS);
        } else {
          registerFailure(registerFails, ip, MAX_REGISTER_ATTEMPTS);
        }
        const detail = (reply && reply.error) || String(r.stderr || '').trim() || '注册失败，请稍后重试';
        logLine(req, 200, 'register-fail ' + username + ' ' + detail.slice(0, 160));
        return renderErr(detail);
      }
      // The supervisor has persisted the user; drop the gateway's users cache
      // so the immediate redirect and any follow-up login see it right away.
      usersCacheAt = 0;
      if (CLUSTER_ENABLED) await clusterStore.clearRateLimit('register-ip', ip);
      else registerFails.delete(ip);
      logLine(req, 302, 'register ' + username + ' port=' + (reply.result && reply.result.port));
      return redirect(res, '/login?ok=1');
    }
    return json(res, 405, { ok: false, error: '方法不允许' });
  }

  // ---------- external browser login (trusted backend -> one-time ticket) ----------
  // 1. Trusted backend POSTs here with Authorization: Bearer DSH_LOGIN_API_KEY.
  // 2. It redirects the user's browser to the returned loginUrl.
  // 3. The browser consumes the one-time ticket, receives a session cookie,
  //    and is redirected to a validated same-origin path.
  if (pathname === '/api/login-ticket' && req.method === 'POST') {
    if (!loginApiAuthorized(req)) return json(res, 401, { ok: false, error: 'unauthorized' });
    let body;
    try { body = await readJsonBody(req, 10000); } catch (e) { return json(res, 400, { ok: false, error: 'invalid JSON body' }); }
    const username = String(body.username || '').trim();
    if (!/^[A-Za-z0-9_-]{1,64}$/.test(username)) return json(res, 400, { ok: false, error: 'invalid username' });
    if (!getUser(username)) return json(res, 404, { ok: false, error: 'user not found' });
    const returnTo = safeReturnTo(body.returnTo);
    if (returnTo === null) return json(res, 400, { ok: false, error: 'returnTo must be a same-origin absolute path' });
    const ticket = await issueLoginTicket(username, returnTo);
    if (!ticket) return json(res, 503, { ok: false, error: 'too many outstanding login tickets' });
    res.setHeader('Cache-Control', 'no-store');
    logLine(req, 200, 'login-ticket ' + username);
    return json(res, 200, {
      ok: true,
      loginUrl: '/auth/external?ticket=' + encodeURIComponent(ticket),
      expiresIn: LOGIN_TICKET_TTL,
    });
  }

  if (pathname === '/auth/external' && req.method === 'GET') {
    let ticket = '';
    try { ticket = new URL(req.url, 'http://gw').searchParams.get('ticket') || ''; } catch (e) {}
    const login = await consumeLoginTicket(ticket);
    if (!login || !getUser(login.user)) {
      logLine(req, 302, 'external-login invalid');
      return redirect(res, '/login');
    }
    const loginUser = getUser(login.user);
    if (loginUser.port) {
      try {
        await ensureTenantInstance(login.user);
      } catch (error) {
        logLine(req, 503, 'external-tenant-start-fail ' + login.user + ' ' + String(error.message).slice(0, 160));
        return json(res, 503, { ok: false, error: '实例启动失败，请重新登录：' + error.message });
      }
    }
    setSession(res, login.user);
    res.setHeader('Referrer-Policy', 'no-referrer');
    const destination = loginDestination(login.user, login.returnTo);
    logLine(req, 302, 'external-login ' + login.user);
    return redirect(res, destination);
  }

  // ---------- external registration API (Bearer token) ----------
  // Creates the user only; custom providers are registered afterwards via
  // POST /api/users/<username>/provider (with the API key).
  if (pathname === '/api/register' && req.method === 'POST') {
    if (!apiAuthorized(req)) return json(res, 401, { ok: false, error: 'unauthorized' });
    let body;
    try { body = await readJsonBody(req, 10000); } catch (e) { return json(res, 400, { ok: false, error: 'invalid JSON body' }); }
    if (body.provider !== undefined && body.provider !== null) {
      return json(res, 400, { ok: false, error: 'provider is not accepted here; use POST /api/users/<username>/provider' });
    }
    const username = String(body.username || '').trim();
    const password = String(body.password || '');
    if (!/^[A-Za-z0-9_-]{1,64}$/.test(username)) return json(res, 400, { ok: false, error: 'invalid username' });
    if (password.length < 8) return json(res, 400, { ok: false, error: 'password must be at least 8 characters' });
    const r = await runHelper([REGISTER_HELPER, username, CONTROL_SOCKET], { input: password, timeoutMs: 130000, maxStdout: 64 * 1024 });
    let reply = null;
    try { reply = JSON.parse(r.stdout); } catch (e) {}
    if (r.code !== 0 || !reply || reply.ok !== true) {
      const detail = (reply && reply.error) || String(r.stderr || '').trim() || 'registration failed';
      logLine(req, 200, 'api-register-fail ' + username + ' ' + detail.slice(0, 160));
      return json(res, 409, { ok: false, error: detail });
    }
    usersCacheAt = 0;
    logLine(req, 200, 'api-register ' + username + ' port=' + (reply.result && reply.result.port));
    return json(res, 200, { ok: true, user: username, port: reply.result.port });
  }

  // ---------- message history API: GET /api/users/<name>/messages ----------
  const apiMessagesMatch = /^\/api\/users\/([A-Za-z0-9_-]{1,64})\/messages$/.exec(pathname);
  if (apiMessagesMatch) {
    if (req.method !== 'GET') return json(res, 405, { ok: false, error: 'method not allowed' });
    if (!apiAuthorized(req)) return json(res, 401, { ok: false, error: 'unauthorized' });
    const name = apiMessagesMatch[1];
    const u = getUser(name);
    if (!u || !u.port) return json(res, 404, { ok: false, error: 'user not found' });
    let params;
    try { params = new URL(req.url, 'http://gw').searchParams; } catch (error) {
      return json(res, 400, { ok: false, error: 'invalid query string' });
    }
    const sessionId = String(params.get('sessionId') || '');
    if (!sessionId || sessionId.length > 256 || /[\x00-\x1f\x7f]/.test(sessionId)) {
      return json(res, 400, { ok: false, error: 'sessionId is required and must not exceed 256 characters' });
    }
    const maxMessagesRaw = params.get('maxMessages');
    const beforeSeqRaw = params.get('beforeSeq');
    const maxMessages = maxMessagesRaw === null ? 50 : Number(maxMessagesRaw);
    const beforeSeq = beforeSeqRaw === null ? undefined : Number(beforeSeqRaw);
    if (!Number.isInteger(maxMessages) || maxMessages < 1 || maxMessages > 100) {
      return json(res, 400, { ok: false, error: 'maxMessages must be an integer from 1 to 100' });
    }
    if (beforeSeq !== undefined && (!Number.isInteger(beforeSeq) || beforeSeq < 0)) {
      return json(res, 400, { ok: false, error: 'beforeSeq must be a non-negative integer' });
    }
    try {
      await ensureTenantInstance(name);
      const history = await tenantRpc(u.port, 'session.history', {
        sessionId,
        maxMessages,
        ...(beforeSeq === undefined ? {} : { beforeSeq }),
      }, 30000);
      if (!history.ok) {
        const rpcError = history.error || {};
        const status = rpcError.code === 'session-not-found' ? 404 : 409;
        return json(res, status, { ok: false, error: rpcError.message || 'history unavailable', code: rpcError.code || 'history-unavailable' });
      }
      const value = history.value || {};
      const entries = Array.isArray(value.events) ? value.events : [];
      const nextBeforeSeq = entries.length > 0 && entries[0] && entries[0].event
        ? entries[0].event.seq : null;
      return json(res, 200, {
        ok: true,
        user: name,
        sessionId,
        messages: messageViewsFromHistory(entries),
        hasMore: value.hasMore === true,
        nextBeforeSeq,
      });
    } catch (error) {
      readyTenants.delete(name);
      logLine(req, 502, 'api-messages-fail ' + name + ' ' + String(error.message).slice(0, 160));
      return json(res, 502, { ok: false, error: 'failed to read user DSH history: ' + error.message });
    }
  }

  // ---------- machine file upload: POST /api/users/<name>/files ----------
  const apiFilesMatch = /^\/api\/users\/([A-Za-z0-9_-]{1,64})\/files$/.exec(pathname);
  if (apiFilesMatch) {
    if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'method not allowed' });
    if (!apiAuthorized(req)) return json(res, 401, { ok: false, error: 'unauthorized' });
    const name = apiFilesMatch[1];
    const u = getUser(name);
    if (!u || !u.home) return json(res, 404, { ok: false, error: 'user not found' });
    let params;
    try { params = new URL(req.url, 'http://gw').searchParams; } catch (error) {
      return json(res, 400, { ok: false, error: 'invalid query string' });
    }
    const fileName = String(params.get('name') || '');
    if (!validUploadName(fileName)) return json(res, 400, { ok: false, error: 'invalid file name' });
    const workspace = path.join(u.home, 'workspace');
    const requestedDir = String(params.get('dir') || '');
    if (requestedDir.length > 4096 || requestedDir.indexOf('\0') >= 0) {
      return json(res, 400, { ok: false, error: 'invalid target directory' });
    }
    const dirAbs = path.isAbsolute(requestedDir)
      ? path.resolve(requestedDir)
      : path.resolve(workspace, requestedDir || '.');
    const saved = await saveUploadRequest(req, u.home, dirAbs, fileName);
    if (!saved.ok) return json(res, saved.status, { ok: false, error: saved.detail });
    const target = path.join(dirAbs, fileName);
    logLine(req, 201, 'api-upload ' + name + ' ' + path.relative(u.home, target) + ' bytes=' + req.headers['content-length']);
    return json(res, 201, { ok: true, user: name, path: target, name: fileName, bytes: Number(req.headers['content-length']) });
  }

  // ---------- direct message API: POST /api/users/<name>/message ----------
  // A trusted backend can enqueue or steer a text prompt without acquiring a
  // browser session. Supplying sessionId targets an existing conversation;
  // omitting it creates a new conversation first and returns its id.
  const apiMessageMatch = /^\/api\/users\/([A-Za-z0-9_-]{1,64})\/message$/.exec(pathname);
  if (apiMessageMatch) {
    if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'method not allowed' });
    if (!apiAuthorized(req)) return json(res, 401, { ok: false, error: 'unauthorized' });
    const name = apiMessageMatch[1];
    const u = getUser(name);
    if (!u || !u.port) return json(res, 404, { ok: false, error: 'user not found' });
    let body;
    try { body = await readJsonBody(req, 512 * 1024); } catch (error) {
      return json(res, 400, { ok: false, error: error.message === 'payload too large' ? 'payload too large' : 'invalid JSON body' });
    }
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return json(res, 400, { ok: false, error: 'JSON body must be an object' });
    }
    if (typeof body.message !== 'string' || !body.message.trim()) {
      return json(res, 400, { ok: false, error: 'message must be a non-empty string' });
    }
    if (body.message.length > 100000) {
      return json(res, 400, { ok: false, error: 'message must not exceed 100000 characters' });
    }
    if (body.sessionId !== undefined
        && (typeof body.sessionId !== 'string' || !body.sessionId || body.sessionId.length > 256
          || /[\x00-\x1f\x7f]/.test(body.sessionId))) {
      return json(res, 400, { ok: false, error: 'sessionId must be a non-empty string up to 256 characters without control characters' });
    }
    const mode = body.mode === undefined ? 'queue' : body.mode;
    if (mode !== 'queue' && mode !== 'steer') {
      return json(res, 400, { ok: false, error: 'mode must be queue or steer' });
    }
    if (body.stream !== undefined && typeof body.stream !== 'boolean') {
      return json(res, 400, { ok: false, error: 'stream must be a boolean' });
    }
    const wantsStream = body.stream === true || /\btext\/event-stream\b/i.test(String(req.headers.accept || ''));
    try {
      await ensureTenantInstance(name);
    } catch (error) {
      logLine(req, 503, 'api-message-start-fail ' + name + ' ' + String(error.message).slice(0, 160));
      return json(res, 503, { ok: false, error: 'failed to start user DSH: ' + error.message });
    }
    let streamSocket = null;
    try {
      let sessionId = body.sessionId;
      const created = !sessionId;
      if (!sessionId) {
        const createResult = await tenantRpc(u.port, 'session.create', {}, 30000);
        if (!createResult.ok) {
          const rpcError = createResult.error || {};
          logLine(req, 409, 'api-message-create-fail ' + name + ' ' + String(rpcError.code || '').slice(0, 80));
          return json(res, 409, {
            ok: false,
            error: rpcError.message || 'failed to create session',
            code: rpcError.code || 'session-create-failed',
          });
        }
        sessionId = createResult.value && createResult.value.sessionId;
        if (typeof sessionId !== 'string' || !sessionId) throw new Error('DSH returned no session id');
      }
      const bufferedFrames = [];
      let frameConsumer = (frame) => { bufferedFrames.push(frame); };
      if (wantsStream) streamSocket = await openTenantMux(u.port, (frame) => frameConsumer(frame));
      const promptEnvelope = await tenantRpcEnvelope(u.port, 'session.prompt', {
        sessionId,
        mode,
        content: [{ type: 'text', text: body.message }],
      }, 30000);
      const promptResult = promptEnvelope.result;
      if (!promptResult.ok) {
        if (streamSocket) try { streamSocket.close(); } catch (error) {}
        const rpcError = promptResult.error || {};
        const status = rpcError.code === 'session-not-found' ? 404 : 409;
        logLine(req, status, 'api-message-prompt-fail ' + name + ' ' + String(rpcError.code || '').slice(0, 80));
        return json(res, status, {
          ok: false,
          error: rpcError.message || 'message was not accepted',
          code: rpcError.code || 'message-not-accepted',
          sessionId,
          created,
        });
      }
      const details = {
        ok: true, user: name, sessionId, created, mode, accepted: true,
        ...(promptResult.value && promptResult.value.command ? { command: promptResult.value.command } : {}),
      };
      logLine(req, wantsStream ? 200 : 202, 'api-message ' + name + ' session=' + sessionId + ' mode=' + mode + ' chars=' + body.message.length + (wantsStream ? ' stream=1' : ''));
      if (!wantsStream) return json(res, 202, details);
      return streamAcceptedMessage(req, res, streamSocket, details, promptEnvelope.rpcId, bufferedFrames, (consumer) => { frameConsumer = consumer; });
    } catch (error) {
      if (streamSocket) try { streamSocket.close(); } catch (closeError) {}
      readyTenants.delete(name);
      logLine(req, 502, 'api-message-fail ' + name + ' ' + String(error.message).slice(0, 160));
      return json(res, 502, { ok: false, error: 'failed to reach user DSH: ' + error.message });
    }
  }

  // ---------- model registration API: POST /api/users/<name>/provider ----------
  // Registers (or replaces) the user's custom provider AND writes its API key.
  // The supervisor writes both provider config and owner-only key. Dormant
  // tenants stay dormant; already-active instances are restarted.
  const apiProviderMatch = /^\/api\/users\/([A-Za-z0-9_-]{1,64})\/provider$/.exec(pathname);
  if (apiProviderMatch && req.method === 'POST') {
    if (!apiAuthorized(req)) return json(res, 401, { ok: false, error: 'unauthorized' });
    const name = apiProviderMatch[1];
    let body;
    try { body = await readJsonBody(req, 10000); } catch (e) { return json(res, 400, { ok: false, error: 'invalid JSON body' }); }
    const p = body.provider;
    if (!p || typeof p !== 'object' || Array.isArray(p)) return json(res, 400, { ok: false, error: 'provider is required' });
    const pname = String(p.name || '').trim();
    const baseURL = String(p.baseURL || '').trim();
    if (!/^[A-Za-z0-9_-]{1,64}$/.test(pname)) return json(res, 400, { ok: false, error: 'invalid provider name (letters, digits, underscore, hyphen)' });
    if (!/^https?:\/\/[^\s]+$/.test(baseURL)) return json(res, 400, { ok: false, error: 'invalid provider baseURL (must be an http(s) URL)' });
    const papi = (p.api === undefined || p.api === null || p.api === '') ? 'openai-completions' : String(p.api);
    if (!['openai-completions', 'openai-responses', 'anthropic-messages'].includes(papi)) {
      return json(res, 400, { ok: false, error: 'invalid provider api (openai-completions | openai-responses | anthropic-messages)' });
    }
    const key = String(body.apiKey !== undefined ? body.apiKey : body.key || '').trim();
    if (!key) return json(res, 400, { ok: false, error: 'apiKey is required' });
    // Explicit image-capability allowlist. Standard OpenAI-compatible
    // /models replies normally expose only ids, so capability inference from
    // that endpoint is not portable. Accept the canonical top-level field and
    // provider.image_models as a compatibility alias.
    const imageModelsRaw = body.image_models !== undefined ? body.image_models : p.image_models;
    if (imageModelsRaw !== undefined && !Array.isArray(imageModelsRaw)) {
      return json(res, 400, { ok: false, error: 'image_models must be an array of model ids' });
    }
    const imageModels = [];
    const imageModelSet = new Set();
    for (const value of imageModelsRaw || []) {
      if (typeof value !== 'string' || !value.trim() || value.trim().length > 128) {
        return json(res, 400, { ok: false, error: 'image_models must contain non-empty model ids up to 128 characters' });
      }
      const id = value.trim();
      if (!imageModelSet.has(id)) imageModels.push(id);
      imageModelSet.add(id);
    }
    // Models: an explicit `model` (or `models` array) is used as-is; otherwise
    // the gateway asks the provider for its model list (GET <baseURL>/models
    // with the API key) so the caller does not have to know them.
    let models = null;
    if (Array.isArray(p.models) && p.models.length > 0) {
      models = p.models.map((m) => String(m).trim()).filter((m) => m && m.length <= 128);
      if (models.length === 0) return json(res, 400, { ok: false, error: 'invalid provider models' });
    } else if (p.model !== undefined && p.model !== null && String(p.model).trim() !== '') {
      const m = String(p.model).trim();
      if (!m || m.length > 128) return json(res, 400, { ok: false, error: 'invalid provider model' });
      models = [m];
    } else {
      try {
        models = await fetchProviderModels(baseURL, key);
      } catch (e) {
        logLine(req, 502, 'api-provider fetch-models-fail ' + name + ' ' + String(e && e.message || e).slice(0, 160));
        return json(res, 502, {
          ok: false,
          error: 'failed to fetch models from provider: ' + (e && e.message || e) + '; pass provider.model to set it explicitly',
        });
      }
    }
    models = [...new Set(models)];
    const configuredModels = models.map((id) => ({
      id,
      input: imageModelSet.has(id) ? ['text', 'image'] : ['text'],
    }));
    const u = getUser(name);
    if (!u || !u.port) return json(res, 404, { ok: false, error: 'user not found' });
    const r = await runHelper(
      [PROVIDER_HELPER, name, CONTROL_SOCKET, JSON.stringify({ name: pname, baseURL, api: papi, models: configuredModels })],
      { input: key, timeoutMs: 160000, maxStdout: 64 * 1024 },
    );
    let reply = null;
    try { reply = JSON.parse(r.stdout); } catch (e) {}
    if (r.code !== 0 || !reply || reply.ok !== true) {
      const detail = (reply && reply.error) || String(r.stderr || '').trim() || 'provider registration failed';
      logLine(req, 200, 'api-provider-fail ' + name + ' ' + detail.slice(0, 160));
      return json(res, 409, { ok: false, error: detail });
    }
    const ref = reply.result.provider.apiKeyEnv;
    usersCacheAt = 0;
    logLine(req, 200, 'api-provider ' + name + ' ref=' + ref + ' models=' + models.length);
    return json(res, 200, {
      ok: true,
      user: name,
      provider: reply.result.provider,
      ref: ref,
      models: models,
      image_models: imageModels,
    });
  }

  if (pathname === '/__gw/presence') {
    if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'method not allowed' });
    if (!session) return json(res, 401, { ok: false, error: 'not logged in' });
    const presenceUser = getUser(session.u);
    if (!presenceUser || !presenceUser.port) return json(res, 204, {});
    let body = '';
    try { body = await readBody(req, 4096); } catch (e) { return json(res, 413, { ok: false, error: 'payload too large' }); }
    const form = parseForm(body);
    const tabId = String(form.tab || '');
    const event = String(form.event || 'heartbeat');
    if (!/^[A-Za-z0-9_-]{8,128}$/.test(tabId) || !['open', 'heartbeat', 'close'].includes(event)) {
      return json(res, 400, { ok: false, error: 'invalid presence event' });
    }
    updateTenantPresence(session, tabId, event);
    // A close beacon must not extend authentication after the user leaves.
    // Open/heartbeat requests are ordinary credentialed fetches, so browsers
    // accept the renewed HttpOnly Set-Cookie response.
    if (event !== 'close' && sessionNeedsRefresh(session)) {
      const previousExp = session.exp;
      const nextExp = Math.floor(Date.now() / 1000) + SESSION_TTL;
      setSession(res, session.u, session);
      logLine(req, 200, `session-renew ${session.u} previousExp=${previousExp} nextExp=${nextExp}`);
      // Some reverse proxies discard response metadata on 204. Use an
      // explicit 200 body whenever Set-Cookie carries a renewal; ordinary
      // heartbeats that do not renew remain bodyless 204 responses below.
      return json(res, 200, { ok: true, renewed: true, expiresAt: nextExp });
    }
    res.writeHead(204, { 'Cache-Control': 'no-store' });
    return res.end();
  }

  if (pathname === '/logout') {
    // POST-only + same-site token so a third-party page cannot log users out
    // cross-site (GET /logout used to allow exactly that). The SPA login page
    // has no logout button of its own; callers should POST with the CSRF
    // cookie echoed in the body.
    if (req.method !== 'POST') return redirect(res, '/');
    if (session) {
      const c = parseCookies(req);
      let body = '';
      try { body = await readBody(req, 4096); } catch (e) {}
      const form = parseForm(body);
      const tok = form.csrf || req.headers['x-csrf-token'] || '';
      const trustedAction = req.headers['x-dsh-gateway-action'] === 'logout';
      if (!trustedAction && (!c[CSRF_COOKIE] || !timingSafeStr(String(tok), c[CSRF_COOKIE]))) {
        return json(res, 403, { ok: false, error: 'CSRF 校验失败' });
      }
      const logoutUser = getUser(session.u);
      if (logoutUser && logoutUser.port) {
        try {
          await stopTenantInstance(session.u, 'manual-logout', true);
        } catch (error) {
          logLine(req, 503, 'tenant-stop-fail ' + session.u + ' ' + String(error.message).slice(0, 160));
          return json(res, 503, { ok: false, error: '退出失败，用户进程未能停止：' + error.message });
        }
        cancelPresenceStop(session.u);
        tenantTabs.delete(session.u);
        let nonces = presenceNonces.get(session.u);
        if (!nonces) { nonces = new Set(); presenceNonces.set(session.u, nonces); }
        nonces.add(String(session.n || ''));
        revokePresenceSessions(session.u);
        // Mark logged-out instead of dropping the entry: the panel keeps the
        // last-active timestamp and shows "离线" (not "从未活跃"), and the
        // loggedOut flag forces online=false immediately. A later login's
        // markActive overwrites the entry and clears the flag.
        activeUsers.set(session.u, { at: Date.now(), ip: clientIp(req), loggedOut: true });
        if (CLUSTER_ENABLED) {
          await Promise.all([
            clusterStore.clearUserPresence(session.u),
            clusterStore.markUserActive(session.u, clientIp(req), true),
          ]).catch((error) => console.error(`cluster logout state update failed for ${session.u}: ${error.message}`));
        }
        logLine(req, 302, 'logout-stop ' + session.u);
      }
    }
    clearSession(res);
    return redirect(res, '/login');
  }

  if (pathname === '/setup') {
    if (!session) return redirect(res, '/login');
    if (hasKey(session.u)) return redirect(res, '/');
    if (req.method === 'GET') {
      secHeaders(res);
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      return res.end(setupPage(session.n, null, null));
    }
    if (req.method === 'POST') {
      let body;
      try { body = await readBody(req, 10000); } catch (e) { return json(res, 413, { ok: false, error: '请求过大' }); }
      const form = parseForm(body);
      const renderErr = (msg) => {
        secHeaders(res);
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
        return res.end(setupPage(session.n, msg, null));
      };
      if (!form.csrf || !timingSafeStr(form.csrf, session.n)) {
        logLine(req, 403, 'csrf-setup');
        return renderErr('CSRF 校验失败，请刷新页面重试');
      }
      const key = (form.key || '').trim();
      if (!/^sk-[A-Za-z0-9_-]{8,}$/.test(key)) {
        return renderErr('Key 格式不正确（应以 sk- 开头）');
      }
      const v = await validateKey(key, 8000);
      if (!v.ok) return renderErr(v.detail || 'Key 校验失败');
      const u = getUser(session.u);
      if (!u || !u.port) return renderErr('账号配置异常');
      const saved = await rpcCredentialsSet(u.port, key);
      if (!saved.ok) return renderErr('写入失败：' + saved.detail);
      if (!await setUserKeyFlag(session.u, true)) return renderErr('API Key 已写入，但用户状态保存失败，请联系管理员检查 users.json 权限');
      logLine(req, 200, 'set-key ' + session.u);
      return redirect(res, '/');
    }
    return json(res, 405, { ok: false, error: '方法不允许' });
  }

  if (pathname === '/__gw/upload') {
    if (req.method === 'GET') {
      if (!session) return redirect(res, '/login');
      if (!hasKey(session.u)) return redirect(res, '/setup');
      const home = userHome(session.u);
      if (!home) {
        clearSession(res);
        return json(res, 401, { ok: false, error: '账号不可用' });
      }
      let q = {};
      try { q = Object.fromEntries(new URL(req.url, 'http://gw').searchParams.entries()); } catch (e) {}
      const embed = String(q.embed || '') === '1';
      // Target directory: explicit ?dir=, else the tracked conversation cwd,
      // else the workspace default (canonicalized by the list helper).
      let target = String(q.dir || '') || currentCwd(session.u) || '';
      let display = home;
      {
        const r = await runHelper([FILE_LIST_HELPER, home, target]);
        let parsed = null;
        try { parsed = JSON.parse(r.stdout); } catch (e) {}
        if (parsed && parsed.dir) display = parsed.dir;
        else {
          const r2 = await runHelper([FILE_LIST_HELPER, home, '']);
          try { display = JSON.parse(r2.stdout).dir; } catch (e) {}
        }
      }
      const body = [
        '<div class="dlcard' + (embed ? ' embed' : '') + '">',
        '<div class="dlhead"><div><h1>&#128228; 上传文件</h1><p class="sub">文件将上传到你的当前工作目录；在对话中打开时，会自动定位到该对话所在的工作区。</p></div>',
        '<a class="ghost" href="/" id="backbtn">返回应用</a>',
        '</div>',
        '<div class="target">当前目录<span class="tpath">' + esc(display) + '</span></div>',
        '<div class="upbar"><input type="file" id="upfile" multiple><button type="button" id="upbtn">上传</button></div>',
        '<div class="upmsg" id="upmsg"></div>',
        '<div class="uplist" id="uplist"></div>',
        '<div class="afters" id="afters" style="display:none"><a class="ghost" id="viewbtn" href="/__gw/files">打开文件管理</a></div>',
        '<script>',
        'function backToApp(){if(window.parent!==window){try{parent.postMessage("dshgw-close","*");}catch(e){location.href="/";}}else{location.href="/";}}document.getElementById("backbtn").addEventListener("click",function(e){e.preventDefault();backToApp();});',
        (embed ? 'document.getElementById("viewbtn").addEventListener("click",function(e){e.preventDefault();parent.postMessage("dshgw-open-files","*");});' : ''),
        '(function(){var dir=' + JSON.stringify(display).replace(/</g, '\\u003c') + ';var f=document.getElementById("upfile");var b=document.getElementById("upbtn");var m=document.getElementById("upmsg");var ul=document.getElementById("uplist");var done=document.getElementById("afters");',
        'b.addEventListener("click",function(){if(!f.files||f.files.length===0){m.textContent="请先选择文件";return;}var files=Array.prototype.slice.call(f.files);var i=0,ok=0,fail=0;ul.textContent="";m.textContent="";',
        'function next(){if(i>=files.length){m.textContent="完成："+ok+" 个成功"+(fail?"，"+fail+" 个失败":"");if(ok>0)done.style.display="block";return;}var file=files[i];m.textContent="上传中 "+(i+1)+"/"+files.length+"："+file.name;',
        'fetch("/__gw/upload?dir="+encodeURIComponent(dir)+"&name="+encodeURIComponent(file.name),{method:"POST",body:file}).then(function(r){return r.json().catch(function(){return {};}).then(function(j){if(!r.ok)throw new Error(j.error||("HTTP "+r.status));});}).then(function(){var li=document.createElement("div");li.className="uok";li.textContent="✓ "+file.name;ul.appendChild(li);ok++;i++;next();}).catch(function(e){var li=document.createElement("div");li.className="ufail";li.textContent="✕ "+file.name+"："+(e&&e.message?e.message:e);ul.appendChild(li);fail++;i++;next();});}',
        'next();});})();',
        '</scr' + 'ipt>',
        '<style>',
        'body{background:#f6f8fa}',
        '.dlcard{width:100%;max-width:600px;background:#fcfcfd;border:1px solid #e2e8f0;border-radius:14px;padding:24px 26px;box-shadow:0 1px 2px rgba(16,24,40,.05),0 12px 32px rgba(16,24,40,.10)}',
        '.dlcard.embed{max-width:none;width:100%;border:0;border-radius:0;box-shadow:none;padding:18px 22px 24px;min-height:100%;box-sizing:border-box}',
        '.dlhead{display:flex;justify-content:space-between;align-items:flex-start;gap:12px;margin-bottom:16px}',
        '.dlcard.embed .dlhead{padding-right:44px}',
        '.dlhead h1{font-size:17px;font-weight:650;margin:0;color:#0f172a;letter-spacing:.2px}',
        '.dlhead .sub{font-size:13px;color:#64748b;margin:6px 0 0;max-width:520px;line-height:1.55}',
        '.ghost{white-space:nowrap;color:#2563eb;text-decoration:none;font-size:13px;padding:8px 14px;border:1px solid #e2e8f0;border-radius:10px;background:#fff;cursor:pointer;margin-top:0;width:auto}',
        '.ghost:hover{background:#f1f5f9}',
        '.target{font-size:12.5px;color:#64748b;margin-bottom:12px;display:flex;align-items:center;gap:8px}',
        '.tpath{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;color:#334155;background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:5px 10px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1}',
        '.upbar{display:flex;gap:10px;align-items:center;margin-bottom:10px}',
        '.upbar input[type=file]{flex:1;width:auto;background:#f8fafc;border:1px dashed #cbd5e1;border-radius:10px;color:#64748b;font-size:12.5px;padding:9px 12px}',
        '.upbar input[type=file]:focus-visible{outline:2px solid #2563eb;outline-offset:2px}',
        '.upbar button{margin-top:0;width:auto;padding:9px 18px;font-size:13px;font-weight:600;background:#2563eb;color:#fff;border-radius:10px}',
        '.upbar button:hover{filter:none;background:#1d4ed8}',
        '.upbar button:focus-visible{outline:2px solid #2563eb;outline-offset:2px}',
        '.upmsg{font-size:12.5px;color:#64748b;margin:0 0 10px;min-height:16px}',
        '.uplist{display:flex;flex-direction:column;gap:6px;margin-bottom:12px}',
        '.uok,.ufail{font-size:13px;padding:8px 12px;border-radius:8px}',
        '.uok{color:#15803d;background:#f0fdf4;border:1px solid #bbf7d0}',
        '.ufail{color:#b91c1c;background:#fef2f2;border:1px solid #fecaca}',
        '.afters{margin-top:4px}',
        (embed ? 'body{background:#fcfcfd;padding:0;align-items:stretch}' : ''),
        '</style>',
        '</div>',
      ].join('');
      secHeaders(res);
      res.setHeader('X-Frame-Options', 'SAMEORIGIN');
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      return res.end(htmlShell('上传文件', body));
    }
    if (req.method !== 'POST') return json(res, 405, { ok: false, error: '方法不允许' });
    if (!session) return json(res, 401, { ok: false, error: '未登录' });
    if (!hasKey(session.u)) return json(res, 403, { ok: false, error: '请先配置 API Key', redirect: '/setup' });
    const home = userHome(session.u);
    if (!home) {
      clearSession(res);
      return json(res, 401, { ok: false, error: '账号不可用' });
    }
    let q = {};
    try { q = Object.fromEntries(new URL(req.url, 'http://gw').searchParams.entries()); } catch (e) {}
    const dir = String(q.dir || '');
    const name = String(q.name || '');
    if (!dir) return json(res, 400, { ok: false, error: '缺少 dir 参数' });
    const dirAbs = path.resolve(dir);
    if (!validUploadName(name)) {
      return json(res, 400, { ok: false, error: '文件名不合法' });
    }
    const saved = await saveUploadRequest(req, home, dirAbs, name);
    if (!saved.ok) return json(res, saved.status, { ok: false, error: saved.detail });
    const target = path.join(dirAbs, name);
    logLine(req, 200, 'upload ' + path.relative(home, target));
    return json(res, 200, { ok: true, path: target, name: name });
  }

  if (pathname === '/__gw/delete') {
    if (req.method !== 'POST') return json(res, 405, { ok: false, error: '方法不允许' });
    if (!session) return json(res, 401, { ok: false, error: '未登录' });
    if (!hasKey(session.u)) return json(res, 403, { ok: false, error: '请先配置 API Key', redirect: '/setup' });
    if (req.headers['x-dsh-gateway-action'] !== 'delete-file') {
      return json(res, 403, { ok: false, error: 'CSRF 校验失败' });
    }
    const home = userHome(session.u);
    if (!home) {
      clearSession(res);
      return json(res, 401, { ok: false, error: '账号不可用' });
    }
    let body;
    try { body = await readJsonBody(req, 4096); } catch (error) {
      return json(res, 400, { ok: false, error: '请求格式无效' });
    }
    const rawPath = typeof body.path === 'string' ? body.path : '';
    if (!rawPath || rawPath.length > 4096 || rawPath.includes('\0')) {
      return json(res, 400, { ok: false, error: '缺少或非法的 path 参数' });
    }
    const abs = path.resolve(rawPath);
    const result = await runHelper([FILE_DELETE_HELPER, home, abs], { maxStdout: 64 * 1024, maxStderr: 64 * 1024 });
    if (result.code === 2) return json(res, 400, { ok: false, error: '路径参数无效' });
    if (result.code === 3) return json(res, 403, { ok: false, error: '路径超出你的工作区或不能删除根目录' });
    if (result.code === 4) return json(res, 404, { ok: false, error: '文件或目录不存在，或当前类型不支持删除' });
    if (result.code === 5) return json(res, 403, { ok: false, error: '不允许删除隐藏文件' });
    if (result.code === 6) return json(res, 409, { ok: false, error: '目录不为空，不能删除' });
    if (result.code !== 0) {
      const detail = String(result.stderr || '').trim().split('\n')[0];
      return json(res, 500, { ok: false, error: '删除助手不可用或执行失败' + (detail ? '：' + detail : '') });
    }
    let detail = {};
    try { detail = JSON.parse(result.stdout); } catch (error) {}
    logLine(req, 200, 'delete ' + path.relative(home, abs));
    return json(res, 200, { ok: true, path: abs, type: detail.type || 'file' });
  }

  if (pathname === '/__gw/mkdir') {
    if (req.method !== 'POST') return json(res, 405, { ok: false, error: '方法不允许' });
    if (!session) return json(res, 401, { ok: false, error: '未登录' });
    if (!hasKey(session.u)) return json(res, 403, { ok: false, error: '请先配置 API Key', redirect: '/setup' });
    if (req.headers['x-dsh-gateway-action'] !== 'create-directory') {
      return json(res, 403, { ok: false, error: 'CSRF 校验失败' });
    }
    const home = userHome(session.u);
    if (!home) {
      clearSession(res);
      return json(res, 401, { ok: false, error: '账号不可用' });
    }
    let body;
    try { body = await readJsonBody(req, 4096); } catch (error) {
      return json(res, 400, { ok: false, error: '请求格式无效' });
    }
    const dir = typeof body.dir === 'string' ? body.dir : '';
    const name = typeof body.name === 'string' ? body.name.trim() : '';
    if (!dir || dir.length > 4096 || dir.includes('\0')) return json(res, 400, { ok: false, error: '目录路径无效' });
    if (!name || name.length > 200 || name === '.' || name === '..' || name.startsWith('.')
        || /[\\/\r\n]/.test(name) || /[\x00-\x1f\x7f]/.test(name)) {
      return json(res, 400, { ok: false, error: '文件夹名称无效' });
    }
    const result = await runHelper([FILE_MKDIR_HELPER, home, path.resolve(dir), name], {
      maxStdout: 64 * 1024,
      maxStderr: 64 * 1024,
    });
    if (result.code === 2) return json(res, 400, { ok: false, error: '文件夹名称无效' });
    if (result.code === 3) return json(res, 403, { ok: false, error: '目标目录超出你的工作区' });
    if (result.code === 4) return json(res, 404, { ok: false, error: '目标目录不存在' });
    if (result.code === 6) return json(res, 409, { ok: false, error: '同名文件或文件夹已经存在' });
    if (result.code !== 0) {
      const detail = String(result.stderr || '').trim().split('\n')[0];
      return json(res, 500, { ok: false, error: '新建文件夹助手不可用或执行失败' + (detail ? '：' + detail : '') });
    }
    const target = path.join(path.resolve(dir), name);
    logLine(req, 200, 'mkdir ' + path.relative(home, target));
    return json(res, 200, { ok: true, path: target, name });
  }

  if (pathname === '/__gw/download' || pathname === '/__gw/files') {
    if (req.method !== 'GET') return json(res, 405, { ok: false, error: '方法不允许' });
    if (!session) return redirect(res, '/login');
    if (!hasKey(session.u)) return redirect(res, '/setup');
    const home = userHome(session.u);
    if (!home) {
      clearSession(res);
      return json(res, 401, { ok: false, error: '账号不可用' });
    }
    let q = {};
    try { q = Object.fromEntries(new URL(req.url, 'http://gw').searchParams.entries()); } catch (e) {}
    const rawPath = String(q.path || '');

    if (pathname === '/__gw/download') {
      if (!rawPath || rawPath.length > 4096 || rawPath.indexOf('\0') >= 0) return json(res, 400, { ok: false, error: '缺少或非法的 path 参数' });
      const abs = path.resolve(rawPath);
      const base = path.basename(abs);
      if (base.startsWith('.')) return json(res, 403, { ok: false, error: '不允许下载隐藏文件' });
      // All file access runs through the pinned root helpers: the gateway's
      // service account has no read access to user homes by design.
      let size = -1;
      {
        const r = await runHelper([FILE_STAT_HELPER, home, abs], { maxStdout: 1024 * 1024 });
        if (r.code === 3) return json(res, 403, { ok: false, error: '路径超出你的工作区' });
        if (r.code === 5) return json(res, 403, { ok: false, error: '不允许下载隐藏文件' });
        if (r.code !== 0) return json(res, 404, { ok: false, error: '文件不存在' });
        size = parseInt(r.stdout.trim(), 10);
        if (!Number.isFinite(size)) size = -1;
      }
      const ascii = base.replace(/[^\x20-\x7e]/g, '_').replace(/["\\]/g, '_') || 'download';
      secHeaders(res);
      const head = {
        'Content-Type': dlContentType(base),
        'Content-Disposition': 'attachment; filename="' + ascii + '"; filename*=UTF-8\'\'' + encodeURIComponent(base),
        'Cache-Control': 'no-store',
      };
      if (size >= 0) head['Content-Length'] = String(size);
      // Stat already established scope, type and size. Commit the response
      // headers exactly once, then let stream piping own the response end.
      // ChildProcess `exit` may fire before stdout is fully drained; ending or
      // writing an error response from that event races late `data` chunks and
      // previously crashed the whole gateway with ERR_HTTP_HEADERS_SENT.
      const direct = process.env.DSH_HELPER_DIRECT === '1';
      const child = spawn(direct ? FILE_READ_HELPER : 'sudo', direct ? [home, abs] : ['-n', FILE_READ_HELPER, home, abs], {
        stdio: ['ignore', 'pipe', 'ignore'],
      });
      let childSucceeded = false;
      let responseFinished = false;
      let logged = false;
      const logSuccess = () => {
        if (logged || !childSucceeded || !responseFinished) return;
        logged = true;
        logLine(req, 200, 'download ' + path.relative(home, abs));
      };
      res.writeHead(200, head);
      child.stdout.on('error', () => { try { res.destroy(); } catch (error) {} });
      child.stdout.pipe(res);
      child.once('error', () => { try { res.destroy(); } catch (error) {} });
      child.once('close', (code) => {
        childSucceeded = code === 0;
        if (!childSucceeded && !res.writableEnded) { try { res.destroy(); } catch (error) {} }
        logSuccess();
      });
      res.once('finish', () => { responseFinished = true; logSuccess(); });
      req.once('error', () => { try { child.kill(); } catch (error) {} });
      res.once('close', () => {
        if (!res.writableEnded && child.exitCode === null && child.signalCode === null) {
          try { child.kill(); } catch (error) {}
        }
      });
      return;
    }

    // /__gw/files -- directory browser (listing runs in the pinned root helper:
    // the gateway's service account has no read access to user homes by design).
    // Default target: the user's current conversation cwd (tracked from the
    // SPA's session RPCs), else the workspace directory.
    const embed = String(q.embed || '') === '1';
    // The visible root is the workspace directory; the real home root holds
    // DSH internals (profiles/, storages/, cordis.patch.yml, ...) and is out
    // of scope. Deriving it HERE keeps the "根目录" crumb and every clamp
    // consistent no matter what the helper reports as its `home` field. Do NOT
    // probe the filesystem for it: the gateway service account has no access
    // into the 0700 user homes (all file work runs through the root helpers),
    // so fs.existsSync would always report false. The helpers realpath the
    // workspace themselves and fall back to the home when it is missing.
    const wsRoot = path.join(home, 'workspace');
    let dirParam = String(q.dir || '') || currentCwd(session.u) || '';
    if (dirParam && dirParam !== wsRoot && !dirParam.startsWith(wsRoot + path.sep)) {
      // A stale crumb or tracked cwd pointing above the workspace (e.g. the
      // old home root) would 403 and strand the popup iframe: clamp to the
      // visible root before listing.
      dirParam = wsRoot;
    }
    let listing = null;
    {
      const r = await runHelper([FILE_LIST_HELPER, home, dirParam]);
      let parsed = null;
      try { parsed = JSON.parse(r.stdout); } catch (e) {}
      if (parsed && Array.isArray(parsed.entries)) {
        listing = parsed;
      } else if (r.code === 3 && !q.dir) {
        // tracked cwd went stale/out of scope - fall back to the workspace root
        const r2 = await runHelper([FILE_LIST_HELPER, home, '']);
        try { listing = JSON.parse(r2.stdout); } catch (e2) {}
      }
      if (!listing) {
        const code = r.code;
        const reason = code === 3 ? '路径超出你的工作区' : '目录不存在或无法读取';
        if (embed) {
          // Recoverable page INSIDE the popup iframe: a bare JSON error would
          // leave the drawer stuck until the whole app refreshes.
          secHeaders(res);
          res.writeHead(403, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
          return res.end(filesErrorPage(reason));
        }
        return json(res, code === 3 ? 403 : 404, { ok: false, error: reason });
      }
    }
    const dir = listing.dir;
    const root = listing.home === home ? wsRoot : (listing.home || wsRoot);
    const crumbs = [];
    {
      const rel = path.relative(root, dir);
      const safe = !rel || (!rel.startsWith('..') && !path.isAbsolute(rel));
      const parts = safe ? (rel ? rel.split(path.sep) : []) : [];
      let acc = root;
      crumbs.push('<a href="/__gw/files?dir=' + encodeURIComponent(root) + '">&#127968; 根目录</a>');
      for (const part of parts) {
        acc = path.join(acc, part);
        crumbs.push('<span class="sep">/</span><a href="/__gw/files?dir=' + encodeURIComponent(acc) + '">' + esc(part) + '</a>');
      }
    }
    const rows = [];
    for (const e of listing.entries) {
      const p = path.join(dir, e.name);
      if (e.dir) {
        rows.push('<div class="row"><a class="folder" href="/__gw/files?dir=' + encodeURIComponent(p) + '"><span class="ic">&#128193;</span><span class="nm">' + esc(e.name) + '/</span><span class="sz"></span></a><button type="button" class="del" data-delete-path="' + esc(p) + '" data-delete-kind="directory" data-delete-name="' + esc(e.name) + '">删除</button></div>');
      } else {
        rows.push('<div class="row"><span class="ic">&#128196;</span><span class="nm">' + esc(e.name) + '</span><span class="sz">' + (e.size >= 0 ? fmtSize(e.size) : '') + '</span><a class="dl" href="/__gw/download?path=' + encodeURIComponent(p) + '">下载</a><button type="button" class="del" data-delete-path="' + esc(p) + '" data-delete-kind="file" data-delete-name="' + esc(e.name) + '">删除</button></div>');
      }
    }
    const truncated = listing.truncated === true;
    const body = [
      '<div class="dlcard' + (embed ? ' embed' : '') + '">',
      '<div class="dlhead"><div><h1>&#128193; 文件管理</h1><p class="sub">任务产出的文件保存在你的工作区里：点击「下载」保存到本地，也可以从本机上传文件到当前目录。</p></div>',
      '<a class="ghost" href="/" id="backbtn">返回应用</a>',
      '</div>',
      '<div class="crumbs">' + crumbs.join('') + '</div>',
      '<div class="upbar"><input type="file" id="upfile" multiple><button type="button" id="upbtn">上传到当前目录</button></div>',
      '<div class="mkdirbar"><input type="text" id="mkdirname" maxlength="200" placeholder="新文件夹名称"><button type="button" id="mkdirbtn">新建文件夹</button></div>',
      '<div class="upmsg" id="upmsg"></div>',
      '<div class="list">' + (rows.length ? rows.join('') : '<p class="empty">此目录为空</p>') + '</div>',
      truncated ? '<p class="hint">目录内容过多，仅显示前 2000 项。</p>' : '',
      '<script>',
      'function backToApp(){if(window.parent!==window){try{parent.postMessage("dshgw-close","*");}catch(e){location.href="/";}}else{location.href="/";}}document.getElementById("backbtn").addEventListener("click",function(e){e.preventDefault();backToApp();});',
      '(function(){var dir=' + JSON.stringify(dir).replace(/</g, '\\u003c') + ';var f=document.getElementById("upfile");var b=document.getElementById("upbtn");var m=document.getElementById("upmsg");',
      'b.addEventListener("click",function(){if(!f.files||f.files.length===0){m.textContent="请先选择文件";return;}var files=Array.prototype.slice.call(f.files);var i=0;',
      'function next(){if(i>=files.length){m.textContent="上传完成，正在刷新…";location.reload();return;}var file=files[i];m.textContent="上传中 "+(i+1)+"/"+files.length+"："+file.name;',
      'fetch("/__gw/upload?dir="+encodeURIComponent(dir)+"&name="+encodeURIComponent(file.name),{method:"POST",body:file}).then(function(r){return r.json().catch(function(){return {};}).then(function(j){if(!r.ok)throw new Error(j.error||("HTTP "+r.status));});}).then(function(){i++;next();}).catch(function(e){m.textContent="上传失败："+(e&&e.message?e.message:e)+"（第 "+(i+1)+" 个："+file.name+"）";});}',
      'next();});})();',
      '(function(){var dir=' + JSON.stringify(dir).replace(/</g, '\\u003c') + ';var input=document.getElementById("mkdirname"),button=document.getElementById("mkdirbtn"),m=document.getElementById("upmsg");function create(){var name=input.value.trim();if(!name){m.textContent="请输入文件夹名称";input.focus();return;}button.disabled=true;button.textContent="创建中…";fetch("/__gw/mkdir",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-DSH-Gateway-Action":"create-directory"},body:JSON.stringify({dir:dir,name:name})}).then(function(r){return r.json().catch(function(){return {};}).then(function(j){if(!r.ok||!j.ok)throw new Error(j.error||("HTTP "+r.status));});}).then(function(){m.textContent="文件夹已创建，正在刷新…";location.reload();}).catch(function(e){button.disabled=false;button.textContent="新建文件夹";m.textContent="创建失败："+(e&&e.message?e.message:e);});}button.addEventListener("click",create);input.addEventListener("keydown",function(e){if(e.key==="Enter"){e.preventDefault();create();}});})();',
      '(function(){var m=document.getElementById("upmsg");Array.prototype.forEach.call(document.querySelectorAll("[data-delete-path]"),function(button){button.addEventListener("click",function(){var target=button.getAttribute("data-delete-path"),name=button.getAttribute("data-delete-name"),kind=button.getAttribute("data-delete-kind");var hint=kind==="directory"?"仅空目录可以删除。":"删除后无法从文件管理中恢复。";if(!window.confirm("确定删除“"+name+"”吗？\\n"+hint))return;button.disabled=true;button.textContent="删除中…";fetch("/__gw/delete",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-DSH-Gateway-Action":"delete-file"},body:JSON.stringify({path:target})}).then(function(r){return r.json().catch(function(){return {};}).then(function(j){if(!r.ok||!j.ok)throw new Error(j.error||("HTTP "+r.status));});}).then(function(){m.textContent="已删除 "+name+"，正在刷新…";location.reload();}).catch(function(e){button.disabled=false;button.textContent="删除";m.textContent="删除失败："+(e&&e.message?e.message:e);});});});})();',
      '</scr' + 'ipt>',
      '<style>',
      'body{background:#f6f8fa}',
      '.dlcard{width:100%;max-width:780px;background:#fcfcfd;border:1px solid #e2e8f0;border-radius:14px;padding:24px 26px;box-shadow:0 1px 2px rgba(16,24,40,.05),0 12px 32px rgba(16,24,40,.10)}',
      '.dlcard.embed{max-width:none;width:100%;border:0;border-radius:0;box-shadow:none;padding:18px 22px 24px;min-height:100%;box-sizing:border-box}',
      '.dlhead{display:flex;justify-content:space-between;align-items:flex-start;gap:12px;margin-bottom:14px}',
      '.dlcard.embed .dlhead{padding-right:44px}',
      '.dlhead h1{font-size:17px;font-weight:650;margin:0;color:#0f172a;letter-spacing:.2px}',
      '.dlhead .sub{font-size:13px;color:#64748b;margin:6px 0 0;max-width:560px;line-height:1.55}',
      '.ghost{white-space:nowrap;color:#2563eb;text-decoration:none;font-size:13px;padding:8px 14px;border:1px solid #e2e8f0;border-radius:10px;background:#fff;cursor:pointer;margin-top:0;width:auto}',
      '.ghost:hover{background:#f1f5f9}',
      '.crumbs{font-size:12.5px;color:#64748b;padding:9px 12px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;margin-bottom:12px;overflow-x:auto;white-space:nowrap}',
      '.crumbs a{color:#2563eb;text-decoration:none}.crumbs a:hover{text-decoration:underline}',
      '.crumbs .sep{margin:0 6px;color:#cbd5e1}',
      '.list{border:1px solid #e2e8f0;border-radius:12px;overflow:hidden;max-height:52vh;overflow-y:auto;background:#fff}',
      '.row{display:flex;align-items:center;gap:10px;padding:10px 14px;font-size:14px;border-bottom:1px solid #f1f5f9;color:#1e293b;text-decoration:none}',
      '.row:last-child{border-bottom:0}.row:hover{background:#f8fafc}',
      '.folder{display:flex;align-items:center;gap:10px;flex:1;min-width:0;color:#1e293b;text-decoration:none}',
      '.ic{width:20px;text-align:center}.nm{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}',
      '.sz{color:#94a3b8;font-size:12px;white-space:nowrap;font-variant-numeric:tabular-nums}',
      '.dl{color:#2563eb;text-decoration:none;font-size:12.5px;font-weight:600;white-space:nowrap;padding:5px 12px;border:1px solid #dbeafe;border-radius:8px;background:#eff6ff}',
      '.dl:hover{background:#dbeafe}',
      '.del{color:#b42318;font-size:12.5px;font-weight:600;white-space:nowrap;padding:5px 12px;border:1px solid #fecaca;border-radius:8px;background:#fff1f2;cursor:pointer;width:auto;margin:0}.del:hover{background:#ffe4e6}.del:disabled{opacity:.6;cursor:not-allowed}',
      '.empty{color:#64748b;font-size:13px;padding:20px 14px;margin:0}',
      '.upbar{display:flex;gap:10px;align-items:center;margin-bottom:10px}',
      '.upbar input[type=file]{flex:1;width:auto;background:#f8fafc;border:1px dashed #cbd5e1;border-radius:10px;color:#64748b;font-size:12.5px;padding:9px 12px}',
      '.upbar input[type=file]:focus-visible{outline:2px solid #2563eb;outline-offset:2px}',
      '.upbar button{margin-top:0;width:auto;padding:9px 18px;font-size:13px;font-weight:600;background:#2563eb;color:#fff;border-radius:10px}',
      '.upbar button:hover{filter:none;background:#1d4ed8}',
      '.upbar button:focus-visible{outline:2px solid #2563eb;outline-offset:2px}',
      '.mkdirbar{display:flex;gap:10px;align-items:center;margin-bottom:10px}.mkdirbar input{flex:1;margin:0;padding:9px 12px;font-size:12.5px;background:#f8fafc;border:1px solid #cbd5e1;border-radius:10px}.mkdirbar button{margin:0;width:auto;padding:9px 18px;font-size:13px;font-weight:600;background:#fff;color:#2563eb;border:1px solid #bfdbfe;border-radius:10px}.mkdirbar button:hover{background:#eff6ff}',
      '.upmsg{font-size:12.5px;color:#64748b;margin:0 0 10px;min-height:16px}',
      '.hint{font-size:12.5px;color:#64748b;margin-top:10px}',
      (embed ? 'body{background:#fcfcfd;padding:0;align-items:stretch}' : ''),
      '</style>',
      '</div>',
    ].join('');
    secHeaders(res);
    // The in-page drawer embeds this page in a same-origin iframe inside the SPA.
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    return res.end(htmlShell('文件管理', body));
  }

  // everything else
  if (!session) {
    if (req.method === 'GET' && !pathname.startsWith('/api/')) {
      const csrf = crypto.randomBytes(16).toString('hex');
      res.setHeader('Set-Cookie', cookieHeader(CSRF_COOKIE, csrf, { maxAge: 600, path: '/', sameSite: 'Lax' }));
      secHeaders(res);
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      return res.end(loginPage(csrf, null));
    }
    return json(res, 401, { ok: false, error: '未登录' });
  }
  if (!hasKey(session.u)) {
    if (req.method === 'GET' && !pathname.startsWith('/api/')) return redirect(res, '/setup');
    return json(res, 403, { ok: false, error: '请先配置 API Key', redirect: '/setup' });
  }
  const u = getUser(session.u);
  if (!u || !u.port) {
    clearSession(res);
    return json(res, 401, { ok: false, error: '账号不可用' });
  }
  try {
    await ensureTenantInstance(session.u);
  } catch (error) {
    logLine(req, 503, 'tenant-start-fail ' + session.u + ' ' + String(error.message).slice(0, 160));
    return json(res, 503, { ok: false, error: '实例启动失败，请稍后重试：' + error.message });
  }
  proxyRequest(req, res, u.port, session.u);
});

server.on('upgrade', async (req, socket, head) => {
  const peerHop = req.headers['x-dsh-cluster-hop'] === '1';
  if (CLUSTER_ENABLED && req.headers['x-dsh-cluster-hop']
      && (!peerHop || !timingSafeStr(String(req.headers['x-dsh-cluster-token'] || ''), CLUSTER_TOKEN))) {
    socket.write('HTTP/1.1 403 Forbidden\r\n\r\n'); socket.destroy(); return;
  }
  const session = getSession(req);
  if (!session) { logRejectedSession(req); socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n'); socket.destroy(); return; }
  if (!hasKey(session.u)) { socket.write('HTTP/1.1 403 Forbidden\r\n\r\n'); socket.destroy(); return; }
  const u = getUser(session.u);
  if (!u || !u.port) { socket.destroy(); return; }
  let owner;
  try { owner = await ensureTenantInstance(session.u); } catch (error) {
    socket.write('HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n');
    socket.destroy();
    return;
  }
  if (CLUSTER_ENABLED && owner && !owner.local) {
    if (peerHop) {
      socket.write('HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n');
      socket.destroy();
      return;
    }
    return proxyPeerUpgrade(req, socket, head, owner, session.u);
  }
  proxyUpgrade(req, socket, head, u.port, session.u);
});

server.listen(PORT, HOST, () => {
  console.log('dsh-gateway listening on ' + HOST + ':' + PORT
    + ` (sessionTTL=${SESSION_TTL}s, refreshInterval=${SESSION_REFRESH_INTERVAL}s, secretId=${SECRET_ID})`);
});

// Graceful shutdown: stop accepting, let in-flight proxies/uploads finish.
function shutdown() {
  server.close(() => {
    clusterStore.close().catch(() => {}).finally(() => process.exit(0));
  });
  setTimeout(() => process.exit(0), 10000).unref();
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
