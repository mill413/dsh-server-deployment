'use strict';
const http = require('http');
const https = require('https');
const net = require('net');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const url = require('url');
const { spawn } = require('child_process');
const zlib = require('zlib');
const { verifyPassword, timingSafeStr } = require('./auth.js');

const HOST = process.env.HOST || '127.0.0.1';
const PORT = parseInt(process.env.PORT || '3081', 10);
const USERS_FILE = process.env.USERS_FILE || '/opt/deepseek-harness/gateway/users.json';
const SECRET_FILE = process.env.SECRET_FILE || '/opt/deepseek-harness/gateway/secret';
const USERS_DIR = process.env.USERS_DIR || '/opt/deepseek-harness/users';
const SESSION_TTL = parseInt(process.env.SESSION_TTL || '43200', 10);
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
  activeUsers.set(user, { at: now, ip: clientIp(req) });
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
    return ids.slice(0, 100);
  } finally {
    clearTimeout(timer);
  }
}
const UPLOAD_HELPER = process.env.UPLOAD_HELPER || '/opt/deepseek-harness/bin/dsh-file-put';
const FILE_STAT_HELPER = process.env.FILE_STAT_HELPER || '/opt/deepseek-harness/bin/dsh-file-stat';
const FILE_READ_HELPER = process.env.FILE_READ_HELPER || '/opt/deepseek-harness/bin/dsh-file-read';
const FILE_LIST_HELPER = process.env.FILE_LIST_HELPER || '/opt/deepseek-harness/bin/dsh-file-list';
const UPLOAD_MAX_MB = parseInt(process.env.UPLOAD_MAX_MB || '100', 10);

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
  try {
    const s = fs.readFileSync(SECRET_FILE, 'utf8').trim();
    if (s.length >= 32) return s;
  } catch (e) {}
  const s = crypto.randomBytes(32).toString('hex');
  try {
    fs.mkdirSync(path.dirname(SECRET_FILE), { recursive: true, mode: 0o700 });
    fs.writeFileSync(SECRET_FILE, s + '\n', { mode: 0o600 });
  } catch (e) { console.error('cannot persist session secret:', e.message); }
  return s;
}
const SECRET = loadSecret();

function hmac(data) {
  return crypto.createHmac('sha256', SECRET).update(data).digest('base64url');
}

// ---------- users store (small JSON, cached) ----------
let usersCache = { version: 1, users: {} };
let usersCacheAt = 0;
function loadUsers() {
  const now = Date.now();
  if (now - usersCacheAt < 2000) return usersCache;
  try {
    usersCache = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
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
function mutateUserStore(user, fn) {
  let db;
  try { db = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); }
  catch (e) { db = { version: 1, users: {} }; }
  if (db.users && db.users[user]) fn(db.users[user]);
  try {
    const tmp = USERS_FILE + '.tmp-' + process.pid + '-' + Date.now().toString(36);
    fs.writeFileSync(tmp, JSON.stringify(db, null, 2) + '\n', { mode: 0o640 });
    fs.renameSync(tmp, USERS_FILE);
  } catch (e) { console.error('users.json write failed:', e.message); }
  usersCache = db;
  usersCacheAt = Date.now();
}

// Persist the flag and refresh the in-memory cache so the very next request
// sees it (no 2s staleness on the /setup -> / redirect).
function setUserKeyFlag(user, val) {
  mutateUserStore(user, (rec) => { rec.keyConfigured = !!val; });
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
function checkAttempts(req, username) {
  const ip = clientIp(req);
  const a = lockedUntil(ipFails, ip);
  const b = lockedUntil(userFails, username);
  if (a || b) return { allowed: false, retryAfter: Math.ceil((Math.max(a, b) - Date.now()) / 1000) };
  return { allowed: true, retryAfter: 0 };
}
function recordFailure(req, username) {
  registerFailure(ipFails, clientIp(req), MAX_IP_ATTEMPTS);
  registerFailure(userFails, username, MAX_USER_ATTEMPTS);
  if (ipFails.size > 10000 || userFails.size > 10000) {
    const now = Date.now();
    for (const m of [ipFails, userFails]) for (const [k, v] of m) if (now - v.windowStart > WINDOW_MS + LOCK_MS) m.delete(k);
  }
}
function recordSuccess(req, username) {
  ipFails.delete(clientIp(req));
  userFails.delete(username);
}

// ---------- session ----------
function makeToken(user) {
  const payload = { u: user, v: pwdVersion(user), exp: Math.floor(Date.now() / 1000) + SESSION_TTL, n: crypto.randomBytes(8).toString('hex') };
  const b = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return b + '.' + hmac(b);
}
function verifyToken(tok) {
  if (!tok || typeof tok !== 'string') return null;
  const i = tok.lastIndexOf('.');
  if (i <= 0) return null;
  const b = tok.slice(0, i);
  const sig = tok.slice(i + 1);
  if (!timingSafeStr(hmac(b), sig)) return null;
  let p;
  try { p = JSON.parse(Buffer.from(b, 'base64url').toString('utf8')); } catch (e) { return null; }
  if (!p || typeof p.exp !== 'number' || Date.now() / 1000 > p.exp) return null;
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
  const c = parseCookies(req);
  const tok = c[COOKIE_NAME];
  if (!tok) return null;
  const p = verifyToken(tok);
  if (!p || !p.u) return null;
  if (p.n && revokedSessionNonces.has(p.n)) return null;
  if (!getUser(p.u)) return null;
  // Reject tokens minted before the current password generation. Tokens
  // without a generation number are pre-migration relics: they must not
  // outlive a password reset either.
  if ((p.v || 0) !== pwdVersion(p.u)) return null;
  return p;
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
function setSession(res, user) {
  res.setHeader('Set-Cookie', cookieHeader(COOKIE_NAME, makeToken(user), { maxAge: SESSION_TTL, path: '/' }));
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
function issueLoginTicket(user, returnTo) {
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
function consumeLoginTicket(ticket) {
  if (!ticket || typeof ticket !== 'string' || ticket.length > 256) return null;
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
  const record = getUser(user);
  if (record && record.admin === true) return '/__gw/admin';
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

// Admin panel data: every user with online status. "online" means a valid
// session was seen within ACTIVE_WINDOW_MS (sessions are stateless cookies, so
// this is last-activity, not a live presence).
function adminUsersPayload() {
  const db = loadUsers();
  const now = Date.now();
  const users = Object.keys(db.users || {}).sort().map((name) => {
    const u = db.users[name];
    const act = activeUsers.get(name);
    return {
      name: name,
      admin: u.admin === true,
      online: !!act && (now - act.at <= ACTIVE_WINDOW_MS),
      lastActiveAt: act ? act.at : null,
      ip: act ? act.ip : null,
      keyConfigured: !!u.keyConfigured,
      created: u.created || null,
    };
  });
  return { ok: true, now: now, onlineCount: users.filter((x) => x.online).length, users: users };
}

function adminPage(csrf) {
  const body = [
    '<div class="card" style="max-width:880px"><div class="brand"><div class="logo">A</div><div><h1>管理控制台</h1><div class="sub">DeepSeek Harness · 在线用户</div></div></div>',
    '<p class="lead" id="stat">加载中…</p>',
    '<table id="tbl"><thead><tr><th>用户</th><th>状态</th><th>IP</th><th>最近活跃</th><th>API Key</th><th>创建时间</th></tr></thead><tbody></tbody></table>',
    '<div class="rule"></div>',
    '<form method="post" action="/logout" style="display:inline"><input type="hidden" name="csrf" value="' + csrf + '"><button type="submit" class="ghost">退出登录</button></form>',
    '<button type="button" class="ghost" id="refresh" style="margin-left:10px">刷新</button>',
    '</div>',
    '<script>',
    'function esc(s){return String(s==null?"":s).replace(/[&<>"]/g,function(c){return{"&":"&amp;","<":"&lt;",">":"&gt;",\'"\':"&quot;"}[c];});}',
    'function fmt(ts){if(!ts)return "-";try{return new Date(ts).toLocaleString();}catch(e){return "-";}}',
    'function load(){fetch("/__gw/admin/users",{credentials:"same-origin"}).then(function(r){return r.json();}).then(function(j){',
    'if(!j.ok){document.getElementById("stat").textContent="加载失败";return;}',
    'document.getElementById("stat").textContent="在线用户："+j.onlineCount+" · 用户总数："+j.users.length;',
    'var tb=document.querySelector("#tbl tbody");tb.innerHTML="";',
    'j.users.forEach(function(u){var tr=document.createElement("tr");',
    'var st=u.online?"<span class=on>● 在线</span>":(u.lastActiveAt?"<span class=off>○ 离线</span>":"<span class=off>○ 从未活跃</span>");',
    'tr.innerHTML="<td>"+esc(u.name)+(u.admin?" <span class=adm>管理员</span>":"")+"</td>"+"<td>"+st+"</td>"+"<td>"+esc(u.ip)+"</td>"+"<td>"+fmt(u.lastActiveAt)+"</td>"+"<td>"+(u.keyConfigured?"已配置":"—")+"</td>"+"<td>"+fmt(u.created)+"</td>";',
    'tb.appendChild(tr);});}).catch(function(){document.getElementById("stat").textContent="加载失败";});}',
    'document.getElementById("refresh").addEventListener("click",load);',
    'load();setInterval(load,10000);',
    '</scr' + 'ipt>',
    '<style>',
    'table{width:100%;border-collapse:collapse;font-size:13px}',
    'th,td{text-align:left;padding:10px;border-bottom:1px solid var(--hairline);color:var(--ink)}',
    'th{color:var(--muted);font-weight:600;letter-spacing:.3px;font-size:12px}',
    '.on{color:var(--ok)}.off{color:var(--faint)}',
    '.adm{color:var(--gold);font-size:11px;border:1px solid var(--hairline);padding:1px 6px;border-radius:6px;margin-left:6px}',
    '.ghost{background:transparent;border:1px solid var(--hairline);border-radius:9px;color:var(--gold);padding:9px 18px;font-size:13px;font-weight:600;cursor:pointer;width:auto;margin-top:0}',
    '.ghost:hover{background:rgba(226,185,97,.08)}',
    '</style>',
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
    const o = Object.assign({ timeoutMs: 15000, maxStdout: 8 * 1024 * 1024 }, opts || {});
    let child;
    try {
      const direct = process.env.DSH_HELPER_DIRECT === '1';
      child = spawn(direct ? args[0] : 'sudo', direct ? args.slice(1) : ['-n'].concat(args), {
        stdio: o.input !== undefined ? ['pipe', 'pipe', 'pipe'] : ['ignore', 'pipe', 'pipe'],
      });
    } catch (e) { return resolve({ code: null, stdout: '', stderr: String(e && e.message || e) }); }
    let out = [];
    let outLen = 0;
    let err = '';
    let done = false;
    const timer = setTimeout(() => { try { child.kill('SIGKILL'); } catch (e) {} }, o.timeoutMs);
    const finish = (code) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      resolve({ code: code, stdout: Buffer.concat(out).toString('utf8'), stderr: err });
    };
    child.stdout.on('data', (c) => {
      outLen += c.length;
      if (outLen <= o.maxStdout) out.push(c);
    });
    child.stderr.on('data', (c) => { err += c.toString('utf8'); });
    child.on('error', () => finish(null));
    child.on('close', (code) => finish(code));
    if (o.input !== undefined) {
      child.stdin.on('error', () => {});
      child.stdin.end(o.input);
    }
  });
}

// Tenant DSH processes are lazy: successful authentication wakes the user's
// instance through the root-only supervisor. Cache readiness for this gateway
// lifetime and coalesce concurrent browser/API/WebSocket requests so one user
// can never spawn duplicate processes.
const readyTenants = new Map(); // username -> stable record marker (port + created)
const wakingTenants = new Map();
const stoppingTenants = new Map();
function ensureTenantInstance(name) {
  const record = getUser(name);
  if (!record || record.admin === true || !record.port) return Promise.reject(new Error('user has no tenant instance'));
  const marker = String(record.port) + ':' + String(record.created || '');
  if (readyTenants.get(name) === marker) return Promise.resolve();
  if (wakingTenants.has(name)) return wakingTenants.get(name);
  const wake = (async () => {
    const controlSocket = path.join(path.dirname(USERS_FILE), 'control.sock');
    const r = await runHelper([REGISTER_HELPER, '--wake', name, controlSocket], {
      timeoutMs: 130000,
      maxStdout: 64 * 1024,
    });
    let reply = null;
    try { reply = JSON.parse(r.stdout); } catch (e) {}
    if (r.code !== 0 || !reply || reply.ok !== true) {
      throw new Error((reply && reply.error) || String(r.stderr || '').trim() || 'tenant startup failed');
    }
    readyTenants.set(name, marker);
  })();
  wakingTenants.set(name, wake);
  return wake.finally(() => wakingTenants.delete(name));
}

function stopTenantInstance(name, reason) {
  if (stoppingTenants.has(name)) return stoppingTenants.get(name);
  const stop = (async () => {
    const controlSocket = path.join(path.dirname(USERS_FILE), 'control.sock');
    const r = await runHelper([REGISTER_HELPER, '--sleep', name, controlSocket, reason || 'logout'], {
      timeoutMs: 150000,
      maxStdout: 64 * 1024,
    });
    let reply = null;
    try { reply = JSON.parse(r.stdout); } catch (e) {}
    if (r.code !== 0 || !reply || reply.ok !== true) {
      throw new Error((reply && reply.error) || String(r.stderr || '').trim() || 'tenant stop failed');
    }
    readyTenants.delete(name);
    usersCacheAt = 0;
    return reply.result;
  })();
  stoppingTenants.set(name, stop);
  return stop.finally(() => stoppingTenants.delete(name));
}

// Browser presence drives automatic process recycling. pagehide/sendBeacon
// handles normal tab closes quickly; heartbeat expiry handles crashes, force
// quits and lost networks. A short zero-tab grace avoids stopping/restarting
// DSH during reloads. Multiple tabs and devices are coalesced per user.
const PRESENCE_HEARTBEAT_MS = 10000;
const PRESENCE_TTL_MS = Math.max(30000, Number(process.env.DSH_BROWSER_PRESENCE_TTL_MS || '120000'));
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
    revokePresenceSessions(user);
    tenantTabs.delete(user);
    activeUsers.delete(user);
    try {
      await stopTenantInstance(user, reason || 'browser-close');
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
// cloned from the native Settings row and placed above Logout + Settings, so
// it follows the sidebar's expanded-label / collapsed-icon geometry exactly.
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
  'function cloneSidebarAction(settings,id,label,title,iconMarkup,onClick,popup){var button=settings.cloneNode(true);button.id=id;button.setAttribute("aria-label",label);button.setAttribute("title",title);button.removeAttribute("aria-expanded");if(popup)button.setAttribute("aria-haspopup","dialog");else button.removeAttribute("aria-haspopup");button.querySelectorAll("[data-slot]").forEach(function(node){node.removeAttribute("data-slot");});var icon=button.querySelector("svg");if(icon){while(icon.firstChild)icon.removeChild(icon.firstChild);icon.setAttribute("viewBox","0 0 16 16");icon.setAttribute("fill","none");icon.setAttribute("aria-hidden","true");icon.innerHTML=iconMarkup;}var labels=button.querySelectorAll("span");if(labels.length)labels[labels.length-1].textContent=label;button.addEventListener("click",function(){onClick(button);});return button;}',
  'function syncSidebarActions(){var slot=document.querySelector("[data-slot=\\"sidebar.settings\\"]");var settings=slot&&slot.querySelector("button");var area=slot&&slot.parentElement;var foot=area&&area.parentElement;if(!settings||!area||!foot)return;var wide=!!settings.querySelector("span");var signature=String(settings.className)+"|"+(wide?"wide":"rail");var files=document.getElementById("dshgw-sidebar-files");var logout=document.getElementById("dshgw-sidebar-logout");if(files&&logout&&files.parentElement===foot&&files.nextElementSibling===logout&&logout.nextElementSibling===area&&files.getAttribute("data-signature")===signature&&logout.getAttribute("data-signature")===signature)return;if(files)files.remove();if(logout)logout.remove();var folderIcon="<path d=\\"M1.75 4.25h4l1.25 1.5h7.25v6.5H1.75z\\" stroke=\\"currentColor\\" stroke-width=\\"1.3\\" stroke-linejoin=\\"round\\"/><path d=\\"M1.75 4.25V3h3.5l1 1.25\\" stroke=\\"currentColor\\" stroke-width=\\"1.3\\" stroke-linejoin=\\"round\\"/>";var powerIcon="<path d=\\"M8 1.5v6\\" stroke=\\"currentColor\\" stroke-width=\\"1.4\\" stroke-linecap=\\"round\\"/><path d=\\"M4.25 3.5a5.25 5.25 0 1 0 7.5 0\\" stroke=\\"currentColor\\" stroke-width=\\"1.4\\" stroke-linecap=\\"round\\"/>";files=cloneSidebarAction(settings,"dshgw-sidebar-files","文件管理","浏览、下载与上传当前工作区的文件",folderIcon,function(){open();},true);logout=cloneSidebarAction(settings,"dshgw-sidebar-logout","退出登录","退出登录并停止当前用户的全部进程",powerIcon,function(button){window.__DSH_GATEWAY_LOGOUT__(button);},false);files.setAttribute("data-signature",signature);logout.setAttribute("data-signature",signature);foot.insertBefore(files,area);foot.insertBefore(logout,area);}',
  'syncSidebarActions();',
  'var mo=new MutationObserver(function(){syncSidebarActions();});',
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
      upstreamRes.on('error', () => { try { res.destroy(); } catch (e) {} });
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
        // UUID shim must run before the SPA bundle: inject right after the
        // opening <head> tag (the DSH client scripts are deferred modules),
        // falling back to the very top of the document when there is no head.
        const headAt = html.toLowerCase().indexOf('<head');
        if (headAt >= 0) {
          const headEnd = html.indexOf('>', headAt);
          html = html.slice(0, headEnd + 1) + BROWSER_BOOTSTRAP + TENANT_LIFECYCLE_SCRIPT + html.slice(headEnd + 1);
        } else {
          html = BROWSER_BOOTSTRAP + TENANT_LIFECYCLE_SCRIPT + html;
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
      if (!settled) { settled = true; if (!res.headersSent) { try { res.writeHead(502, { 'Content-Type': 'text/plain; charset=utf-8' }); } catch (e) {} } }
      try { res.destroy(); } catch (e) {}
    });
    upstreamRes.on('aborted', () => { try { res.destroy(); } catch (e) {} });
  });
  upstreamReq.on('error', (e) => {
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
function proxyUpgrade(req, socket, head, port) {
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
  upstream.on('error', () => socket.destroy());
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
  if (session) markActive(session.u, req);

  if (req.method === 'GET' && STATIC_ASSETS[pathname]) {
    const asset = STATIC_ASSETS[pathname];
    try {
      const data = fs.readFileSync(asset.file);
      res.writeHead(200, { 'Content-Type': asset.type, 'Cache-Control': 'no-cache' });
      return res.end(data);
    } catch (e) { /* fall through to normal handling */ }
  }

  if (pathname === '/__gw/health') return json(res, 200, { ok: true, now: Date.now() });

  if (pathname === '/__gw/status') {
    if (!session) return json(res, 401, { ok: false, user: null });
    return json(res, 200, { ok: true, user: session.u, keyConfigured: hasKey(session.u) });
  }

  // ---------- admin panel (admin account only) ----------
  if (pathname === '/__gw/admin' || pathname === '/__gw/admin/users') {
    const au = session && getUser(session.u);
    if (!session || !au || au.admin !== true) {
      if (req.method === 'GET') return redirect(res, '/login');
      return json(res, 403, { ok: false, error: '需要管理员权限' });
    }
    if (pathname === '/__gw/admin/users') return json(res, 200, adminUsersPayload());
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
        return redirect(res, (su && su.admin) ? '/__gw/admin' : (hasKey(session.u) ? '/' : '/setup'));
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
      const attempt = checkAttempts(req, username);
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
        recordFailure(req, username);
        logLine(req, 401, 'bad-creds ' + username);
        const csrf2 = crypto.randomBytes(16).toString('hex');
        res.setHeader('Set-Cookie', cookieHeader(CSRF_COOKIE, csrf2, { maxAge: 600, path: '/', sameSite: 'Lax' }));
        secHeaders(res);
        res.writeHead(401, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
        return res.end(loginPage(csrf2, '用户名或密码错误'));
      }
      recordSuccess(req, username);
      if (!u.admin) {
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
      if (u.admin) return redirect(res, '/__gw/admin');
      return redirect(res, hasKey(username) ? '/' : '/setup');
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
      const locked = lockedUntil(registerFails, ip);
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
      // which strips custom env vars (env_reset), so it cannot rely on
      // DSH_GATEWAY_STATE_DIR. The socket lives next to users.json.
      const regSocket = path.join(path.dirname(USERS_FILE), 'control.sock');
      const r = await runHelper([REGISTER_HELPER, username, regSocket], { input: password, timeoutMs: 130000, maxStdout: 64 * 1024 });
      let reply = null;
      try { reply = JSON.parse(r.stdout); } catch (e) {}
      if (r.code !== 0 || !reply || reply.ok !== true) {
        registerFailure(registerFails, ip, MAX_REGISTER_ATTEMPTS);
        const detail = (reply && reply.error) || String(r.stderr || '').trim() || '注册失败，请稍后重试';
        logLine(req, 200, 'register-fail ' + username + ' ' + detail.slice(0, 160));
        return renderErr(detail);
      }
      // The supervisor has persisted the user; drop the gateway's users cache
      // so the immediate redirect and any follow-up login see it right away.
      usersCacheAt = 0;
      registerFails.delete(ip);
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
    const ticket = issueLoginTicket(username, returnTo);
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
    const login = consumeLoginTicket(ticket);
    if (!login || !getUser(login.user)) {
      logLine(req, 302, 'external-login invalid');
      return redirect(res, '/login');
    }
    const loginUser = getUser(login.user);
    if (!loginUser.admin) {
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
    const regSocket = path.join(path.dirname(USERS_FILE), 'control.sock');
    const r = await runHelper([REGISTER_HELPER, username, regSocket], { input: password, timeoutMs: 130000, maxStdout: 64 * 1024 });
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
    const u = getUser(name);
    if (!u || !u.port) return json(res, 404, { ok: false, error: 'user not found' });
    if (u.admin === true) return json(res, 400, { ok: false, error: 'admin has no instance' });
    const regSocket = path.join(path.dirname(USERS_FILE), 'control.sock');
    const r = await runHelper(
      [PROVIDER_HELPER, name, regSocket, JSON.stringify({ name: pname, baseURL, api: papi, models })],
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
    return json(res, 200, { ok: true, user: name, provider: reply.result.provider, ref: ref, models: models });
  }

  if (pathname === '/__gw/presence') {
    if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'method not allowed' });
    if (!session) return json(res, 401, { ok: false, error: 'not logged in' });
    const presenceUser = getUser(session.u);
    if (!presenceUser || presenceUser.admin === true) return json(res, 204, {});
    let body = '';
    try { body = await readBody(req, 4096); } catch (e) { return json(res, 413, { ok: false, error: 'payload too large' }); }
    const form = parseForm(body);
    const tabId = String(form.tab || '');
    const event = String(form.event || 'heartbeat');
    if (!/^[A-Za-z0-9_-]{8,128}$/.test(tabId) || !['open', 'heartbeat', 'close'].includes(event)) {
      return json(res, 400, { ok: false, error: 'invalid presence event' });
    }
    updateTenantPresence(session, tabId, event);
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
      if (logoutUser && logoutUser.admin !== true) {
        try {
          await stopTenantInstance(session.u, 'manual-logout');
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
        activeUsers.delete(session.u);
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
      setUserKeyFlag(session.u, true);
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
    if (!name || name.length > 200 || name.indexOf('\0') >= 0 || /[\/\\]/.test(name) || name === '.' || name === '..' || name.startsWith('.') || /[\x00-\x1f\x7f]/.test(name)) {
      return json(res, 400, { ok: false, error: '文件名不合法' });
    }
    // True streaming: the request body is piped straight into the root
    // helper's stdin (which demotes to dsh-<name> before writing) with
    // backpressure - constant memory regardless of file size. Completeness is
    // enforced end-to-end: we require Content-Length and tell the helper the
    // exact byte count ("BYTES <n>\n" protocol); the helper refuses to commit
    // a short stream (exit 6), so an aborted / timed-out / oversized upload
    // can never leave a truncated file behind.
    const LIMIT = UPLOAD_MAX_MB * 1024 * 1024;
    const contentLength = parseInt(req.headers['content-length'] || '', 10);
    if (!Number.isFinite(contentLength) || contentLength < 0) return json(res, 411, { ok: false, error: '缺少 Content-Length' });
    if (contentLength > LIMIT) return json(res, 413, { ok: false, error: '文件过大（上限 ' + UPLOAD_MAX_MB + ' MB）' });
    let saved = { ok: false, status: 500, detail: '上传失败' };
    {
      const r = await new Promise((resolve) => {
        let child;
        try {
          child = spawn('sudo', ['-n', UPLOAD_HELPER, home, dirAbs, name], { stdio: ['pipe', 'ignore', 'pipe'] });
        } catch (e) { return resolve({ code: null, stderr: String((e && e.message) || e) }); }
        let stderr = '';
        let done = false;
        let over = false;      // gateway-side cap tripped mid-stream (defence in depth)
        let timedOut = false;
        let aborted = false;
        let reqEnded = false;
        let paused = false;
        let size = 0;
        const finish = (code) => {
          if (done) return;
          done = true;
          clearTimeout(timer);
          // Close our end of the pipe so an orphaned helper (sudo killed on
          // timeout/abort) sees EOF, verifies its byte count, and lets the
          // EXIT trap clean the temp file.
          try { child.stdin.destroy(); } catch (e) {}
          resolve({ code: code, stderr: stderr, over: over, timedOut: timedOut, aborted: aborted });
        };
        const timer = setTimeout(() => { timedOut = true; try { child.kill('SIGKILL'); } catch (e) {} }, 600000);
        child.stderr.on('data', (c) => { stderr += c.toString('utf8'); });
        child.on('error', () => finish(null));
        child.on('close', (code) => finish(code));
        child.stdin.on('error', () => {}); // EPIPE when the helper rejected args early
        try { child.stdin.write('BYTES ' + contentLength + '\n'); } catch (e) {}
        req.on('data', (c) => {
          if (done || over) return; // over: draining the remainder of a doomed body
          size += c.length;
          if (size > LIMIT) {
            over = true;
            try { child.kill('SIGKILL'); } catch (e) {}
            finish(null);
            req.resume();
            return;
          }
          let writable = true;
          try { writable = child.stdin.write(c); } catch (e) { writable = false; }
          if (!writable && !paused) { paused = true; req.pause(); }
        });
        child.stdin.on('drain', () => { if (paused && !done && !over) { paused = false; req.resume(); } });
        req.on('end', () => { reqEnded = true; if (!done && !over) { try { child.stdin.end(); } catch (e) {} } });
        req.on('error', () => { if (!done) { aborted = true; try { child.kill('SIGKILL'); } catch (e) {} finish(null); } });
        req.on('close', () => { if (!done && !reqEnded) { aborted = true; try { child.kill('SIGKILL'); } catch (e) {} finish(null); } });
      });
      if (r.over) saved = { ok: false, status: 413, detail: '文件过大（上限 ' + UPLOAD_MAX_MB + ' MB）' };
      else if (r.timedOut) saved = { ok: false, status: 504, detail: '上传超时' };
      else if (r.aborted) saved = { ok: false, status: 400, detail: '上传中断' };
      else if (r.code === 0) saved = { ok: true, status: 200, detail: '' };
      else if (r.code === 2) saved = { ok: false, status: 400, detail: '文件名不合法' };
      else if (r.code === 3) saved = { ok: false, status: 403, detail: '目标目录超出你的工作区' };
      else if (r.code === 4) saved = { ok: false, status: 404, detail: '目标目录不存在' };
      else if (r.code === 5) saved = { ok: false, status: 413, detail: '文件过大' };
      else if (r.code === 6) saved = { ok: false, status: 400, detail: '上传中断（数据不完整）' };
      else saved = { ok: false, status: 500, detail: '写入失败：' + ((r.stderr && r.stderr.split('\n')[0]) ? String(r.stderr).split('\n')[0] : '未知错误') };
    }
    if (!saved.ok) return json(res, saved.status, { ok: false, error: saved.detail });
    const target = path.join(dirAbs, name);
    logLine(req, 200, 'upload ' + path.relative(home, target));
    return json(res, 200, { ok: true, path: target, name: name });
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
      const child = spawn('sudo', ['-n', FILE_READ_HELPER, home, abs], { stdio: ['ignore', 'pipe', 'ignore'] });
      let started = false;
      child.stdout.on('data', (c) => {
        if (!started) { res.writeHead(200, head); started = true; }
        res.write(c);
      });
      child.on('error', () => { try { res.destroy(); } catch (e) {} });
      child.on('exit', (code) => {
        if (!started) {
          if (code === 3) return json(res, 403, { ok: false, error: '路径超出你的工作区' });
          if (code === 5) return json(res, 403, { ok: false, error: '不允许下载隐藏文件' });
          return json(res, 404, { ok: false, error: '文件不存在' });
        }
        res.end();
        logLine(req, 200, 'download ' + path.relative(home, abs));
      });
      req.on('error', () => { try { child.kill(); } catch (e) {} });
      res.on('close', () => { try { child.kill(); } catch (e) {} });
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
        rows.push('<a class="row" href="/__gw/files?dir=' + encodeURIComponent(p) + '"><span class="ic">&#128193;</span><span class="nm">' + esc(e.name) + '/</span><span class="sz"></span></a>');
      } else {
        rows.push('<div class="row"><span class="ic">&#128196;</span><span class="nm">' + esc(e.name) + '</span><span class="sz">' + (e.size >= 0 ? fmtSize(e.size) : '') + '</span><a class="dl" href="/__gw/download?path=' + encodeURIComponent(p) + '">下载</a></div>');
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
      '.ic{width:20px;text-align:center}.nm{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}',
      '.sz{color:#94a3b8;font-size:12px;white-space:nowrap;font-variant-numeric:tabular-nums}',
      '.dl{color:#2563eb;text-decoration:none;font-size:12.5px;font-weight:600;white-space:nowrap;padding:5px 12px;border:1px solid #dbeafe;border-radius:8px;background:#eff6ff}',
      '.dl:hover{background:#dbeafe}',
      '.empty{color:#64748b;font-size:13px;padding:20px 14px;margin:0}',
      '.upbar{display:flex;gap:10px;align-items:center;margin-bottom:10px}',
      '.upbar input[type=file]{flex:1;width:auto;background:#f8fafc;border:1px dashed #cbd5e1;border-radius:10px;color:#64748b;font-size:12.5px;padding:9px 12px}',
      '.upbar input[type=file]:focus-visible{outline:2px solid #2563eb;outline-offset:2px}',
      '.upbar button{margin-top:0;width:auto;padding:9px 18px;font-size:13px;font-weight:600;background:#2563eb;color:#fff;border-radius:10px}',
      '.upbar button:hover{filter:none;background:#1d4ed8}',
      '.upbar button:focus-visible{outline:2px solid #2563eb;outline-offset:2px}',
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
  if (u && u.admin) {
    // Admin has no DSH instance; send every page request to the panel.
    if (req.method === 'GET' && !pathname.startsWith('/api/')) return redirect(res, '/__gw/admin');
    return json(res, 403, { ok: false, error: '管理员账号不提供实例访问' });
  }
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
  const session = getSession(req);
  if (!session) { socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n'); socket.destroy(); return; }
  if (!hasKey(session.u)) { socket.write('HTTP/1.1 403 Forbidden\r\n\r\n'); socket.destroy(); return; }
  const u = getUser(session.u);
  if (!u || !u.port) { socket.destroy(); return; }
  try { await ensureTenantInstance(session.u); } catch (error) {
    socket.write('HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n');
    socket.destroy();
    return;
  }
  proxyUpgrade(req, socket, head, u.port);
});

server.listen(PORT, HOST, () => {
  console.log('dsh-gateway listening on ' + HOST + ':' + PORT);
});

// Graceful shutdown: stop accepting, let in-flight proxies/uploads finish.
function shutdown() {
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 10000).unref();
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
