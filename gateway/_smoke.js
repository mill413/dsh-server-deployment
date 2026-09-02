'use strict';
const fs = require('fs');
const path = require('path');
const os = require('os');
const http = require('http');
const { execFileSync } = require('child_process');
const { hashPassword } = require('./auth.js');

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'dshgw-'));
const USERS_DIR = path.join(TMP, 'users');
const USERS_FILE = path.join(TMP, 'users.json');
const TENANT_HELPER = path.join(TMP, 'dsh-register-test-helper');
const TENANT_HELPER_LOG = path.join(TMP, 'dsh-register-test-helper.log');
const FILE_LIST_TEST_HELPER = path.join(TMP, 'dsh-file-list-test-helper');
const FILE_DELETE_TEST_HELPER = path.join(TMP, 'dsh-file-delete-test-helper');
const FILE_DELETE_TEST_LOG = path.join(TMP, 'dsh-file-delete-test-helper.log');
const FILE_MKDIR_TEST_HELPER = path.join(TMP, 'dsh-file-mkdir-test-helper');
const FILE_MKDIR_TEST_LOG = path.join(TMP, 'dsh-file-mkdir-test-helper.log');
const FILE_STAT_TEST_HELPER = path.join(TMP, 'dsh-file-stat-test-helper');
const FILE_READ_TEST_HELPER = path.join(TMP, 'dsh-file-read-test-helper');
const FILE_PUT_TEST_HELPER = path.join(TMP, 'dsh-file-put-test-helper');
const CONTROL_SOCKET = path.join(TMP, 'run', 'control.sock');
const PLUGIN_TARBALL_DIR = path.join(TMP, 'plugin-tarballs');
const TEST_TARBALL = path.join(TMP, 'offline-plugin-1.0.0.tgz');
const packageDir = path.join(TMP, 'pack', 'package');
fs.mkdirSync(path.join(USERS_DIR, 'tester'), { recursive: true });
fs.mkdirSync(path.join(USERS_DIR, 'nokey'), { recursive: true });
fs.mkdirSync(path.join(USERS_DIR, 'admin'), { recursive: true });
fs.mkdirSync(packageDir, { recursive: true });
fs.writeFileSync(path.join(packageDir, 'package.json'), JSON.stringify({
  name: 'offline-plugin',
  version: '1.0.0',
  dsh: { bundle: { patch: './cordis.patch.yml' } },
}));
fs.writeFileSync(path.join(packageDir, 'cordis.patch.yml'), '[]\n');
execFileSync('/usr/bin/tar', ['-czf', TEST_TARBALL, '-C', path.join(TMP, 'pack'), 'package']);
// The production gateway reaches the root supervisor through dsh-register for
// lazy wake/sleep. This standalone smoke test already owns a mock upstream, so
// use a tiny successful control helper instead of invoking host sudo.
fs.writeFileSync(TENANT_HELPER, [
  '#!/bin/sh',
  'EXPECTED_SOCKET=' + JSON.stringify(CONTROL_SOCKET),
  'printf \'%s\\n\' "$*" >> ' + JSON.stringify(TENANT_HELPER_LOG),
  'case "$1" in',
  '  --wake|--sleep) ACTUAL_SOCKET="$3" ;;',
  '  --plugin-add) ACTUAL_SOCKET="$4" ;;',
  '  --plugin-remove) ACTUAL_SOCKET="$3" ;;',
  '  *) ACTUAL_SOCKET="$2" ;;',
  'esac',
  '[ "$ACTUAL_SOCKET" = "$EXPECTED_SOCKET" ] || { echo "unexpected control socket: $ACTUAL_SOCKET" >&2; exit 9; }',
  'if [ "$1" = "tester" ] && [ -n "${3:-}" ]; then',
  '  printf \'%s\\n\' \'{"ok":true,"result":{"provider":{"apiKeyEnv":"VISION_GATEWAY_API_KEY"}}}\'',
  '  exit 0',
  'fi',
  'case "$1" in',
  '  --stats) printf \'%s\\n\' \'{"ok":true,"result":{"tester":{"running":true,"processCount":2,"rssBytes":104857600},"admin":{"running":true,"processCount":1,"rssBytes":52428800}}}\' ;;',
  '  --plugin-list) printf \'%s\\n\' \'{"ok":true,"result":[{"name":"dsh-better-sidebar","version":"0.15.2","source":"image","dir":"/opt/shared"}]}\' ;;',
  '  --plugin-add) printf \'%s\\n\' \'{"ok":true,"result":{"name":"test-plugin","users":3,"restarted":1}}\' ;;',
  '  --plugin-remove) printf \'%s\\n\' \'{"ok":true,"result":{"name":"test-plugin","users":3,"restarted":1}}\' ;;',
  '  *) printf \'%s\\n\' \'{"ok":true,"result":{"started":true}}\' ;;',
  'esac',
  '',
].join('\n'), { mode: 0o755 });
const testerWorkspace = path.join(USERS_DIR, 'tester', 'workspace');
fs.mkdirSync(path.join(testerWorkspace, 'empty-dir'), { recursive: true });
fs.writeFileSync(path.join(testerWorkspace, 'result.txt'), 'result');
fs.writeFileSync(FILE_LIST_TEST_HELPER, [
  '#!/bin/sh',
  'printf \'%s\\n\' ' + JSON.stringify(JSON.stringify({
    home: testerWorkspace,
    dir: testerWorkspace,
    truncated: false,
    entries: [
      { name: 'empty-dir', dir: true, size: -1, mtime: 0 },
      { name: 'result.txt', dir: false, size: 6, mtime: 0 },
    ],
  })),
  '',
].join('\n'), { mode: 0o755 });
fs.writeFileSync(FILE_DELETE_TEST_HELPER, [
  '#!/bin/sh',
  'printf \'%s\\n\' "$*" >> ' + JSON.stringify(FILE_DELETE_TEST_LOG),
  'printf \'%s\\n\' \'{"ok":true,"type":"file"}\'',
  '',
].join('\n'), { mode: 0o755 });
fs.writeFileSync(FILE_MKDIR_TEST_HELPER, [
  '#!/bin/sh',
  'printf \'%s\\n\' "$*" >> ' + JSON.stringify(FILE_MKDIR_TEST_LOG),
  'printf \'%s\\n\' \'{"ok":true}\'',
  '',
].join('\n'), { mode: 0o755 });
fs.writeFileSync(FILE_STAT_TEST_HELPER, [
  '#!/bin/sh',
  'case "$2" in',
  '  *empty.txt) printf \'0\\n\' ;;',
  '  *) printf \'6\\n\' ;;',
  'esac',
  '',
].join('\n'), { mode: 0o755 });
fs.writeFileSync(FILE_READ_TEST_HELPER, [
  '#!/bin/sh',
  'case "$2" in',
  '  *empty.txt) exit 0 ;;',
  '  *) printf result ;;',
  'esac',
  '',
].join('\n'), { mode: 0o755 });
fs.writeFileSync(FILE_PUT_TEST_HELPER, [
  '#!/bin/sh',
  'read -r magic bytes',
  '[ "$magic" = "BYTES" ] || exit 2',
  'head -c "$bytes" > "$2/$3"',
  '[ "$(wc -c < "$2/$3")" -eq "$bytes" ] || exit 6',
  '',
].join('\n'), { mode: 0o755 });

const users = {
  version: 1,
  users: {
    tester: { port: 3999, home: path.join(USERS_DIR, 'tester'), osUser: 'ubuntu', pwd: hashPassword('secret123'), keyConfigured: true },
    nokey: { port: 3999, home: path.join(USERS_DIR, 'nokey'), osUser: 'ubuntu', pwd: hashPassword('secret123'), keyConfigured: false },
    admin: { admin: true, port: 3999, home: path.join(USERS_DIR, 'admin'), osUser: 'ubuntu', pwd: hashPassword('adminsecret'), keyConfigured: true },
  },
};
fs.writeFileSync(USERS_FILE, JSON.stringify(users));

process.env.HOST = '127.0.0.1';
process.env.PORT = '3998';
process.env.USERS_FILE = USERS_FILE;
process.env.DSH_CONTROL_SOCKET = CONTROL_SOCKET;
process.env.SECRET_FILE = path.join(TMP, 'secret');
process.env.USERS_DIR = USERS_DIR;
process.env.COOKIE_SECURE = '0';
process.env.DSH_LOGIN_API_KEY = 'login-test-token';
process.env.DSH_REGISTER_API_KEY = 'register-test-token';
process.env.DSH_REGISTER_HELPER = TENANT_HELPER;
process.env.DSH_PROVIDER_HELPER = TENANT_HELPER;
process.env.FILE_LIST_HELPER = FILE_LIST_TEST_HELPER;
process.env.FILE_DELETE_HELPER = FILE_DELETE_TEST_HELPER;
process.env.FILE_MKDIR_HELPER = FILE_MKDIR_TEST_HELPER;
process.env.FILE_STAT_HELPER = FILE_STAT_TEST_HELPER;
process.env.FILE_READ_HELPER = FILE_READ_TEST_HELPER;
process.env.UPLOAD_HELPER = FILE_PUT_TEST_HELPER;
process.env.DSH_HELPER_DIRECT = '1';
process.env.DSH_BROWSER_STOP_GRACE_MS = '1000';
process.env.SESSION_TTL = '60';
process.env.SESSION_REFRESH_INTERVAL = '1';
process.env.DSH_PLUGIN_TARBALL_DIR = PLUGIN_TARBALL_DIR;
process.env.PLUGIN_TARBALL_MAX_MB = '10';
process.env.DEEPSEEK_BASE_URL = 'http://127.0.0.1:3999';

const tenantRpcCalls = [];
const muxSockets = new Set();
function websocketTextFrame(value) {
  const payload = Buffer.from(value);
  if (payload.length < 126) return Buffer.concat([Buffer.from([0x81, payload.length]), payload]);
  const header = Buffer.alloc(4);
  header[0] = 0x81;
  header[1] = 126;
  header.writeUInt16BE(payload.length, 2);
  return Buffer.concat([header, payload]);
}
function pushMux(payload) {
  const full = JSON.stringify({ type: 'server-request', rpcId: 'mux-' + Date.now(), method: payload.type, payload });
  const frame = websocketTextFrame(full);
  for (const socket of muxSockets) socket.write(frame);
}
const upstream = http.createServer((req, res) => {
  if (req.method === 'POST' && req.url.startsWith('/api/')) {
    let body = '';
    req.on('data', (c) => body += c);
    req.on('end', () => {
      let rpcId = 'x';
      let message = {};
      try { message = JSON.parse(body); rpcId = message.rpcId || 'x'; } catch (e) {}
      tenantRpcCalls.push({ path: req.url, message });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      if (req.url === '/api/session.create') {
        return res.end(JSON.stringify({ type: 'server-response', rpcId, result: { ok: true, value: { sessionId: 'api-created-session' } } }));
      }
      if (req.url === '/api/session.prompt') {
        res.end(JSON.stringify({ type: 'server-response', rpcId, result: { ok: true, value: { accepted: true } } }));
        if (muxSockets.size > 0) setTimeout(() => {
          const sessionId = message.payload.sessionId;
          pushMux({ type: 'session/event', sessionId, event: { type: 'user/message', seq: 10, time: Date.now(), data: { id: 'u1', role: 'user', content: [{ type: 'text', text: message.payload.content[0].text }], source: { kind: 'user', rpcId } } } });
          pushMux({ type: 'session/event', sessionId, event: { type: 'assistant/chunk', seq: 11, time: Date.now(), data: { turn: 1, step: 0, chunk: { type: 'text-delta', index: 0, text: '流式回复' } } } });
          pushMux({ type: 'session/event', sessionId, event: { type: 'assistant/message', seq: 12, time: Date.now(), data: { turn: 1, step: 0, message: { id: 'a1', role: 'assistant', content: [{ type: 'text', text: '流式回复' }], source: { kind: 'model', provider: 'test', model: 'test' } } } } });
          pushMux({ type: 'session/event', sessionId, event: { type: 'turn/end', seq: 13, time: Date.now(), data: { turn: 1, reason: { kind: 'completed' } } } });
        }, 10);
        return;
      }
      if (req.url === '/api/session.history') {
        return res.end(JSON.stringify({ type: 'server-response', rpcId, result: { ok: true, value: {
          events: [
            { event: { type: 'user/message', seq: 1, time: 100, data: { id: 'u-history', role: 'user', content: [{ type: 'text', text: '历史问题' }], source: { kind: 'user' } } } },
            { event: { type: 'assistant/message', seq: 2, time: 200, data: { turn: 1, step: 0, message: { id: 'a-history', role: 'assistant', content: [{ type: 'text', text: '历史回答' }], source: { kind: 'model', provider: 'test', model: 'test' } } } } },
          ],
          hasMore: false,
        } } }));
      }
      if (req.url === '/api/session.list') {
        return res.end(JSON.stringify({ type: 'server-response', rpcId, result: { ok: true, value: {
          items: [
            { sessionId: 'existing-session', updatedAt: 200, running: true, blank: false, cwd: testerWorkspace },
            { sessionId: 'older-session', updatedAt: 100, running: false, blank: false, cwd: testerWorkspace },
          ],
        } } }));
      }
      res.end(JSON.stringify({ type: 'server-response', rpcId, result: { ok: true, value: {} } }));
    });
    return;
  }
  if (req.url === '/models') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end('{"data":[{"id":"text-model"},{"id":"vision-model"}]}');
    return;
  }
  res.writeHead(200, { 'Content-Type': 'text/html' });
  res.end('UPSTREAM-OK ' + req.url);
});
upstream.on('upgrade', (req, socket) => {
  if (req.url !== '/api/events.mux') return socket.destroy();
  const accept = require('crypto').createHash('sha1')
    .update(String(req.headers['sec-websocket-key']) + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')
    .digest('base64');
  socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + accept + '\r\n\r\n');
  muxSockets.add(socket);
  socket.on('close', () => muxSockets.delete(socket));
  socket.on('error', () => muxSockets.delete(socket));
});
upstream.listen(3999, '127.0.0.1');

require('./server.js');

function req(method, pathname, opts) {
  return new Promise((resolve, reject) => {
    opts = opts || {};
    const headers = Object.assign({}, opts.headers || {});
    const body = opts.body;
    if (body && !headers['Content-Type']) headers['Content-Type'] = 'application/x-www-form-urlencoded';
    if (body) headers['Content-Length'] = Buffer.byteLength(body);
    const r = http.request({ host: '127.0.0.1', port: 3998, method: method, path: pathname, headers: headers }, (res) => {
      let data = '';
      res.on('data', (c) => data += c);
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    r.on('error', reject);
    if (body) r.write(body);
    r.end();
  });
}
function cookies(setCookie) {
  const out = {};
  if (!setCookie) return out;
  const arr = Array.isArray(setCookie) ? setCookie : [setCookie];
  for (const c of arr) {
    const kv = c.split(';')[0].trim();
    const i = kv.indexOf('=');
    if (i > 0) out[kv.slice(0, i)] = kv.slice(i + 1);
  }
  return out;
}

let pass = 0, fail = 0;
function check(name, cond) {
  if (cond) { pass++; console.log('PASS ' + name); }
  else { fail++; console.log('FAIL ' + name); }
}

(async () => {
  await new Promise((r) => setTimeout(r, 500));
  let r;

  r = await req('GET', '/__gw/health');
  check('health 200', r.status === 200 && r.body.indexOf('"ok":true') >= 0);
  r = await req('GET', '/__gw/status');
  check('status reports missing session reason', r.status === 401
    && JSON.parse(r.body).reason === 'missing-cookie');

  const providerHeaders = { Authorization: 'Bearer register-test-token', 'Content-Type': 'application/json' };
  r = await req('POST', '/api/users/tester/message', {
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message: 'unauthorized' }),
  });
  check('direct message requires bearer token', r.status === 401);
  r = await req('POST', '/api/users/missing/message', {
    headers: providerHeaders,
    body: JSON.stringify({ message: 'hello' }),
  });
  check('direct message rejects unknown user', r.status === 404);
  r = await req('POST', '/api/users/tester/message', {
    headers: providerHeaders,
    body: JSON.stringify({ message: 'API 新会话消息' }),
  });
  const newMessageReply = JSON.parse(r.body);
  const createCall = tenantRpcCalls.find((call) => call.path === '/api/session.create');
  const newPromptCall = tenantRpcCalls.find((call) => call.path === '/api/session.prompt');
  check('direct message creates a session and queues the prompt', r.status === 202
    && newMessageReply.sessionId === 'api-created-session'
    && newMessageReply.created === true
    && createCall.message.method === 'session.create'
    && newPromptCall.message.payload.content[0].text === 'API 新会话消息'
    && newPromptCall.message.payload.mode === 'queue');
  r = await req('POST', '/api/users/tester/message', {
    headers: providerHeaders,
    body: JSON.stringify({ message: '插入运行中的会话', sessionId: 'existing-session', mode: 'steer' }),
  });
  const existingMessageReply = JSON.parse(r.body);
  const lastPromptCall = tenantRpcCalls.filter((call) => call.path === '/api/session.prompt').pop();
  check('direct message can steer an existing session', r.status === 202
    && existingMessageReply.sessionId === 'existing-session'
    && existingMessageReply.created === false
    && lastPromptCall.message.payload.sessionId === 'existing-session'
    && lastPromptCall.message.payload.mode === 'steer');

  r = await req('GET', '/api/users/tester/sessions');
  check('session list requires bearer token', r.status === 401);
  r = await req('GET', '/api/users/tester/sessions', {
    headers: { Authorization: 'Bearer register-test-token' },
  });
  const sessionsReply = JSON.parse(r.body);
  check('session list returns stable session summaries', r.status === 200
    && sessionsReply.user === 'tester'
    && sessionsReply.sessions.length === 2
    && sessionsReply.sessions[0].sessionId === 'existing-session'
    && sessionsReply.sessions[0].running === true
    && sessionsReply.sessions[1].sessionId === 'older-session');

  r = await req('GET', '/api/users/tester/messages?sessionId=existing-session&maxMessages=20', {
    headers: { Authorization: 'Bearer register-test-token' },
  });
  const historyReply = JSON.parse(r.body);
  check('message history returns user and assistant messages', r.status === 200
    && historyReply.messages.length === 2
    && historyReply.messages[0].role === 'user'
    && historyReply.messages[0].message.content[0].text === '历史问题'
    && historyReply.messages[1].role === 'assistant'
    && historyReply.nextBeforeSeq === 1);

  r = await req('POST', '/api/users/tester/message', {
    headers: { ...providerHeaders, Accept: 'text/event-stream' },
    body: JSON.stringify({ message: '请流式回复', sessionId: 'stream-session', stream: true }),
  });
  check('direct message streams the correlated DSH turn as SSE', r.status === 200
    && /^text\/event-stream/.test(r.headers['content-type'])
    && r.body.indexOf('event: accepted') >= 0
    && r.body.indexOf('event: assistant.chunk') >= 0
    && r.body.indexOf('流式回复') >= 0
    && r.body.indexOf('event: assistant.message') >= 0
    && r.body.indexOf('event: done') >= 0);

  r = await req('POST', '/api/users/tester/files?name=machine-upload.txt', {
    headers: { Authorization: 'Bearer register-test-token', 'Content-Type': 'application/octet-stream' },
    body: Buffer.from('machine-upload-body'),
  });
  const uploadReply = JSON.parse(r.body);
  check('machine API uploads a raw file into the user workspace', r.status === 201
    && uploadReply.bytes === 19
    && fs.readFileSync(path.join(testerWorkspace, 'machine-upload.txt'), 'utf8') === 'machine-upload-body');

  r = await req('POST', '/api/users/tester/provider', {
    headers: providerHeaders,
    body: JSON.stringify({
      provider: { name: 'vision-gateway', baseURL: 'http://127.0.0.1:3999' },
      apiKey: 'sk-provider-test',
      image_models: ['vision-model'],
      model_limits: [
        { id: 'text-model', context_window: 131072, max_tokens: 16384 },
        { id: 'missing-model', context_window: 65536, max_tokens: 4096 },
      ],
    }),
  });
  const providerReply = JSON.parse(r.body);
  const providerLog = fs.readFileSync(TENANT_HELPER_LOG, 'utf8');
  check('provider image_models registration succeeds', r.status === 200
    && providerReply.image_models[0] === 'vision-model');
  check('provider model_limits registration succeeds', r.status === 200
    && providerReply.model_limits[0].id === 'text-model'
    && providerReply.model_limits[0].context_window === 131072
    && providerReply.model_limits[0].max_tokens === 16384
    && providerReply.model_limits[1].id === 'missing-model');
  check('provider helper receives text-only model input', providerLog.indexOf('"id":"text-model","input":["text"]') >= 0);
  check('provider helper receives image model input', providerLog.indexOf('"id":"vision-model","input":["text","image"]') >= 0);
  check('provider helper receives matched model limits', providerLog.indexOf('"id":"text-model","input":["text"],"contextWindow":131072,"maxTokens":16384') >= 0);
  check('provider ignores unmatched model_limits entries', providerLog.indexOf('"id":"missing-model"') < 0);

  r = await req('POST', '/api/users/tester/provider', {
    headers: providerHeaders,
    body: JSON.stringify({
      provider: { name: 'vision-gateway', baseURL: 'http://127.0.0.1:3999', image_models: ['missing-model'] },
      apiKey: 'sk-provider-test',
    }),
  });
  const unknownImageReply = JSON.parse(r.body);
  check('provider treats image_models as an unchecked allowlist', r.status === 200
    && unknownImageReply.image_models[0] === 'missing-model');

  r = await req('POST', '/api/users/tester/provider', {
    headers: providerHeaders,
    body: JSON.stringify({
      provider: { name: 'vision-gateway', baseURL: 'http://127.0.0.1:3999', models: ['vision-model'] },
      apiKey: 'sk-provider-test',
    }),
  });
  const defaultImageReply = JSON.parse(r.body);
  const defaultImageLog = fs.readFileSync(TENANT_HELPER_LOG, 'utf8').trim().split('\n').pop();
  check('provider defaults image_models to an empty allowlist', r.status === 200
    && Array.isArray(defaultImageReply.image_models) && defaultImageReply.image_models.length === 0
    && defaultImageLog.indexOf('"id":"vision-model","input":["text"],"contextWindow":32768,"maxTokens":8192') >= 0);
  check('provider defaults model_limits to an empty allowlist', r.status === 200
    && Array.isArray(defaultImageReply.model_limits) && defaultImageReply.model_limits.length === 0);

  r = await req('POST', '/api/users/tester/provider', {
    headers: providerHeaders,
    body: JSON.stringify({
      provider: { name: 'vision-gateway', baseURL: 'http://127.0.0.1:3999' },
      apiKey: 'sk-provider-test',
      model_limits: [
        { id: 'text-model', max_tokens: 4096 },
        { id: 'text-model', context_window: 65536 },
      ],
    }),
  });
  check('provider rejects duplicate model_limits ids', r.status === 400);

  r = await req('POST', '/api/users/tester/provider', {
    headers: providerHeaders,
    body: JSON.stringify({
      provider: { name: 'vision-gateway', baseURL: 'http://127.0.0.1:3999' },
      apiKey: 'sk-provider-test',
      model_limits: [{ id: 'text-model', context_window: 4096, max_tokens: 8192 }],
    }),
  });
  check('provider rejects max_tokens above context_window', r.status === 400);

  r = await req('POST', '/api/login-ticket', {
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'tester' }),
  });
  check('login ticket requires bearer token', r.status === 401);

  const loginApiHeaders = { Authorization: 'Bearer login-test-token', 'Content-Type': 'application/json' };
  r = await req('POST', '/api/login-ticket', {
    headers: loginApiHeaders,
    body: JSON.stringify({ username: 'tester', returnTo: 'https://evil.example/' }),
  });
  check('login ticket rejects external returnTo', r.status === 400);

  r = await req('POST', '/api/login-ticket', {
    headers: loginApiHeaders,
    body: JSON.stringify({ username: 'tester', returnTo: '/some/path?from=sso' }),
  });
  const issued = JSON.parse(r.body);
  check('login ticket issued', r.status === 200 && issued.ok === true && /^\/auth\/external\?ticket=/.test(issued.loginUrl) && issued.expiresIn === 60);
  r = await req('GET', issued.loginUrl);
  check('login ticket sets session and redirects', r.status === 302 && r.headers.location === '/some/path?from=sso' && !!cookies(r.headers['set-cookie'])['dsh_session']);
  const externalSess = cookies(r.headers['set-cookie'])['dsh_session'];
  r = await req('GET', issued.loginUrl);
  check('login ticket cannot be replayed', r.status === 302 && r.headers.location === '/login');
  r = await req('GET', '/some/path', { headers: { Cookie: 'dsh_session=' + externalSess } });
  check('external login session works', r.status === 200 && r.body.indexOf('UPSTREAM-OK /some/path') >= 0);

  r = await req('POST', '/api/login-ticket', {
    headers: loginApiHeaders,
    body: JSON.stringify({ username: 'nokey', returnTo: '/some/path' }),
  });
  const noKeyIssued = JSON.parse(r.body);
  r = await req('GET', noKeyIssued.loginUrl);
  check('external login without key redirects to setup', r.status === 302 && r.headers.location === '/setup');

  r = await req('GET', '/login');
  check('login page brand', r.status === 200 && r.body.indexOf('DeepSeek Harness') >= 0);
  const csrf = cookies(r.headers['set-cookie'])['dsh_csrf'];

  r = await req('POST', '/login', { headers: { 'Cookie': 'dsh_csrf=' + csrf }, body: 'csrf=' + csrf + '&username=tester&password=WRONG' });
  check('wrong pw -> 401', r.status === 401);

  const csrf2 = cookies((await req('GET', '/login')).headers['set-cookie'])['dsh_csrf'];
  r = await req('POST', '/login', { headers: { 'Cookie': 'dsh_csrf=' + csrf2 }, body: 'csrf=' + csrf2 + '&username=tester&password=secret123' });
  check('tester(key) login -> 302 /', r.status === 302 && r.headers.location === '/');
  const sess = cookies(r.headers['set-cookie'])['dsh_session'];

  r = await req('GET', '/some/path', { headers: { 'Cookie': 'dsh_session=' + sess } });
  check('proxy upstream', r.status === 200 && r.body.indexOf('UPSTREAM-OK /some/path') >= 0);
  check('file manager trigger targets composer permission control', r.body.indexOf('dshgw-composer-files') >= 0
    && r.body.indexOf('aria-label^=\\"访问模式\\"') >= 0
    && r.body.indexOf('nextElementSibling') >= 0
    && r.body.indexOf('files=cloneSidebarAction') < 0);
  const proxyScripts = Array.from(r.body.matchAll(/<script>([\s\S]*?)<\/script>/g), (match) => match[1]);
  let proxyScriptsValid = proxyScripts.length > 0;
  try { proxyScripts.forEach((script) => { new Function(script); }); } catch (error) { proxyScriptsValid = false; }
  check('injected gateway scripts parse', proxyScriptsValid);

  r = await req('GET', '/__gw/files?dir=' + encodeURIComponent(testerWorkspace), {
    headers: { Cookie: 'dsh_session=' + sess },
  });
  check('file manager renders delete controls', r.status === 200
    && r.body.indexOf('delete-file') >= 0
    && r.body.indexOf('create-directory') >= 0
    && r.body.indexOf('data-delete-kind="file"') >= 0
    && r.body.indexOf('data-delete-kind="directory"') >= 0);
  const fileScripts = Array.from(r.body.matchAll(/<script>([\s\S]*?)<\/script>/g), (match) => match[1]);
  let fileScriptsValid = fileScripts.length > 0;
  try { fileScripts.forEach((script) => { new Function(script); }); } catch (error) { fileScriptsValid = false; }
  check('file manager inline scripts parse', fileScriptsValid);
  r = await req('GET', '/__gw/download?path=' + encodeURIComponent(path.join(testerWorkspace, 'result.txt')), {
    headers: { Cookie: 'dsh_session=' + sess },
  });
  check('download streams one committed response', r.status === 200
    && r.body === 'result' && r.headers['content-length'] === '6');
  r = await req('GET', '/__gw/download?path=' + encodeURIComponent(path.join(testerWorkspace, 'empty.txt')), {
    headers: { Cookie: 'dsh_session=' + sess },
  });
  check('download supports an empty file', r.status === 200
    && r.body === '' && r.headers['content-length'] === '0');
  r = await req('POST', '/__gw/delete', {
    headers: { Cookie: 'dsh_session=' + sess, 'Content-Type': 'application/json' },
    body: JSON.stringify({ path: path.join(testerWorkspace, 'result.txt') }),
  });
  check('file delete requires action header', r.status === 403);
  r = await req('POST', '/__gw/delete', {
    headers: { Cookie: 'dsh_session=' + sess, 'Content-Type': 'application/json', 'X-DSH-Gateway-Action': 'delete-file' },
    body: JSON.stringify({ path: path.join(testerWorkspace, 'result.txt') }),
  });
  check('file delete uses the scoped helper', r.status === 200
    && fs.readFileSync(FILE_DELETE_TEST_LOG, 'utf8').indexOf(path.join(testerWorkspace, 'result.txt')) >= 0);
  r = await req('POST', '/__gw/mkdir', {
    headers: { Cookie: 'dsh_session=' + sess, 'Content-Type': 'application/json' },
    body: JSON.stringify({ dir: testerWorkspace, name: 'reports' }),
  });
  check('mkdir requires action header', r.status === 403);
  r = await req('POST', '/__gw/mkdir', {
    headers: { Cookie: 'dsh_session=' + sess, 'Content-Type': 'application/json', 'X-DSH-Gateway-Action': 'create-directory' },
    body: JSON.stringify({ dir: testerWorkspace, name: 'reports' }),
  });
  check('mkdir uses the scoped helper', r.status === 200
    && fs.readFileSync(FILE_MKDIR_TEST_LOG, 'utf8').indexOf(testerWorkspace + ' reports') >= 0);

  // Closing the last tab may recycle the tenant process, but it is not a
  // logout. Browser timer throttling and reloads must not invalidate the
  // signed session cookie.
  const sessionPayload = JSON.parse(Buffer.from(sess.split('.')[0], 'base64url').toString('utf8'));
  await new Promise((resolve) => setTimeout(resolve, 1100));
  r = await req('POST', '/__gw/presence', {
    headers: { Cookie: 'dsh_session=' + sess },
    body: 'tab=smoke-tab-1234&event=open',
  });
  const refreshedSess = cookies(r.headers['set-cookie'])['dsh_session'];
  const refreshedPayload = JSON.parse(Buffer.from(refreshedSess.split('.')[0], 'base64url').toString('utf8'));
  check('presence opens tenant lease', r.status === 200 && JSON.parse(r.body).renewed === true);
  check('presence renews an aged session cookie', refreshedPayload.n === sessionPayload.n
    && refreshedPayload.iat > sessionPayload.iat && refreshedPayload.exp > sessionPayload.exp);
  r = await req('POST', '/__gw/presence', {
    headers: { Cookie: 'dsh_session=' + refreshedSess },
    body: 'tab=smoke-tab-1234&event=close',
  });
  check('presence closes tenant lease', r.status === 204 && !!sessionPayload.n);
  await new Promise((resolve) => setTimeout(resolve, 1200));
  const autoSleepLog = fs.readFileSync(TENANT_HELPER_LOG, 'utf8');
  check('automatic tenant sleep preserves sessions', autoSleepLog.indexOf('--sleep tester ' + CONTROL_SOCKET + ' browser-close 0') >= 0);
  r = await req('GET', '/some/path', { headers: { Cookie: 'dsh_session=' + refreshedSess } });
  check('session survives automatic tenant sleep', r.status === 200 && r.body.indexOf('UPSTREAM-OK /some/path') >= 0);

  const adminCsrf = cookies((await req('GET', '/login')).headers['set-cookie'])['dsh_csrf'];
  r = await req('POST', '/login', { headers: { 'Cookie': 'dsh_csrf=' + adminCsrf }, body: 'csrf=' + adminCsrf + '&username=admin&password=adminsecret' });
  check('admin login enters own DSH', r.status === 302 && r.headers.location === '/');
  const adminSess = cookies(r.headers['set-cookie'])['dsh_session'];
  r = await req('GET', '/some/path', { headers: { Cookie: 'dsh_session=' + adminSess } });
  check('admin DSH proxy works', r.status === 200 && r.body.indexOf('UPSTREAM-OK /some/path') >= 0);
  r = await req('GET', '/__gw/admin', { headers: { Cookie: 'dsh_session=' + adminSess } });
  check('admin console remains available', r.status === 200 && r.body.indexOf('管理控制台') >= 0);
  check('admin console keeps browser presence lease', r.body.indexOf('__DSH_GATEWAY_LIFECYCLE__') >= 0);
  check('admin user metrics refresh is manual only', r.body.indexOf('restoreUsersCache();') >= 0 && r.body.indexOf('load();setInterval(load') < 0);
  check('admin user metrics keep a local cache', r.body.indexOf('dsh-admin-users-v1') >= 0 && r.body.indexOf('localStorage.setItem') >= 0);
  check('admin user metrics show last update time', r.body.indexOf('id="last-updated"') >= 0 && r.body.indexOf('上次更新：') >= 0);
  check('admin console omits live resource columns', r.body.indexOf('内存（RSS）') < 0 && r.body.indexOf('<th>存储</th>') < 0 && r.body.indexOf('<th>DSH</th>') < 0);
  const inlineScripts = Array.from(r.body.matchAll(/<script>([\s\S]*?)<\/script>/g), (m) => m[1]);
  let adminScriptsValid = inlineScripts.length > 0;
  try { inlineScripts.forEach((script) => { new Function(script); }); } catch (e) { adminScriptsValid = false; }
  check('admin console inline scripts parse', adminScriptsValid);
  r = await req('GET', '/__gw/admin/users', { headers: { Cookie: 'dsh_session=' + adminSess } });
  const adminUsers = JSON.parse(r.body);
  const testerStats = adminUsers.users.find((u) => u.name === 'tester');
  // The mock --stats helper reports non-zero values; zeros here prove the
  // admin user route no longer invokes the control-socket metrics helper.
  check('admin user list avoids live metrics helpers', r.status === 200 && testerStats.rssBytes === 0 && testerStats.processCount === 0 && testerStats.diskBytes === null);
  check('admin user list keeps persisted fields', testerStats.port === 3999 && testerStats.keyConfigured === true);
  r = await req('GET', '/__gw/admin/plugins', { headers: { Cookie: 'dsh_session=' + adminSess } });
  const pluginList = JSON.parse(r.body);
  check('admin plugin list', r.status === 200 && pluginList.plugins[0].name === 'dsh-better-sidebar');
  r = await req('POST', '/__gw/admin/plugins/add', {
    headers: { Cookie: 'dsh_session=' + adminSess, 'Content-Type': 'application/json' },
    body: JSON.stringify({ spec: 'test-plugin@1.0.0' }),
  });
  check('admin plugin mutation requires action header', r.status === 403);
  const tarballBody = fs.readFileSync(TEST_TARBALL);
  r = await req('POST', '/__gw/admin/plugins/upload', {
    headers: { Cookie: 'dsh_session=' + adminSess, 'Content-Type': 'application/octet-stream' },
    body: tarballBody,
  });
  check('admin plugin upload requires action header', r.status === 403);
  r = await req('POST', '/__gw/admin/plugins/upload', {
    headers: { Cookie: 'dsh_session=' + adminSess, 'Content-Type': 'application/octet-stream', 'X-DSH-Gateway-Action': 'admin-plugin' },
    body: tarballBody,
  });
  const uploadedTarball = JSON.parse(r.body).tarball;
  check('admin accepts an npm plugin tarball', r.status === 201
    && uploadedTarball.name === 'offline-plugin'
    && uploadedTarball.version === '1.0.0'
    && uploadedTarball.spec.startsWith('file:' + PLUGIN_TARBALL_DIR + '/'));
  r = await req('POST', '/__gw/admin/plugins/add', {
    headers: { Cookie: 'dsh_session=' + adminSess, 'Content-Type': 'application/json', 'X-DSH-Gateway-Action': 'admin-plugin' },
    body: JSON.stringify({ spec: uploadedTarball.spec, name: uploadedTarball.name }),
  });
  const pluginJob = JSON.parse(r.body).job;
  check('admin starts plugin install job', r.status === 202 && pluginJob.status === 'running');
  await new Promise((resolve) => setTimeout(resolve, 50));
  r = await req('GET', '/__gw/admin/plugin-job?id=' + pluginJob.id, { headers: { Cookie: 'dsh_session=' + adminSess } });
  check('admin plugin job completes', r.status === 200 && JSON.parse(r.body).job.status === 'success');

  const csrf3 = cookies((await req('GET', '/login')).headers['set-cookie'])['dsh_csrf'];
  r = await req('POST', '/login', { headers: { 'Cookie': 'dsh_csrf=' + csrf3 }, body: 'csrf=' + csrf3 + '&username=nokey&password=secret123' });
  check('nokey login -> /setup', r.status === 302 && r.headers.location === '/setup');
  const sess2 = cookies(r.headers['set-cookie'])['dsh_session'];

  r = await req('GET', '/setup', { headers: { 'Cookie': 'dsh_session=' + sess2 } });
  check('setup page renders', r.status === 200 && r.body.indexOf('API Key') >= 0);

  const b64 = sess2.split('.')[0];
  const payload = JSON.parse(Buffer.from(b64, 'base64url').toString('utf8'));
  r = await req('POST', '/setup', { headers: { 'Cookie': 'dsh_session=' + sess2 }, body: 'csrf=' + payload.n + '&key=sk-abcdefgh123456' });
  check('setup via RPC -> 302 /', r.status === 302 && r.headers.location === '/');

  const db = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
  check('flag set after setup', db.users.nokey.keyConfigured === true);

  r = await req('POST', '/logout', { headers: { Cookie: 'dsh_session=' + sess + '; dsh_csrf=' + csrf2 }, body: 'csrf=' + csrf2 });
  check('logout POST -> 302 /login', r.status === 302 && r.headers.location === '/login');
  const manualSleepLog = fs.readFileSync(TENANT_HELPER_LOG, 'utf8');
  check('manual logout revokes sessions', manualSleepLog.indexOf('--sleep tester ' + CONTROL_SOCKET + ' manual-logout 1') >= 0);
  r = await req('POST', '/logout', { headers: { Cookie: 'dsh_session=' + sess }, body: 'csrf=' + csrf2 });
  check('revoked logout session stays logged out', r.status === 302 && r.headers.location === '/login');
  r = await req('GET', '/logout');
  check('logout GET -> 302 /', r.status === 302 && r.headers.location === '/');

  r = await req('GET', '/api/something');
  check('unauth api -> 401', r.status === 401);

  console.log('\n' + pass + ' passed, ' + fail + ' failed');
  upstream.close();
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error('TEST ERROR', e); process.exit(1); });
