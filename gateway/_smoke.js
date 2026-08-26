'use strict';
const fs = require('fs');
const path = require('path');
const os = require('os');
const http = require('http');
const { hashPassword } = require('./auth.js');

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'dshgw-'));
const USERS_DIR = path.join(TMP, 'users');
const USERS_FILE = path.join(TMP, 'users.json');
const TENANT_HELPER = path.join(TMP, 'dsh-register-test-helper');
const TENANT_HELPER_LOG = path.join(TMP, 'dsh-register-test-helper.log');
const CONTROL_SOCKET = path.join(TMP, 'run', 'control.sock');
fs.mkdirSync(path.join(USERS_DIR, 'tester'), { recursive: true });
fs.mkdirSync(path.join(USERS_DIR, 'nokey'), { recursive: true });
fs.mkdirSync(path.join(USERS_DIR, 'admin'), { recursive: true });
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
process.env.DSH_HELPER_DIRECT = '1';
process.env.DSH_BROWSER_STOP_GRACE_MS = '1000';
process.env.DEEPSEEK_BASE_URL = 'http://127.0.0.1:3999';

const upstream = http.createServer((req, res) => {
  if (req.method === 'POST' && req.url === '/api/credentials.set') {
    let body = '';
    req.on('data', (c) => body += c);
    req.on('end', () => {
      let rpcId = 'x';
      try { rpcId = JSON.parse(body).rpcId || 'x'; } catch (e) {}
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ type: 'server-response', rpcId: rpcId, result: { ok: true, value: {} } }));
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

  const providerHeaders = { Authorization: 'Bearer register-test-token', 'Content-Type': 'application/json' };
  r = await req('POST', '/api/users/tester/provider', {
    headers: providerHeaders,
    body: JSON.stringify({
      provider: { name: 'vision-gateway', baseURL: 'http://127.0.0.1:3999' },
      apiKey: 'sk-provider-test',
      image_models: ['vision-model'],
    }),
  });
  const providerReply = JSON.parse(r.body);
  const providerLog = fs.readFileSync(TENANT_HELPER_LOG, 'utf8');
  check('provider image_models registration succeeds', r.status === 200
    && providerReply.image_models[0] === 'vision-model');
  check('provider helper receives text-only model input', providerLog.indexOf('"id":"text-model","input":["text"]') >= 0);
  check('provider helper receives image model input', providerLog.indexOf('"id":"vision-model","input":["text","image"]') >= 0);

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
    && defaultImageLog.indexOf('"id":"vision-model","input":["text"]') >= 0);

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

  // Closing the last tab may recycle the tenant process, but it is not a
  // logout. Browser timer throttling and reloads must not invalidate the
  // signed session cookie.
  const sessionPayload = JSON.parse(Buffer.from(sess.split('.')[0], 'base64url').toString('utf8'));
  r = await req('POST', '/__gw/presence', {
    headers: { Cookie: 'dsh_session=' + sess },
    body: 'tab=smoke-tab-1234&event=open',
  });
  check('presence opens tenant lease', r.status === 204);
  r = await req('POST', '/__gw/presence', {
    headers: { Cookie: 'dsh_session=' + sess },
    body: 'tab=smoke-tab-1234&event=close',
  });
  check('presence closes tenant lease', r.status === 204 && !!sessionPayload.n);
  await new Promise((resolve) => setTimeout(resolve, 1200));
  const autoSleepLog = fs.readFileSync(TENANT_HELPER_LOG, 'utf8');
  check('automatic tenant sleep preserves sessions', autoSleepLog.indexOf('--sleep tester ' + CONTROL_SOCKET + ' browser-close 0') >= 0);
  r = await req('GET', '/some/path', { headers: { Cookie: 'dsh_session=' + sess } });
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
  r = await req('POST', '/__gw/admin/plugins/add', {
    headers: { Cookie: 'dsh_session=' + adminSess, 'Content-Type': 'application/json', 'X-DSH-Gateway-Action': 'admin-plugin' },
    body: JSON.stringify({ spec: 'test-plugin@1.0.0' }),
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
