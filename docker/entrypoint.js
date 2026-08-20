'use strict';

// Container entrypoint / supervisor for the dsh-server-deployment image.
//
// Owns the whole tenant lifecycle inside the container:
//   - seeds tenants from DSH_TENANTS_JSON at boot (bootstrap only), merging
//     with users that were added at runtime and persisted in the volume-backed
//     users.json, so runtime users survive container restarts;
//   - spawns one DSH web instance per tenant (runuser -> dsh-<name>) and the
//     gateway, re-applies the loopback firewall whenever the user set changes;
//   - exposes a root-only Unix control socket (DSH_CONTROL_SOCKET) so the
//     in-container `dsh-users` CLI can add / passwd / delete / list / set-key
//     users at runtime without editing compose.yml or recreating the container.

const fs = require('fs');
const http = require('http');
const net = require('net');
const path = require('path');
const { execFileSync, spawn } = require('child_process');
const { hashPassword, verifyPassword } = require('../gateway/auth.js');
const { hasApiKey, setApiKey } = require('../gateway/credentials.js');

const APP_DIR = process.env.DSH_APP_DIR || '/opt/deepseek-harness';
const USERS_DIR = process.env.DSH_USERS_DIR || '/srv/dsh/users';
const STATE_DIR = process.env.DSH_GATEWAY_STATE_DIR || '/var/lib/dsh-gateway';
const USERS_FILE = process.env.USERS_FILE || path.join(STATE_DIR, 'users.json');
const IDENTITY_FILE = path.join(STATE_DIR, 'tenant-identities.json');
const SECRET_FILE = process.env.SECRET_FILE || path.join(STATE_DIR, 'secret');
const CWD_STATE_FILE = process.env.CWD_STATE_FILE || path.join(STATE_DIR, 'state-cwd.json');
const CONTROL_SOCKET = process.env.DSH_CONTROL_SOCKET || path.join(STATE_DIR, 'control.sock');
const DSH_BIN = process.env.DSH_DSH_BIN || path.join(APP_DIR, 'apps/cli/lib/bin.js');
const NODE_BIN = process.execPath;
const GATEWAY_PORT = numberEnv('DSH_GATEWAY_PORT', 3100);
const TENANT_PORT_BASE = numberEnv('DSH_TENANT_PORT_BASE', 3101);
const SKIP_KEY_SETUP = process.env.DSH_SKIP_KEY_SETUP === '1';
const LOOPBACK_GUARD = '/usr/local/libexec/dsh/dsh-loopback-guard';
const GATEWAY_SERVER = '/opt/dsh-server-deployment/gateway/server.js';
const MIN_PASSWORD_LENGTH = 8;
// Admin account: a management-only user (no DSH instance / OS account / port).
// Provisioned at boot from DSH_ADMIN_PASSWORD, marked admin:true in users.json;
// the gateway serves them the admin panel instead of a tenant instance.
const ADMIN_NAME = (process.env.DSH_ADMIN_NAME || 'admin').trim();
const ADMIN_PASSWORD = process.env.DSH_ADMIN_PASSWORD;
const children = [];

// Runtime state shared by boot provisioning and the control socket handlers.
const state = {
  db: { version: 1, users: {} }, // live users.json mirror
  tenants: new Map(),            // exact username -> { record, child }
  stopping: false,
  controlServer: null,
};

function numberEnv(name, fallback) {
  const value = Number(process.env[name] || fallback);
  if (!Number.isInteger(value) || value < 1 || value > 65535) throw new Error(`${name} must be a TCP port`);
  return value;
}

function parseTenants() {
  let tenants;
  try {
    tenants = JSON.parse(process.env.DSH_TENANTS_JSON || '[]');
  } catch (error) {
    throw new Error(`DSH_TENANTS_JSON is not valid JSON: ${error.message}`);
  }
  if (!Array.isArray(tenants) || tenants.length === 0) throw new Error('DSH_TENANTS_JSON must contain at least one tenant');
  const names = new Set();
  return tenants.map((tenant, index) => {
    const name = tenant && tenant.name;
    const password = tenant && tenant.password;
    if (typeof name !== 'string' || !/^[A-Za-z0-9_-]+$/.test(name)) throw new Error(`tenant ${index} has an invalid name`);
    const folded = name.toLowerCase();
    if (names.has(folded)) throw new Error(`tenant name ${name} conflicts by case`);
    names.add(folded);
    if (typeof password !== 'string' || password.length < MIN_PASSWORD_LENGTH) {
      throw new Error(`tenant ${name} password must contain at least ${MIN_PASSWORD_LENGTH} characters`);
    }
    if (tenant.apiKey !== undefined && (typeof tenant.apiKey !== 'string' || tenant.apiKey.length === 0)) {
      throw new Error(`tenant ${name} apiKey must be a non-empty string`);
    }
    return { name, password, apiKey: tenant.apiKey };
  });
}

function osUserOf(name) {
  return `dsh-${name.toLowerCase()}`;
}

function ensureOsUser(name, home, uid) {
  const osUser = osUserOf(name);
  try {
    execFileSync('id', [osUser], { stdio: 'ignore' });
  } catch {
    const args = ['--no-create-home', '--home', home, '--shell', '/usr/sbin/nologin'];
    if (Number.isInteger(uid)) args.unshift('--uid', String(uid));
    execFileSync('useradd', args.concat(osUser));
  }
  return osUser;
}

function writeAtomic(file, content, mode) {
  const temporary = `${file}.tmp-${process.pid}`;
  fs.writeFileSync(temporary, content, { mode });
  fs.renameSync(temporary, file);
  fs.chmodSync(file, mode);
}

function searchPatchContent() {
  return [
    '- id: session-query-sqlite',
    '  config:',
    "    path: ':memory:'",
    '    openAt: first-search',
    '',
  ].join('\n');
}

// ---------- custom provider provisioning (llm-pi-ai) ----------

function providerApiKeyEnv(name) {
  return String(name).toUpperCase().replace(/[^A-Z0-9]/g, '_') + '_API_KEY';
}

// Validate an optional custom-provider spec from the registration API.
// Returns null when absent; throws on malformed values. The API key itself is
// NOT set here - the external caller writes it later via the key endpoint.
// `api` must be one of the pi-ai protocols (an invalid protocol makes the
// whole llm-pi-ai settings section fail validation and the route stays
// dormant); 'openai-completions' is the OpenAI-compatible default.
const SUPPORTED_PROVIDER_APIS = ['openai-completions', 'openai-responses', 'anthropic-messages'];
function validateProvider(provider) {
  if (provider === undefined || provider === null) return null;
  if (typeof provider !== 'object' || Array.isArray(provider)) throw new Error('provider must be an object');
  const { name, baseURL, model } = provider;
  if (typeof name !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(name)) {
    throw new Error('provider name must be letters, digits, underscore or hyphen');
  }
  if (typeof baseURL !== 'string' || !/^https?:\/\/[^\s]+$/.test(baseURL)) {
    throw new Error('provider baseURL must be an http(s) URL');
  }
  if (typeof model !== 'string' || model.length === 0 || model.length > 128) {
    throw new Error('provider model is required');
  }
  const api = provider.api === undefined || provider.api === null || provider.api === ''
    ? 'openai-completions'
    : String(provider.api);
  if (!SUPPORTED_PROVIDER_APIS.includes(api)) {
    throw new Error(`provider api must be one of: ${SUPPORTED_PROVIDER_APIS.join(', ')}`);
  }
  return { name, baseURL, model, api };
}

// yq-safe YAML scalar quoting (double-quoted; JSON.stringify output is valid
// YAML for these simple values).
function yq(v) { return JSON.stringify(String(v)); }

// settings.yaml for a user whose account is bound to a custom provider: the
// llm-pi-ai namespace defines the provider (OpenAI-compatible adapter), and
// agent-default-model points at it so the web client uses it by default.
function providerSettingsYaml(provider) {
  const ref = providerApiKeyEnv(provider.name);
  const model = provider.model;
  return [
    'agent-default-model:',
    `  provider: ${provider.name}`,
    `  model: ${yq(model)}`,
    // No reasoningEffort: custom OpenAI-compatible models usually do not
    // declare reasoning capability, and a configured effort then fails every
    // call with UNSUPPORTED_REASONING_EFFORT. Omit it so the provider default
    // applies; users who need a thinking level can add it in settings later.
    '',
    'llm-pi-ai:',
    '  providers:',
    `    ${provider.name}:`,
    `      apiKeyEnv: ${ref}`,
    `      displayName: ${yq(provider.name)}`,
    `      api: ${provider.api}`,
    `      baseURL: ${yq(provider.baseURL)}`,
    '      models:',
    `        - id: ${yq(model)}`,
    `          name: ${yq(model)}`,
    '          contextWindow: 32768',
    '          maxTokens: 8192',
    '',
  ].join('\n');
}

function provisionTenant(tenant, port, uid, existing) {
  const home = path.join(USERS_DIR, tenant.name);
  const workspace = path.join(home, 'workspace');
  const osUser = ensureOsUser(tenant.name, home, uid);
  fs.mkdirSync(workspace, { recursive: true, mode: 0o700 });
  const searchPatch = path.join(home, 'cordis.patch.yml');
  if (!fs.existsSync(searchPatch)) {
    fs.writeFileSync(searchPatch, searchPatchContent(), { mode: 0o644 });
  }
  if (tenant.provider) {
    // Custom provider: default the web client to it and skip the /setup gate
    // (the API key is written afterwards by the external key endpoint).
    fs.writeFileSync(path.join(home, 'settings.yaml'), providerSettingsYaml(tenant.provider), { mode: 0o644 });
  }
  if (tenant.apiKey !== undefined) {
    const escaped = tenant.apiKey.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
    fs.writeFileSync(path.join(home, '.credentials.yaml'), `DEEPSEEK_API_KEY: "${escaped}"\n`, { mode: 0o600 });
  }
  execFileSync('chown', ['-R', `${osUser}:${osUser}`, home]);
  fs.chmodSync(home, 0o700);
  const passwordUnchanged = existing && existing.pwd && verifyPassword(tenant.password, existing.pwd);
  const record = {
    port,
    home,
    osUser,
    pwd: passwordUnchanged ? existing.pwd : hashPassword(tenant.password),
    pwdVer: passwordUnchanged ? (existing.pwdVer || 1) : ((existing && existing.pwdVer) || 0) + 1,
    keyConfigured: SKIP_KEY_SETUP || tenant.apiKey !== undefined || tenant.provider !== undefined || hasApiKey(USERS_DIR, tenant.name),
    created: (existing && existing.created) || new Date().toISOString(),
  };
  if (tenant.provider) {
    record.provider = {
      name: tenant.provider.name,
      baseURL: tenant.provider.baseURL,
      model: tenant.provider.model,
      api: tenant.provider.api,
      apiKeyEnv: providerApiKeyEnv(tenant.provider.name),
    };
  }
  return record;
}

// Re-create home / OS account for a user that was persisted in users.json but
// is not in the DSH_TENANTS_JSON seed (added at runtime in a previous run).
// Their password record is kept verbatim - we never see their plaintext.
function ensurePreservedRecord(name, record, uid) {
  const osUser = ensureOsUser(name, record.home, uid);
  const workspace = path.join(record.home, 'workspace');
  fs.mkdirSync(workspace, { recursive: true, mode: 0o700 });
  const searchPatch = path.join(record.home, 'cordis.patch.yml');
  if (!fs.existsSync(searchPatch)) {
    fs.writeFileSync(searchPatch, searchPatchContent(), { mode: 0o644 });
  }
  execFileSync('chown', ['-R', `${osUser}:${osUser}`, record.home]);
  fs.chmodSync(record.home, 0o700);
  return { ...record, osUser, home: record.home, port: record.port };
}

function readJson(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (error) {
    if (error && error.code === 'ENOENT') return fallback;
    throw new Error(`cannot read ${file}: ${error.message}`);
  }
}

// Create or update the admin record in the user store. The password comes from
// DSH_ADMIN_PASSWORD (scrypt-hashed, never stored in plaintext); an unchanged
// password keeps the existing hash and pwdVer so sessions survive restarts.
function upsertAdmin(db) {
  if (ADMIN_PASSWORD === undefined || ADMIN_PASSWORD === '') return;
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(ADMIN_NAME)) throw new Error(`invalid DSH_ADMIN_NAME: ${ADMIN_NAME}`);
  if (typeof ADMIN_PASSWORD !== 'string' || ADMIN_PASSWORD.length < MIN_PASSWORD_LENGTH) {
    throw new Error(`DSH_ADMIN_PASSWORD must contain at least ${MIN_PASSWORD_LENGTH} characters`);
  }
  const existing = db.users[ADMIN_NAME];
  const unchanged = existing && existing.pwd && verifyPassword(ADMIN_PASSWORD, existing.pwd);
  db.users[ADMIN_NAME] = {
    admin: true,
    pwd: unchanged ? existing.pwd : hashPassword(ADMIN_PASSWORD),
    pwdVer: unchanged ? (existing.pwdVer || 1) : ((existing && existing.pwdVer) || 0) + 1,
    keyConfigured: true, // admin has no DSH instance; bypass the /setup gate
    created: (existing && existing.created) || new Date().toISOString(),
  };
}

function assignUids(tenants) {
  const identities = readJson(IDENTITY_FILE, { version: 1, tenants: {} });
  if (!identities || typeof identities !== 'object' || !identities.tenants || typeof identities.tenants !== 'object') {
    throw new Error(`${IDENTITY_FILE} has an invalid structure`);
  }
  const used = new Set(Object.values(identities.tenants).map((entry) => entry && entry.uid));
  let nextUid = 20000;
  for (const tenant of tenants) {
    const key = tenant.name.toLowerCase();
    const existing = identities.tenants[key];
    if (existing && Number.isInteger(existing.uid) && existing.uid >= 20000) continue;
    while (used.has(nextUid)) nextUid += 1;
    identities.tenants[key] = { name: tenant.name, uid: nextUid };
    used.add(nextUid);
  }
  writeAtomic(IDENTITY_FILE, `${JSON.stringify(identities, null, 2)}\n`, 0o600);
  execFileSync('chown', ['root:root', IDENTITY_FILE]);
  return identities.tenants;
}

function spawnManaged(label, command, args, options = {}) {
  const child = spawn(command, args, { stdio: 'inherit', detached: true, ...options });
  children.push({ label, child });
  child.once('exit', (code, signal) => {
    if (state.stopping) return;
    if (child.__dshDeliberateStop) return;
    console.error(`${label} exited unexpectedly (code=${code}, signal=${signal})`);
    shutdown(1);
  });
  return child;
}

function waitForPort(port, timeoutMs = 120000) {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolve, reject) => {
    const attempt = () => {
      const socket = net.connect({ host: '127.0.0.1', port });
      socket.once('connect', () => {
        socket.end();
        resolve();
      });
      socket.once('error', () => {
        socket.destroy();
        if (Date.now() >= deadline) reject(new Error(`port ${port} did not become ready`));
        else setTimeout(attempt, 250);
      });
    };
    attempt();
  });
}

// True readiness probe for a tenant instance: the HTTP port answers before the
// per-user composition finishes mounting its plugins, so TCP alone is not
// enough - the gateway's loopback credentials RPC would hit "credentials
// service is absent" during that window. Poll credentials.describe until the
// service answers ok (i.e. the credentials provider is mounted).
function instanceCredentialsReady(port) {
  return new Promise((resolve) => {
    const rpcId = 'boot-probe-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 6);
    const body = JSON.stringify({ type: 'client-request', rpcId: rpcId, method: 'credentials.describe', payload: { refs: [] } });
    const req = http.request({
      host: '127.0.0.1', port: port, method: 'POST', path: '/api/credentials.describe',
      headers: { 'content-type': 'application/json', host: '127.0.0.1:' + port, 'content-length': Buffer.byteLength(body) },
    }, (res) => {
      let data = '';
      res.on('data', (c) => data += c);
      res.on('end', () => {
        try {
          const j = JSON.parse(data);
          resolve(!!(j && j.result && j.result.ok === true));
        } catch (e) { resolve(false); }
      });
    });
    req.on('error', () => resolve(false));
    req.setTimeout(3000, () => { req.destroy(); resolve(false); });
    req.write(body);
    req.end();
  });
}

async function waitForInstanceReady(port, timeoutMs = 60000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await instanceCredentialsReady(port)) return true;
    await new Promise((r) => setTimeout(r, 1000));
  }
  return false;
}

function tenantArgs(record) {
  const env = [
    `DSH_HOME=${record.home}`,
    `HOME=${record.home}`,
    `PATH=${process.env.PATH || '/usr/local/bin:/usr/bin:/bin'}`,
    `DEEPSEEK_BASE_URL=${process.env.DEEPSEEK_BASE_URL || 'https://api.deepseek.com'}`,
  ];
  return ['-u', record.osUser, '--', 'env', ...env, NODE_BIN, DSH_BIN,
    '--profile', 'web', '--host', '127.0.0.1', '--port', String(record.port)];
}

function gatewayArgs() {
  const env = [
    'HOST=0.0.0.0',
    `PORT=${GATEWAY_PORT}`,
    `USERS_FILE=${USERS_FILE}`,
    `SECRET_FILE=${SECRET_FILE}`,
    `CWD_STATE_FILE=${CWD_STATE_FILE}`,
    `USERS_DIR=${USERS_DIR}`,
    `COOKIE_SECURE=${process.env.COOKIE_SECURE || '0'}`,
    `DEEPSEEK_BASE_URL=${process.env.DEEPSEEK_BASE_URL || 'https://api.deepseek.com'}`,
    'UPLOAD_HELPER=/usr/local/libexec/dsh/dsh-file-put',
    'FILE_STAT_HELPER=/usr/local/libexec/dsh/dsh-file-stat',
    'FILE_READ_HELPER=/usr/local/libexec/dsh/dsh-file-read',
    'FILE_LIST_HELPER=/usr/local/libexec/dsh/dsh-file-list',
  ];
  return ['-u', 'dsh-gateway', '--', 'env', ...env, NODE_BIN, GATEWAY_SERVER];
}

// ---------- users.json persistence + firewall refresh ----------

function saveUsersDb(db) {
  writeAtomic(USERS_FILE, `${JSON.stringify(db, null, 2)}\n`, 0o640);
  execFileSync('chown', ['dsh-gateway:dsh-gateway', USERS_FILE]);
}

function usedPorts(db) {
  const used = new Set();
  for (const record of Object.values(db.users || {})) {
    if (record && Number.isInteger(record.port)) used.add(record.port);
  }
  return used;
}

function nextFreePort(used) {
  let p = TENANT_PORT_BASE;
  while (used.has(p)) p += 1;
  return p;
}

// Rebuild the tenant loopback firewall from the live user set. Called at boot
// and after every add/del so isolation rules always match reality. Admin has
// no OS account / port and is excluded.
function applyLoopbackGuard() {
  const specs = Object.values(state.db.users)
    .filter((record) => record && !record.admin && record.osUser && Number.isInteger(record.port))
    .map((record) => `${record.osUser}:${record.port}`);
  execFileSync(LOOPBACK_GUARD, ['--apply', ...specs], {
    stdio: 'inherit',
    env: { ...process.env, GW_PORT: String(GATEWAY_PORT) },
  });
}

// ---------- tenant process lifecycle ----------

function startTenant(name, record) {
  if (state.tenants.has(name)) return;
  const child = spawnManaged(`tenant:${name}`, 'runuser', tenantArgs(record));
  state.tenants.set(name, { record, child });
}

function stopTenant(name, timeoutMs = 8000) {
  const entry = state.tenants.get(name);
  if (!entry) return Promise.resolve();
  state.tenants.delete(name);
  const { child } = entry;
  child.__dshDeliberateStop = true;
  if (child.exitCode !== null || child.signalCode !== null) return Promise.resolve();
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      try { process.kill(-child.pid, 'SIGKILL'); } catch (e) { resolve(); }
    }, timeoutMs);
    child.once('exit', () => { clearTimeout(timer); resolve(); });
    try { process.kill(-child.pid, 'SIGTERM'); } catch (e) { resolve(); }
  });
}

// ---------- control socket (dsh-users CLI <-> supervisor) ----------

function validName(name) {
  return typeof name === 'string' && /^[A-Za-z0-9_-]+$/.test(name);
}

function caseConflict(db, name) {
  const lower = String(name).toLowerCase();
  for (const k of Object.keys(db.users || {})) {
    if (k !== name && k.toLowerCase() === lower) return k;
  }
  return null;
}

function requirePassword(password) {
  if (typeof password !== 'string' || password.length < MIN_PASSWORD_LENGTH) {
    throw new Error(`password must contain at least ${MIN_PASSWORD_LENGTH} characters`);
  }
  return password;
}

function controlAdd(payload) {
  const { name, password } = payload;
  if (!validName(name)) throw new Error('invalid username (letters, digits, underscore, hyphen only)');
  if (name.toLowerCase() === ADMIN_NAME.toLowerCase()) throw new Error(`reserved username: ${ADMIN_NAME}`);
  requirePassword(password);
  if (state.db.users[name]) throw new Error(`user already exists: ${name}`);
  const clash = caseConflict(state.db, name);
  if (clash) throw new Error(`username conflicts with existing user "${clash}" (OS account is lowercase, files would merge)`);
  const provider = validateProvider(payload.provider);

  const identities = assignUids([{ name }]);
  const uid = identities[name.toLowerCase()].uid;
  const port = nextFreePort(usedPorts(state.db));
  const record = provisionTenant({ name, password, provider }, port, uid, undefined);
  state.db.users[name] = record;
  saveUsersDb(state.db);
  startTenant(name, record);
  applyLoopbackGuard();
  waitForPort(port, 60000).catch((error) => {
    console.error(`WARNING: tenant ${name} did not become ready on ${port}: ${error.message}`);
  });
  return {
    ok: true,
    result: {
      name,
      port,
      osUser: record.osUser,
      keyConfigured: record.keyConfigured,
      provider: record.provider || undefined,
    },
  };
}

function controlPasswd(payload) {
  const { name, password } = payload;
  const record = state.db.users[name];
  if (!record) throw new Error(`user not found: ${name}`);
  requirePassword(password);
  record.pwd = hashPassword(password);
  // Bump pwdVer so every outstanding gateway session token (which embeds
  // pwdVer) becomes invalid - a stolen token must not survive a reset.
  record.pwdVer = (typeof record.pwdVer === 'number' ? record.pwdVer : 0) + 1;
  saveUsersDb(state.db);
  return { ok: true, result: { name } };
}

async function controlDel(payload) {
  const { name } = payload;
  const record = state.db.users[name];
  if (!record) throw new Error(`user not found: ${name}`);
  await stopTenant(name);
  try { execFileSync('userdel', [record.osUser]); } catch (e) {}
  try { fs.rmSync(record.home, { recursive: true, force: true }); } catch (e) {}
  delete state.db.users[name];
  saveUsersDb(state.db);
  applyLoopbackGuard();
  return { ok: true, result: { name } };
}

function controlList() {
  const names = Object.keys(state.db.users).sort();
  return {
    ok: true,
    result: names.map((name) => {
      const u = state.db.users[name];
      return {
        name,
        port: u.port,
        osUser: u.osUser,
        algo: (u.pwd && u.pwd.algo) || '-',
        keyConfigured: !!u.keyConfigured,
        created: u.created,
      };
    }),
  };
}

function controlSetKey(payload) {
  const { name, key } = payload;
  const record = state.db.users[name];
  if (!record) throw new Error(`user not found: ${name}`);
  if (typeof key !== 'string' || key.length === 0) throw new Error('API key required');
  setApiKey(USERS_DIR, name, key);
  try { execFileSync('chown', ['-R', `${record.osUser}:${record.osUser}`, record.home]); } catch (e) {}
  record.keyConfigured = true;
  saveUsersDb(state.db);
  return { ok: true, result: { name } };
}

function controlKeyStatus(payload) {
  const { name } = payload;
  const record = state.db.users[name];
  if (!record) throw new Error(`user not found: ${name}`);
  return { ok: true, result: { name, configured: !!record.keyConfigured } };
}

// Register (or replace) a custom provider for an EXISTING user: write their
// settings.yaml (llm-pi-ai profile + agent-default-model), update the user
// record, then restart the tenant so the running instance loads the new
// config. The API key itself is written later by the gateway through the
// loopback credentials RPC.
async function controlSetProvider(payload) {
  const { name } = payload;
  const record = state.db.users[name];
  if (!record) throw new Error(`user not found: ${name}`);
  if (record.admin === true) throw new Error('admin has no instance');
  const provider = validateProvider(payload.provider);
  const settingsFile = path.join(record.home, 'settings.yaml');
  fs.writeFileSync(settingsFile, providerSettingsYaml(provider), { mode: 0o644 });
  try { execFileSync('chown', [record.osUser + ':' + record.osUser, settingsFile]); } catch (e) {}
  record.provider = {
    name: provider.name,
    baseURL: provider.baseURL,
    model: provider.model,
    api: provider.api,
    apiKeyEnv: providerApiKeyEnv(provider.name),
  };
  record.keyConfigured = true; // provider users skip the /setup gate
  saveUsersDb(state.db);
  await stopTenant(name);
  startTenant(name, record);
  await waitForPort(record.port, 60000);
  // Wait for the credentials service to actually be mounted, not just the TCP
  // port: the gateway writes the API key right after this reply, and a
  // half-booted instance answers "credentials service is absent".
  await waitForInstanceReady(record.port, 60000);
  return { ok: true, result: { name, provider: record.provider } };
}

async function handleControl(payload) {
  switch (payload && payload.cmd) {
    case 'add': return controlAdd(payload);
    case 'passwd': return controlPasswd(payload);
    case 'del': return controlDel(payload);
    case 'list': return controlList();
    case 'set-key': return controlSetKey(payload);
    case 'key-status': return controlKeyStatus(payload);
    case 'set-provider': return controlSetProvider(payload);
    default: return { ok: false, error: `unknown command: ${payload && payload.cmd}` };
  }
}

function startControlServer() {
  if (fs.existsSync(CONTROL_SOCKET)) fs.unlinkSync(CONTROL_SOCKET);
  const server = net.createServer((socket) => {
    let buf = '';
    socket.setEncoding('utf8');
    socket.on('data', (chunk) => {
      buf += chunk;
      const idx = buf.indexOf('\n');
      if (idx < 0) return;
      const line = buf.slice(0, idx);
      buf = buf.slice(idx + 1);
      let payload = {};
      try { payload = JSON.parse(line); } catch (e) {}
      Promise.resolve()
        .then(() => handleControl(payload))
        .then((reply) => socket.end(JSON.stringify(reply) + '\n'))
        .catch((error) => socket.end(JSON.stringify({ ok: false, error: error.message }) + '\n'));
    });
    socket.on('error', () => {});
  });
  server.listen(CONTROL_SOCKET, () => {
    fs.chmodSync(CONTROL_SOCKET, 0o600);
    console.log(`control socket ready: ${CONTROL_SOCKET}`);
  });
  state.controlServer = server;
}

function shutdown(exitCode = 0) {
  if (state.stopping) return;
  state.stopping = true;
  try {
    if (state.controlServer) state.controlServer.close();
    if (fs.existsSync(CONTROL_SOCKET)) fs.unlinkSync(CONTROL_SOCKET);
  } catch (e) {}
  for (const { child } of children) {
    try { process.kill(-child.pid, 'SIGTERM'); } catch {}
  }
  setTimeout(() => {
    for (const { child } of children) {
      try { process.kill(-child.pid, 'SIGKILL'); } catch {}
    }
    process.exit(exitCode);
  }, 10000).unref();
  Promise.all(children.map(({ child }) =>
    (child.exitCode !== null || child.signalCode !== null)
      ? Promise.resolve()
      : new Promise((resolve) => child.once('exit', resolve)),
  )).finally(() => process.exit(exitCode));
}

async function main() {
  if (process.getuid() !== 0) throw new Error('container entrypoint must run as root');
  if (!fs.existsSync(DSH_BIN)) throw new Error(`built dsh CLI not found: ${DSH_BIN}`);
  const seedTenants = parseTenants();
  fs.mkdirSync(USERS_DIR, { recursive: true, mode: 0o711 });
  fs.chmodSync(USERS_DIR, 0o711);
  fs.mkdirSync(STATE_DIR, { recursive: true, mode: 0o700 });
  execFileSync('chown', ['dsh-gateway:dsh-gateway', STATE_DIR]);
  fs.chmodSync(STATE_DIR, 0o700);

  // Merge: DSH_TENANTS_JSON is a bootstrap seed; users that were added at
  // runtime (persisted in the volume-backed users.json) survive restarts and
  // keep their port / password / identity.
  const previousDb = readJson(USERS_FILE, { version: 1, users: {} });
  const previousUsers = (previousDb && previousDb.users) || {};
  const seedNames = new Set(seedTenants.map((t) => t.name.toLowerCase()));
  const preserved = [];
  for (const [name, record] of Object.entries(previousUsers)) {
    if (seedNames.has(name.toLowerCase())) continue;
    // Admin records are management-only (no home/port/osUser); keep verbatim.
    if (record && record.admin === true) { preserved.push({ name, record }); continue; }
    if (!record || typeof record !== 'object' ||
        typeof record.home !== 'string' || typeof record.osUser !== 'string' ||
        !Number.isInteger(record.port) || !record.pwd || typeof record.pwd !== 'object') {
      console.error(`skipping invalid preserved user record: ${name}`);
      continue;
    }
    preserved.push({ name, record });
  }

  const identities = assignUids([...seedTenants, ...preserved.filter((p) => p.record.admin !== true).map((p) => ({ name: p.name }))]);
  const db = { version: 1, users: {} };
  // Only preserved users occupy ports from the start; a seed user reuses its
  // OWN previous port (so restarts never shuffle ports) and only truly new
  // users draw from the free range.
  const used = new Set(preserved.filter((p) => p.record.admin !== true).map((p) => p.record.port));
  for (const tenant of seedTenants) {
    const identity = identities[tenant.name.toLowerCase()];
    const prev = previousUsers[tenant.name];
    let port;
    if (prev && Number.isInteger(prev.port) && !used.has(prev.port)) port = prev.port;
    else port = nextFreePort(used);
    used.add(port);
    db.users[tenant.name] = provisionTenant(tenant, port, identity.uid, prev);
  }
  for (const { name, record } of preserved) {
    if (record.admin === true) { db.users[name] = record; continue; }
    const identity = identities[name.toLowerCase()];
    db.users[name] = ensurePreservedRecord(name, record, identity.uid);
    used.add(record.port);
  }
  upsertAdmin(db);
  state.db = db;
  saveUsersDb(db);

  applyLoopbackGuard();
  startControlServer();

  for (const [name, record] of Object.entries(db.users)) {
    if (record.admin === true) continue;
    startTenant(name, record);
  }
  await Promise.all(Object.values(db.users)
    .filter((record) => record.admin !== true)
    .map((record) => waitForPort(record.port)));
  spawnManaged('gateway', 'runuser', gatewayArgs());
  await waitForPort(GATEWAY_PORT, 30000);
  console.log(`dsh multi-tenant gateway ready on 0.0.0.0:${GATEWAY_PORT} (${Object.keys(db.users).join(', ')})`);
}

process.once('SIGTERM', () => shutdown(0));
process.once('SIGINT', () => shutdown(0));
main().catch((error) => {
  console.error(error.stack || error.message);
  shutdown(1);
});
