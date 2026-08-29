'use strict';

// Container entrypoint / supervisor for the dsh-server-deployment image.
//
// Owns the whole tenant lifecycle inside the container:
//   - seeds tenants from DSH_TENANTS_JSON at boot (bootstrap only), merging
//     with users that were added at runtime and persisted in the volume-backed
//     users.json, so runtime users survive container restarts;
//   - spawns the gateway and, by default, starts each tenant DSH web instance
//     on first successful login (runuser -> dsh-<name>), while re-applying the
//     loopback firewall whenever the registered user set changes;
//   - exposes a root-only Unix control socket (DSH_CONTROL_SOCKET) so the
//     in-container `dsh-users` CLI can add / passwd / delete / list / set-key
//     users and persistent shared plugins at runtime without editing
//     compose.yml or recreating the container.

const fs = require('fs');
const http = require('http');
const net = require('net');
const path = require('path');
const { execFileSync, spawn } = require('child_process');
const { hashPassword, verifyPassword } = require('../gateway/auth.js');
const { credentialsPath, hasApiKey, hasAnyApiKey, repairCredentials, setApiKey, setCredential } = require('../gateway/credentials.js');
const { ClusterStore } = require('../cluster/store.js');
const { withFileLock } = require('../cluster/file-lock.js');

const APP_DIR = process.env.DSH_APP_DIR || '/opt/deepseek-harness';
const USERS_DIR = process.env.DSH_USERS_DIR || '/srv/dsh/users';
const STATE_DIR = process.env.DSH_GATEWAY_STATE_DIR || '/var/lib/dsh-gateway';
const USERS_FILE = process.env.USERS_FILE || path.join(STATE_DIR, 'users.json');
const IDENTITY_FILE = path.join(STATE_DIR, 'tenant-identities.json');
const SECRET_FILE = process.env.SECRET_FILE || path.join(STATE_DIR, 'secret');
const CLUSTER_STATE_ID = String(process.env.DSH_NODE_ID || process.env.POD_UID || process.env.HOSTNAME || 'node')
  .replace(/[^A-Za-z0-9_.-]/g, '_').slice(0, 128);
const CWD_STATE_FILE = process.env.CWD_STATE_FILE
  || path.join(STATE_DIR, process.env.DSH_CLUSTER_MODE === '1' ? `state-cwd-${CLUSTER_STATE_ID}.json` : 'state-cwd.json');
const CONTROL_SOCKET = process.env.DSH_CONTROL_SOCKET || '/run/dsh/control.sock';
const DSH_BIN = process.env.DSH_DSH_BIN || path.join(APP_DIR, 'apps/cli/lib/bin.js');
const DEPLOYMENT_PATCH = '/opt/dsh-server-deployment/docker/disable-llm-deepseek.patch.yml';
const BETTER_SIDEBAR_PACKAGE = 'dsh-better-sidebar';
const BETTER_SIDEBAR_DIR = '/opt/dsh-public/profiles/web/node_modules/dsh-better-sidebar';
const BETTER_SIDEBAR_SPEC = `link:${BETTER_SIDEBAR_DIR}`;
const RUNTIME_SHARED_HOME = process.env.DSH_SHARED_PLUGINS_HOME
  || path.join(path.dirname(USERS_DIR), 'shared-plugins');
const RUNTIME_SHARED_PROFILE = path.join(RUNTIME_SHARED_HOME, 'profiles', 'web');
const RUNTIME_SHARED_RECEIPTS = path.join(RUNTIME_SHARED_HOME, 'install-receipts.json');
const SHARED_PLUGINS_FILE = '.dsh-shared-plugins.json';
const WEB_PROFILE_BUNDLES = ['@deepseek-ai/dsh-base', '@deepseek-ai/dsh-web-app'];
const NODE_BIN = process.execPath;
const GATEWAY_PORT = numberEnv('DSH_GATEWAY_PORT', 3100);
const TENANT_PORT_BASE = numberEnv('DSH_TENANT_PORT_BASE', 3101);
const SKIP_KEY_SETUP = process.env.DSH_SKIP_KEY_SETUP === '1';
const LAZY_TENANTS = process.env.DSH_LAZY_TENANTS !== '0';
const LOOPBACK_GUARD = '/usr/local/libexec/dsh/dsh-loopback-guard';
const GATEWAY_SERVER = '/opt/dsh-server-deployment/gateway/server.js';
const MIN_PASSWORD_LENGTH = 8;
// Admin account: a full tenant provisioned from DSH_ADMIN_PASSWORD with its
// own OS account / HOME / port / lazy DSH, plus admin:true authorization.
const ADMIN_NAME = (process.env.DSH_ADMIN_NAME || 'admin').trim();
const ADMIN_PASSWORD = process.env.DSH_ADMIN_PASSWORD;
const children = [];
const clusterStore = new ClusterStore({ gatewayPort: GATEWAY_PORT });
const CLUSTER_ENABLED = clusterStore.enabled;
const USERS_DB_LOCK_OPTIONS = { timeoutMs: 180000, staleMs: 600000 };

// Runtime state shared by boot provisioning and the control socket handlers.
const state = {
  db: { version: 1, users: {} }, // live users.json mirror
  tenants: new Map(),            // exact username -> { record, child }
  tenantStarts: new Map(),        // exact username -> in-flight readiness promise
  tenantLeases: new Map(),        // exact username -> current local cluster lease
  sharedWebPlugins: [],           // immutable image plugin + persistent runtime plugins
  sharedPluginBusy: false,        // serialize shared package mutations
  sharedPluginRevision: 0,        // cluster-wide published plugin generation
  sharedPluginSyncBusy: false,    // local reaction to a peer-published generation
  stopping: false,
  controlServer: null,
  leaseHeartbeat: null,
  leaseHeartbeatBusy: false,
  leaseLastSuccessAt: Date.now(),
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

function writeAtomic(file, content, mode, owner) {
  const temporary = `${file}.tmp-${process.pid}`;
  try {
    fs.writeFileSync(temporary, content, { mode });
    // Publish with the final owner already set. Renaming a root-owned 0640
    // file and chowning afterwards exposes a short EACCES window to the
    // concurrently running dsh-gateway process.
    if (owner) execFileSync('chown', [owner, temporary]);
    fs.renameSync(temporary, file);
    fs.chmodSync(file, mode);
  } finally {
    try { fs.unlinkSync(temporary); } catch (error) {}
  }
}

// A tenant cannot open the shared 0711 USERS_DIR to fsync its own HOME entry.
// The root provisioner owns that durability boundary, so sync it once when a
// new HOME is created; attachment-local can then safely stop at DSH_HOME.
function fsyncDirectory(directory) {
  const fd = fs.openSync(directory, fs.constants.O_RDONLY);
  try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
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

function validPackageName(name) {
  return typeof name === 'string'
    && /^(?:@[A-Za-z0-9._-]+\/)?[A-Za-z0-9._-]+$/.test(name);
}

function validateSharedPluginConfig(value, label = 'shared plugin') {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  const name = value.name;
  const spec = value.spec === undefined ? name : value.spec;
  if (!validPackageName(name) || name === BETTER_SIDEBAR_PACKAGE) {
    throw new Error(`${label} has an invalid or reserved name`);
  }
  if (typeof spec !== 'string' || spec.length === 0 || spec.length > 512
      || spec.startsWith('-') || /[\r\n\0]/.test(spec)) {
    throw new Error(`${label} has an invalid spec`);
  }
  return { name, spec };
}

function parseSharedPluginConfigs() {
  let values;
  try {
    values = JSON.parse(process.env.DSH_SHARED_WEB_PLUGINS_JSON || '[]');
  } catch (error) {
    throw new Error(`DSH_SHARED_WEB_PLUGINS_JSON is not valid JSON: ${error.message}`);
  }
  if (!Array.isArray(values)) throw new Error('DSH_SHARED_WEB_PLUGINS_JSON must be an array');
  const names = new Set();
  return values.map((value, index) => {
    const config = validateSharedPluginConfig(value, `shared plugin ${index}`);
    const { name } = config;
    if (names.has(name)) throw new Error(`duplicate shared plugin name: ${name}`);
    names.add(name);
    return config;
  });
}

function readManifest(file, label) {
  let value;
  try { value = JSON.parse(fs.readFileSync(file, 'utf8')); } catch (error) {
    throw new Error(`cannot read ${label} manifest ${file}: ${error.message}`);
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} manifest must contain a JSON object: ${file}`);
  }
  return value;
}

function ensureDirectoryLink(link, target) {
  fs.mkdirSync(path.dirname(link), { recursive: true, mode: 0o700 });
  let stat;
  try { stat = fs.lstatSync(link); } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  const correct = stat && stat.isSymbolicLink() && fs.readlinkSync(link) === target;
  if (stat && !correct) {
    if (stat.isSymbolicLink()) fs.unlinkSync(link);
    else fs.rmSync(link, { recursive: true, force: true });
  }
  if (!correct) fs.symlinkSync(target, link, 'dir');
}

function workspaceContent() {
  return [
    'packages:',
    '  - .',
    '',
    'nodeLinker: hoisted',
    'autoInstallPeers: false',
    // Shared-plugin management is root-only. Per deployment policy, trust all
    // selected plugin dependency lifecycle scripts without per-package flags.
    'dangerouslyAllowAllBuilds: true',
    '',
  ].join('\n');
}

function ensureRuntimeSharedProfileSkeleton() {
  fs.mkdirSync(RUNTIME_SHARED_PROFILE, { recursive: true, mode: 0o755 });
  const manifestFile = path.join(RUNTIME_SHARED_PROFILE, 'package.json');
  let manifest = fs.existsSync(manifestFile)
    ? readManifest(manifestFile, 'runtime shared profile')
    : { name: 'dsh-runtime-shared-web-plugins', private: true, dependencies: {}, dsh: { profile: { bundles: [...WEB_PROFILE_BUNDLES] } } };
  const dependencies = manifest.dependencies && typeof manifest.dependencies === 'object'
    && !Array.isArray(manifest.dependencies) ? manifest.dependencies : {};
  dependencies[BETTER_SIDEBAR_PACKAGE] = BETTER_SIDEBAR_SPEC;
  const dsh = manifest.dsh && typeof manifest.dsh === 'object' && !Array.isArray(manifest.dsh) ? manifest.dsh : {};
  const profile = dsh.profile && typeof dsh.profile === 'object' && !Array.isArray(dsh.profile) ? dsh.profile : {};
  const bundles = Array.isArray(profile.bundles) ? profile.bundles : [...WEB_PROFILE_BUNDLES];
  if (!bundles.includes(BETTER_SIDEBAR_PACKAGE)) bundles.push(BETTER_SIDEBAR_PACKAGE);
  manifest = { ...manifest, private: true, dependencies, dsh: { ...dsh, profile: { ...profile, bundles } } };
  writeAtomic(manifestFile, `${JSON.stringify(manifest, null, 2)}\n`, 0o644);
  const patchFile = path.join(RUNTIME_SHARED_PROFILE, 'cordis.patch.yml');
  if (!fs.existsSync(patchFile)) fs.writeFileSync(patchFile, '[]\n', { mode: 0o644 });
  writeAtomic(path.join(RUNTIME_SHARED_PROFILE, 'pnpm-workspace.yaml'), workspaceContent(), 0o644);
  ensureDirectoryLink(path.join(RUNTIME_SHARED_PROFILE, 'node_modules', BETTER_SIDEBAR_PACKAGE), BETTER_SIDEBAR_DIR);
}

function healRuntimeSharedFallback() {
  execFileSync(NODE_BIN, ['--input-type=module', '-e',
    'const m=await import("/opt/deepseek-harness/packages/boot/app-boot/lib/index.js"); m.healProfilesModuleFallback("/opt/deepseek-harness/apps/cli/package.json", process.env.DSH_SHARED_PLUGINS_HOME)'], {
    stdio: 'inherit',
    env: { ...process.env, DSH_SHARED_PLUGINS_HOME: RUNTIME_SHARED_HOME },
  });
}

// The shared-plugin command currently executing (if any), so an admin cancel
// can kill a hung pnpm install. `detached: true` makes the child a process-
// group leader, so the kill below sweeps pnpm and its whole tree.
let activeSharedPluginChild = null;
function runRuntimeSharedPluginCommand(action, spec, onProgress) {
  const streamOutput = typeof onProgress === 'function';
  return new Promise((resolve, reject) => {
    const child = spawn(NODE_BIN, [DSH_BIN, 'plugin', '--profile', 'web', action, spec], {
      cwd: RUNTIME_SHARED_HOME,
      detached: true,
      stdio: streamOutput ? ['ignore', 'pipe', 'pipe'] : 'inherit',
      env: {
        ...process.env,
        DSH_HOME: RUNTIME_SHARED_HOME,
        HOME: RUNTIME_SHARED_HOME,
        SHELL: '/bin/bash',
        NPM_CONFIG_UPDATE_NOTIFIER: 'false',
      },
    });
    activeSharedPluginChild = child;
    if (streamOutput) {
      const forward = (target) => (chunk) => {
        target.write(chunk);
        onProgress(chunk.toString('utf8'));
      };
      child.stdout.on('data', forward(process.stdout));
      child.stderr.on('data', forward(process.stderr));
    }
    child.once('error', (error) => { if (activeSharedPluginChild === child) activeSharedPluginChild = null; reject(error); });
    child.once('close', (code, signal) => {
      if (activeSharedPluginChild === child) activeSharedPluginChild = null;
      if (code === 0) resolve();
      else if (signal === 'SIGKILL') reject(new Error('plugin operation canceled'));
      else reject(new Error(`dsh plugin ${action} failed (code=${code}, signal=${signal || 'none'})`));
    });
  });
}

function controlPluginCancel() {
  const child = activeSharedPluginChild;
  activeSharedPluginChild = null;
  if (!child) return { ok: true, result: { canceled: false } };
  try { process.kill(-child.pid, 'SIGKILL'); } catch (e) {
    try { child.kill('SIGKILL'); } catch (e2) {}
  }
  return { ok: true, result: { canceled: true } };
}

function discoverRuntimeSharedPlugins() {
  const manifestFile = path.join(RUNTIME_SHARED_PROFILE, 'package.json');
  if (!fs.existsSync(manifestFile)) return [];
  const manifest = readManifest(manifestFile, 'runtime shared profile');
  const dependencies = manifest.dependencies && typeof manifest.dependencies === 'object' ? manifest.dependencies : {};
  const bundles = manifest.dsh && manifest.dsh.profile && Array.isArray(manifest.dsh.profile.bundles)
    ? manifest.dsh.profile.bundles : [];
  const result = [];
  for (const name of bundles) {
    if (name === BETTER_SIDEBAR_PACKAGE || !Object.prototype.hasOwnProperty.call(dependencies, name)) continue;
    const dir = path.join(RUNTIME_SHARED_PROFILE, 'node_modules', name);
    const packageFile = path.join(dir, 'package.json');
    if (!fs.existsSync(packageFile)) throw new Error(`runtime shared plugin is missing: ${packageFile}`);
    const pluginManifest = readManifest(packageFile, `runtime shared plugin ${name}`);
    if (!pluginManifest.dsh || !pluginManifest.dsh.bundle || typeof pluginManifest.dsh.bundle.patch !== 'string') {
      throw new Error(`runtime shared dependency ${name} does not declare dsh.bundle.patch`);
    }
    result.push({ name, dir });
  }
  return result;
}

function discoverAllSharedPlugins() {
  return [
    { name: BETTER_SIDEBAR_PACKAGE, dir: BETTER_SIDEBAR_DIR },
    ...discoverRuntimeSharedPlugins(),
  ];
}

async function ensureRuntimeSharedPlugins(configs, onProgress) {
  const sharedManifest = path.join(BETTER_SIDEBAR_DIR, 'package.json');
  if (!fs.existsSync(sharedManifest)) throw new Error(`shared better-sidebar package is missing: ${sharedManifest}`);
  const alreadyExists = fs.existsSync(path.join(RUNTIME_SHARED_PROFILE, 'package.json'));
  if (configs.length === 0 && !alreadyExists) return [{ name: BETTER_SIDEBAR_PACKAGE, dir: BETTER_SIDEBAR_DIR }];

  ensureRuntimeSharedProfileSkeleton();
  const receipts = readJson(RUNTIME_SHARED_RECEIPTS, { version: 1, specs: {} });
  if (!receipts.specs || typeof receipts.specs !== 'object') receipts.specs = {};
  for (const config of configs) {
    const packageFile = path.join(RUNTIME_SHARED_PROFILE, 'node_modules', config.name, 'package.json');
    const profileManifest = readManifest(path.join(RUNTIME_SHARED_PROFILE, 'package.json'), 'runtime shared profile');
    const installed = fs.existsSync(packageFile)
      && profileManifest.dependencies && Object.prototype.hasOwnProperty.call(profileManifest.dependencies, config.name)
      && profileManifest.dsh && profileManifest.dsh.profile && Array.isArray(profileManifest.dsh.profile.bundles)
      && profileManifest.dsh.profile.bundles.includes(config.name)
      && receipts.specs[config.name] === config.spec;
    if (installed) continue;
    console.log(`installing runtime shared plugin ${config.name} from ${config.spec}`);
    const previousDependencies = new Set(Object.keys(profileManifest.dependencies || {}));
    await runRuntimeSharedPluginCommand('add', config.spec, onProgress);
    try {
      const installedManifest = readManifest(packageFile, `runtime shared plugin ${config.name}`);
      if (installedManifest.name !== config.name) {
        throw new Error(`spec installed ${installedManifest.name || 'an unnamed package'}, expected ${config.name}`);
      }
      if (!installedManifest.dsh || !installedManifest.dsh.bundle
          || typeof installedManifest.dsh.bundle.patch !== 'string') {
        throw new Error(`${config.name} does not declare dsh.bundle.patch`);
      }
    } catch (error) {
      // A wrong --name or a non-DSH package must not poison the persistent
      // profile. Remove every dependency introduced by this failed add.
      const failedManifest = readManifest(path.join(RUNTIME_SHARED_PROFILE, 'package.json'), 'runtime shared profile');
      const addedNames = Object.keys(failedManifest.dependencies || {})
        .filter((name) => !previousDependencies.has(name) && name !== BETTER_SIDEBAR_PACKAGE);
      for (const addedName of addedNames) {
        try { await runRuntimeSharedPluginCommand('remove', addedName, onProgress); } catch (removeError) {
          console.error(`WARNING: DSH could not roll back ${addedName}: ${removeError.message}`);
        }
      }
      const cleanedManifest = readManifest(path.join(RUNTIME_SHARED_PROFILE, 'package.json'), 'runtime shared profile');
      for (const addedName of addedNames) {
        if (cleanedManifest.dependencies && typeof cleanedManifest.dependencies === 'object') {
          delete cleanedManifest.dependencies[addedName];
        }
        if (cleanedManifest.dsh && cleanedManifest.dsh.profile && Array.isArray(cleanedManifest.dsh.profile.bundles)) {
          cleanedManifest.dsh.profile.bundles = cleanedManifest.dsh.profile.bundles.filter((name) => name !== addedName);
        }
      }
      writeAtomic(path.join(RUNTIME_SHARED_PROFILE, 'package.json'), `${JSON.stringify(cleanedManifest, null, 2)}\n`, 0o644);
      throw new Error(`shared plugin ${config.spec} was rejected and rolled back: ${error.message}`);
    }
    receipts.specs[config.name] = config.spec;
  }
  healRuntimeSharedFallback();
  writeAtomic(RUNTIME_SHARED_RECEIPTS, `${JSON.stringify(receipts, null, 2)}\n`, 0o600);
  execFileSync('chown', ['-hR', 'root:root', RUNTIME_SHARED_HOME]);
  execFileSync('chmod', ['-R', 'a+rX', RUNTIME_SHARED_HOME]);
  execFileSync('chmod', ['-R', 'go-w', RUNTIME_SHARED_HOME]);
  return [
    { name: BETTER_SIDEBAR_PACKAGE, dir: BETTER_SIDEBAR_DIR },
    ...discoverRuntimeSharedPlugins(),
  ];
}

function sharedPluginDetails(plugin) {
  const manifest = readManifest(path.join(plugin.dir, 'package.json'), `shared plugin ${plugin.name}`);
  return {
    name: plugin.name,
    version: typeof manifest.version === 'string' ? manifest.version : null,
    source: plugin.name === BETTER_SIDEBAR_PACKAGE ? 'image' : 'runtime',
    dir: plugin.dir,
  };
}

// Synchronize every image/runtime shared bundle into one tenant profile. The
// tracking file lets a future shared-plugin removal clean only links managed
// by this deployment while preserving plugins the tenant installed itself.
function ensureSharedWebPluginsProfile(home) {
  const sharedPlugins = state.sharedWebPlugins;

  const profileDir = path.join(home, 'profiles', 'web');
  const profileManifest = path.join(profileDir, 'package.json');
  const profilePatch = path.join(profileDir, 'cordis.patch.yml');
  const profileWorkspace = path.join(profileDir, 'pnpm-workspace.yaml');
  fs.mkdirSync(profileDir, { recursive: true, mode: 0o700 });

  let manifest;
  if (fs.existsSync(profileManifest)) {
    try {
      manifest = JSON.parse(fs.readFileSync(profileManifest, 'utf8'));
    } catch (error) {
      throw new Error(`cannot read web profile manifest ${profileManifest}: ${error.message}`);
    }
    if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) {
      throw new Error(`web profile manifest must contain a JSON object: ${profileManifest}`);
    }
  } else {
    manifest = {
      name: 'dsh-profile-web',
      private: true,
      dependencies: {},
      dsh: { profile: { bundles: [...WEB_PROFILE_BUNDLES] } },
    };
  }

  const dependencies = manifest.dependencies && typeof manifest.dependencies === 'object'
    && !Array.isArray(manifest.dependencies) ? manifest.dependencies : {};
  const trackingFile = path.join(profileDir, SHARED_PLUGINS_FILE);
  const tracked = readJson(trackingFile, { version: 1, plugins: [] });
  const previousNames = Array.isArray(tracked.plugins) ? tracked.plugins.filter(validPackageName) : [];
  const currentNames = sharedPlugins.map((plugin) => plugin.name);
  for (const name of previousNames) {
    if (currentNames.includes(name)) continue;
    const spec = dependencies[name];
    if (typeof spec === 'string' && (spec.startsWith(`link:${RUNTIME_SHARED_HOME}/`) || spec.startsWith('link:/opt/dsh-public/'))) {
      delete dependencies[name];
    }
  }
  for (const plugin of sharedPlugins) dependencies[plugin.name] = `link:${plugin.dir}`;
  const dsh = manifest.dsh && typeof manifest.dsh === 'object' && !Array.isArray(manifest.dsh)
    ? manifest.dsh : {};
  const profile = dsh.profile && typeof dsh.profile === 'object' && !Array.isArray(dsh.profile)
    ? dsh.profile : {};
  const existingBundles = Array.isArray(profile.bundles) ? profile.bundles : [...WEB_PROFILE_BUNDLES];
  const baseBundles = WEB_PROFILE_BUNDLES.filter((name) => existingBundles.includes(name));
  const tenantBundles = existingBundles.filter((name) => !WEB_PROFILE_BUNDLES.includes(name)
    && !previousNames.includes(name) && !currentNames.includes(name));
  const bundles = [...baseBundles, ...currentNames, ...tenantBundles];
  manifest = { ...manifest, dependencies, dsh: { ...dsh, profile: { ...profile, bundles } } };
  writeAtomic(profileManifest, `${JSON.stringify(manifest, null, 2)}\n`, 0o644);

  if (!fs.existsSync(profilePatch)) fs.writeFileSync(profilePatch, '[]\n', { mode: 0o644 });
  if (!fs.existsSync(profileWorkspace)) {
    writeAtomic(profileWorkspace, [
      'packages:',
      '  - .',
      '',
      'nodeLinker: hoisted',
      'autoInstallPeers: false',
      '',
    ].join('\n'), 0o644);
  }

  for (const name of previousNames) {
    if (currentNames.includes(name)) continue;
    const link = path.join(profileDir, 'node_modules', name);
    try {
      const stat = fs.lstatSync(link);
      if (stat.isSymbolicLink()) fs.unlinkSync(link);
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
  }
  for (const plugin of sharedPlugins) {
    if (!fs.existsSync(path.join(plugin.dir, 'package.json'))) {
      throw new Error(`shared plugin package is missing: ${plugin.dir}`);
    }
    ensureDirectoryLink(path.join(profileDir, 'node_modules', plugin.name), plugin.dir);
  }
  writeAtomic(trackingFile, `${JSON.stringify({ version: 1, plugins: currentNames }, null, 2)}\n`, 0o644);

  // Remove the sibling fallback link created by the first shared-package
  // revision; the current profile-local link lives inside web/node_modules.
  const legacyLink = path.join(home, 'profiles', 'node_modules', BETTER_SIDEBAR_PACKAGE);
  try {
    const stat = fs.lstatSync(legacyLink);
    if (stat.isSymbolicLink() && fs.readlinkSync(legacyLink).startsWith('/opt/dsh-plugins/')) {
      fs.unlinkSync(legacyLink);
    }
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
}

// ---------- custom provider provisioning (llm-pi-ai) ----------

function providerApiKeyEnv(name) {
  return String(name).toUpperCase().replace(/[^A-Z0-9]/g, '_') + '_API_KEY';
}

// Validate an optional custom-provider spec from the registration API.
// Returns null when absent; throws on malformed values. The API key itself is
// NOT set here - the external caller writes it later via the key endpoint.
// `models` accepts legacy model-id strings and capability-aware
// `{id,input:[text,image]}` entries (a single `model` string is also accepted
// for convenience). `api` must be one of the pi-ai protocols (an invalid
// protocol makes the whole llm-pi-ai settings section fail validation and the
// route stays dormant); 'openai-completions' is the OpenAI-compatible default.
const SUPPORTED_PROVIDER_APIS = ['openai-completions', 'openai-responses', 'anthropic-messages'];
const SUPPORTED_MODEL_INPUTS = ['text', 'image'];
function validateProviderModel(value, index) {
  const source = typeof value === 'string' ? { id: value } : value;
  if (!source || typeof source !== 'object' || Array.isArray(source)) {
    throw new Error(`provider model ${index} must be a string or object`);
  }
  const id = typeof source.id === 'string' ? source.id.trim() : '';
  if (!id || id.length > 128) throw new Error(`provider model ${index} has an invalid id`);
  const rawInput = source.input === undefined ? ['text'] : source.input;
  if (!Array.isArray(rawInput) || rawInput.length === 0
      || rawInput.some((entry) => !SUPPORTED_MODEL_INPUTS.includes(entry))
      || new Set(rawInput).size !== rawInput.length) {
    throw new Error(`provider model ${id} input must contain unique text/image values`);
  }
  return { id, input: [...rawInput] };
}
function validateProvider(provider) {
  if (provider === undefined || provider === null) return null;
  if (typeof provider !== 'object' || Array.isArray(provider)) throw new Error('provider must be an object');
  const { name, baseURL } = provider;
  if (typeof name !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(name)) {
    throw new Error('provider name must be letters, digits, underscore or hyphen');
  }
  if (typeof baseURL !== 'string' || !/^https?:\/\/[^\s]+$/.test(baseURL)) {
    throw new Error('provider baseURL must be an http(s) URL');
  }
  let models;
  if (Array.isArray(provider.models) && provider.models.length > 0) {
    models = provider.models.map(validateProviderModel);
  } else if (typeof provider.model === 'string' && provider.model.trim() !== '') {
    const m = provider.model.trim();
    if (m.length > 128) throw new Error('provider model is too long');
    models = [{ id: m, input: ['text'] }];
  } else {
    throw new Error('provider model(s) are required');
  }
  const api = provider.api === undefined || provider.api === null || provider.api === ''
    ? 'openai-completions'
    : String(provider.api);
  if (!SUPPORTED_PROVIDER_APIS.includes(api)) {
    throw new Error(`provider api must be one of: ${SUPPORTED_PROVIDER_APIS.join(', ')}`);
  }
  const ids = models.map((entry) => entry.id);
  if (new Set(ids).size !== ids.length) throw new Error('provider model ids must not contain duplicates');
  return { name, baseURL, model: models[0].id, models, api };
}

// yq-safe YAML scalar quoting (double-quoted; JSON.stringify output is valid
// YAML for these simple values).
function yq(v) { return JSON.stringify(String(v)); }

// settings.yaml for a user whose account is bound to a custom provider: the
// llm-pi-ai namespace defines the provider (OpenAI-compatible adapter), and
// agent-default-model points at it so the web client uses it by default.
// Suppress the web UI's first-run welcome notice for managed tenants.
const WELCOME_NOTICE_VERSION = '2026-08-13.1';
function ensureWelcomeNoticeAck(home, osUser) {
  const file = path.join(home, 'settings.yaml');
  let content = '';
  try { content = fs.readFileSync(file, 'utf8'); } catch (e) {}
  if (/^\s*welcomeNoticeVersion\s*:/m.test(content)) return;
  const field = '  welcomeNoticeVersion: "' + WELCOME_NOTICE_VERSION + '"\n';
  if (/^\s*ui-onboarding\s*:/m.test(content)) {
    content = content.replace(/^(\s*ui-onboarding\s*:.*(?:\n|$))/m, (match, head) => head + field);
  } else {
    content = content.replace(/\s*$/, '\n') + 'ui-onboarding:\n' + field;
  }
  fs.writeFileSync(file, content, { mode: 0o644 });
  try { execFileSync('chown', [osUser + ':' + osUser, file]); } catch (e) {}
}

function providerSettingsYaml(provider) {
  const ref = providerApiKeyEnv(provider.name);
  const lines = [
    'agent-default-model:',
    `  provider: ${provider.name}`,
    `  model: ${yq(provider.models[0].id)}`,
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
  ];
  for (const m of provider.models) {
    lines.push(
      `        - id: ${yq(m.id)}`,
      `          name: ${yq(m.id)}`,
      '          contextWindow: 32768',
      '          maxTokens: 8192',
      `          input: [${m.input.join(', ')}]`,
    );
  }
  lines.push('');
  return lines.join('\n');
}

function provisionTenant(tenant, port, uid, existing) {
  const home = path.join(USERS_DIR, tenant.name);
  const workspace = path.join(home, 'workspace');
  const homeExisted = fs.existsSync(home);
  const osUser = ensureOsUser(tenant.name, home, uid);
  fs.mkdirSync(workspace, { recursive: true, mode: 0o700 });
  if (!homeExisted) fsyncDirectory(USERS_DIR);
  const searchPatch = path.join(home, 'cordis.patch.yml');
  if (!fs.existsSync(searchPatch)) {
    fs.writeFileSync(searchPatch, searchPatchContent(), { mode: 0o644 });
  }
  ensureSharedWebPluginsProfile(home);
  if (tenant.provider) {
    // Custom provider: default the web client to it and skip the /setup gate
    // (the API key is written afterwards by the external key endpoint).
    fs.writeFileSync(path.join(home, 'settings.yaml'), providerSettingsYaml(tenant.provider), { mode: 0o644 });
  }
  ensureWelcomeNoticeAck(home, osUser);
  if (tenant.apiKey !== undefined) {
    setApiKey(USERS_DIR, tenant.name, tenant.apiKey);
  } else {
    if (repairCredentials(USERS_DIR, tenant.name)) console.log(`credentials repaired for tenant ${tenant.name}`);
  }
  execFileSync('chown', ['-hR', `${osUser}:${osUser}`, home]);
  fs.chmodSync(home, 0o700);
  const passwordUnchanged = existing && existing.pwd && verifyPassword(tenant.password, existing.pwd);
  const record = {
    uid,
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
      models: tenant.provider.models,
      api: tenant.provider.api,
      apiKeyEnv: providerApiKeyEnv(tenant.provider.name),
    };
  } else if (existing && existing.provider) {
    record.provider = existing.provider;
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
  ensureSharedWebPluginsProfile(record.home);
  ensureWelcomeNoticeAck(record.home, osUser);
  if (repairCredentials(USERS_DIR, name)) console.log(`credentials repaired for tenant ${name}`);
  execFileSync('chown', ['-hR', `${osUser}:${osUser}`, record.home]);
  fs.chmodSync(record.home, 0o700);
  return { ...record, uid, osUser, home: record.home, port: record.port };
}

function readJson(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (error) {
    if (error && error.code === 'ENOENT') return fallback;
    throw new Error(`cannot read ${file}: ${error.message}`);
  }
}

// Create or migrate the admin as a full tenant. The password still comes from
// DSH_ADMIN_PASSWORD, but admin now owns an OS account, HOME, port and lazy DSH
// process just like every other user while retaining the authorization flag.
function provisionAdmin(db, previousUsers, identities, usedPortsSet) {
  if (ADMIN_PASSWORD === undefined || ADMIN_PASSWORD === '') return;
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(ADMIN_NAME)) throw new Error(`invalid DSH_ADMIN_NAME: ${ADMIN_NAME}`);
  if (typeof ADMIN_PASSWORD !== 'string' || ADMIN_PASSWORD.length < MIN_PASSWORD_LENGTH) {
    throw new Error(`DSH_ADMIN_PASSWORD must contain at least ${MIN_PASSWORD_LENGTH} characters`);
  }
  const existing = previousUsers[ADMIN_NAME];
  let port;
  if (existing && Number.isInteger(existing.port) && !usedPortsSet.has(existing.port)) port = existing.port;
  else port = nextFreePort(usedPortsSet);
  usedPortsSet.add(port);
  const identity = identities[ADMIN_NAME.toLowerCase()];
  const record = provisionTenant({ name: ADMIN_NAME, password: ADMIN_PASSWORD }, port, identity.uid, existing);
  if (existing && existing.provider) record.provider = existing.provider;
  db.users[ADMIN_NAME] = { ...record, admin: true };
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

function spawnManaged(label, command, args, options = {}, lifecycle = {}) {
  const child = spawn(command, args, { stdio: 'inherit', detached: true, ...options });
  const managed = { label, child };
  children.push(managed);
  let settled = false;
  let resolveTermination;
  child.__dshTermination = new Promise((resolve) => { resolveTermination = resolve; });
  const terminated = (code, signal, error) => {
    if (settled) return;
    settled = true;
    const detail = { code, signal, error: error || null };
    resolveTermination(detail);
    const managedIndex = children.indexOf(managed);
    if (managedIndex >= 0) children.splice(managedIndex, 1);
    if (state.stopping) return;
    if (child.__dshDeliberateStop) return;
    const suffix = error
      ? `spawn failed (${error.message})`
      : `exited unexpectedly (code=${code}, signal=${signal})`;
    const disposition = lifecycle.fatal === false ? '; isolated without supervisor shutdown' : '';
    console.error(`${label} ${suffix}${disposition}`);
    if (typeof lifecycle.onUnexpectedExit === 'function') {
      try { lifecycle.onUnexpectedExit(detail, child); } catch (hookError) {
        console.error(`${label} exit handler failed: ${hookError.message}`);
      }
    }
    if (lifecycle.fatal !== false) shutdown(1);
  };
  child.once('error', (error) => terminated(null, null, error));
  child.once('exit', (code, signal) => terminated(code, signal, null));
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
    // Visible home for the tenant process: point at the workspace so the SPA
    // directory picker / homedir() / shell default all land in the user's
    // work directory instead of the home root (which holds DSH internals:
    // profiles/, storages/, settings.yaml, ...). DSH state itself stays under
    // DSH_HOME, so credentials and profiles are unaffected.
    `HOME=${record.home}/workspace`,
    'SHELL=/bin/bash',
    `PATH=${process.env.PATH || '/usr/local/bin:/usr/bin:/bin'}`,
    `DEEPSEEK_BASE_URL=${process.env.DEEPSEEK_BASE_URL || 'https://api.deepseek.com'}`,
  ];
  return ['-u', record.osUser, '--', 'env', ...env, NODE_BIN, DSH_BIN,
    '--profile', 'web', '--patch', DEPLOYMENT_PATCH,
    '--no-open',
    '--host', '127.0.0.1', '--port', String(record.port)];
}

function gatewayArgs() {
  const env = [
    'HOST=0.0.0.0',
    `PORT=${GATEWAY_PORT}`,
    `USERS_FILE=${USERS_FILE}`,
    `SECRET_FILE=${SECRET_FILE}`,
    `CWD_STATE_FILE=${CWD_STATE_FILE}`,
    `DSH_CONTROL_SOCKET=${CONTROL_SOCKET}`,
    `USERS_DIR=${USERS_DIR}`,
    `COOKIE_SECURE=${process.env.COOKIE_SECURE || '0'}`,
    `SESSION_TTL=${process.env.SESSION_TTL || '43200'}`,
    `SESSION_REFRESH_INTERVAL=${process.env.SESSION_REFRESH_INTERVAL || '0'}`,
    `DSH_PLUGIN_TARBALL_DIR=${process.env.DSH_PLUGIN_TARBALL_DIR || path.join(STATE_DIR, 'plugin-tarballs')}`,
    `PLUGIN_TARBALL_MAX_MB=${process.env.PLUGIN_TARBALL_MAX_MB || '100'}`,
    `DEEPSEEK_BASE_URL=${process.env.DEEPSEEK_BASE_URL || 'https://api.deepseek.com'}`,
    `DSH_BROWSER_PRESENCE_TTL_MS=${process.env.DSH_BROWSER_PRESENCE_TTL_MS || '86400000'}`,
    `DSH_BROWSER_STOP_GRACE_MS=${process.env.DSH_BROWSER_STOP_GRACE_MS || '5000'}`,
    'UPLOAD_HELPER=/usr/local/libexec/dsh/dsh-file-put',
    'FILE_STAT_HELPER=/usr/local/libexec/dsh/dsh-file-stat',
    'FILE_READ_HELPER=/usr/local/libexec/dsh/dsh-file-read',
    'FILE_LIST_HELPER=/usr/local/libexec/dsh/dsh-file-list',
    'FILE_DELETE_HELPER=/usr/local/libexec/dsh/dsh-file-delete',
    'FILE_MKDIR_HELPER=/usr/local/libexec/dsh/dsh-file-mkdir',
  ];
  for (const name of [
    'DSH_CLUSTER_MODE',
    'DSH_CLUSTER_DATABASE_URL',
    'DSH_CLUSTER_TOKEN',
    'DSH_NODE_ID',
    'DSH_NODE_ADDRESS',
    'POD_UID',
    'POD_IP',
    'DSH_SESSION_SECRET',
    'DSH_TENANT_LEASE_SECONDS',
  ]) {
    if (process.env[name]) env.push(`${name}=${process.env[name]}`);
  }
  return ['-u', 'dsh-gateway', '--', 'env', ...env, NODE_BIN, GATEWAY_SERVER];
}

// ---------- users.json persistence + firewall refresh ----------

function saveUsersDb(db) {
  writeAtomic(USERS_FILE, `${JSON.stringify(db, null, 2)}\n`, 0o640, 'dsh-gateway:dsh-gateway');
}

function refreshUsersDb() {
  const db = readJson(USERS_FILE, { version: 1, users: {} });
  if (!db || typeof db !== 'object' || !db.users || typeof db.users !== 'object') {
    throw new Error(`${USERS_FILE} has an invalid structure`);
  }
  state.db = db;
  return db;
}

function ensureLocalUser(record, name) {
  const uid = Number(record && record.uid);
  if (!Number.isInteger(uid) || uid < 20000) throw new Error(`user ${name} has no valid uid`);
  let existed = true;
  try { execFileSync('id', [record.osUser || osUserOf(name)], { stdio: 'ignore' }); } catch (error) { existed = false; }
  const osUser = ensureOsUser(name, record.home, uid);
  if (record.osUser !== osUser) record.osUser = osUser;
  return { osUser, created: !existed };
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
// and after every add/del so isolation rules always match reality. Admin is a
// full tenant and receives the same loopback isolation rule as other users.
function applyLoopbackGuard() {
  const specs = Object.values(state.db.users)
    .filter((record) => {
      if (!record || !record.osUser || !Number.isInteger(record.port)) return false;
      try { execFileSync('id', [record.osUser], { stdio: 'ignore' }); return true; } catch (error) { return false; }
    })
    .map((record) => `${record.osUser}:${record.port}`);
  execFileSync(LOOPBACK_GUARD, ['--apply', ...specs], {
    stdio: 'inherit',
    env: { ...process.env, GW_PORT: String(GATEWAY_PORT) },
  });
}

// ---------- tenant process lifecycle ----------

function ownerResult(owner, started = false) {
  return {
    name: owner.username,
    port: owner.tenantPort,
    started,
    local: owner.local,
    owner: {
      nodeId: owner.nodeId,
      address: owner.nodeAddress,
      gatewayPort: owner.gatewayPort,
      generation: owner.generation,
      leaseUntil: owner.leaseUntil,
    },
  };
}

function stopRemoteTenant(owner, name, reason, revokeSessions) {
  const token = process.env.DSH_CLUSTER_TOKEN || '';
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ action: 'sleep', name, reason, revokeSessions });
    const request = http.request({
      host: owner.nodeAddress,
      port: owner.gatewayPort,
      method: 'POST',
      path: '/__gw/internal/tenant-control',
      headers: {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(body),
        'x-dsh-cluster-token': token,
      },
    }, (response) => {
      let raw = '';
      response.setEncoding('utf8');
      response.on('data', (chunk) => { if (raw.length < 65536) raw += chunk; });
      response.on('end', () => {
        let reply;
        try { reply = JSON.parse(raw); } catch (error) {}
        if ((response.statusCode || 500) >= 200 && (response.statusCode || 500) < 300 && reply && reply.ok === true) resolve(reply);
        else reject(new Error((reply && reply.error) || `remote owner returned HTTP ${response.statusCode}`));
      });
    });
    request.setTimeout(150000, () => request.destroy(new Error('remote tenant stop timeout')));
    request.once('error', reject);
    request.end(body);
  });
}

async function releaseTenantLease(name) {
  const lease = state.tenantLeases.get(name);
  state.tenantLeases.delete(name);
  if (!lease) return;
  try {
    await clusterStore.releaseTenant(name, lease.generation);
  } catch (error) {
    console.error(`tenant ${name} lease release failed: ${error.message}`);
  }
}

function startLeaseHeartbeat() {
  if (!CLUSTER_ENABLED || state.leaseHeartbeat) return;
  const intervalMs = Math.max(1000, Math.floor(clusterStore.leaseSeconds * 1000 / 4));
  const fenceMs = Math.max(5000, Math.floor(clusterStore.leaseSeconds * 1000 * 0.6));
  state.leaseLastSuccessAt = Date.now();
  state.leaseHeartbeat = setInterval(async () => {
    if (state.stopping || state.leaseHeartbeatBusy) return;
    state.leaseHeartbeatBusy = true;
    try {
      await clusterStore.registerNode(false);
      for (const [name, lease] of state.tenantLeases) {
        const renewed = await clusterStore.renewTenant(name, lease.generation);
        if (!renewed) throw new Error(`tenant lease was lost: ${name}`);
        lease.lastRenewedAt = Date.now();
      }
      const pluginRevision = await clusterStore.getRevision('shared-plugins');
      if (pluginRevision > state.sharedPluginRevision && !state.sharedPluginSyncBusy) {
        synchronizePublishedSharedPlugins(pluginRevision).catch(() => {});
      }
      state.leaseLastSuccessAt = Date.now();
    } catch (error) {
      console.error(`cluster lease heartbeat failed: ${error.message}`);
      if (Date.now() - state.leaseLastSuccessAt >= fenceMs) {
        console.error('cluster lease fencing deadline reached; stopping this container before leases expire');
        shutdown(1);
      }
    } finally {
      state.leaseHeartbeatBusy = false;
    }
  }, intervalMs);
  state.leaseHeartbeat.unref();
}

function startTenant(name, record) {
  const existing = state.tenants.get(name);
  if (existing) return existing;
  let child;
  child = spawnManaged(`tenant:${name}`, 'runuser', tenantArgs(record), {}, {
    fatal: false,
    onUnexpectedExit: () => {
      const active = state.tenants.get(name);
      if (active && active.child === child) state.tenants.delete(name);
      releaseTenantLease(name).catch(() => {});
    },
  });
  const entry = { record, child, termination: child.__dshTermination };
  state.tenants.set(name, entry);
  return entry;
}

function tenantTerminationError(name, detail) {
  if (detail && detail.error) return new Error(`tenant ${name} failed to start: ${detail.error.message}`);
  return new Error(`tenant ${name} exited during startup (code=${detail && detail.code}, signal=${detail && detail.signal})`);
}

function waitWhileTenantRunning(name, entry, operation) {
  return Promise.race([
    operation,
    entry.termination.then((detail) => { throw tenantTerminationError(name, detail); }),
  ]);
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

function killAllProcessesForOsUser(osUser) {
  let uid;
  try { uid = Number(execFileSync('id', ['-u', osUser], { encoding: 'utf8' }).trim()); } catch (e) { return 0; }
  if (!Number.isInteger(uid) || uid < 1) return 0;
  let killed = 0;
  for (const entry of fs.readdirSync('/proc')) {
    if (!/^\d+$/.test(entry)) continue;
    const pid = Number(entry);
    try {
      const status = fs.readFileSync(`/proc/${entry}/status`, 'utf8');
      const match = /^Uid:\s+(\d+)/m.exec(status);
      if (!match || Number(match[1]) !== uid) continue;
      process.kill(pid, 'SIGKILL');
      killed += 1;
    } catch (e) {}
  }
  return killed;
}

function tenantProcessStats() {
  const uidToName = new Map();
  const stats = {};
  for (const [name, record] of Object.entries(state.db.users)) {
    if (!record || !record.osUser) continue;
    try {
      const uid = Number(execFileSync('id', ['-u', record.osUser], { encoding: 'utf8' }).trim());
      if (!Number.isInteger(uid)) continue;
      uidToName.set(uid, name);
      const active = state.tenants.get(name);
      stats[name] = {
        running: !!active,
        launcherPid: active ? active.child.pid : null,
        processCount: 0,
        rssBytes: 0,
      };
    } catch (e) {}
  }
  for (const entry of fs.readdirSync('/proc')) {
    if (!/^\d+$/.test(entry)) continue;
    try {
      const status = fs.readFileSync(`/proc/${entry}/status`, 'utf8');
      const uidMatch = /^Uid:\s+(\d+)/m.exec(status);
      if (!uidMatch) continue;
      const name = uidToName.get(Number(uidMatch[1]));
      if (!name) continue;
      const rssMatch = /^VmRSS:\s+(\d+)\s+kB/m.exec(status);
      stats[name].processCount += 1;
      if (rssMatch) stats[name].rssBytes += Number(rssMatch[1]) * 1024;
    } catch (e) {}
  }
  return stats;
}

async function ensureTenantStarted(name, record) {
  if (state.tenantStarts.has(name)) return state.tenantStarts.get(name);
  if (state.tenants.has(name)) return { name, port: record.port, started: false };
  const startup = (async () => {
    const entry = startTenant(name, record);
    try {
      await waitWhileTenantRunning(name, entry, waitForPort(record.port, 90000));
      const ready = await waitWhileTenantRunning(name, entry, waitForInstanceReady(record.port, 30000));
      if (!ready) throw new Error(`tenant ${name} did not finish initialization within 30 seconds`);
      console.log(`tenant ${name} started on demand at 127.0.0.1:${record.port}`);
      return { name, port: record.port, started: true };
    } catch (error) {
      await stopTenant(name);
      throw error;
    }
  })();
  state.tenantStarts.set(name, startup);
  try {
    return await startup;
  } finally {
    state.tenantStarts.delete(name);
  }
}

function syncSharedPluginsToAllUsers() {
  let count = 0;
  for (const record of Object.values(state.db.users)) {
    if (!record || !record.home || !record.osUser) continue;
    ensureSharedWebPluginsProfile(record.home);
    execFileSync('chown', ['-hR', `${record.osUser}:${record.osUser}`, path.join(record.home, 'profiles', 'web')]);
    count += 1;
  }
  return count;
}

async function restartAllTenantProcesses() {
  const tenants = [...state.tenants.entries()].map(([name, entry]) => ({ name, record: entry.record }));
  await Promise.all(tenants.map(({ name }) => stopTenant(name)));
  for (const { name, record } of tenants) startTenant(name, record);
  await Promise.all(tenants.map(({ record }) => waitForPort(record.port, 120000)));
  const ready = await Promise.all(tenants.map(({ record }) => waitForInstanceReady(record.port, 60000)));
  ready.forEach((isReady, index) => {
    if (!isReady) console.error(`WARNING: tenant ${tenants[index].name} did not finish plugin composition within 60 seconds`);
  });
  return tenants.length;
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

function controlAddUnlocked(payload) {
  const startedAt = Date.now();
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
  const provisionedAt = Date.now();
  state.db.users[name] = record;
  saveUsersDb(state.db);
  const persistedAt = Date.now();
  if (!LAZY_TENANTS) startTenant(name, record);
  const spawnedAt = Date.now();
  applyLoopbackGuard();
  const guardedAt = Date.now();
  console.log(`tenant add ${name}: provision=${provisionedAt - startedAt}ms `
    + `persist=${persistedAt - provisionedAt}ms spawn=${spawnedAt - persistedAt}ms `
    + `firewall=${guardedAt - spawnedAt}ms total=${guardedAt - startedAt}ms`);
  if (!LAZY_TENANTS) {
    waitForPort(port, 60000).catch((error) => {
      console.error(`WARNING: tenant ${name} did not become ready on ${port}: ${error.message}`);
    });
  }
  return {
    ok: true,
    result: {
      name,
      port,
      osUser: record.osUser,
      keyConfigured: record.keyConfigured,
      provider: record.provider || undefined,
      started: !LAZY_TENANTS,
    },
  };
}

function controlAdd(payload) {
  return withFileLock(USERS_FILE, async () => {
    refreshUsersDb();
    return controlAddUnlocked(payload);
  }, USERS_DB_LOCK_OPTIONS);
}

async function controlWake(payload) {
  const { name } = payload;
  refreshUsersDb();
  const record = state.db.users[name];
  if (!record) throw new Error(`user not found: ${name}`);
  const localUser = ensureLocalUser(record, name);
  if (localUser.created) applyLoopbackGuard();
  const owner = await clusterStore.acquireTenant(name, record.port);
  if (!owner.local) return { ok: true, result: ownerResult(owner, false) };
  state.tenantLeases.set(name, { ...owner, lastRenewedAt: Date.now() });
  try {
    const result = await ensureTenantStarted(name, record);
    return { ok: true, result: ownerResult(owner, result.started) };
  } catch (error) {
    await releaseTenantLease(name);
    throw error;
  }
}

async function controlSleep(payload) {
  const { name } = payload;
  refreshUsersDb();
  const record = state.db.users[name];
  if (!record) throw new Error(`user not found: ${name}`);
  const startup = state.tenantStarts.get(name);
  if (startup) {
    try { await startup; } catch (e) {}
  }
  const wasRunning = state.tenants.has(name);
  await stopTenant(name);
  // The DSH launcher is a detached process-group leader, so stopTenant kills
  // the whole normal tree. Kill by the tenant's unique OS uid as a final sweep
  // for any tool that deliberately escaped that process group. Files remain
  // untouched in the user's persistent HOME.
  const swept = killAllProcessesForOsUser(record.osUser);
  if (payload.revokeSessions === true) {
    await withFileLock(USERS_FILE, async () => {
      refreshUsersDb();
      const current = state.db.users[name];
      if (current) {
        current.pwdVer = (typeof current.pwdVer === 'number' ? current.pwdVer : 0) + 1;
        saveUsersDb(state.db);
      }
    }, USERS_DB_LOCK_OPTIONS);
  }
  await releaseTenantLease(name);
  console.log(`tenant ${name} stopped on ${payload.reason || 'logout'} `
    + `(wasRunning=${wasRunning}, swept=${swept}, revokeSessions=${payload.revokeSessions === true}, pwdVer=${record.pwdVer || 0})`);
  return { ok: true, result: { name, stopped: wasRunning, swept } };
}

function controlPasswdUnlocked(payload) {
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

function controlPasswd(payload) {
  return withFileLock(USERS_FILE, async () => {
    refreshUsersDb();
    return controlPasswdUnlocked(payload);
  }, USERS_DB_LOCK_OPTIONS);
}

async function controlDel(payload) {
  return withFileLock(USERS_FILE, async () => {
    refreshUsersDb();
    const { name } = payload;
    const record = state.db.users[name];
    if (!record) throw new Error(`user not found: ${name}`);
    const owner = await clusterStore.getTenantOwner(name);
    if (owner && !owner.local) {
      await stopRemoteTenant(owner, name, 'user-delete', false);
    }
    await stopTenant(name);
    await releaseTenantLease(name);
    await clusterStore.deleteUserState(name);
    try { execFileSync('userdel', [record.osUser]); } catch (e) {}
    try { fs.rmSync(record.home, { recursive: true, force: true }); } catch (e) {}
    delete state.db.users[name];
    saveUsersDb(state.db);
    applyLoopbackGuard();
    return { ok: true, result: { name } };
  }, USERS_DB_LOCK_OPTIONS);
}

function controlList() {
  refreshUsersDb();
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

function controlStats() {
  if (CLUSTER_ENABLED) throw new Error('synchronous process statistics are disabled in cluster mode');
  return { ok: true, result: tenantProcessStats() };
}

// Retained for explicit diagnostics; the admin user list no longer invokes it.
let diskUsageCache = { at: 0, result: null };
function controlDiskUsage() {
  if (CLUSTER_ENABLED) throw new Error('synchronous disk usage scans are disabled in cluster mode');
  const now = Date.now();
  if (diskUsageCache.result && now - diskUsageCache.at < 60000) {
    return { ok: true, result: diskUsageCache.result };
  }
  const result = {};
  for (const [name, record] of Object.entries(state.db.users)) {
    if (!record || typeof record.home !== 'string' || !record.home) continue;
    try {
      const out = execFileSync('du', ['-s', '--block-size=1', record.home], { encoding: 'utf8' }).trim();
      const bytes = Number(out.split(/\s+/)[0]);
      result[name] = Number.isFinite(bytes) && bytes >= 0 ? bytes : null;
    } catch (e) {
      result[name] = null;
    }
  }
  diskUsageCache = { at: now, result };
  return { ok: true, result };
}

function controlSetKeyUnlocked(payload) {
  const { name, key } = payload;
  const record = state.db.users[name];
  if (!record) throw new Error(`user not found: ${name}`);
  if (typeof key !== 'string' || key.length === 0) throw new Error('API key required');
  const localUser = ensureLocalUser(record, name);
  if (localUser.created) applyLoopbackGuard();
  setApiKey(USERS_DIR, name, key);
  execFileSync('chown', [`${record.osUser}:${record.osUser}`, credentialsPath(USERS_DIR, name)]);
  record.keyConfigured = true;
  saveUsersDb(state.db);
  return { ok: true, result: { name } };
}

function controlSetKey(payload) {
  return withFileLock(USERS_FILE, async () => {
    refreshUsersDb();
    return controlSetKeyUnlocked(payload);
  }, USERS_DB_LOCK_OPTIONS);
}

function controlKeyStatus(payload) {
  refreshUsersDb();
  const { name } = payload;
  const record = state.db.users[name];
  if (!record) throw new Error(`user not found: ${name}`);
  return { ok: true, result: { name, configured: hasAnyApiKey(USERS_DIR, name) } };
}

function controlKeyStatusAll() {
  refreshUsersDb();
  const result = {};
  for (const name of Object.keys(state.db.users)) {
    result[name] = hasAnyApiKey(USERS_DIR, name);
  }
  return { ok: true, result };
}

function controlSharedPluginList() {
  if (CLUSTER_ENABLED) state.sharedWebPlugins = discoverAllSharedPlugins();
  return { ok: true, result: state.sharedWebPlugins.map(sharedPluginDetails) };
}

async function publishSharedPluginRevision() {
  if (!CLUSTER_ENABLED) return 0;
  const revision = await clusterStore.bumpRevision('shared-plugins');
  state.sharedPluginRevision = revision;
  return revision;
}

async function controlSharedPluginAddLocked(payload, onProgress) {
  if (state.sharedPluginBusy) throw new Error('another shared plugin operation is still running');
  const config = validateSharedPluginConfig(payload, 'shared plugin');
  state.sharedPluginBusy = true;
  try {
    onProgress(`Installing shared plugin ${config.spec} into ${RUNTIME_SHARED_HOME}\n`);
    state.sharedWebPlugins = await ensureRuntimeSharedPlugins([config], onProgress);
    onProgress('Synchronizing shared plugin links to all users...\n');
    const users = syncSharedPluginsToAllUsers();
    onProgress(`Restarting ${state.tenants.size} tenant DSH process(es)...\n`);
    const restarted = await restartAllTenantProcesses();
    const plugin = state.sharedWebPlugins.find((item) => item.name === config.name);
    if (!plugin) throw new Error(`installed plugin was not discovered: ${config.name}`);
    const revision = await publishSharedPluginRevision();
    return { ok: true, result: { ...sharedPluginDetails(plugin), users, restarted, revision } };
  } finally {
    state.sharedPluginBusy = false;
  }
}

function controlSharedPluginAdd(payload, onProgress) {
  return clusterStore.withAdvisoryLock('shared-plugin-mutation', () => controlSharedPluginAddLocked(payload, onProgress));
}

async function controlSharedPluginRemoveLocked(payload, onProgress) {
  if (state.sharedPluginBusy) throw new Error('another shared plugin operation is still running');
  const { name } = payload;
  if (!validPackageName(name)) throw new Error('invalid shared plugin package name');
  if (name === BETTER_SIDEBAR_PACKAGE) throw new Error(`${name} is built into the image and cannot be removed at runtime`);
  if (!state.sharedWebPlugins.some((plugin) => plugin.name === name)) {
    throw new Error(`shared plugin is not installed: ${name}`);
  }
  state.sharedPluginBusy = true;
  try {
    onProgress(`Removing shared plugin ${name} from ${RUNTIME_SHARED_HOME}\n`);
    await runRuntimeSharedPluginCommand('remove', name, onProgress);
    const manifestFile = path.join(RUNTIME_SHARED_PROFILE, 'package.json');
    const manifest = readManifest(manifestFile, 'runtime shared profile');
    if (manifest.dependencies && typeof manifest.dependencies === 'object') delete manifest.dependencies[name];
    if (manifest.dsh && manifest.dsh.profile && Array.isArray(manifest.dsh.profile.bundles)) {
      manifest.dsh.profile.bundles = manifest.dsh.profile.bundles.filter((bundle) => bundle !== name);
    }
    writeAtomic(manifestFile, `${JSON.stringify(manifest, null, 2)}\n`, 0o644);
    const receipts = readJson(RUNTIME_SHARED_RECEIPTS, { version: 1, specs: {} });
    if (receipts.specs && typeof receipts.specs === 'object') delete receipts.specs[name];
    writeAtomic(RUNTIME_SHARED_RECEIPTS, `${JSON.stringify(receipts, null, 2)}\n`, 0o600);
    healRuntimeSharedFallback();
    execFileSync('chown', ['-hR', 'root:root', RUNTIME_SHARED_HOME]);
    execFileSync('chmod', ['-R', 'a+rX', RUNTIME_SHARED_HOME]);
    execFileSync('chmod', ['-R', 'go-w', RUNTIME_SHARED_HOME]);
    state.sharedWebPlugins = discoverAllSharedPlugins();
    onProgress('Synchronizing shared plugin links to all users...\n');
    const users = syncSharedPluginsToAllUsers();
    onProgress(`Restarting ${state.tenants.size} tenant DSH process(es)...\n`);
    const restarted = await restartAllTenantProcesses();
    const revision = await publishSharedPluginRevision();
    return { ok: true, result: { name, users, restarted, revision } };
  } finally {
    state.sharedPluginBusy = false;
  }
}

function controlSharedPluginRemove(payload, onProgress) {
  return clusterStore.withAdvisoryLock('shared-plugin-mutation', () => controlSharedPluginRemoveLocked(payload, onProgress));
}

async function synchronizePublishedSharedPlugins(revision) {
  if (!CLUSTER_ENABLED || revision <= state.sharedPluginRevision || state.sharedPluginSyncBusy) return;
  state.sharedPluginSyncBusy = true;
  try {
    state.sharedWebPlugins = discoverAllSharedPlugins();
    const restarted = await restartAllTenantProcesses();
    state.sharedPluginRevision = revision;
    console.log(`cluster shared plugins synchronized at revision ${revision}; restarted=${restarted}`);
  } catch (error) {
    console.error(`cluster shared plugin synchronization failed at revision ${revision}: ${error.message}`);
  } finally {
    state.sharedPluginSyncBusy = false;
  }
}

// Register (or replace) a custom provider for an EXISTING user: write their
// settings.yaml, owner-only credential and user record. Restart only an
// already-active tenant; a dormant account stays dormant until login.
async function controlSetProviderUnlocked(payload) {
  const { name } = payload;
  const record = state.db.users[name];
  if (!record) throw new Error(`user not found: ${name}`);
  const provider = validateProvider(payload.provider);
  const key = payload.key;
  if (typeof key !== 'string' || key.length === 0) throw new Error('provider API key required');
  const localUser = ensureLocalUser(record, name);
  if (localUser.created) applyLoopbackGuard();
  const settingsFile = path.join(record.home, 'settings.yaml');
  fs.writeFileSync(settingsFile, providerSettingsYaml(provider), { mode: 0o644 });
  const ref = providerApiKeyEnv(provider.name);
  setCredential(USERS_DIR, name, ref, key);
  execFileSync('chown', [record.osUser + ':' + record.osUser, settingsFile, credentialsPath(USERS_DIR, name)]);
  record.provider = {
    name: provider.name,
    baseURL: provider.baseURL,
    model: provider.model,
    models: provider.models,
    api: provider.api,
    apiKeyEnv: ref,
  };
  record.keyConfigured = true; // provider users skip the /setup gate
  saveUsersDb(state.db);
  const wasRunning = state.tenants.has(name);
  if (wasRunning) {
    await stopTenant(name);
    await ensureTenantStarted(name, record);
  }
  return { ok: true, result: { name, provider: record.provider, started: wasRunning } };
}

function controlSetProvider(payload) {
  return withFileLock(USERS_FILE, async () => {
    refreshUsersDb();
    return controlSetProviderUnlocked(payload);
  }, USERS_DB_LOCK_OPTIONS);
}

async function handleControl(payload, onProgress = () => {}) {
  switch (payload && payload.cmd) {
    case 'add': return controlAdd(payload);
    case 'wake': return controlWake(payload);
    case 'sleep': return controlSleep(payload);
    case 'passwd': return controlPasswd(payload);
    case 'del': return controlDel(payload);
    case 'list': return controlList();
    case 'stats': return controlStats();
    case 'du': return controlDiskUsage();
    case 'set-key': return controlSetKey(payload);
    case 'key-status': return controlKeyStatus(payload);
    case 'key-status-all': return controlKeyStatusAll();
    case 'set-provider': return controlSetProvider(payload);
    case 'shared-plugin-list': return controlSharedPluginList();
    case 'shared-plugin-add': return controlSharedPluginAdd(payload, onProgress);
    case 'shared-plugin-remove': return controlSharedPluginRemove(payload, onProgress);
    case 'plugin-cancel': return controlPluginCancel();
    default: return { ok: false, error: `unknown command: ${payload && payload.cmd}` };
  }
}

function startControlServer() {
  fs.mkdirSync(path.dirname(CONTROL_SOCKET), { recursive: true, mode: 0o700 });
  fs.chmodSync(path.dirname(CONTROL_SOCKET), 0o700);
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
      const onProgress = (message) => {
        if (!socket.destroyed) socket.write(JSON.stringify({ progress: String(message) }) + '\n');
      };
      Promise.resolve()
        .then(() => handleControl(payload, onProgress))
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
  if (state.leaseHeartbeat) clearInterval(state.leaseHeartbeat);
  clusterStore.setDraining(true).catch((error) => {
    console.error(`cannot mark cluster node draining: ${error.message}`);
  });
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
    clusterStore.releaseNode().catch(() => {}).finally(() => process.exit(exitCode));
  }, 10000).unref();
  Promise.all(children.map(({ child }) =>
    (child.exitCode !== null || child.signalCode !== null)
      ? Promise.resolve()
      : new Promise((resolve) => child.once('exit', resolve)),
  )).then(async () => {
    try { await clusterStore.releaseNode(); } catch (error) {}
    try { await clusterStore.close(); } catch (error) {}
    process.exit(exitCode);
  });
}

async function main() {
  if (process.getuid() !== 0) throw new Error('container entrypoint must run as root');
  if (!fs.existsSync(DSH_BIN)) throw new Error(`built dsh CLI not found: ${DSH_BIN}`);
  if (CLUSTER_ENABLED && !LAZY_TENANTS) throw new Error('DSH cluster mode requires DSH_LAZY_TENANTS=1');
  await clusterStore.init();
  const allSeedTenants = parseTenants();
  const adminEnabled = ADMIN_PASSWORD !== undefined && ADMIN_PASSWORD !== '';
  // When DSH_ADMIN_PASSWORD owns the reserved name, provision it once through
  // the full-admin migration path below instead of also treating it as a seed.
  const seedTenants = adminEnabled
    ? allSeedTenants.filter((tenant) => tenant.name.toLowerCase() !== ADMIN_NAME.toLowerCase())
    : allSeedTenants;
  const usersParent = path.dirname(USERS_DIR);
  const stateParent = path.dirname(STATE_DIR);
  if (usersParent === stateParent) {
    fs.mkdirSync(usersParent, { recursive: true, mode: 0o711 });
    fs.chmodSync(usersParent, 0o711);
  }
  fs.mkdirSync(USERS_DIR, { recursive: true, mode: 0o711 });
  fs.chmodSync(USERS_DIR, 0o711);
  fs.mkdirSync(STATE_DIR, { recursive: true, mode: 0o700 });
  execFileSync('chown', ['dsh-gateway:dsh-gateway', STATE_DIR]);
  fs.chmodSync(STATE_DIR, 0o700);
  // Heal state files created by an older root-running gateway. An unreadable
  // persisted secret makes every gateway restart mint a new signing key and
  // invalidates otherwise-live browser sessions.
  for (const file of [SECRET_FILE, CWD_STATE_FILE]) {
    if (!fs.existsSync(file)) continue;
    execFileSync('chown', ['dsh-gateway:dsh-gateway', file]);
    fs.chmodSync(file, 0o600);
  }

  const sharedPluginConfigs = parseSharedPluginConfigs();
  state.sharedWebPlugins = await clusterStore.withAdvisoryLock(
    'shared-plugin-mutation',
    () => ensureRuntimeSharedPlugins(sharedPluginConfigs),
  );
  state.sharedPluginRevision = await clusterStore.getRevision('shared-plugins');
  console.log(`shared web plugins ready: ${state.sharedWebPlugins.map((plugin) => plugin.name).join(', ')}`);

  // Merge: DSH_TENANTS_JSON is a bootstrap seed; users that were added at
  // runtime (persisted in the volume-backed users.json) survive restarts and
  // keep their port / password / identity.
  let db;
  await withFileLock(USERS_FILE, async () => {
    const previousDb = readJson(USERS_FILE, { version: 1, users: {} });
    const previousUsers = (previousDb && previousDb.users) || {};
    const seedNames = new Set(seedTenants.map((t) => t.name.toLowerCase()));
    if (adminEnabled) seedNames.add(ADMIN_NAME.toLowerCase());
    const preserved = [];
    for (const [name, record] of Object.entries(previousUsers)) {
      if (seedNames.has(name.toLowerCase())) continue;
      if (!record || typeof record !== 'object' ||
          typeof record.home !== 'string' || typeof record.osUser !== 'string' ||
          !Number.isInteger(record.port) || !record.pwd || typeof record.pwd !== 'object') {
        console.error(`skipping invalid preserved user record: ${name}`);
        continue;
      }
      preserved.push({ name, record });
    }

    const identityRequests = [...seedTenants, ...preserved.map((p) => ({ name: p.name }))];
    if (adminEnabled) identityRequests.push({ name: ADMIN_NAME });
    const identities = assignUids(identityRequests);
    db = { version: 1, users: {} };
    // Only preserved users occupy ports from the start; a seed user reuses its
    // OWN previous port (so restarts never shuffle ports) and only truly new
    // users draw from the free range.
    const used = new Set(preserved.map((p) => p.record.port));
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
      const identity = identities[name.toLowerCase()];
      db.users[name] = ensurePreservedRecord(name, record, identity.uid);
      used.add(record.port);
    }
    provisionAdmin(db, previousUsers, identities, used);
    state.db = db;
    saveUsersDb(db);
  }, USERS_DB_LOCK_OPTIONS);
  // Backfill the managed-container acknowledgement for every surviving user,
  // including records created by an older image.
  for (const record of Object.values(db.users)) {
    if (record && record.home && record.osUser) ensureWelcomeNoticeAck(record.home, record.osUser);
  }

  applyLoopbackGuard();
  startControlServer();
  startLeaseHeartbeat();

  if (!LAZY_TENANTS) {
    for (const [name, record] of Object.entries(db.users)) {
      const reply = await controlWake({ name });
      if (!reply.result.local) console.log(`tenant ${name} is owned by cluster node ${reply.result.owner.nodeId}`);
    }
  }
  spawnManaged('gateway', 'runuser', gatewayArgs());
  await waitForPort(GATEWAY_PORT, 30000);
  console.log(`dsh multi-tenant gateway ready on 0.0.0.0:${GATEWAY_PORT} `
    + `(${Object.keys(db.users).join(', ')}; tenants=${LAZY_TENANTS ? 'lazy' : 'eager'})`);
}

if (require.main === module) {
  process.once('SIGTERM', () => shutdown(0));
  process.once('SIGINT', () => shutdown(0));
  main().catch((error) => {
    console.error(error.stack || error.message);
    shutdown(1);
  });
} else {
  module.exports = { CONTROL_SOCKET, providerSettingsYaml, spawnManaged, validateProvider };
}
