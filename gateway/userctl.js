'use strict';
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const { hashPassword } = require('./auth.js');
const { hasApiKey, setApiKey } = require('./credentials.js');
const { readUsers, mutateUsers } = require('./store.js');

const BASE_DIR = process.env.DSH_BASE_DIR || '/opt/deepseek-harness';
const USERS_DIR = process.env.DSH_USERS_DIR || path.join(BASE_DIR, 'users');
const USERS_FILE = process.env.DSH_USERS_FILE || path.join(BASE_DIR, 'gateway', 'users.json');
const SETTINGS_SRC = process.env.DSH_SETTINGS_SRC || path.join(BASE_DIR, 'settings.yaml');
const NODE_BIN = process.env.DSH_NODE_BIN || path.join(BASE_DIR, 'runtime', 'bin', 'node');
const DSH_BIN = process.env.DSH_DSH_BIN || path.join(BASE_DIR, 'app', 'node_modules', '@deepseek-ai', 'dsh', 'lib', 'bin.js');
const TRUSTED_HOST = process.env.DSH_TRUSTED_HOST || '127.0.0.1:1145';
const BASE_URL = process.env.DEEPSEEK_BASE_URL || 'https://api.deepseek.com';
const MIN_PORT = 3101;

function fail(msg) { console.error('error: ' + msg); process.exit(1); }
function validUser(n) { return typeof n === 'string' && /^[A-Za-z0-9_-]+$/.test(n); }
// usernames differing only in case map to the SAME OS account (dsh-<lower>),
// which would silently merge two portal users' file spaces; forbid duplicates
// by lowercase form at every entry point that creates users.
function caseConflict(db, name) {
  const lower = String(name).toLowerCase();
  for (const k of Object.keys(db.users || {})) {
    if (k !== name && k.toLowerCase() === lower) return k;
  }
  return null;
}

// OS account per DSH user: 'dsh-' + lowercase(username). Each user's DSH
// instance runs as its own OS account so one user cannot read another's files.
function osUserOf(name) { return 'dsh-' + String(name).toLowerCase(); }
function osUserExists(name) {
  try { execFileSync('id', [name], { stdio: 'ignore' }); return true; } catch (e) { return false; }
}
function createOsUser(name) {
  const osu = osUserOf(name);
  if (osUserExists(osu)) return;
  execFileSync('useradd', ['--system', '--no-create-home', '--home', homeOf(name), '--shell', '/usr/sbin/nologin', osu]);
}
function removeOsUser(name) {
  const osu = osUserOf(name);
  if (!osUserExists(osu)) return;
  try { execFileSync('userdel', [osu]); } catch (e) {}
}

// Owner of gateway runtime files (users.json / secret / state-cwd.json).
// Override with DSH_GATEWAY_OWNER when the gateway runs as a dedicated
// service account instead of the deploy user.
const GATEWAY_OWNER = process.env.DSH_GATEWAY_OWNER || 'dsh-gateway';

function loadUsers() {
  return readUsers(USERS_FILE);
}
// All writes go through store.js's optimistic-concurrency read-modify-write:
// the gateway mutates users.json concurrently (keyConfigured flags), and a
// blind whole-file save could silently drop its change - or ours.
function commitUsers(fn) {
  return mutateUsers(USERS_FILE, fn, { chownOwner: GATEWAY_OWNER });
}
function allocPort(db) {
  const used = new Set();
  for (const k in (db.users || {})) used.add(db.users[k].port);
  let p = MIN_PORT;
  while (used.has(p)) p++;
  return p;
}
function homeOf(name) { return path.join(USERS_DIR, name); }

// Enable full-text session search for this user. DSH ships the
// session-query-sqlite index with openAt: never (content search is opt-in),
// which makes the web client degrade to name-only matching. The home-level
// patch layer applies over every profile, so this one file enables content
// search for web and headless profiles alike; the in-memory SQLite index
// opens on first search.
const SEARCH_PATCH = [
  '# $DSH_HOME patch layer - applied over every profile own layer.',
  '# Enables full-text session search (opt-in in DSH): the session-query-sqlite',
  '# index defaults to openAt: never; open the in-memory SQLite index on first',
  '# search instead.',
  '- id: session-query-sqlite',
  '  config:',
  "    path: ':memory:'",
  '    openAt: first-search',
  '',
].join('\n');
function writeSearchPatch(name) {
  const file = path.join(homeOf(name), 'cordis.patch.yml');
  if (fs.existsSync(file)) return;
  fs.writeFileSync(file, SEARCH_PATCH, { mode: 0o644 });
}

function createHome(name) {
  const home = homeOf(name);
  // The users root must stay traversable (0711) so every dsh-<name> account
  // can reach its own 0700 home; recursive mkdirSync would create it 0700
  // root and break per-user instance startup (CHDIR permission denied).
  try { fs.mkdirSync(USERS_DIR, { recursive: true }); fs.chmodSync(USERS_DIR, 0o711); } catch (e) {}
  fs.mkdirSync(path.join(home, 'workspace'), { recursive: true, mode: 0o700 });
  const settings = path.join(home, 'settings.yaml');
  if (!fs.existsSync(settings)) {
    if (fs.existsSync(SETTINGS_SRC)) fs.copyFileSync(SETTINGS_SRC, settings);
    else {
      const def = ['agent-default-model:', '  provider: deepseek-official', '  model: deepseek-v4-flash', '  reasoningEffort: max', ''].join('\n');
      fs.writeFileSync(settings, def);
    }
  }
  writeSearchPatch(name);
  const osu = osUserOf(name);
  execFileSync('chown', ['-R', osu + ':' + osu, home]);
  try { fs.chmodSync(home, 0o700); } catch (e) {}
  stripGatewayAcl(home);
}

// File access for the web gateway now runs through pinned root helpers
// (dsh-file-list/stat/read/put), so user homes must NOT carry a gateway-read
// ACL. Older userctl versions granted one (named + default), which also broke
// DSH's owner-only credentials boot check (the ACL mask showed up in stat
// mode). Strip any extended ACL so .credentials.yaml stays a plain 0600 file.
function stripGatewayAcl(home) {
  try { execFileSync('setfacl', ['-b', '-R', home]); } catch (e) {}
}

function unitFor(name, port) {
  const home = homeOf(name);
  const osu = osUserOf(name);
  return [
    '[Unit]',
    'Description=DeepSeek Harness Web - user ' + name,
    'After=network-online.target',
    'Wants=network-online.target',
    '',
    '[Service]',
    'Type=simple',
    'User=' + osu,
    'Group=' + osu,
    'WorkingDirectory=' + path.join(home, 'workspace'),
    'Environment=DSH_HOME=' + home,
    'Environment=HOME=' + home,
    'Environment=PATH=' + path.join(BASE_DIR, 'runtime', 'bin') + ':/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
    'Environment=DEEPSEEK_BASE_URL=' + BASE_URL,
    'ExecStart=' + NODE_BIN + ' ' + DSH_BIN + ' --profile web --host 127.0.0.1 --port ' + port + ' --trusted-host ' + TRUSTED_HOST,
    'Restart=on-failure',
    'RestartSec=5',
    // Basic fairness limits: one tenant\'s runaway agent (fork bombs, memory
    // leaks, crypto miners) must not starve the other instances or the host.
    'TasksMax=512',
    'MemoryMax=' + (process.env.DSH_MEM_MAX || '2G'),
    'CPUQuota=' + (process.env.DSH_CPU_QUOTA || '200%'),
    'LimitNOFILE=8192',
    // Kernel-level hardening; note NoNewPrivileges/ProtectSystem=strict are
    // deliberately NOT set: DSH agents execute arbitrary shell commands that
    // legitimately use sudo/writable HOME.
    'ProtectKernelTunables=yes',
    'ProtectKernelModules=yes',
    'ProtectKernelLogs=yes',
    'ProtectControlGroups=yes',
    'ProtectClock=yes',
    'ProtectHostname=yes',
    'PrivateTmp=yes',
    'RestrictRealtime=yes',
    'RestrictSUIDSGID=yes',
    'LockPersonality=yes',
    'MemoryDenyWriteExecute=no',
    '',
    '[Install]',
    'WantedBy=multi-user.target',
    '',
  ].join('\n');
}
function writeUnit(name, port) {
  const file = '/etc/systemd/system/dsh-web-' + name + '.service';
  fs.writeFileSync(file, unitFor(name, port), { mode: 0o644 });
  execFileSync('systemctl', ['daemon-reload']);
  execFileSync('systemctl', ['enable', '--now', 'dsh-web-' + name + '.service']);
}
function removeUnit(name) {
  const unit = 'dsh-web-' + name + '.service';
  try { execFileSync('systemctl', ['disable', '--now', unit]); } catch (e) {}
  try { fs.unlinkSync('/etc/systemd/system/' + unit); } catch (e) {}
  try { execFileSync('systemctl', ['daemon-reload']); } catch (e) {}
}

// Re-apply the loopback firewall (bin/dsh-loopback-guard) after any change to
// the user set. Failure is non-fatal: the guard also runs from its own
// systemd unit, this is just immediate consistency - but a failed refresh
// means the new port map is NOT enforced, so print it loudly.
function refreshLoopbackGuard(db) {
  const guard = path.join(path.dirname(USERS_FILE), '..', 'bin', 'dsh-loopback-guard');
  const args = [guard, '--apply'];
  for (const n of Object.keys(db.users || {})) {
    const u = db.users[n];
    if (u && u.port && u.osUser) args.push(u.osUser + ':' + u.port);
  }
  try { execFileSync(guard, args); }
  catch (e) { console.error('WARNING: loopback guard refresh failed - tenant isolation rules NOT updated:', e.message); }
}

function promptHidden(promptText) {
  return new Promise((resolve) => {
    process.stderr.write(promptText);
    const stdin = process.stdin;
    if (stdin.isTTY) stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');
    let buf = '';
    const onData = (ch) => {
      const c = ch.charCodeAt(0);
      if (c === 3) { process.exit(130); }
      else if (c === 13 || c === 10) {
        if (stdin.isTTY) stdin.setRawMode(false);
        stdin.pause();
        stdin.removeListener('data', onData);
        process.stderr.write(String.fromCharCode(10));
        resolve(buf);
      } else if (c === 127 || c === 8) {
        buf = buf.slice(0, -1);
      } else {
        buf += ch;
      }
    };
    stdin.on('data', onData);
  });
}
function promptLine(promptText) {
  return new Promise((resolve) => {
    const readline = require('readline');
    const rl = readline.createInterface({ input: process.stdin, output: process.stderr });
    rl.question(promptText, (ans) => { rl.close(); resolve(ans.trim()); });
  });
}

function usage() {
  console.log('Usage:');
  console.log('  dsh-users.sh add <user> [password]');
  console.log('  dsh-users.sh passwd <user> [password]');
  console.log('  dsh-users.sh del <user> [--yes]');
  console.log('  dsh-users.sh list');
  console.log('  dsh-users.sh set-key <user> [key]');
  console.log('  dsh-users.sh key-status [user]');
  console.log('  dsh-users.sh rehome <user>   # (internal) move user to their OS account');
  process.exit(1);
}

async function main() {
  const argv = process.argv.slice(2);
  const cmd = argv[0];
  const user = argv[1];
  const rest = argv.slice(2);

  if (!cmd) usage();

  if (cmd === 'list') {
    const db = loadUsers();
    const names = Object.keys(db.users || {}).sort();
    if (names.length === 0) { console.log('(no users)'); return; }
    console.log('USER\tPORT\tOS_USER\tALGO\tAPI_KEY');
    for (const n of names) {
      const u = db.users[n];
      console.log(n + '\t' + (u.port || '-') + '\t' + (u.osUser || '-') + '\t' + ((u.pwd && u.pwd.algo) || '-') + '\t' + (u.keyConfigured ? 'configured' : 'MISSING'));
    }
    return;
  }

  if (!user || !validUser(user)) fail('invalid username (letters, digits, underscore, hyphen only)');

  const db = loadUsers();

  if (cmd === 'add') {
    if (db.users[user]) fail('user already exists: ' + user);
    const clash = caseConflict(db, user);
    if (clash) fail('username conflicts with existing user "' + clash + '" (OS account is lowercase, files would merge)');
    const password = rest[0] || await promptHidden('Password: ');
    if (!password) fail('password required');
    const osu = osUserOf(user);
    const pwd = hashPassword(password);
    createOsUser(user);
    let portUsed = 0;
    try {
      commitUsers((d) => {
        // Re-check inside the mutation: the store may have changed since the
        // pre-checks above (concurrent admin, gateway flag writes).
        if (d.users[user]) throw new Error('user already exists: ' + user);
        const c = caseConflict(d, user);
        if (c) throw new Error('username conflicts with existing user "' + c + '" (OS account is lowercase, files would merge)');
        portUsed = allocPort(d);
        d.users[user] = { port: portUsed, home: homeOf(user), osUser: osu, pwd: pwd, pwdVer: 1, keyConfigured: false, created: new Date().toISOString() };
      });
    } catch (e) { fail(e.message); }
    try {
      createHome(user);
      writeUnit(user, portUsed);
    } catch (e) {
      // Leave no half-built user behind. The users.json record and the unit
      // are rolled back; the OS account and home directory are data paths,
      // never auto-deleted on error - tell the admin to clean them up.
      removeUnit(user);
      try { commitUsers((d) => { delete d.users[user]; }); } catch (e2) {}
      fail('provisioning failed (record rolled back; OS account ' + osu + ' and ' + homeOf(user) + ' left for manual cleanup): ' + (e && e.message ? e.message : e));
    }
    refreshLoopbackGuard(loadUsers());
    console.log('Created user: ' + user + ' (port ' + portUsed + ', os ' + osu + ')');
    return;
  }

  if (cmd === 'passwd') {
    if (!db.users[user]) fail('user not found: ' + user);
    const password = rest[0] || await promptHidden('New password: ');
    if (!password) fail('password required');
    const pwd = hashPassword(password);
    try {
      commitUsers((d) => {
        if (!d.users[user]) throw new Error('user not found: ' + user);
        d.users[user].pwd = pwd;
        // Invalidate every outstanding gateway session token (tokens embed pwdVer).
        d.users[user].pwdVer = (typeof d.users[user].pwdVer === 'number' ? d.users[user].pwdVer : 0) + 1;
      });
    } catch (e) { fail(e.message); }
    console.log('Password updated: ' + user + ' (now scrypt, sessions revoked)');
    return;
  }

  if (cmd === 'del') {
    if (!db.users[user]) fail('user not found: ' + user);
    const yes = rest.indexOf('--yes') >= 0;
    if (!yes) {
      const ans = await promptLine('Delete user "' + user + '" and ALL their data (sessions, files, key)? [y/N] ');
      if (ans !== 'y' && ans !== 'Y') { console.log('aborted'); return; }
    }
    removeUnit(user);
    removeOsUser(user);
    try { fs.rmSync(homeOf(user), { recursive: true, force: true }); } catch (e) {}
    try {
      commitUsers((d) => { if (!d.users[user]) return false; delete d.users[user]; });
    } catch (e) { fail('failed to update users.json: ' + e.message); }
    refreshLoopbackGuard(loadUsers());
    console.log('Deleted user: ' + user);
    return;
  }

  if (cmd === 'set-key') {
    if (!db.users[user]) fail('user not found: ' + user);
    const key = rest[0] || await promptHidden('API Key: ');
    if (!key) fail('key required');
    setApiKey(USERS_DIR, user, key);
    const osu = db.users[user].osUser || osUserOf(user);
    try { execFileSync('chown', [osu + ':' + osu, path.join(USERS_DIR, user, '.credentials.yaml')]); } catch (e) {}
    // setApiKey chmods the home to 0700; keep the tree free of extended ACLs
    // so .credentials.yaml stays a plain 0600 owner-only file.
    stripGatewayAcl(homeOf(user));
    try {
      commitUsers((d) => {
        if (!d.users[user]) throw new Error('user not found: ' + user);
        d.users[user].keyConfigured = true;
      });
    } catch (e) { fail(e.message); }
    console.log('API key saved for: ' + user);
    return;
  }

  if (cmd === 'key-status') {
    if (!db.users[user]) fail('user not found: ' + user);
    console.log(user + ': ' + (db.users[user].keyConfigured ? 'configured' : 'MISSING'));
    return;
  }

  if (cmd === 'rehome') {
    if (!db.users[user]) fail('user not found: ' + user);
    const osu = osUserOf(user);
    createOsUser(user);
    execFileSync('chown', ['-R', osu + ':' + osu, homeOf(user)]);
    try { fs.chmodSync(homeOf(user), 0o700); } catch (e) {}
    stripGatewayAcl(homeOf(user));
    let portUsed = db.users[user].port;
    try {
      const committed = commitUsers((d) => {
        if (!d.users[user]) throw new Error('user not found: ' + user);
        d.users[user].osUser = osu;
        if (d.users[user].keyConfigured === undefined) d.users[user].keyConfigured = hasApiKey(USERS_DIR, user);
        if (typeof d.users[user].pwdVer !== 'number') d.users[user].pwdVer = 1;
        portUsed = d.users[user].port;
      });
      if (!committed) fail('user not found: ' + user);
    } catch (e) { fail(e.message); }
    const file = '/etc/systemd/system/dsh-web-' + user + '.service';
    fs.writeFileSync(file, unitFor(user, portUsed), { mode: 0o644 });
    execFileSync('systemctl', ['daemon-reload']);
    execFileSync('systemctl', ['restart', 'dsh-web-' + user + '.service']);
    refreshLoopbackGuard(loadUsers());
    console.log('Rehomed user: ' + user + ' -> os ' + osu);
    return;
  }

  if (cmd === 'seed-legacy') {
    const apr1 = rest[0];
    if (db.users[user]) fail('user already exists: ' + user);
    const clash = caseConflict(db, user);
    if (clash) fail('username conflicts with existing user "' + clash + '" (OS account is lowercase, files would merge)');
    if (!apr1 || apr1.indexOf('$apr1$') !== 0) fail('seed-legacy requires an $apr1$ hash');
    const osu = osUserOf(user);
    createOsUser(user);
    let portUsed = 0;
    try {
      commitUsers((d) => {
        if (d.users[user]) throw new Error('user already exists: ' + user);
        const c = caseConflict(d, user);
        if (c) throw new Error('username conflicts with existing user "' + c + '" (OS account is lowercase, files would merge)');
        portUsed = allocPort(d);
        d.users[user] = { port: portUsed, home: homeOf(user), osUser: osu, pwd: { algo: 'apr1', value: apr1 }, pwdVer: 1, keyConfigured: false, created: new Date().toISOString() };
      });
    } catch (e) { fail(e.message); }
    try {
      createHome(user);
      writeUnit(user, portUsed);
    } catch (e) {
      removeUnit(user);
      try { commitUsers((d) => { delete d.users[user]; }); } catch (e2) {}
      fail('provisioning failed (record rolled back; OS account ' + osu + ' and ' + homeOf(user) + ' left for manual cleanup): ' + (e && e.message ? e.message : e));
    }
    refreshLoopbackGuard(loadUsers());
    console.log('Seeded legacy user: ' + user + ' (port ' + portUsed + ', os ' + osu + ')');
    return;
  }

  usage();
}

main().catch((e) => { console.error('error: ' + (e && e.message ? e.message : e)); process.exit(1); });
