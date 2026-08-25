'use strict';
// Unit tests for the pure logic (no root/sudo needed): form parsing,
// history trimming, auth/credentials round-trips, the optimistic-concurrency
// users store, and bin/dsh-file-list.js against a temp tree.
// Run: node gateway/_unit.js
const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawnSync } = require('child_process');

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'dshunit-'));
process.env.HOST = '127.0.0.1';
process.env.PORT = '0'; // ephemeral listener; state-port.json is skipped for 0
process.env.USERS_FILE = path.join(TMP, 'users.json');
process.env.SECRET_FILE = path.join(TMP, 'secret');
process.env.USERS_DIR = path.join(TMP, 'users');
process.env.COOKIE_SECURE = '0';
process.env.DEEPSEEK_BASE_URL = 'http://127.0.0.1:1';

const server = require('./server.js'); // starts an ephemeral listener
const { hashPassword, verifyPassword, timingSafeStr } = require('./auth.js');
const { hasApiKey, setApiKey } = require('./credentials.js');
const { readUsers, mutateUsers } = require('./store.js');

let pass = 0, fail = 0;
function check(name, cond) {
  if (cond) { pass++; console.log('PASS ' + name); }
  else { fail++; console.log('FAIL ' + name); }
}

// ---------- server.js pure helpers ----------
{
  const f = server.parseForm('csrf=abc&username=a+b%40c&key=sk-xyz&novalue&bad=%zz');
  check('parseForm basic', f.csrf === 'abc' && f.key === 'sk-xyz');
  check('parseForm plus->space', f.username === 'a b@c');
  check('parseForm bare key', f.novalue === '');
  check('parseForm bad escape skipped', f.bad === undefined);

  check('esc html', server.esc('<img "x">') === '&lt;img &quot;x&quot;&gt;');
  check('dlContentType txt', server.dlContentType('a.txt').indexOf('text/plain') === 0);
  check('dlContentType case-insensitive', server.dlContentType('a.PDF') === 'application/pdf');
  check('dlContentType fallback', server.dlContentType('a.zzz') === 'application/octet-stream');
}

// ---------- trimHistoryValue ----------
{
  const ev = (seq, extra) => ({ event: Object.assign({ seq: seq, type: 'user/message', surfaceOp: 'append' }, extra || {}) });
  const small = { events: [ev(1), ev(2), ev(3)] };
  check('trim: small page untouched', server.trimHistoryValue(small) === null);

  const events = [];
  for (let i = 0; i < 2500; i++) events.push(ev(i));
  const t = server.trimHistoryValue({ events: events });
  check('trim: trims big page', !!t && t.hasMore === true && t.events.length < events.length);

  // group extension: an event whose sourceEventSeqs reach further back must
  // pull in the whole group
  const grouped = [];
  for (let i = 0; i < 2050; i++) grouped.push(ev(i));
  grouped[2044].event.sourceEventSeqs = [2042];
  const g = server.trimHistoryValue({ events: grouped });
  check('trim: group kept together', !!g && g.events.some((x) => x.event.seq === 2042));

  const noSeq = { events: [] };
  for (let i = 0; i < 2050; i++) noSeq.events.push({ event: { type: 'user/message' } });
  check('trim: non-numeric seq -> untouched', server.trimHistoryValue(noSeq) === null);
}

// ---------- auth ----------
{
  const rec = hashPassword('secret123');
  check('auth: scrypt roundtrip', verifyPassword('secret123', rec) === true);
  check('auth: wrong password', verifyPassword('secret124', rec) === false);
  check('auth: garbage record', verifyPassword('x', null) === false && verifyPassword('x', { algo: 'nope', value: 'y' }) === false);
  check('auth: timingSafeStr', timingSafeStr('abc', 'abc') === true && timingSafeStr('abc', 'abd') === false && timingSafeStr('abc', 'abcd') === false);
}

// ---------- credentials ----------
{
  const dir = path.join(TMP, 'users', 'cred');
  check('credentials: missing -> no key', hasApiKey(dir, 'cred') === false);
  setApiKey(dir, 'cred', 'sk-test_12345');
  check('credentials: set -> has key', hasApiKey(dir, 'cred') === true);
  setApiKey(dir, 'cred', 'sk-other');
  const raw = fs.readFileSync(path.join(dir, 'cred', '.credentials.yaml'), 'utf8');
  check('credentials: single key line', (raw.match(/DEEPSEEK_API_KEY/g) || []).length === 1);
}

// ---------- store (optimistic concurrency) ----------
{
  const file = path.join(TMP, 'store.json');
  check('store: readUsers missing file', readUsers(file).users !== undefined);
  const db1 = mutateUsers(file, (d) => { d.users.alice = { port: 1 }; });
  check('store: mutate commits', !!db1 && readUsers(file).users.alice.port === 1);
  check('store: fn abort writes nothing', mutateUsers(file, (d) => { if (d.users.nope) return; return false; }) === null);
  // simulate the gateway racing us: the store changes after our read but
  // before our rename -> the mutation must replay on the fresh content
  let calls = 0;
  const db2 = mutateUsers(file, (d) => {
    calls++;
    if (calls === 1) fs.writeFileSync(file, JSON.stringify({ version: 1, users: { bob: { flag: true } } }));
    d.users.alice = { port: 2 };
  });
  const after = readUsers(file);
  check('store: race replayed, both sides kept', !!db2 && after.users.bob.flag === true && after.users.alice.port === 2 && calls === 2);
}

// ---------- bin/dsh-file-list.js (runs as the current user on a temp tree) ----------
{
  const home = path.join(TMP, 'users', 'lister');
  const ws = path.join(home, 'workspace');
  fs.mkdirSync(path.join(ws, 'sub'), { recursive: true });
  fs.writeFileSync(path.join(ws, 'b.txt'), 'hello');
  fs.writeFileSync(path.join(ws, 'a.txt'), 'x');
  fs.writeFileSync(path.join(ws, '.credentials.yaml'), 'secret');
  const run = (dir) => spawnSync(process.execPath, [path.join(__dirname, '..', 'bin', 'dsh-file-list.js'), home, dir || ''], { encoding: 'utf8' });

  const r = run('');
  check('list: exit 0 on default', r.status === 0);
  let j = null;
  try { j = JSON.parse(r.stdout); } catch (e) {}
  check('list: dotfiles hidden', !!j && j.entries.every((e) => !e.name.startsWith('.')));
  check('list: dirs first + sorted', !!j && j.entries[0].name === 'sub' && j.entries[1].name === 'a.txt' && j.entries[2].name === 'b.txt');
  check('list: size reported', !!j && j.entries.find((e) => e.name === 'b.txt').size === 5);
  check('list: dir is the workspace', !!j && path.relative(ws, j.dir) === '');

  const out = run(path.join(TMP, 'users', 'lister', 'nope'));
  check('list: missing dir -> exit 4', out.status === 4);
  const outside = run(os.tmpdir());
  check('list: outside home -> exit 3', outside.status === 3);
}

console.log('\n' + pass + ' passed, ' + fail + ' failed');
process.exit(fail ? 1 : 0);
