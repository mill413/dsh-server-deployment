'use strict';
// users.json store with optimistic concurrency control, shared by the
// gateway (mutateUserStore) and host-side userctl. Both are whole-file
// read-modify-write writers; a blind last-writer-wins save can silently
// drop the other side's change (e.g. an admin adding a user while another
// user completes /setup). Before renaming the temp file into place we
// verify the store was not modified since it was read; on a race we
// re-read and replay the mutation.
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

function readUsers(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch (e) { return { version: 1, users: {} }; }
}

function mtimeOf(file) {
  try { return fs.statSync(file).mtimeMs; } catch (e) { return -1; }
}

// fn(db) mutates the parsed store in place; return false from fn to abort
// with no write. Returns the committed db, or null when fn aborted.
// chownOwner: when running as root (userctl), hand the fresh file to the
// gateway service account before the atomic rename.
function mutateUsers(file, fn, opts) {
  const o = Object.assign({ attempts: 5, chownOwner: null }, opts || {});
  for (let i = 0; i < o.attempts; i++) {
    const m0 = mtimeOf(file);
    const db = readUsers(file);
    if (!db.users) db.users = {};
    const r = fn(db);
    if (r === false) return null;
    if (mtimeOf(file) !== m0) continue; // lost the race: re-read and replay
    const tmp = file + '.tmp-' + process.pid + '-' + Date.now().toString(36);
    try {
      try { fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 }); } catch (e) {}
      fs.writeFileSync(tmp, JSON.stringify(db, null, 2) + '\n', { mode: 0o640 });
      if (o.chownOwner) { try { execFileSync('chown', [o.chownOwner + ':' + o.chownOwner, tmp]); } catch (e) {} }
      if (mtimeOf(file) !== m0) { try { fs.unlinkSync(tmp); } catch (e) {} continue; }
      fs.renameSync(tmp, file);
      return db;
    } catch (e) {
      try { fs.unlinkSync(tmp); } catch (e2) {}
      if (i === o.attempts - 1) throw e;
    }
  }
  throw new Error('users.json kept changing under concurrent writers, mutation not applied');
}

module.exports = { readUsers, mutateUsers };
