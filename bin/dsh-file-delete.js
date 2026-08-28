'use strict';
// Runs as the tenant OS user. Deletes a visible regular file/symlink or an
// empty directory below <home>/workspace; never the workspace root itself.
const fs = require('fs');
const path = require('path');

const home = process.argv[2] || '';
const requested = process.argv[3] || '';
function fail(code) { process.exit(code); }
if (!home || !requested || home.includes('\0') || requested.includes('\0')) fail(2);

let homeReal;
try { homeReal = fs.realpathSync(home); } catch (error) { fail(3); }
let root;
try { root = fs.realpathSync(path.join(homeReal, 'workspace')); } catch (error) { root = homeReal; }

const lexical = path.resolve(requested);
const name = path.basename(lexical);
if (!name || name === '.' || name === '..') fail(2);
let parent;
try { parent = fs.realpathSync(path.dirname(lexical)); } catch (error) { fail(4); }
const target = path.join(parent, name);
if (target === root || !target.startsWith(root + path.sep)) fail(3);
const relative = path.relative(root, target);
if (relative.split(path.sep).some((part) => part.startsWith('.'))) fail(5);

let stat;
try { stat = fs.lstatSync(target); } catch (error) { fail(4); }
try {
  if (stat.isDirectory()) fs.rmdirSync(target);
  else if (stat.isFile() || stat.isSymbolicLink()) fs.unlinkSync(target);
  else fail(4);
} catch (error) {
  if (error && (error.code === 'ENOTEMPTY' || error.code === 'EEXIST')) fail(6);
  if (error && error.code === 'ENOENT') fail(4);
  throw error;
}
process.stdout.write(JSON.stringify({ ok: true, type: stat.isDirectory() ? 'directory' : 'file' }) + '\n');
