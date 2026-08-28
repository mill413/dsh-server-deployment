'use strict';
const fs = require('fs');
const path = require('path');

const home = process.argv[2] || '';
const requestedDir = process.argv[3] || '';
const name = process.argv[4] || '';
function fail(code) { process.exit(code); }
if (!home || !requestedDir || !name || home.includes('\0') || requestedDir.includes('\0') || name.includes('\0')) fail(2);
if (name === '.' || name === '..' || name.startsWith('.') || name.length > 200
    || /[\\/\r\n]/.test(name) || /[\x00-\x1f\x7f]/.test(name)) fail(2);

let homeReal;
try { homeReal = fs.realpathSync(home); } catch (error) { fail(3); }
let root;
try { root = fs.realpathSync(path.join(homeReal, 'workspace')); } catch (error) { root = homeReal; }
let parent;
try { parent = fs.realpathSync(requestedDir); } catch (error) { fail(4); }
if (parent !== root && !parent.startsWith(root + path.sep)) fail(3);

const target = path.join(parent, name);
try {
  fs.mkdirSync(target, { mode: 0o755 });
} catch (error) {
  if (error && error.code === 'EEXIST') fail(6);
  if (error && error.code === 'ENOENT') fail(4);
  throw error;
}
process.stdout.write(JSON.stringify({ ok: true, path: target }) + '\n');
