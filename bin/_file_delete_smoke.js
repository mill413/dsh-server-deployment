'use strict';
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-delete-'));
const home = path.join(root, 'alice');
const workspace = path.join(home, 'workspace');
fs.mkdirSync(workspace, { recursive: true });
const helper = path.join(__dirname, 'dsh-file-delete.js');
function remove(target) {
  return spawnSync(process.execPath, [helper, home, target], { encoding: 'utf8' });
}

const file = path.join(workspace, 'result.txt');
fs.writeFileSync(file, 'result');
assert.strictEqual(remove(file).status, 0);
assert.strictEqual(fs.existsSync(file), false);

const empty = path.join(workspace, 'empty');
fs.mkdirSync(empty);
assert.strictEqual(remove(empty).status, 0);
assert.strictEqual(fs.existsSync(empty), false);

const nonempty = path.join(workspace, 'nonempty');
fs.mkdirSync(nonempty);
fs.writeFileSync(path.join(nonempty, 'keep.txt'), 'keep');
assert.strictEqual(remove(nonempty).status, 6);
assert.strictEqual(fs.existsSync(nonempty), true);

const hidden = path.join(workspace, '.secret');
fs.writeFileSync(hidden, 'secret');
assert.strictEqual(remove(hidden).status, 5);
assert.strictEqual(fs.existsSync(hidden), true);

const outside = path.join(home, 'settings.yaml');
fs.writeFileSync(outside, 'settings');
assert.strictEqual(remove(outside).status, 3);
assert.strictEqual(fs.existsSync(outside), true);

assert.strictEqual(remove(workspace).status, 3);
console.log('file delete smoke tests passed');
