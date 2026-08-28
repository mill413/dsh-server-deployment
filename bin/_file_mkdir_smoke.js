'use strict';
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-mkdir-'));
const home = path.join(root, 'alice');
const workspace = path.join(home, 'workspace');
fs.mkdirSync(workspace, { recursive: true });
const helper = path.join(__dirname, 'dsh-file-mkdir.js');
function create(parent, name) {
  return spawnSync(process.execPath, [helper, home, parent, name], { encoding: 'utf8' });
}

assert.strictEqual(create(workspace, 'reports').status, 0);
assert.strictEqual(fs.statSync(path.join(workspace, 'reports')).isDirectory(), true);
assert.strictEqual(create(workspace, 'reports').status, 6);
assert.strictEqual(create(workspace, '.hidden').status, 2);
assert.strictEqual(create(workspace, '../outside').status, 2);
assert.strictEqual(create(home, 'outside').status, 3);
console.log('file mkdir smoke tests passed');
