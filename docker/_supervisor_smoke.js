#!/usr/bin/env node
'use strict';

const assert = require('assert');
const { spawnSync } = require('child_process');

delete process.env.DSH_CONTROL_SOCKET;
const entrypoint = require('./entrypoint.js');

assert.strictEqual(entrypoint.CONTROL_SOCKET, '/run/dsh/control.sock');

async function main() {
  const tenant = entrypoint.spawnManaged(
    'tenant:smoke',
    process.execPath,
    ['-e', 'process.exit(1)'],
    { stdio: 'ignore' },
    { fatal: false },
  );
  const tenantExit = await tenant.__dshTermination;
  assert.strictEqual(tenantExit.code, 1);

  const missing = entrypoint.spawnManaged(
    'tenant:missing',
    '/definitely/not/a/dsh-command',
    [],
    { stdio: 'ignore' },
    { fatal: false },
  );
  const missingExit = await missing.__dshTermination;
  assert.strictEqual(missingExit.error.code, 'ENOENT');

  const fatalScript = [
    "const { spawnManaged } = require('./entrypoint.js');",
    "spawnManaged('gateway', process.execPath, ['-e', 'process.exit(1)'], { stdio: 'ignore' });",
  ].join('');
  const fatal = spawnSync(process.execPath, ['-e', fatalScript], {
    cwd: __dirname,
    encoding: 'utf8',
    timeout: 5000,
  });
  assert.strictEqual(fatal.status, 1, fatal.stderr || fatal.stdout);
  console.log('supervisor smoke tests passed');
}

main().catch((error) => {
  console.error(error.stack || error.message);
  process.exit(1);
});
