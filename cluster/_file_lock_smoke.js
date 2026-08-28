'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');
const { withFileLock } = require('./file-lock.js');

async function child(file, iterations) {
  for (let i = 0; i < iterations; i += 1) {
    await withFileLock(file, async () => {
      const value = Number(fs.readFileSync(file, 'utf8'));
      await new Promise((resolve) => setTimeout(resolve, Math.floor(Math.random() * 4)));
      fs.writeFileSync(file, String(value + 1));
    }, { timeoutMs: 30000, staleMs: 60000 });
  }
}

function runWorker(file, iterations) {
  return new Promise((resolve, reject) => {
    const worker = spawn(process.execPath, [__filename, '--child', file, String(iterations)], { stdio: 'inherit' });
    worker.once('error', reject);
    worker.once('exit', (code) => code === 0 ? resolve() : reject(new Error(`lock worker exited ${code}`)));
  });
}

async function main() {
  if (process.argv[2] === '--child') return child(process.argv[3], Number(process.argv[4]));
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-cluster-lock-'));
  const file = path.join(directory, 'counter');
  fs.writeFileSync(file, '0');
  try {
    await Promise.all(Array.from({ length: 8 }, () => runWorker(file, 20)));
    assert.equal(Number(fs.readFileSync(file, 'utf8')), 160);
    assert.equal(fs.existsSync(`${file}.cluster-lock`), false);
    console.log('cluster file lock smoke tests passed');
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error(error.stack || error.message);
  process.exit(1);
});
