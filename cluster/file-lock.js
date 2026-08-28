'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function withFileLock(target, operation, options = {}) {
  const lock = `${target}.cluster-lock`;
  const timeoutMs = Number(options.timeoutMs || 120000);
  const staleMs = Number(options.staleMs || 300000);
  const deadline = Date.now() + timeoutMs;
  const ownerToken = `${process.pid}-${crypto.randomBytes(12).toString('hex')}`;
  fs.mkdirSync(path.dirname(lock), { recursive: true });

  while (true) {
    try {
      fs.mkdirSync(lock, { mode: 0o700 });
      try {
        fs.writeFileSync(path.join(lock, 'owner'), `${ownerToken}\n`, { mode: 0o600 });
      } catch (error) {}
      break;
    } catch (error) {
      if (!error || error.code !== 'EEXIST') throw error;
      try {
        const stat = fs.statSync(lock);
        if (Date.now() - stat.mtimeMs > staleMs) {
          fs.rmSync(lock, { recursive: true, force: true });
          continue;
        }
      } catch (statError) {
        if (statError && statError.code === 'ENOENT') continue;
      }
      if (Date.now() >= deadline) throw new Error(`timed out acquiring shared state lock: ${lock}`);
      await delay(50 + Math.floor(Math.random() * 100));
    }
  }

  const touchInterval = setInterval(() => {
    try {
      const now = new Date();
      fs.utimesSync(lock, now, now);
    } catch (error) {}
  }, Math.max(1000, Math.floor(staleMs / 3)));
  touchInterval.unref();
  try {
    return await operation();
  } finally {
    clearInterval(touchInterval);
    try {
      const currentOwner = fs.readFileSync(path.join(lock, 'owner'), 'utf8').trim();
      if (currentOwner === ownerToken) fs.rmSync(lock, { recursive: true, force: true });
    } catch (error) {}
  }
}

module.exports = { withFileLock };
