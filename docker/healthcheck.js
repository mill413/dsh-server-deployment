'use strict';

const fs = require('fs');
const http = require('http');
const net = require('net');
const path = require('path');

const stateDir = process.env.DSH_GATEWAY_STATE_DIR || '/var/lib/dsh-gateway';
const usersFile = process.env.USERS_FILE || path.join(stateDir, 'users.json');
const gatewayPort = Number(process.env.DSH_GATEWAY_PORT || '3100');
const lazyTenants = process.env.DSH_LAZY_TENANTS !== '0';

function checkTcp(port) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host: '127.0.0.1', port });
    const timer = setTimeout(() => socket.destroy(new Error('timeout')), 3000);
    socket.once('connect', () => {
      clearTimeout(timer);
      socket.end();
      resolve();
    });
    socket.once('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
  });
}

function checkGateway() {
  return new Promise((resolve, reject) => {
    const req = http.get({ host: '127.0.0.1', port: gatewayPort, path: '/__gw/health', timeout: 3000 }, (res) => {
      res.resume();
      res.once('end', () => res.statusCode === 200 ? resolve() : reject(new Error(`gateway HTTP ${res.statusCode}`)));
    });
    req.once('timeout', () => req.destroy(new Error('timeout')));
    req.once('error', reject);
  });
}

(async () => {
  if (lazyTenants) {
    await checkGateway();
    return;
  }
  const db = JSON.parse(fs.readFileSync(usersFile, 'utf8'));
  const ports = Object.values(db.users || {})
    .filter((user) => user && Number.isInteger(Number(user.port)))
    .map((user) => Number(user.port));
  if (ports.length === 0 || ports.some((port) => !Number.isInteger(port))) throw new Error('no valid tenants');
  await Promise.all([checkGateway(), ...ports.map(checkTcp)]);
})().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
