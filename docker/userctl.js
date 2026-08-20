#!/usr/bin/env node
'use strict';
// Container-side user management CLI. Talks to the entrypoint supervisor over
// its Unix control socket, so users can be added / changed / removed at
// runtime without editing compose.yml or recreating the container:
//
//   docker compose -f docker/compose.yml exec dsh-multitenant dsh-users add <user> [password]
//   docker compose -f docker/compose.yml exec dsh-multitenant dsh-users passwd <user> [password]
//   docker compose -f docker/compose.yml exec dsh-multitenant dsh-users del <user> [--yes]
//   docker compose -f docker/compose.yml exec dsh-multitenant dsh-users list
//   docker compose -f docker/compose.yml exec dsh-multitenant dsh-users set-key <user> [key]
//   docker compose -f docker/compose.yml exec dsh-multitenant dsh-users key-status <user>
//
// The supervisor (not this client) performs the actual provisioning; this
// script only forwards the command and formats the reply.

const fs = require('fs');
const net = require('net');
const path = require('path');
const readline = require('readline');

const STATE_DIR = process.env.DSH_GATEWAY_STATE_DIR || '/var/lib/dsh-gateway';
const SOCKET = process.env.DSH_CONTROL_SOCKET || path.join(STATE_DIR, 'control.sock');

function fail(msg) { console.error('error: ' + msg); process.exit(1); }
function validUser(n) { return typeof n === 'string' && /^[A-Za-z0-9_-]+$/.test(n); }

function rpc(payload) {
  return new Promise((resolve, reject) => {
    const sock = net.connect(SOCKET);
    let buf = '';
    const timer = setTimeout(() => {
      sock.destroy();
      reject(new Error('control socket timeout (is the container entrypoint running?)'));
    }, 10000);
    sock.setEncoding('utf8');
    sock.on('connect', () => sock.write(JSON.stringify(payload) + '\n'));
    sock.on('data', (chunk) => { buf += chunk; });
    sock.on('end', () => {
      clearTimeout(timer);
      try { resolve(JSON.parse(buf)); }
      catch (e) { reject(new Error('invalid reply from supervisor')); }
    });
    sock.on('error', (e) => {
      clearTimeout(timer);
      reject(new Error('cannot reach supervisor control socket ' + SOCKET + ': ' + e.message));
    });
  });
}

async function call(payload) {
  const reply = await rpc(payload);
  if (!reply || reply.ok !== true) fail((reply && reply.error) || 'command failed');
  return reply.result;
}

function promptHidden(promptText) {
  return new Promise((resolve) => {
    process.stderr.write(promptText);
    const stdin = process.stdin;
    if (stdin.isTTY) stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');
    let buf = '';
    const onData = (ch) => {
      const c = ch.charCodeAt(0);
      if (c === 3) { process.exit(130); }
      else if (c === 13 || c === 10) {
        if (stdin.isTTY) stdin.setRawMode(false);
        stdin.pause();
        stdin.removeListener('data', onData);
        process.stderr.write(String.fromCharCode(10));
        resolve(buf);
      } else if (c === 127 || c === 8) {
        buf = buf.slice(0, -1);
      } else {
        buf += ch;
      }
    };
    stdin.on('data', onData);
  });
}

function promptLine(promptText) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stderr });
    rl.question(promptText, (ans) => { rl.close(); resolve(ans.trim()); });
  });
}

function usage() {
  console.log('Usage (inside the container):');
  console.log('  dsh-users add <user> [password]');
  console.log('  dsh-users passwd <user> [password]');
  console.log('  dsh-users del <user> [--yes]');
  console.log('  dsh-users list');
  console.log('  dsh-users set-key <user> [key]');
  console.log('  dsh-users key-status <user>');
  console.log('Password is prompted (hidden) when omitted; minimum 8 characters.');
  process.exit(1);
}

async function main() {
  const argv = process.argv.slice(2);
  const cmd = argv[0];
  const user = argv[1];
  const rest = argv.slice(2);

  if (!cmd) usage();

  if (cmd === 'list') {
    const result = await call({ cmd: 'list' });
    if (result.length === 0) { console.log('(no users)'); return; }
    console.log('USER\tPORT\tOS_USER\tALGO\tAPI_KEY');
    for (const u of result) {
      console.log(u.name + '\t' + (u.port || '-') + '\t' + (u.osUser || '-') + '\t' + (u.algo || '-') + '\t' + (u.keyConfigured ? 'configured' : 'MISSING'));
    }
    return;
  }

  if (!user || !validUser(user)) fail('invalid username (letters, digits, underscore, hyphen only)');

  if (cmd === 'add') {
    const password = rest[0] || await promptHidden('Password: ');
    if (!password) fail('password required');
    const r = await call({ cmd: 'add', name: user, password });
    console.log('Created user: ' + r.name + ' (port ' + r.port + ', os ' + r.osUser + ')');
    return;
  }

  if (cmd === 'passwd') {
    const password = rest[0] || await promptHidden('New password: ');
    if (!password) fail('password required');
    await call({ cmd: 'passwd', name: user, password });
    console.log('Password updated: ' + user + ' (sessions revoked)');
    return;
  }

  if (cmd === 'del') {
    const yes = rest.indexOf('--yes') >= 0;
    if (!yes) {
      const ans = await promptLine('Delete user "' + user + '" and ALL their data (sessions, files, key)? [y/N] ');
      if (ans !== 'y' && ans !== 'Y') { console.log('aborted'); return; }
    }
    await call({ cmd: 'del', name: user });
    console.log('Deleted user: ' + user);
    return;
  }

  if (cmd === 'set-key') {
    const key = rest[0] || await promptHidden('API Key: ');
    if (!key) fail('key required');
    await call({ cmd: 'set-key', name: user, key });
    console.log('API key saved for: ' + user);
    return;
  }

  if (cmd === 'key-status') {
    const r = await call({ cmd: 'key-status', name: user });
    console.log(user + ': ' + (r.configured ? 'configured' : 'MISSING'));
    return;
  }

  usage();
}

main().catch((e) => { console.error('error: ' + (e && e.message ? e.message : e)); process.exit(1); });
