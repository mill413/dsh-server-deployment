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
//   docker compose -f docker/compose.yml exec dsh-multitenant dsh-users plugin list
//   docker compose -f docker/compose.yml exec dsh-multitenant dsh-users plugin add <spec> [--name <package>]
//   docker compose -f docker/compose.yml exec dsh-multitenant dsh-users plugin remove <package>
//
// The supervisor (not this client) performs the actual provisioning; this
// script only forwards the command and formats the reply.

const fs = require('fs');
const net = require('net');
const path = require('path');
const readline = require('readline');

const STATE_DIR = process.env.DSH_GATEWAY_STATE_DIR || '/var/lib/dsh-gateway';
const SOCKET = process.env.DSH_CONTROL_SOCKET || path.join(STATE_DIR, 'control.sock');
const CONTROL_TIMEOUT_MS = 120000;
// Registry downloads and native dependency builds can be slow. The supervisor
// keeps doing the installation if the client exits, so use a deliberately
// generous client deadline to avoid a misleading socket timeout.
const PLUGIN_CONTROL_TIMEOUT_MS = 1800000;

function fail(msg) { console.error('error: ' + msg); process.exit(1); }
function validUser(n) { return typeof n === 'string' && /^[A-Za-z0-9_-]+$/.test(n); }
function validPackageName(n) { return typeof n === 'string' && /^(?:@[A-Za-z0-9._-]+\/)?[A-Za-z0-9._-]+$/.test(n); }

// Infer the package name from normal registry specs (pkg, pkg@version,
// @scope/pkg, @scope/pkg@version). Git/file/alias specs need --name because
// their installed package name cannot be known without resolving them first.
function inferPackageName(spec) {
  if (typeof spec !== 'string' || spec.length === 0) return null;
  if (spec.startsWith('@')) {
    const slash = spec.indexOf('/');
    if (slash < 2) return null;
    const versionAt = spec.indexOf('@', slash);
    const name = versionAt < 0 ? spec : spec.slice(0, versionAt);
    return validPackageName(name) ? name : null;
  }
  const versionAt = spec.indexOf('@');
  const name = versionAt < 0 ? spec : spec.slice(0, versionAt);
  return validPackageName(name) ? name : null;
}

function rpc(payload) {
  return new Promise((resolve, reject) => {
    const sock = net.connect(SOCKET);
    let buf = '';
    let reply = null;
    const timeoutMs = String(payload && payload.cmd).startsWith('shared-plugin-')
      ? PLUGIN_CONTROL_TIMEOUT_MS : CONTROL_TIMEOUT_MS;
    const timer = setTimeout(() => {
      sock.destroy();
      reject(new Error('control socket timeout (is the container entrypoint running?)'));
    }, timeoutMs);
    sock.setEncoding('utf8');
    sock.on('connect', () => sock.write(JSON.stringify(payload) + '\n'));
    sock.on('data', (chunk) => {
      buf += chunk;
      while (true) {
        const newline = buf.indexOf('\n');
        if (newline < 0) break;
        const line = buf.slice(0, newline);
        buf = buf.slice(newline + 1);
        let message;
        try { message = JSON.parse(line); } catch (e) {
          reject(new Error('invalid reply from supervisor'));
          sock.destroy();
          return;
        }
        if (message && Object.prototype.hasOwnProperty.call(message, 'progress')) {
          process.stderr.write(String(message.progress));
        } else {
          reply = message;
        }
      }
    });
    sock.on('end', () => {
      clearTimeout(timer);
      if (reply) resolve(reply);
      else reject(new Error('invalid reply from supervisor'));
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
  console.log('  dsh-users plugin list');
  console.log('  dsh-users plugin add <spec> [--name <package>]');
  console.log('  dsh-users plugin remove <package>');
  console.log('Password is prompted (hidden) when omitted; minimum 8 characters.');
  process.exit(1);
}

function parsePluginAdd(argv) {
  const spec = argv[0];
  if (typeof spec !== 'string' || spec.length === 0 || spec.length > 512
      || spec.startsWith('-') || /[\r\n\0]/.test(spec)) {
    fail('plugin add requires a valid package spec');
  }
  let name = inferPackageName(spec);
  for (let i = 1; i < argv.length; i += 1) {
    const option = argv[i];
    const value = argv[i + 1];
    if (option === '--name') {
      if (!value || !validPackageName(value)) fail('--name requires a valid package name');
      name = value;
      i += 1;
    } else {
      fail('unknown plugin add option: ' + option);
    }
  }
  if (!name) fail('cannot infer package name from this spec; pass --name <package>');
  return { name, spec };
}

async function pluginMain(argv) {
  const action = argv[0];
  if (action === 'list') {
    if (argv.length !== 1) usage();
    const result = await call({ cmd: 'shared-plugin-list' });
    if (result.length === 0) { console.log('(no shared plugins)'); return; }
    console.log('NAME\tVERSION\tSOURCE\tPATH');
    for (const plugin of result) {
      console.log(plugin.name + '\t' + (plugin.version || '-') + '\t' + plugin.source + '\t' + plugin.dir);
    }
    return;
  }
  if (action === 'add') {
    const plugin = parsePluginAdd(argv.slice(1));
    const result = await call({ cmd: 'shared-plugin-add', ...plugin });
    console.log('Shared plugin ready: ' + result.name + (result.version ? '@' + result.version : ''));
    console.log('Synced users: ' + result.users + '; restarted DSH instances: ' + result.restarted);
    return;
  }
  if (action === 'remove' || action === 'rm') {
    const name = argv[1];
    if (argv.length !== 2 || !validPackageName(name)) fail('plugin remove requires a valid package name');
    const result = await call({ cmd: 'shared-plugin-remove', name });
    console.log('Removed shared plugin: ' + result.name);
    console.log('Synced users: ' + result.users + '; restarted DSH instances: ' + result.restarted);
    return;
  }
  usage();
}

async function main() {
  const argv = process.argv.slice(2);
  const cmd = argv[0];
  const user = argv[1];
  const rest = argv.slice(2);

  if (!cmd) usage();

  if (cmd === 'plugin') {
    await pluginMain(argv.slice(1));
    return;
  }

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
