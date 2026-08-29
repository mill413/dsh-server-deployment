#!/usr/bin/env node
'use strict';

const BASE_URL = String(process.env.BASE_URL || 'http://127.0.0.1:20810').replace(/\/+$/, '');
const API_TOKEN = process.env.DSH_REGISTER_API_KEY || 'register-test-token';
const PREFIX = process.env.USER_PREFIX || 'load';
const COUNT = Number(process.env.USER_COUNT || 50);
const CONCURRENCY = Number(process.env.CONCURRENCY || 10);
const PASSWORD = process.env.USER_PASSWORD || 'cluster-load-password';
const MODE = process.env.MODE || 'register-login';
const ALLOW_EXISTING = process.env.ALLOW_EXISTING === '1';

if (!Number.isInteger(COUNT) || COUNT < 1 || COUNT > 10000) throw new Error('USER_COUNT must be 1..10000');
if (!Number.isInteger(CONCURRENCY) || CONCURRENCY < 1 || CONCURRENCY > 1000) throw new Error('CONCURRENCY must be 1..1000');
if (!/^[A-Za-z0-9_-]+$/.test(PREFIX)) throw new Error('USER_PREFIX is invalid');
if (PASSWORD.length < 8) throw new Error('USER_PASSWORD must contain at least 8 characters');
if (!['register', 'login', 'register-login'].includes(MODE)) throw new Error('MODE must be register, login, or register-login');

function username(index) {
  return PREFIX + String(index + 1).padStart(3, '0');
}

function percentile(values, ratio) {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * ratio))];
}

async function register(name) {
  const response = await fetch(BASE_URL + '/api/register', {
    method: 'POST',
    headers: { authorization: 'Bearer ' + API_TOKEN, 'content-type': 'application/json' },
    body: JSON.stringify({ username: name, password: PASSWORD }),
    signal: AbortSignal.timeout(180000),
  });
  const body = await response.json().catch(() => ({}));
  if (response.status === 409 && ALLOW_EXISTING && /already exists/i.test(String(body.error || ''))) return 'existing';
  if (!response.ok || body.ok !== true) throw new Error(`register ${name}: HTTP ${response.status} ${body.error || ''}`);
  return 'created';
}

function cookieValue(setCookie, name) {
  const match = new RegExp('(?:^|,\\s*)' + name + '=([^;]+)').exec(setCookie || '');
  return match ? match[1] : '';
}

async function login(name) {
  const page = await fetch(BASE_URL + '/login', { redirect: 'manual', signal: AbortSignal.timeout(30000) });
  const csrf = cookieValue(page.headers.get('set-cookie'), 'dsh_csrf');
  await page.arrayBuffer();
  if (page.status !== 200 || !csrf) throw new Error(`login page ${name}: HTTP ${page.status}, csrf=${!!csrf}`);
  const form = new URLSearchParams({ csrf, username: name, password: PASSWORD });
  const response = await fetch(BASE_URL + '/login', {
    method: 'POST',
    redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: 'dsh_csrf=' + csrf },
    body: form,
    signal: AbortSignal.timeout(180000),
  });
  await response.arrayBuffer();
  if (response.status !== 302 || !cookieValue(response.headers.get('set-cookie'), 'dsh_session')) {
    throw new Error(`login ${name}: HTTP ${response.status}`);
  }
}

async function runPhase(label, operation) {
  const startedAt = Date.now();
  const latencies = [];
  const errors = [];
  let cursor = 0;
  async function worker() {
    while (true) {
      const index = cursor++;
      if (index >= COUNT) return;
      const began = Date.now();
      try { await operation(username(index)); } catch (error) { errors.push(error.message); }
      latencies.push(Date.now() - began);
    }
  }
  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, COUNT) }, worker));
  const result = {
    phase: label,
    total: COUNT,
    succeeded: COUNT - errors.length,
    failed: errors.length,
    concurrency: CONCURRENCY,
    elapsedMs: Date.now() - startedAt,
    p50Ms: percentile(latencies, 0.50),
    p95Ms: percentile(latencies, 0.95),
    maxMs: Math.max(...latencies),
    errors: errors.slice(0, 10),
  };
  console.log(JSON.stringify(result));
  if (errors.length) throw new Error(`${label} failed for ${errors.length} user(s)`);
}

(async () => {
  if (MODE === 'register' || MODE === 'register-login') await runPhase('register', register);
  if (MODE === 'login' || MODE === 'register-login') await runPhase('login', login);
})().catch((error) => {
  console.error(error.stack || error.message);
  process.exit(1);
});
