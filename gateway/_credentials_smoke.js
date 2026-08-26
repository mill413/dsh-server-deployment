'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const {
  credentialsPath,
  hasApiKey,
  hasAnyApiKey,
  normalizeCredentialsDocument,
  repairCredentials,
  setApiKey,
  setCredential,
} = require('./credentials.js');

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-credentials-'));
const user = 'tester';
fs.mkdirSync(path.join(root, user), { recursive: true });
const file = credentialsPath(root, user);

function read() { return fs.readFileSync(file, 'utf8'); }
function occurrences(text, pattern) { return (text.match(pattern) || []).length; }

try {
  setCredential(root, user, 'YICE_API_KEY', 'first-key');
  assert.strictEqual(read(), 'version: 1\nrefs:\n  YICE_API_KEY: "first-key"\n');
  assert.strictEqual(hasAnyApiKey(root, user), true);
  assert.strictEqual(fs.statSync(file).mode & 0o777, 0o600);
  console.log('PASS new credentials use version 1 refs layout');

  setCredential(root, user, 'YICE_API_KEY', 'second-key');
  assert.strictEqual(occurrences(read(), /YICE_API_KEY:/g), 1);
  assert.match(read(), /^  YICE_API_KEY: "second-key"$/m);
  assert.doesNotMatch(read(), /^YICE_API_KEY:/m);
  console.log('PASS repeated provider update stays nested and deduplicated');

  fs.writeFileSync(file, 'DEEPSEEK_API_KEY: "deepseek"\n');
  setCredential(root, user, 'YICE_API_KEY', 'provider');
  assert.match(read(), /^version: 1$/m);
  assert.match(read(), /^  DEEPSEEK_API_KEY: "deepseek"$/m);
  assert.match(read(), /^  YICE_API_KEY: "provider"$/m);
  assert.strictEqual(hasApiKey(root, user), true);
  console.log('PASS pre-version flat layout is migrated');

  fs.writeFileSync(file, [
    'version: 1',
    'refs:',
    '  DEEPSEEK_API_KEY: "deepseek"',
    '  YICE_API_KEY: "stale-nested-value"',
    'records:',
    '  llm-pi-ai/example:',
    '    kind: api-key',
    'YICE_API_KEY: "misplaced"',
    '',
  ].join('\n'));
  assert.strictEqual(repairCredentials(root, user), true);
  const repaired = read();
  assert.doesNotMatch(repaired, /^YICE_API_KEY:/m);
  assert.match(repaired, /^  YICE_API_KEY: "misplaced"$/m);
  assert.strictEqual(occurrences(repaired, /YICE_API_KEY:/g), 1);
  assert.match(repaired, /^records:\n  llm-pi-ai\/example:\n    kind: api-key$/m);
  assert.strictEqual(repairCredentials(root, user), false);
  console.log('PASS mixed v1/top-level layout is repaired without losing records');

  setApiKey(root, user, 'quote" slash\\ newline\nvalue');
  assert.match(read(), /^  DEEPSEEK_API_KEY: "quote\\" slash\\\\ newline\\nvalue"$/m);
  assert.strictEqual(occurrences(read(), /DEEPSEEK_API_KEY:/g), 1);
  console.log('PASS credential values use safe YAML-compatible JSON quoting');

  assert.throws(
    () => normalizeCredentialsDocument('version: 2\nrefs:\n'),
    /unsupported version/,
  );
  console.log('PASS unknown document versions are rejected');

  fs.writeFileSync(file, 'version: 2\nrefs: { FUTURE_API_KEY: "future" }\n');
  assert.strictEqual(repairCredentials(root, user), false);
  assert.strictEqual(read(), 'version: 2\nrefs: { FUTURE_API_KEY: "future" }\n');
  console.log('PASS startup repair leaves future versioned layouts untouched');
} finally {
  fs.rmSync(root, { recursive: true, force: true });
}
