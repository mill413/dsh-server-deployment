'use strict';
const fs = require('fs');
const path = require('path');

const REF_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;
const API_KEY_REF_RE = /^[A-Za-z0-9_]+_API_KEY$/;

function credentialsPath(usersDir, user) {
  return path.join(usersDir, user, '.credentials.yaml');
}

function topLevelBlocks(lines) {
  const starts = [];
  for (let i = 0; i < lines.length; i += 1) {
    const match = /^([A-Za-z_][A-Za-z0-9_-]*):(?:\s*(.*))?$/.exec(lines[i]);
    if (match) starts.push({ key: match[1], value: match[2] || '', start: i, end: lines.length });
  }
  for (let i = 0; i + 1 < starts.length; i += 1) starts[i].end = starts[i + 1].start;
  return starts;
}

// Convert the pre-release flat layout and repair the mixed layout produced by
// the old deployment writer (`version/refs` plus a top-level FOO_API_KEY).
// Unknown top-level structures are rejected rather than overwritten because
// this file contains secrets and DSH itself applies the same strict policy.
function normalizeCredentialsDocument(raw) {
  const hadFinalNewline = raw.endsWith('\n');
  let lines = raw.split(/\r?\n/);
  if (hadFinalNewline) lines.pop();
  if (lines.every((line) => line.trim() === '' || line.trimStart().startsWith('#'))) {
    return 'version: 1\nrefs:\n';
  }

  let blocks = topLevelBlocks(lines);
  const version = blocks.find((block) => block.key === 'version');
  if (!version) {
    const invalid = blocks.find((block) => !REF_RE.test(block.key));
    if (invalid || blocks.length === 0) throw new Error('credentials file has an unsupported pre-version layout');
    const nested = lines.map((line) => line.length === 0 ? line : `  ${line}`);
    return deduplicateCredentialRefs(`version: 1\nrefs:\n${nested.join('\n')}\n`);
  }
  if (!/^1(?:\s+#.*)?$/.test(version.value.trim())) {
    throw new Error(`credentials file declares unsupported version ${JSON.stringify(version.value.trim())}`);
  }

  const allowed = new Set(['version', 'refs', 'records']);
  const misplaced = blocks.filter((block) => !allowed.has(block.key));
  for (const block of misplaced) {
    if (!REF_RE.test(block.key)) throw new Error(`credentials file has unknown top-level key ${JSON.stringify(block.key)}`);
  }

  // Remove misplaced reference blocks from bottom to top, then append their
  // content inside refs. A block includes indented continuation lines, so a
  // legacy quoted/block scalar is carried without exposing or re-parsing it.
  const moved = [];
  for (const block of misplaced) moved.push(...lines.slice(block.start, block.end).map((line) => line ? `  ${line}` : line));
  for (const block of [...misplaced].sort((a, b) => b.start - a.start)) lines.splice(block.start, block.end - block.start);

  blocks = topLevelBlocks(lines);
  let refs = blocks.find((block) => block.key === 'refs');
  if (!refs) {
    const currentVersion = blocks.find((block) => block.key === 'version');
    const at = currentVersion ? currentVersion.end : 1;
    lines.splice(at, 0, 'refs:');
    blocks = topLevelBlocks(lines);
    refs = blocks.find((block) => block.key === 'refs');
  }
  if (!/^refs:\s*(?:#.*)?$/.test(lines[refs.start])) {
    throw new Error('credentials refs section must be a mapping');
  }
  if (moved.length > 0) lines.splice(refs.end, 0, ...moved);
  return deduplicateCredentialRefs(`${lines.join('\n')}\n`);
}

function refsRange(lines) {
  const refs = topLevelBlocks(lines).find((block) => block.key === 'refs');
  if (!refs) throw new Error('credentials file has no refs section');
  return refs;
}

function directRefHeader(line) {
  const match = /^  ([A-Za-z_][A-Za-z0-9_]*):(?:\s*(.*))?$/.exec(line);
  return match && { ref: match[1], value: match[2] || '' };
}

function refBlockEnd(lines, start, sectionEnd) {
  let end = start + 1;
  while (end < sectionEnd && (/^ {4}/.test(lines[end]) || lines[end].trim() === '')) end += 1;
  return end;
}

function deduplicateCredentialRefs(document) {
  const lines = document.replace(/\n$/, '').split('\n');
  let range = refsRange(lines);
  const seen = new Set();
  // Keep the last copy: misplaced top-level entries are appended after refs
  // during migration and represent the most recent value written by the old
  // deployment helper.
  for (let i = range.end - 1; i > range.start; i -= 1) {
    const header = directRefHeader(lines[i]);
    if (!header) continue;
    if (!seen.has(header.ref)) { seen.add(header.ref); continue; }
    lines.splice(i, refBlockEnd(lines, i, range.end) - i);
    range = refsRange(lines);
  }
  return `${lines.join('\n')}\n`;
}

function setRef(document, ref, value) {
  if (!REF_RE.test(ref)) throw new Error(`invalid credential reference: ${ref}`);
  const lines = document.replace(/\n$/, '').split('\n');
  let range = refsRange(lines);
  // Remove every existing copy of this ref (including a block-scalar body),
  // which also repairs duplicates left by older repeated provider updates.
  for (let i = range.end - 1; i > range.start; i -= 1) {
    const header = directRefHeader(lines[i]);
    if (!header || header.ref !== ref) continue;
    lines.splice(i, refBlockEnd(lines, i, range.end) - i);
    range = refsRange(lines);
  }
  range = refsRange(lines);
  lines.splice(range.end, 0, `  ${ref}: ${JSON.stringify(String(value))}`);
  return `${lines.join('\n')}\n`;
}

function configuredRefs(raw) {
  let document;
  try { document = normalizeCredentialsDocument(raw); } catch (e) { return new Set(); }
  const lines = document.replace(/\n$/, '').split('\n');
  const range = refsRange(lines);
  const result = new Set();
  for (let i = range.start + 1; i < range.end; i += 1) {
    const header = directRefHeader(lines[i]);
    if (!header) continue;
    const value = header.value.trim();
    if (value && value !== '""' && value !== "''" && value !== 'null' && value !== '~') result.add(header.ref);
  }
  return result;
}

function hasApiKey(usersDir, user) {
  try {
    return configuredRefs(fs.readFileSync(credentialsPath(usersDir, user), 'utf8')).has('DEEPSEEK_API_KEY');
  } catch (e) { return false; }
}

function hasAnyApiKey(usersDir, user) {
  try {
    const refs = configuredRefs(fs.readFileSync(credentialsPath(usersDir, user), 'utf8'));
    for (const ref of refs) if (API_KEY_REF_RE.test(ref)) return true;
    return false;
  } catch (e) { return false; }
}

function writeOwnerOnly(file, content) {
  const dir = path.dirname(file);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const temporary = `${file}.tmp-${process.pid}-${Date.now()}`;
  try {
    fs.writeFileSync(temporary, content, { mode: 0o600 });
    fs.renameSync(temporary, file);
    fs.chmodSync(file, 0o600);
    fs.chmodSync(dir, 0o700);
  } finally {
    try { fs.unlinkSync(temporary); } catch (e) {}
  }
}

function needsCredentialsRepair(raw) {
  const lines = raw.replace(/\r?\n$/, '').split(/\r?\n/);
  if (lines.every((line) => line.trim() === '' || line.trimStart().startsWith('#'))) return true;
  const blocks = topLevelBlocks(lines);
  if (!blocks.some((block) => block.key === 'version')) return true;
  const allowed = new Set(['version', 'refs', 'records']);
  return blocks.some((block) => !allowed.has(block.key));
}

function repairCredentials(usersDir, user) {
  const file = credentialsPath(usersDir, user);
  let raw;
  try { raw = fs.readFileSync(file, 'utf8'); } catch (e) {
    if (e && e.code === 'ENOENT') return false;
    throw e;
  }
  // A versioned document with only supported top-level sections is already
  // DSH-owned. Leave unfamiliar but potentially future-valid YAML spellings
  // untouched; this deployment only repairs layouts it previously emitted.
  if (!needsCredentialsRepair(raw)) return false;
  const normalized = normalizeCredentialsDocument(raw);
  if (normalized === raw) return false;
  writeOwnerOnly(file, normalized);
  return true;
}

function setCredential(usersDir, user, ref, key) {
  const file = credentialsPath(usersDir, user);
  let raw = '';
  try { raw = fs.readFileSync(file, 'utf8'); } catch (e) {
    if (!e || e.code !== 'ENOENT') throw e;
  }
  const next = setRef(normalizeCredentialsDocument(raw), ref, key);
  writeOwnerOnly(file, next);
}

function setApiKey(usersDir, user, key) {
  setCredential(usersDir, user, 'DEEPSEEK_API_KEY', key);
}

module.exports = {
  credentialsPath,
  hasApiKey,
  hasAnyApiKey,
  normalizeCredentialsDocument,
  repairCredentials,
  setApiKey,
  setCredential,
};
