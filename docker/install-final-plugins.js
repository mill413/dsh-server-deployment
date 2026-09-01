'use strict';

// Build-time installer for deployment-specific DSH web plugins. This runs in
// the final image layer against the image-owned /opt/dsh-public profile, so it
// can reuse an existing DSH base and cannot be hidden by /var/lib/dsh mounts.

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const PUBLIC_HOME = '/opt/dsh-public';
const PROFILE_DIR = path.join(PUBLIC_HOME, 'profiles', 'web');
const PROFILE_MANIFEST = path.join(PROFILE_DIR, 'package.json');
const WORKSPACE_FILE = path.join(PROFILE_DIR, 'pnpm-workspace.yaml');
const DSH_BIN = '/opt/deepseek-harness/apps/cli/lib/bin.js';
const CORE_BUNDLES = new Set(['@deepseek-ai/dsh-base', '@deepseek-ai/dsh-web-app']);

function fail(message) {
  console.error(`final plugin installation failed: ${message}`);
  process.exit(1);
}

function readJson(file, label) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (error) {
    fail(`cannot read ${label} ${file}: ${error.message}`);
  }
}

function packageManagerEnvironment(environment = process.env) {
  const registry = String(environment.DSH_NPM_REGISTRY || environment.NPM_CONFIG_REGISTRY || '').trim();
  if (!registry) return {};
  if (!/^https?:\/\/[^\s]+$/.test(registry)) fail('DSH_NPM_REGISTRY must be an http(s) URL');
  return {
    DSH_NPM_REGISTRY: registry,
    NPM_CONFIG_REGISTRY: registry,
    npm_config_registry: registry,
    PNPM_CONFIG_REGISTRY: registry,
    pnpm_config_registry: registry,
    NPM_CONFIG_GLOBALCONFIG: environment.NPM_CONFIG_GLOBALCONFIG || '/etc/npmrc',
  };
}

function displayRegistry(registry) {
  try {
    const url = new URL(registry);
    if (url.username) url.username = '***';
    if (url.password) url.password = '***';
    return url.toString();
  } catch (error) {
    return '(invalid registry URL)';
  }
}

let specs;
try {
  specs = JSON.parse(process.env.DSH_FINAL_WEB_PLUGINS_JSON || '[]');
} catch (error) {
  fail(`DSH_FINAL_WEB_PLUGINS_JSON is not valid JSON: ${error.message}`);
}
if (!Array.isArray(specs)) fail('DSH_FINAL_WEB_PLUGINS_JSON must be an array');
if (specs.length > 64) fail('DSH_FINAL_WEB_PLUGINS_JSON cannot contain more than 64 plugins');
specs = specs.map((value, index) => {
  if (typeof value !== 'string') fail(`plugin spec ${index} must be a string`);
  const spec = value.trim();
  if (!spec || spec.length > 512 || spec.startsWith('-') || /[\r\n\0]/.test(spec)) {
    fail(`plugin spec ${index} is invalid`);
  }
  return spec;
});

if (specs.length > 0) {
  // Final-stage plugins are explicitly selected by the image builder. Match
  // runtime shared-plugin policy and permit their dependency build scripts.
  fs.writeFileSync(WORKSPACE_FILE, [
    'packages:',
    '  - .',
    '',
    'nodeLinker: hoisted',
    'autoInstallPeers: false',
    'dangerouslyAllowAllBuilds: true',
    '',
  ].join('\n'));
}

const packageManagerEnv = packageManagerEnvironment();
if (packageManagerEnv.NPM_CONFIG_REGISTRY) {
  console.log(`final plugin npm registry: ${displayRegistry(packageManagerEnv.NPM_CONFIG_REGISTRY)}`);
}

for (let index = 0; index < specs.length; index += 1) {
  console.log(`installing final web plugin ${index + 1}/${specs.length}`);
  const result = spawnSync(process.execPath, [DSH_BIN, 'plugin', '--profile', 'web', 'add', specs[index]], {
    cwd: PUBLIC_HOME,
    env: {
      ...process.env,
      DSH_HOME: PUBLIC_HOME,
      HOME: '/root',
      SHELL: '/bin/bash',
      NPM_CONFIG_UPDATE_NOTIFIER: 'false',
      ...packageManagerEnv,
    },
    stdio: 'inherit',
  });
  if (result.error) fail(`plugin spec ${index} could not start: ${result.error.message}`);
  if (result.status !== 0) fail(`plugin spec ${index} exited with status ${result.status}`);
}

// Validate all non-core bundles, including the one inherited from the base.
// A successful package-manager exit is insufficient if a spec is not a DSH
// bundle or resolves to an unexpected/missing package directory.
const profile = readJson(PROFILE_MANIFEST, 'public profile manifest');
const dependencies = profile.dependencies && typeof profile.dependencies === 'object'
  && !Array.isArray(profile.dependencies) ? profile.dependencies : {};
const bundles = profile.dsh && profile.dsh.profile && Array.isArray(profile.dsh.profile.bundles)
  ? profile.dsh.profile.bundles : [];
for (const name of bundles) {
  if (CORE_BUNDLES.has(name)) continue;
  if (!Object.prototype.hasOwnProperty.call(dependencies, name)) fail(`bundle ${name} has no profile dependency`);
  const packageFile = path.join(PROFILE_DIR, 'node_modules', name, 'package.json');
  const manifest = readJson(packageFile, `bundle ${name} manifest`);
  if (manifest.name !== name) fail(`bundle ${name} resolved to ${manifest.name || 'an unnamed package'}`);
  if (!manifest.dsh || !manifest.dsh.bundle || typeof manifest.dsh.bundle.patch !== 'string') {
    fail(`bundle ${name} does not declare dsh.bundle.patch`);
  }
}

console.log(`final web plugins ready: ${bundles.filter((name) => !CORE_BUNDLES.has(name)).join(', ')}`);
