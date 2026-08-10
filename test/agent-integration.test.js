const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const test = require('node:test');

const { ROOT, installLocalEntrypoints, uninstallLocalEntrypoints, loadManifest } = require('../core/agent/toolchain');
const { validateConfig, validateRuntimeTarget } = require('../core/agent/project-config');

function tempDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

test('toolchain manifest records all required upstream tools without bundling them', () => {
  const manifest = loadManifest();
  assert.equal(manifest.tools.length, 8);
  assert.ok(manifest.tools.every((tool) => tool.required === true));
  assert.ok(manifest.tools.every((tool) => typeof tool.supportedVersionRange === 'string'));
  assert.ok(manifest.tools.every((tool) => tool.install?.official?.startsWith('https://github.com/')));
  assert.ok(manifest.tools.every((tool) => !tool.binary || !fs.existsSync(path.join(ROOT, tool.binary))));
});

test('project config accepts safe local targets and rejects arbitrary commands or traversal', () => {
  assert.deepEqual(validateConfig({ profile: 'full', runtimeTargets: ['http://127.0.0.1:3000'], ignoredPaths: ['dist/'] }), {
    profile: 'full', runtimeTargets: ['http://127.0.0.1:3000'], ignoredPaths: ['dist/'],
  });
  assert.throws(() => validateConfig({ profile: 'full', command: 'rm -rf /' }), /Unsupported config field/);
  assert.throws(() => validateConfig({ ignoredPaths: ['../secrets'] }), /relative paths/);
  assert.equal(validateRuntimeTarget('https://example.com').allowed, false);
});

test('explicitly authorized non-local runtime targets require an exact allowlist', () => {
  const previous = process.env.VIBE_CODE_GUARD_AUTHORIZED_TARGETS;
  process.env.VIBE_CODE_GUARD_AUTHORIZED_TARGETS = 'https://staging.example.test/app';
  try {
    assert.equal(validateRuntimeTarget('https://staging.example.test/app').allowed, true);
    assert.equal(validateRuntimeTarget('https://staging.example.test/other').allowed, false);
  } finally {
    if (previous === undefined) delete process.env.VIBE_CODE_GUARD_AUTHORIZED_TARGETS;
    else process.env.VIBE_CODE_GUARD_AUTHORIZED_TARGETS = previous;
  }
});

test('installer creates only Vibe Code Guard-owned launchers and uninstall preserves unrelated files', () => {
  const toolkitHome = tempDir('vcg-toolkit-');
  const binDir = path.join(toolkitHome, 'bin');
  fs.mkdirSync(binDir, { recursive: true });
  const unrelated = path.join(binDir, 'unrelated-tool');
  fs.writeFileSync(unrelated, '#!/bin/sh\nexit 0\n');
  const installed = installLocalEntrypoints({ toolkitHome });
  assert.equal(installed.conflicts.length, 0);
  assert.equal(fs.existsSync(path.join(binDir, 'vibe-code-guard')), true);
  assert.equal(fs.existsSync(path.join(binDir, 'security-check')), true);
  assert.equal(fs.existsSync(unrelated), true);
  const removed = uninstallLocalEntrypoints({ toolkitHome });
  assert.equal(removed.status, 'REMOVED');
  assert.equal(fs.existsSync(path.join(binDir, 'vibe-code-guard')), false);
  assert.equal(fs.existsSync(path.join(binDir, 'security-check')), false);
  assert.equal(fs.existsSync(unrelated), true);
});

test('installer reports a command-name conflict instead of overwriting it', () => {
  const toolkitHome = tempDir('vcg-conflict-');
  const binDir = path.join(toolkitHome, 'bin');
  fs.mkdirSync(binDir, { recursive: true });
  const conflict = path.join(binDir, 'security-check');
  fs.writeFileSync(conflict, '#!/bin/sh\n# unrelated command\n');
  const result = installLocalEntrypoints({ toolkitHome, dryRun: true });
  assert.deepEqual(result.conflicts, [conflict]);
  assert.match(fs.readFileSync(conflict, 'utf8'), /unrelated command/);
});

test('agent audit dry run returns structured output without invoking scanners', () => {
  const project = tempDir('vcg-project-');
  fs.writeFileSync(path.join(project, 'package.json'), JSON.stringify({ name: 'synthetic-project', dependencies: { react: '^18.0.0' } }));
  const output = execFileSync(process.execPath, [path.join(ROOT, 'bin/vibe-code-guard.js'), 'audit', project, '--profile', 'quick', '--dry-run', '--json'], { encoding: 'utf8' });
  const result = JSON.parse(output);
  assert.equal(result.status, 'PLANNED');
  assert.equal(result.profile, 'quick');
  assert.equal(result.project, project);
  assert.equal(result.plan.projectPath, project);
});

test('agent version command is stable and package aliases remain available', () => {
  const version = execFileSync(process.execPath, [path.join(ROOT, 'bin/vibe-code-guard.js'), '--version'], { encoding: 'utf8' }).trim();
  assert.equal(version, require('../package.json').version);
  assert.equal(require('../package.json').bin['security-check'], 'bin/vibe-code-guard.js');
});
