const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const test = require('node:test');

const { ROOT, installLocalEntrypoints, uninstallLocalEntrypoints, loadManifest, installPlan, inspectTool } = require('../core/agent/toolchain');
const { validateConfig, validateRuntimeTarget } = require('../core/agent/project-config');

function tempDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

test('toolchain manifest records all required upstream tools without bundling them', () => {
  const manifest = loadManifest();
  assert.equal(manifest.tools.length, 8);
  assert.ok(manifest.tools.every((tool) => tool.required === true));
  assert.ok(manifest.tools.every((tool) => typeof tool.supportedVersionRange === 'string'));
  assert.ok(manifest.tools.every((tool) => tool.doctorCheck && tool.selfTest?.runner));
  assert.ok(manifest.tools.every((tool) => tool.install?.official?.startsWith('https://github.com/')));
  assert.ok(manifest.tools.every((tool) => !tool.binary || !fs.existsSync(path.join(ROOT, tool.binary))));
});

test('project config accepts safe local targets and rejects arbitrary commands or traversal', () => {
  assert.deepEqual(validateConfig({ profile: 'full', runtimeTargets: ['http://127.0.0.1:3000'], ignoredPaths: ['dist/'] }), {
    profile: 'full', runtimeTargets: ['http://127.0.0.1:3000'], ignoredPaths: ['dist/'],
  });
  assert.throws(() => validateConfig({ profile: 'full', command: 'rm -rf /' }), /Unsupported config field/);
  assert.throws(() => validateConfig({ updateSource: 'https://untrusted.example' }), /Unsupported config field/);
  assert.throws(() => validateConfig({ ignoredPaths: ['../secrets'] }), /relative paths/);
  assert.throws(() => validateConfig({ ignoredPaths: ['$(touch /tmp/pwned)'] }), /shell metacharacters/);
  assert.equal(validateRuntimeTarget('https://example.com').allowed, false);
  assert.equal(validateRuntimeTarget('http://[::1]:3000').allowed, true);
  assert.equal(validateRuntimeTarget('http://0.0.0.0:3000').allowed, false);
  assert.throws(() => validateConfig({ ignoredPaths: ['x'.repeat(1025)] }), /1024 characters/);
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
  const upstreamTools = ['gitleaks', 'trufflehog', 'semgrep', 'trivy', 'osv-scanner', 'checkov', 'zap', 'nuclei'];
  for (const tool of upstreamTools) fs.writeFileSync(path.join(binDir, tool), `#!/bin/sh\n# upstream fixture: ${tool}\n`);
  const installed = installLocalEntrypoints({ toolkitHome });
  assert.equal(installed.conflicts.length, 0);
  assert.equal(fs.existsSync(path.join(binDir, 'vibe-code-guard')), true);
  assert.equal(fs.existsSync(path.join(binDir, 'security-check')), true);
  assert.equal(fs.existsSync(unrelated), true);
  for (const tool of upstreamTools) assert.equal(fs.existsSync(path.join(binDir, tool)), true);
  const removed = uninstallLocalEntrypoints({ toolkitHome });
  assert.equal(removed.status, 'REMOVED');
  assert.equal(fs.existsSync(path.join(binDir, 'vibe-code-guard')), false);
  assert.equal(fs.existsSync(path.join(binDir, 'security-check')), false);
  assert.equal(fs.existsSync(unrelated), true);
  for (const tool of upstreamTools) assert.equal(fs.existsSync(path.join(binDir, tool)), true);
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

test('installer rejects symlink launcher paths and never follows an escape target', () => {
  const toolkitHome = tempDir('vcg-symlink-');
  const outside = path.join(tempDir('vcg-outside-'), 'launcher');
  fs.writeFileSync(outside, '#!/bin/sh\n# outside target\n');
  const binDir = path.join(toolkitHome, 'bin');
  fs.mkdirSync(binDir, { recursive: true });
  fs.symlinkSync(outside, path.join(binDir, 'vibe-code-guard'));
  const result = installLocalEntrypoints({ toolkitHome, dryRun: true });
  assert.deepEqual(result.conflicts, [path.join(binDir, 'vibe-code-guard')]);
  assert.match(fs.readFileSync(outside, 'utf8'), /outside target/);
});

test('installer rejects broad toolkit roots before any filesystem mutation', () => {
  assert.throws(() => installLocalEntrypoints({ toolkitHome: path.parse(os.homedir()).root, dryRun: true }), /filesystem root/);
  const parent = tempDir('vcg-parent-');
  const outside = tempDir('vcg-parent-outside-');
  const redirect = path.join(parent, 'redirect');
  fs.symlinkSync(outside, redirect);
  assert.throws(() => installLocalEntrypoints({ toolkitHome: path.join(redirect, 'toolkit'), dryRun: true }), /symbolic link/);
});

test('fresh-machine planner handles missing tools, missing installers, degraded versions, and healthy newer tools', async () => {
  const manifest = loadManifest();
  const inspected = Object.fromEntries(manifest.tools.map((tool, index) => [tool.id, {
    id: tool.id,
    displayName: tool.displayName,
    status: index === 0 ? 'READY' : index === 1 ? 'NOT_INSTALLED' : index === 2 ? 'DEGRADED' : 'NOT_INSTALLED',
    binaryPath: index === 0 ? '/tmp/newer-gitleaks' : null,
    version: index === 0 ? '99.0.0' : null,
  }]));
  const result = await installPlan({
    inspect: async (tool) => inspected[tool.id],
    commandExistsFn: async (command) => command === 'python3',
  });
  assert.equal(result.actions.length, 0);
  assert.match(result.notes.join('\n'), /Semgrep: DEGRADED/);
  assert.match(result.notes.join('\n'), /pipx is unavailable/);
  assert.equal(result.inspected.gitleaks.status, 'READY');
  assert.equal(result.inspected.gitleaks.version, '99.0.0');
});

test('non-default tool paths are resolved without shell execution', async () => {
  const directory = tempDir('vcg-tool-path-');
  const fake = path.join(directory, 'fake-scanner');
  fs.writeFileSync(fake, '#!/bin/sh\nprintf "9.2.1\\n"\n');
  fs.chmodSync(fake, 0o755);
  const previous = process.env.SECURITY_TOOL_PATHS;
  process.env.SECURITY_TOOL_PATHS = directory;
  try {
    const result = await inspectTool({ id: 'fake', displayName: 'Fake', required: true, candidates: ['fake-scanner'], versionArgs: ['--version'], supportedVersionRange: '>=1.0.0', install: { type: 'manual' } });
    assert.equal(result.status, 'READY');
    assert.equal(result.binaryPath, fake);
    assert.equal(result.versionNumber, '9.2.1');
    const old = path.join(directory, 'old-scanner');
    fs.writeFileSync(old, '#!/bin/sh\nprintf "0.5.0\\n"\n');
    fs.chmodSync(old, 0o755);
    const incompatible = await inspectTool({ id: 'old', displayName: 'Old', required: true, candidates: ['old-scanner'], versionArgs: ['--version'], supportedVersionRange: '>=1.0.0', install: { type: 'manual' } });
    assert.equal(incompatible.status, 'DEGRADED');
    assert.match(incompatible.reason, /below the supported range/);
  } finally {
    if (previous === undefined) delete process.env.SECURITY_TOOL_PATHS;
    else process.env.SECURITY_TOOL_PATHS = previous;
  }
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
