const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  actionFor,
  acquireToolLock,
  checkUpdates,
  contentState,
  defaultFetchJson,
  discoverLatestStable,
  lifecycleStatus,
  parseVersion,
  provenanceFor,
  readState,
  refreshContent,
  statePath,
  updateTool,
  writeState,
} = require('../core/agent/tool-lifecycle');
const { loadManifest } = require('../core/agent/toolchain');

function tempDir(prefix) { return fs.mkdtempSync(path.join(os.tmpdir(), prefix)); }

function readyInspection(tool) {
  return {
    id: tool.id,
    displayName: tool.displayName,
    status: 'READY',
    binaryPath: `/opt/homebrew/bin/${tool.id}`,
    version: '1.0.0',
    versionNumber: '1.0.0',
  };
}

test('official release discovery ignores prereleases and selects the newest stable version', async () => {
  const tool = loadManifest().tools.find((item) => item.id === 'gitleaks');
  const result = await discoverLatestStable(tool, {
    fetchJson: async () => [
      { tag_name: 'v9.0.0-rc.1', prerelease: true },
      { tag_name: '1.2', prerelease: false },
      { tag_name: '2026.08.11', prerelease: false },
      { tag_name: 'latest', prerelease: false },
      { tag_name: `v${'9'.repeat(5000)}.1.1`, prerelease: false },
      { tag_name: 'v8.31.0', prerelease: false, html_url: 'https://github.com/gitleaks/gitleaks/releases/tag/v8.31.0' },
      { tag_name: 'v8.30.0', prerelease: false },
    ],
  });
  assert.equal(result.latestStableVersion, '8.31.0');
  assert.equal(result.source, 'OFFICIAL');
  assert.match(result.releaseUrl, /v8\.31\.0/);
  assert.equal(parseVersion('1.2'), null);
  assert.equal(parseVersion('2026.08.11'), null);
  assert.equal(parseVersion('1.2.3-rc1').value, '1.2.3');
  const hostileUrl = await discoverLatestStable(tool, { fetchJson: async () => [{ tag_name: 'v8.31.0', prerelease: false, html_url: 'https://untrusted.example/payload' }] });
  assert.equal(hostileUrl.releaseUrl, null);
});

test('official release fetch rejects redirects and does not execute remote metadata', async () => {
  const originalFetch = global.fetch;
  global.fetch = async (_url, options) => {
    assert.equal(options.redirect, 'error');
    return { ok: true, url: 'https://untrusted.example/releases', json: async () => [] };
  };
  try {
    await assert.rejects(defaultFetchJson('https://api.github.com/repos/gitleaks/gitleaks/releases?per_page=30'), /redirected/);
  } finally {
    global.fetch = originalFetch;
  }
});

test('lifecycle status separates engine readiness from Trivy database freshness', async () => {
  const toolkitHome = tempDir('vcg-lifecycle-status-');
  const cache = tempDir('vcg-trivy-cache-');
  const metadataPath = path.join(cache, 'db', 'metadata.json');
  fs.mkdirSync(path.dirname(metadataPath), { recursive: true });
  fs.writeFileSync(metadataPath, JSON.stringify({ Version: 2, UpdatedAt: '2026-08-11T00:00:00.000Z', NextUpdate: '2026-08-12T00:00:00.000Z' }));
  const previous = process.env.TRIVY_CACHE_DIR;
  process.env.TRIVY_CACHE_DIR = cache;
  try {
    const status = await lifecycleStatus({ toolkitHome, inspect: async (tool) => readyInspection(tool), now: () => new Date('2026-08-11T01:00:00.000Z').getTime() });
    assert.equal(status.tools.trivy.state, 'READY');
    assert.equal(status.tools.trivy.content.state, 'CURRENT');
    assert.equal(status.tools.trivy.content.schemaVersion, 2);
    assert.equal(status.tools.trivy.updateAvailable, null);
  } finally {
    if (previous === undefined) delete process.env.TRIVY_CACHE_DIR;
    else process.env.TRIVY_CACHE_DIR = previous;
    fs.rmSync(toolkitHome, { recursive: true, force: true });
    fs.rmSync(cache, { recursive: true, force: true });
  }
});

test('manual update checks record official latest versions and preserve offline uncertainty', async () => {
  const toolkitHome = tempDir('vcg-lifecycle-check-');
  const inspect = async (tool) => readyInspection(tool);
  const result = await checkUpdates({
    toolkitHome,
    inspect,
    fetchJson: async () => [{ tag_name: 'v2.0.0', prerelease: false }],
  });
  assert.equal(result.tools.gitleaks.latestStableVersion, '2.0.0');
  assert.equal(result.tools.gitleaks.updateAvailable, true);
  assert.equal(fs.existsSync(statePath(toolkitHome)), true);
  const offline = await checkUpdates({ toolkitHome, inspect, fetchJson: async () => { throw new Error('offline'); } });
  assert.equal(offline.tools.gitleaks.updateCheck, 'UPDATE_CHECK_UNAVAILABLE');
  assert.equal(offline.overall, 'DEGRADED');
  fs.rmSync(toolkitHome, { recursive: true, force: true });
});

test('unverified version text cannot masquerade as the scanner version', async () => {
  const toolkitHome = tempDir('vcg-unverified-version-');
  const result = await lifecycleStatus({
    toolkitHome,
    inspect: async (tool) => tool.id === 'zap'
      ? { ...readyInspection(tool), status: 'DEGRADED', version: 'Found Java version 17.0.17', versionNumber: null, binaryPath: '/Applications/ZAP.app/Contents/Java/zap.sh' }
      : readyInspection(tool),
  });
  assert.equal(result.tools.zap.installedVersion, null);
  assert.equal(result.tools.zap.updateAvailable, null);
  assert.notEqual(result.tools.zap.state, 'READY');
  fs.rmSync(toolkitHome, { recursive: true, force: true });
});

test('one-tool update and content refresh default to plans without mutation', async () => {
  const toolkitHome = tempDir('vcg-lifecycle-plan-');
  const inspect = async (tool) => readyInspection(tool);
  const fetchJson = async () => [{ tag_name: 'v2.0.0', prerelease: false }];
  let commandCalls = 0;
  const update = await updateTool('semgrep', { toolkitHome, inspect, fetchJson, dryRun: true, runCommand: async () => { commandCalls += 1; return { code: 0, output: '' }; } });
  assert.equal(update.state, 'PLAN_ONLY');
  assert.equal(update.plan.method, 'homebrew');
  assert.equal(commandCalls, 0);
  assert.equal(fs.existsSync(statePath(toolkitHome)), false, 'dry-run must not persist lifecycle state');
  const refresh = await refreshContent('trivy', { toolkitHome, dryRun: true, inspect });
  assert.equal(refresh.state, 'PLAN_ONLY');
  assert.equal(refresh.plan.method, 'official Trivy vulnerability DB refresh');
  assert.equal(refresh.plan.source, 'https://github.com/aquasecurity/trivy');
  const unknown = actionFor(loadManifest().tools.find((item) => item.id === 'semgrep'), { installMethod: 'unknown' });
  assert.equal(unknown, null);
  const semgrep = loadManifest().tools.find((item) => item.id === 'semgrep');
  assert.equal(provenanceFor('/Users/test/.local/share/uv/tools/semgrep/bin/semgrep', semgrep).method, 'uv');
  assert.equal(provenanceFor('/Users/test/manual/semgrep', semgrep).method, 'unknown');
  assert.equal(provenanceFor('/Users/test/manual/semgrep', semgrep, { installMethod: 'brew' }).method, 'unknown');
  fs.rmSync(toolkitHome, { recursive: true, force: true });
});

test('content refresh requires trust review and never executes a repository-external command', async () => {
  const toolkitHome = tempDir('vcg-content-review-');
  let calls = 0;
  const result = await refreshContent('nuclei', {
    toolkitHome,
    dryRun: false,
    yes: true,
    inspect: async (tool) => ({ ...readyInspection(tool), binaryPath: '/trusted/bin/nuclei' }),
    runCommand: async () => { calls += 1; return { code: 0, output: '' }; },
  });
  assert.equal(result.state, 'SECURITY_REVIEW_REQUIRED');
  assert.equal(result.plan.command, '/trusted/bin/nuclei');
  assert.equal(result.plan.source, 'https://github.com/projectdiscovery/nuclei-templates');
  assert.equal(calls, 0);
  fs.rmSync(toolkitHome, { recursive: true, force: true });
});

test('failed update preserves known-good state and cannot be promoted', async () => {
  const toolkitHome = tempDir('vcg-update-failure-');
  writeState({ tools: { gitleaks: { knownGoodVersion: '8.0.0', lastSuccessfulValidation: '2026-08-10T00:00:00.000Z' } } }, toolkitHome);
  const result = await updateTool('gitleaks', {
    toolkitHome,
    dryRun: false,
    yes: true,
    securityReviewed: true,
    inspect: async (tool) => tool.id === 'gitleaks' ? { ...readyInspection(tool), version: '8.0.0', versionNumber: '8.0.0' } : readyInspection(tool),
    fetchJson: async () => [{ tag_name: 'v9.0.0', prerelease: false, html_url: 'https://untrusted.example/payload' }],
    runCommand: async (command, args) => {
      assert.equal(command, 'brew');
      assert.deepEqual(args, ['upgrade', 'gitleaks']);
      return { code: 1, output: 'synthetic package-manager failure' };
    },
  });
  assert.equal(result.state, 'BROKEN');
  assert.equal(result.rollback.state, 'UNAVAILABLE');
  assert.equal(readState(toolkitHome).tools.gitleaks.knownGoodVersion, '8.0.0');
  fs.rmSync(toolkitHome, { recursive: true, force: true });
});

test('scanner lifecycle lock refuses overlapping mutation and releases safely', () => {
  const toolkitHome = tempDir('vcg-lifecycle-lock-');
  const first = acquireToolLock(toolkitHome, 'verification');
  try {
    assert.throws(() => acquireToolLock(toolkitHome, 'update:gitleaks'), (error) => error.code === 'TOOL_LIFECYCLE_BUSY');
  } finally {
    first.release();
  }
  const second = acquireToolLock(toolkitHome, 'update:gitleaks');
  second.release();
  fs.rmSync(toolkitHome, { recursive: true, force: true });
});

test('content freshness reports missing Trivy metadata without claiming current', () => {
  const cache = tempDir('vcg-trivy-missing-');
  const previous = process.env.TRIVY_CACHE_DIR;
  process.env.TRIVY_CACHE_DIR = cache;
  try {
    const trivy = loadManifest().tools.find((item) => item.id === 'trivy');
    assert.equal(contentState(trivy).state, 'MISSING');
  } finally {
    if (previous === undefined) delete process.env.TRIVY_CACHE_DIR;
    else process.env.TRIVY_CACHE_DIR = previous;
    fs.rmSync(cache, { recursive: true, force: true });
  }
});

test('invalid Trivy database metadata is BROKEN rather than current', async () => {
  const toolkitHome = tempDir('vcg-trivy-broken-home-');
  const cache = tempDir('vcg-trivy-broken-cache-');
  const previous = process.env.TRIVY_CACHE_DIR;
  fs.mkdirSync(path.join(cache, 'db'), { recursive: true });
  fs.writeFileSync(path.join(cache, 'db', 'metadata.json'), JSON.stringify({ Version: 999, UpdatedAt: 'invalid', NextUpdate: 'invalid' }));
  process.env.TRIVY_CACHE_DIR = cache;
  try {
    const trivy = loadManifest().tools.find((item) => item.id === 'trivy');
    assert.equal(contentState(trivy).state, 'BROKEN');
    const status = await lifecycleStatus({ toolkitHome, inspect: async (tool) => readyInspection(tool) });
    assert.equal(status.tools.trivy.state, 'BROKEN');
    assert.equal(status.overall, 'BROKEN');
  } finally {
    if (previous === undefined) delete process.env.TRIVY_CACHE_DIR;
    else process.env.TRIVY_CACHE_DIR = previous;
    fs.rmSync(toolkitHome, { recursive: true, force: true });
    fs.rmSync(cache, { recursive: true, force: true });
  }
});
