const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  actionFor,
  checkUpdates,
  contentState,
  discoverLatestStable,
  lifecycleStatus,
  refreshContent,
  statePath,
  updateTool,
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
      { tag_name: 'v8.31.0', prerelease: false, html_url: 'https://github.com/gitleaks/gitleaks/releases/tag/v8.31.0' },
      { tag_name: 'v8.30.0', prerelease: false },
    ],
  });
  assert.equal(result.latestStableVersion, '8.31.0');
  assert.equal(result.source, 'OFFICIAL');
  assert.match(result.releaseUrl, /v8\.31\.0/);
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

test('one-tool update and content refresh default to plans without mutation', async () => {
  const toolkitHome = tempDir('vcg-lifecycle-plan-');
  const inspect = async (tool) => readyInspection(tool);
  const fetchJson = async () => [{ tag_name: 'v2.0.0', prerelease: false }];
  let commandCalls = 0;
  const update = await updateTool('semgrep', { toolkitHome, inspect, fetchJson, dryRun: true, runCommand: async () => { commandCalls += 1; return { code: 0, output: '' }; } });
  assert.equal(update.state, 'PLAN_ONLY');
  assert.equal(update.plan.method, 'homebrew');
  assert.equal(commandCalls, 0);
  const refresh = await refreshContent('trivy', { toolkitHome, dryRun: true });
  assert.equal(refresh.state, 'PLAN_ONLY');
  assert.equal(refresh.plan.method, 'official Trivy vulnerability DB refresh');
  const unknown = actionFor(loadManifest().tools.find((item) => item.id === 'semgrep'), { installMethod: 'unknown' });
  assert.equal(unknown, null);
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
