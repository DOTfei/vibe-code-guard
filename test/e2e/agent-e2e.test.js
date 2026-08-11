'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const net = require('node:net');
const { spawn } = require('node:child_process');

const {
  ROOT,
  copyFixture,
  createMockToolchain,
  fixtureManifest,
  fixturePath,
  tempDir,
  requestJson,
  runCli,
  assertSuccessfulJson,
} = require('./harness');
const { buildExecutionPlan, detectChanges } = require('../../orchestrator');
const { validateConfig, validateRuntimeTarget } = require('../../core/agent/project-config');
const { projectScopeFingerprint, verificationCoverage } = require('../../core/verification');

// Load the server only with an isolated data root. No E2E test may write to the
// developer's home directory or use the real global security-toolkit.
const isolatedServerRoot = fs.mkdtempSync(path.join(require('node:os').tmpdir(), 'vcg-v07-server-'));
process.env.SECURITY_TOOLKIT_HOME = path.join(isolatedServerRoot, 'toolkit');
process.env.SECURITY_DASHBOARD_DATA_DIR = path.join(isolatedServerRoot, 'runs');
fs.mkdirSync(process.env.SECURITY_TOOLKIT_HOME, { recursive: true });
const { detectStack, safeWebTarget } = require('../../server');

const FIXTURE_NAMES = ['react-vite', 'node-api', 'python', 'supabase-style', 'docker', 'terraform'];

function syntheticChangeSet(projectPath) {
  const files = [];
  const visit = (directory, relative = '') => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      if (entry.name === 'expected-results.json') continue;
      const file = path.join(relative, entry.name);
      if (entry.isDirectory()) visit(path.join(directory, entry.name), file);
      else files.push({ path: file, status: 'modified' });
    }
  };
  visit(projectPath);
  return { source: 'fixture', root: projectPath, base: 'synthetic', files, note: 'v0.7 synthetic fixture change set' };
}

function dependencyFindings() {
  return {
    'osv-scanner': [{
      source: { path: 'package.json' },
      packages: [{ package: { name: 'lodash', version: '4.17.11' }, vulnerabilities: [{ id: 'CVE-2026-0001', summary: 'lodash synthetic vulnerability', database_specific: { severity: 'HIGH' } }] }],
    }],
    trivy: [{
      Target: 'package.json',
      Vulnerabilities: [{ VulnerabilityID: 'CVE-2026-0001', PkgName: 'lodash', InstalledVersion: '4.17.11', Severity: 'HIGH', Title: 'lodash synthetic vulnerability', FixedVersion: '4.17.12' }],
    }],
  };
}

test('v0.7 fixture matrix has expected stack signals and proportionate scanner plans', () => {
  for (const name of FIXTURE_NAMES) {
    const fixture = fixturePath(name);
    const manifest = fixtureManifest(name);
    const detected = detectStack(fixture).stack;
    for (const expected of manifest.expectedStack) assert.ok(detected.includes(expected), `${name}: ${detected.join(', ')}`);
    const plan = buildExecutionPlan({ projectPath: fixture, detectedChanges: syntheticChangeSet(fixture) });
    assert.equal(plan.tools.find((item) => item.tool === 'gitleaks').decision, 'RUN');
    assert.equal(plan.tools.some((item) => item.decision === 'RUN'), true);
    assert.notEqual(plan.tools.find((item) => item.tool === 'strix').decision, 'RUN');
    assert.ok(plan.tools.every((item) => item.reason), `${name} has a scanner without a decision reason`);
  }
});

test('agent E2E runs install-adjacent doctor, change-aware audit, correlation, lifecycle, and Dashboard with isolated mocks', async () => {
  const project = copyFixture('node-api');
  const findings = {
    semgrep: [{
      check_id: 'vcg.synthetic.auth-header', path: 'src/routes/auth.js', start: { line: 3, col: 10 },
      extra: { message: 'Authorization header is accepted without a documented boundary.', severity: 'ERROR', metadata: { category: 'AUTHORIZATION' } },
    }],
    ...dependencyFindings(),
  };
  const tools = createMockToolchain({ findings });
  const install = assertSuccessfulJson(runCli(['install', '--dry-run', '--json'], tools.env));
  assert.equal(install.status, 'PLAN_ONLY');
  assert.equal(install.plan.actions.length, 0, 'healthy mocked tools must not be reinstalled');
  const doctorResult = runCli(['doctor', '--json'], tools.env);
  assert.equal(doctorResult.status, 2, doctorResult.output);
  const doctor = doctorResult.json;
  assert.equal(doctor.status, 'DEGRADED');
  assert.equal(Object.values(doctor.toolchain).filter((tool) => tool.status === 'READY').length, 8);

  const auditResult = runCli(['audit', project, '--profile', 'auto', '--json'], tools.env);
  const audit = assertSuccessfulJson(auditResult);
  assert.equal(audit.status, 'COMPLETED');
  assert.equal(audit.stack.includes('Node.js'), true);
  assert.ok(audit.runId);
  assert.ok(audit.correlatedFindings.length >= 2, 'raw scanner evidence should become correlated findings');
  assert.ok(audit.correlatedFindings.some((finding) => finding.observations.length >= 2), 'dependency evidence should correlate across OSV and Trivy');
  assert.equal(audit.releaseGate.label, 'DO NOT DEPLOY');
  assert.equal(audit.scannerStates.strix, undefined);
  const metadata = JSON.parse(fs.readFileSync(path.join(tools.dataDir, audit.runId, 'metadata.json'), 'utf8'));
  assert.equal(metadata.status, 'FAIL', 'the persisted run keeps the blocking release result while the CLI reports a completed assessment');
  assert.equal(fs.existsSync(path.join(project, 'semgrep-output.json')), false, 'scanner output must stay in run data, not the project');

  const dashboard = assertSuccessfulJson(runCli(['dashboard', '--json'], tools.env));
  assert.equal(dashboard.localOnly, true);
  assert.match(dashboard.dashboardUrl, /^http:\/\/127\.0\.0\.1:\d+$/);
  const state = await requestJson(`${dashboard.dashboardUrl}/api/state`);
  assert.equal(state.statusCode, 200);
  assert.equal(state.json.latest.id, audit.runId);
  assert.ok(state.json.latest.correlatedFindings.length >= 2);

  const target = audit.correlatedFindings.find((finding) => finding.observations.some((observation) => observation.scanner === 'semgrep'));
  assert.ok(target, 'static synthetic finding must be available to the agent');
  const statusResponse = await requestJson(`${dashboard.dashboardUrl}/api/runs/${audit.runId}/findings/${encodeURIComponent(target.id)}/status`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ status: 'FIXED', reason: 'Authorized synthetic E2E fix.' }),
  });
  assert.equal(statusResponse.statusCode, 200);
  assert.equal(statusResponse.json.finding.status, 'FIXED');

  // A scope/config change is not remediation. The clean mock result must still
  // be reported as incomplete rather than VERIFIED.
  fs.writeFileSync(path.join(project, '.semgrepignore'), 'src/routes/auth.js\n');
  const cheated = runCli(['verify', target.id, project, '--json'], { ...tools.env, VCG_E2E_VERIFY_MODE: 'clean' });
  assert.equal(cheated.status, 2, cheated.output);
  assert.equal(cheated.json.verification, 'VERIFICATION_INCOMPLETE');
  fs.unlinkSync(path.join(project, '.semgrepignore'));

  const verified = runCli(['verify', target.id, project, '--json'], { ...tools.env, VCG_E2E_VERIFY_MODE: 'clean' });
  assert.equal(verified.status, 0, verified.output);
  assert.equal(verified.json.verification, 'PASSED');
  assert.equal(verified.json.lifecycle, 'VERIFIED');

  const reopened = runCli(['verify', target.id, project, '--json'], tools.env);
  assert.equal(reopened.status, 1, reopened.output);
  assert.equal(reopened.json.verification, 'STILL_DETECTED');
  assert.equal(reopened.json.lifecycle, 'REOPENED');

  const unauthorized = await requestJson(`${dashboard.dashboardUrl}/api/toolkit/update`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ scanner: 'semgrep', confirm: true }),
  });
  assert.equal(unauthorized.statusCode, 403);
  try { process.kill(dashboard.pid, 'SIGTERM'); } catch { /* child may already have exited */ }
});

test('agent E2E honors offline/degraded status without inventing update or audit success', () => {
  const tools = createMockToolchain();
  const status = runCli(['tools', 'status', '--json'], tools.env);
  assert.equal(status.status, 2, status.output);
  const parsed = status.json;
  assert.ok(parsed);
  assert.equal(parsed.schemaVersion, '1.0');
  assert.ok(parsed.tools);
  assert.equal(parsed.tools.gitleaks.state, 'READY');
  assert.equal(runCli(['tools', 'update', '--dry-run', '--json'], tools.env).status, 2);
  const broken = runCli(['audit', path.join(ROOT, 'test', 'e2e', 'fixtures', 'react-vite'), '--profile', 'quick', '--json'], { ...tools.env, PATH: path.join(tools.root, 'missing'), SECURITY_TOOL_PATHS: path.join(tools.root, 'missing') });
  assert.equal(broken.status, 1);
  assert.equal(broken.json.status, 'BLOCKED');
});

test('runtime scope and config contracts reject public, wildcard, traversal, and command injection inputs', () => {
  assert.equal(validateRuntimeTarget('http://127.0.0.1:4317').allowed, true);
  assert.equal(validateRuntimeTarget('http://0.0.0.0:4317').allowed, false);
  assert.equal(validateRuntimeTarget('https://example.com').allowed, false);
  assert.equal(safeWebTarget('http://127.0.0.1:4317'), 'http://127.0.0.1:4317');
  assert.equal(safeWebTarget('http://0.0.0.0:4317'), null);
  assert.throws(() => validateConfig({ ignoredPaths: ['../outside'] }), /traversal/);
  assert.throws(() => validateConfig({ profile: 'full', command: 'echo unsafe' }), /Unsupported config field/);
});

test('full profile runs authorized runtime checks only against a disposable localhost server', async () => {
  const project = copyFixture('node-api');
  const localServer = http.createServer((request, response) => { response.writeHead(200, { 'content-type': 'text/plain' }); response.end('synthetic local target'); });
  await new Promise((resolve) => localServer.listen(0, '127.0.0.1', resolve));
  const target = `http://127.0.0.1:${localServer.address().port}`;
  const tools = createMockToolchain({ findings: {
    nuclei: [{ 'template-id': 'vcg-safe-local', 'matched-at': target, info: { name: 'Synthetic local observation', severity: 'info', description: 'Safe test-only runtime signal.' } }],
    zap: [{ pluginid: 'vcg-safe-local', url: target, name: 'Synthetic local observation', riskcode: '0', confidence: '3' }],
  } });
  try {
    const result = runCli(['audit', project, '--profile', 'full', '--web-target', target, '--json'], tools.env);
    assert.ok(result.json, result.output);
    assert.equal(result.json.status, 'COMPLETED');
    assert.equal(result.json.scannerStates.nuclei.status, 'PASS');
    assert.equal(result.json.scannerStates.zap.status, 'PASS');
    assert.equal(result.json.config.runtimeTargets.length, 0);
  } finally {
    await new Promise((resolve) => localServer.close(resolve));
  }
});

test('large ignored trees stay outside bounded project discovery', () => {
  const project = tempDir('vcg-v07-large-');
  fs.writeFileSync(path.join(project, 'package.json'), '{"name":"large-synthetic"}');
  for (const directory of ['node_modules', 'dist', 'vendor', 'coverage']) {
    fs.mkdirSync(path.join(project, directory), { recursive: true });
    fs.writeFileSync(path.join(project, directory, 'should-not-be-scanned.txt'), 'synthetic ignored content');
  }
  fs.writeFileSync(path.join(project, 'src.js'), 'export const safe = true;');
  const changes = detectChanges(project);
  assert.equal(changes.files.some((file) => /^(node_modules|dist|vendor|coverage)\//.test(file.path)), false);
  assert.equal(changes.files.some((file) => file.path === 'src.js'), true);
});

test('stopping an in-flight local audit persists STOPPED instead of false COMPLETE', async () => {
  const project = copyFixture('node-api');
  const tools = createMockToolchain({ sleepMs: 2500 });
  const portProbe = net.createServer();
  await new Promise((resolve) => portProbe.listen(0, '127.0.0.1', resolve));
  const port = portProbe.address().port;
  await new Promise((resolve) => portProbe.close(resolve));
  const child = spawn(process.execPath, [path.join(ROOT, 'server.js')], { env: { ...tools.env, PORT: String(port) }, stdio: ['ignore', 'pipe', 'pipe'] });
  const base = `http://127.0.0.1:${port}`;
  try {
    for (let attempt = 0; attempt < 30; attempt += 1) {
      try { if ((await requestJson(`${base}/api/health`)).statusCode === 200) break; } catch { /* wait for child */ }
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    const started = await requestJson(`${base}/api/scans`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ projectPath: project, mode: 'quick' }) });
    assert.equal(started.statusCode, 202);
    const runId = started.json.runId;
    await new Promise((resolve) => setTimeout(resolve, 150));
    const stopped = await requestJson(`${base}/api/runs/${runId}/stop`, { method: 'POST' });
    assert.equal(stopped.statusCode, 202);
    let run = null;
    for (let attempt = 0; attempt < 80; attempt += 1) {
      const current = await requestJson(`${base}/api/runs/${runId}`);
      run = current.json?.run;
      if (run && run.status !== 'SCANNING') break;
      await new Promise((resolve) => setTimeout(resolve, 75));
    }
    assert.equal(run.status, 'STOPPED');
    assert.equal(run.releaseGate.label, 'DO NOT DEPLOY');
  } finally {
    child.kill('SIGTERM');
  }
});

test('scope cheating, incomplete coverage, and interruption states cannot create false verification', () => {
  const project = fixturePath('node-api');
  const baseline = projectScopeFingerprint(project, 'src/routes/auth.js', null);
  const changed = projectScopeFingerprint(project, 'src/routes/auth.js', null);
  const plan = { relevantScanners: ['semgrep'], baselineScopeFingerprint: baseline, target: null, manualReviewRequired: false };
  const complete = verificationCoverage(plan, { semgrep: { status: 'PASS', decision: 'RUN', parseValid: true, version: '1.0.0' } }, { currentScopeFingerprint: changed });
  assert.equal(complete.complete, true);
  const incomplete = verificationCoverage(plan, { semgrep: { status: 'PASS', decision: 'RUN', parseValid: true, version: null } }, { currentScopeFingerprint: changed });
  assert.equal(incomplete.complete, false);
  assert.match(incomplete.reason, /skipped|failed|degraded|malformed|missing|version/i);
  const scopeChanged = verificationCoverage(plan, { semgrep: { status: 'PASS', decision: 'RUN', parseValid: true, version: '1.0.0' } }, { currentScopeFingerprint: 'different' });
  assert.equal(scopeChanged.complete, false);
  assert.match(scopeChanged.reason, /configuration|scope|target/i);
});

test('agent-readable documentation describes the same install, audit, fix, and safety contract', () => {
  const documents = ['README.md', 'AGENTS.md', 'CLAUDE.md', 'docs/agent-integration.md'];
  const text = documents.map((file) => fs.readFileSync(path.join(ROOT, file), 'utf8')).join('\n');
  for (const required of ['vibe-code-guard doctor --json', 'vibe-code-guard audit', 'vibe-code-guard dashboard', '127.0.0.1', 'VERIFICATION_INCOMPLETE', 'no real AI']) {
    assert.match(text, new RegExp(required.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i'), required);
  }
  assert.match(fs.readFileSync(path.join(ROOT, 'AGENTS.md'), 'utf8'), /Never invent scanner output/i);
});
