const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const test = require('node:test');

const { createFinding } = require('../core/findings');
const { explicitLifecycleAction, reconcileFindings } = require('../core/correlation');
const { projectIdentity } = require('../core/correlation');
const { projectScopeFingerprint, verificationCoverage, verificationOutcome, verificationPlan } = require('../core/verification');

const ROOT = path.resolve(__dirname, '..');

function syntheticGroup(category = 'INJECTION', scanner = 'semgrep') {
  const context = { projectId: 'project-verification', projectPath: '/tmp/vcg-verification-project', runId: '2026-08-11-000001', startedAt: '2026-08-11T00:00:00.000Z', observedAt: '2026-08-11T00:01:00.000Z' };
  const raw = createFinding({ scanner: { id: scanner, name: scanner, ruleId: 'synthetic.rule' }, severity: 'HIGH', category, title: 'Synthetic issue', location: { type: 'file', file: 'src/app.js', line: 5 }, evidence: 'Safe synthetic evidence.' }, context);
  return reconcileFindings([], [raw], context).findings[0];
}

test('targeted verification maps scanner families and rejects missing runtime scope', () => {
  const staticFinding = syntheticGroup('INJECTION', 'semgrep');
  assert.deepEqual(verificationPlan(staticFinding).relevantScanners, ['semgrep']);
  const dependency = syntheticGroup('DEPENDENCY_VULNERABILITY', 'trivy');
  assert.deepEqual(verificationPlan(dependency).relevantScanners.sort(), ['osv-scanner', 'trivy']);
  const runtime = syntheticGroup('RUNTIME', 'zap');
  const plan = verificationPlan(runtime);
  assert.equal(plan.authorizationRequired, true);
  const coverage = verificationCoverage(plan, { zap: { status: 'SKIPPED', decision: 'SKIP' }, nuclei: { status: 'SKIPPED', decision: 'SKIP' } });
  assert.equal(coverage.complete, false);
  assert.equal(verificationOutcome({ finding: runtime, updatedFinding: runtime, coverage }).verification, 'VERIFICATION_INCOMPLETE');
});

test('Dashboard preserves explicit verification outcomes', () => {
  const html = fs.readFileSync(path.join(ROOT, 'public', 'index.html'), 'utf8');
  const app = fs.readFileSync(path.join(ROOT, 'public', 'app.js'), 'utf8');
  assert.match(html, /id="run-verification"/);
  assert.match(app, /verification\.verification/);
  assert.match(app, /VERIFICATION_INCOMPLETE|run-verification/);
});

test('scope changes and multi-scanner gaps cannot establish VERIFIED', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vcg-scope-'));
  fs.mkdirSync(path.join(root, 'src'));
  fs.writeFileSync(path.join(root, 'src', 'app.js'), 'const safe = true;\n');
  const finding = syntheticGroup('DEPENDENCY_VULNERABILITY', 'trivy');
  const plan = verificationPlan(finding);
  const baseline = projectScopeFingerprint(root, 'src/app.js');
  fs.writeFileSync(path.join(root, '.semgrepignore'), 'src/\n');
  const changed = projectScopeFingerprint(root, 'src/app.js');
  assert.notEqual(baseline, changed);
  assert.notEqual(projectScopeFingerprint(root, 'src/app.js', 'http://127.0.0.1:3000'), projectScopeFingerprint(root, 'src/app.js', 'http://127.0.0.1:4000'));
  const incomplete = verificationCoverage({ ...plan, baselineScopeFingerprint: baseline }, {
    trivy: { status: 'PASS', decision: 'RUN', parseValid: true, version: '0.73.0' },
    'osv-scanner': { status: 'SKIPPED', decision: 'SKIP', parseValid: false, version: '2.5.0' },
  }, { currentScopeFingerprint: baseline });
  assert.equal(incomplete.complete, false);
  const scopeChanged = verificationCoverage({ ...plan, baselineScopeFingerprint: baseline }, {
    semgrep: { status: 'PASS', decision: 'RUN', parseValid: true, version: '1.0.0' },
  }, { currentScopeFingerprint: changed });
  assert.equal(scopeChanged.complete, false);
  const unknownVersion = verificationCoverage({ ...verificationPlan(syntheticGroup('INJECTION', 'semgrep')), baselineScopeFingerprint: changed }, {
    semgrep: { status: 'PASS', decision: 'RUN', parseValid: true, version: null },
  }, { currentScopeFingerprint: changed });
  assert.equal(unknownVersion.complete, false);
  fs.rmSync(root, { recursive: true, force: true });
});

test('targeted verification integration verifies a fixed finding with only the relevant fake scanner', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vcg-verify-integration-'));
  let project = path.join(root, 'project');
  const toolkit = path.join(root, 'toolkit');
  const data = path.join(root, 'runs');
  fs.mkdirSync(project, { recursive: true });
  project = fs.realpathSync(project);
  fs.writeFileSync(path.join(project, 'package.json'), JSON.stringify({ name: 'synthetic-verification-project' }));
  fs.mkdirSync(path.join(project, 'src'));
  fs.writeFileSync(path.join(project, 'src', 'app.js'), 'const remediated = true;\n');
  const fakeSemgrep = path.join(root, 'fake-semgrep');
  fs.writeFileSync(fakeSemgrep, '#!/bin/sh\nif [ "$1" = "--version" ]; then printf \'1.2.3\\n\'; else printf \'%s\\n\' \'{"results":[]}\'; fi\n');
  fs.chmodSync(fakeSemgrep, 0o755);
  const identity = projectIdentity(project);
  const context = { projectId: identity.id, projectPath: project, runId: '20260811000001-000001', startedAt: '2026-08-11T00:00:00.000Z', observedAt: '2026-08-11T00:01:00.000Z' };
  const raw = createFinding({ scanner: { id: 'semgrep', name: 'Semgrep', ruleId: 'synthetic.rule' }, severity: 'HIGH', category: 'INJECTION', title: 'Synthetic issue', location: { type: 'file', file: 'src/app.js', line: 5 }, evidence: 'Safe synthetic evidence.' }, context);
  const initial = reconcileFindings([], [raw], context).findings[0];
  explicitLifecycleAction(initial, 'FIXED', { runId: context.runId, reason: 'Synthetic authorized fix.' });
  fs.mkdirSync(path.join(data, 'projects', identity.id), { recursive: true });
  fs.mkdirSync(path.join(data, context.runId), { recursive: true });
  fs.writeFileSync(path.join(data, context.runId, 'metadata.json'), JSON.stringify({ projectPath: project, projectId: identity.id, status: 'PASS' }));
  fs.writeFileSync(path.join(data, 'projects', identity.id, 'findings-index.json'), JSON.stringify({ schemaVersion: '1.0', projectId: identity.id, findings: [initial] }));
  const script = `const { verifyFinding } = require(${JSON.stringify(path.join(ROOT, 'server.js'))}); verifyFinding({ projectPath: ${JSON.stringify(project)}, findingId: ${JSON.stringify(initial.id)} }).then((result) => console.log(JSON.stringify({ verification: result.verification.verification, lifecycle: result.finding.status, scanners: result.verification.plan.relevantScanners }))).catch((error) => { console.error(error.message); process.exit(1); });`;
  const output = execFileSync(process.execPath, ['-e', script], {
    cwd: ROOT,
    encoding: 'utf8',
    env: { ...process.env, SECURITY_TOOLKIT_HOME: toolkit, SECURITY_DASHBOARD_DATA_DIR: data, SECURITY_TOOL_BINARIES: JSON.stringify({ semgrep: fakeSemgrep }) },
  });
  const result = JSON.parse(output);
  assert.equal(result.verification, 'PASSED');
  assert.equal(result.lifecycle, 'VERIFIED');
  assert.deepEqual(result.scanners, ['semgrep']);
  const persisted = JSON.parse(fs.readFileSync(path.join(data, 'projects', identity.id, 'findings-index.json'), 'utf8'));
  assert.equal(persisted.findings[0].status, 'VERIFIED');
  fs.rmSync(root, { recursive: true, force: true });
});
