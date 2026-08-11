const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const test = require('node:test');

const { createFinding } = require('../core/findings');
const { explicitLifecycleAction, reconcileFindings } = require('../core/correlation');
const { projectIdentity } = require('../core/correlation');
const { verificationCoverage, verificationOutcome, verificationPlan } = require('../core/verification');

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

test('targeted verification integration verifies a fixed finding with only the relevant fake scanner', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vcg-verify-integration-'));
  const project = path.join(root, 'project');
  const toolkit = path.join(root, 'toolkit');
  const data = path.join(root, 'runs');
  fs.mkdirSync(project, { recursive: true });
  fs.writeFileSync(path.join(project, 'package.json'), JSON.stringify({ name: 'synthetic-verification-project' }));
  const fakeSemgrep = path.join(root, 'fake-semgrep');
  fs.writeFileSync(fakeSemgrep, '#!/bin/sh\nprintf \'%s\\n\' \'{"results":[]}\'\n');
  fs.chmodSync(fakeSemgrep, 0o755);
  const identity = projectIdentity(project);
  const context = { projectId: identity.id, projectPath: project, runId: '2026-08-11-000001', startedAt: '2026-08-11T00:00:00.000Z', observedAt: '2026-08-11T00:01:00.000Z' };
  const raw = createFinding({ scanner: { id: 'semgrep', name: 'Semgrep', ruleId: 'synthetic.rule' }, severity: 'HIGH', category: 'INJECTION', title: 'Synthetic issue', location: { type: 'file', file: 'src/app.js', line: 5 }, evidence: 'Safe synthetic evidence.' }, context);
  const initial = reconcileFindings([], [raw], context).findings[0];
  explicitLifecycleAction(initial, 'FIXED', { runId: context.runId, reason: 'Synthetic authorized fix.' });
  fs.mkdirSync(path.join(data, 'projects', identity.id), { recursive: true });
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
