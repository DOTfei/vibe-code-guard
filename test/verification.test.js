const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync, spawnSync } = require('node:child_process');
const test = require('node:test');

const { createFinding } = require('../core/findings');
const { explicitLifecycleAction, reconcileFindings } = require('../core/correlation');
const { projectIdentity } = require('../core/correlation');
const { projectScopeFingerprint, verificationCoverage, verificationOutcome, verificationPlan } = require('../core/verification');

const ROOT = path.resolve(__dirname, '..');

test('all scanner output boundaries reject invalid shapes while preserving clean reports', () => {
  const source = fs.readFileSync(path.join(ROOT, 'server.js'), 'utf8');
  const validator = require('node:vm').runInNewContext('(' + source.slice(source.indexOf('function validateScannerOutput('), source.indexOf('\nfunction runtimeTargetReachable(')) + ')');
  const clean = { gitleaks: '[]', trufflehog: '', nuclei: '', checkov: '{"results":{"failed_checks":[]}}', zap: '{"site":[{"alerts":[]}]}', semgrep: '{"results":[]}', trivy: '{"Results":[]}', 'osv-scanner': '{"results":[]}' };
  for (const [tool, report] of Object.entries(clean)) {
    assert.equal(validator(tool, report).valid, true, tool);
    for (const invalid of ['null', '{}', 'true', '42', '"text"', '[null]', '[{}]']) assert.equal(validator(tool, invalid).valid, false, `${tool}: ${invalid}`);
  }
  for (const [tool, report] of [
    ['gitleaks', '[{"RuleID":"synthetic"}]'], ['gitleaks', '[{"RuleID":"synthetic","File":" "}]'],
    ['trufflehog', '{"DetectorName":"synthetic"}'], ['semgrep', '{"results":[{"check_id":"synthetic"}]}'],
    ['checkov', '{"results":{"failed_checks":[{"check_id":"synthetic"}]}}'],
    ['nuclei', '{"template-id":"synthetic","info":{}}'], ['zap', '{"alerts":[{"pluginid":"synthetic"}]}'],
    ['trufflehog', '{"DetectorName":"synthetic"}\nnull'], ['nuclei', '{"template-id":"synthetic","info":{}}\n{}'],
    ['gitleaks', '[{"RuleID":"synthetic"},null]'], ['checkov', '{"results":{"failed_checks":[{}]}}'],
    ['zap', '{"alerts":[{}]}'], ['zap', '{"site":[{"alerts":[]},{"alerts":[{"pluginid":"synthetic"}]}]}'],
    ['zap', '{"alerts":[],"site":[{"alerts":[{"pluginid":"synthetic"}]}]}'],
    ['semgrep', '{"results":[{}]}'], ['semgrep', '{"results":[null]}'],
    ['trivy', '{"Results":[{}]}'], ['trivy', '{"Results":[{"Target":"package-lock.json","Vulnerabilities":[{}]}]}'],
    ['osv-scanner', '{"results":[{}]}'], ['osv-scanner', '{"results":[{"packages":[null]}]}'],
    ['osv-scanner', '{"results":[{"packages":[{"package":{},"vulnerabilities":[{}]}]}]}'],
    ['osv-scanner', '{"results":[{"packages":[{"package":{"name":"synthetic","version":"1"},"vulnerabilities":[{"id":"PYSEC-2026-123"}]}]}]}'],
  ]) assert.equal(validator(tool, report).valid, false, `${tool}: ${report}`);
  assert.equal(validator('zap', '{"alerts":[]}').valid, true);
  for (const [tool, report] of [
    ['gitleaks', '[{"RuleID":"synthetic","File":"src/config.js"}]'], ['trufflehog', '{"DetectorName":"synthetic","SourceMetadata":{"Data":{"Filesystem":{"file":"src/config.js"}}}}'],
    ['nuclei', '{"template-id":"synthetic","info":{"name":"Safe fixture"},"matched-at":"http://127.0.0.1:3000"}'],
    ['checkov', '{"results":{"failed_checks":[{"check_id":"synthetic","file_path":"/Dockerfile"}]}}'], ['zap', '{"alerts":[{"pluginid":"synthetic","url":"http://127.0.0.1:3000"}]}'],
    ['osv-scanner', '{"results":[{"source":{"path":"requirements.txt"},"packages":[{"package":{"name":"synthetic","version":"1"},"vulnerabilities":[{"id":"PYSEC-2026-123"}]}]}]}'],
  ]) assert.equal(validator(tool, report).valid, true, `${tool}: ${report}`);
});

test('malformed secret reports cannot verify an unchanged finding through canonical verification', () => {
  const { createMockToolchain, copyFixture } = require('./e2e/harness');
  const tools = createMockToolchain({ findings: { gitleaks: [{ RuleID: 'synthetic-acceptance', File: 'src/config.js', StartLine: 1 }] } });
  const project = fs.realpathSync(copyFixture('node-api'));
  try {
    fs.mkdirSync(path.join(project, 'src'), { recursive: true });
    fs.writeFileSync(path.join(project, 'src/config.js'), 'module.exports = { synthetic: true };\n');
    const invoke = code => JSON.parse(execFileSync(process.execPath, ['-e', code], { env: tools.env, encoding: 'utf8', timeout: 30000 }));
    const server = JSON.stringify(path.join(ROOT, 'server'));
    const finding = invoke(`const {createRun,runAudit}=require(${server});const run=createRun({projectPath:${JSON.stringify(project)},mode:'auto',webTarget:null});runAudit(run).then(()=>console.log(JSON.stringify(run.correlatedFindings.find(f=>f.observations.some(o=>o.scanner==='gitleaks')))));`);
    const indexFile = path.join(tools.dataDir, 'projects', projectIdentity(project).id, 'findings-index.json');
    const initial = JSON.parse(fs.readFileSync(indexFile, 'utf8'));
    initial.findings.find(f => f.id === finding.id).status = 'FIXED';
    const verify = `const {verifyFinding}=require(${server});verifyFinding({projectPath:${JSON.stringify(project)},findingId:${JSON.stringify(finding.id)}}).then(r=>console.log(JSON.stringify({verification:r.verification.verification,status:r.finding.status})));`;
    for (const tool of ['gitleaks', 'trufflehog']) {
      for (const invalid of ['null', '{}', '[null]', tool === 'gitleaks' ? '[{"RuleID":"synthetic-acceptance"}]' : '{"DetectorName":"synthetic"}']) {
        fs.writeFileSync(indexFile, JSON.stringify(initial));
        for (const scanner of ['gitleaks', 'trufflehog']) {
          const output = scanner === tool ? invalid : scanner === 'gitleaks' ? '[]' : '';
          fs.writeFileSync(tools.paths[scanner], '#!' + process.execPath + '\nconst fs=require("node:fs"),args=process.argv.slice(2);if(args.includes("version")||args.includes("--version")){console.log("1.2.3");}else{' + (scanner === 'gitleaks' ? `fs.writeFileSync(args[args.indexOf("--report-path")+1],${JSON.stringify(output)});` : `process.stdout.write(${JSON.stringify(output)});`) + '}\n', { mode: 0o700 });
        }
        const result = invoke(verify);
        assert.equal(result.verification, 'VERIFICATION_INCOMPLETE');
        assert.notEqual(result.status, 'VERIFIED');
        assert.notEqual(JSON.parse(fs.readFileSync(indexFile, 'utf8')).findings.find(f => f.id === finding.id).status, 'VERIFIED');
      }
    }
  } finally {
    fs.rmSync(tools.root, { recursive: true, force: true });
    fs.rmSync(path.dirname(project), { recursive: true, force: true });
  }
});

function syntheticGroup(category = 'INJECTION', scanner = 'semgrep') {
  const context = { projectId: 'project-verification', projectPath: '/tmp/vcg-verification-project', runId: '2026-08-11-000001', startedAt: '2026-08-11T00:00:00.000Z', observedAt: '2026-08-11T00:01:00.000Z' };
  const raw = createFinding({ scanner: { id: scanner, name: scanner, ruleId: 'synthetic.rule' }, severity: 'HIGH', category, title: 'Synthetic issue', location: { type: 'file', file: 'src/app.js', line: 5 }, evidence: 'Safe synthetic evidence.' }, context);
  return reconcileFindings([], [raw], context).findings[0];
}

test('mixed historical dependency and secret evidence retains both scanner families', () => {
  const finding = { ...syntheticGroup('SECRET_EXPOSURE', 'gitleaks'), scopeFingerprint: 'unchanged' };
  finding.observations.push({ scanner: 'trivy', ruleId: 'CVE-2026-1234', identity: { kind: 'secret', packageName: 'synthetic-package', installedVersion: '1' } });
  const plan = verificationPlan(finding);
  assert.deepEqual(plan.relevantScanners.sort(), ['gitleaks', 'osv-scanner', 'trivy', 'trufflehog']);
  const tools = Object.fromEntries(['gitleaks', 'osv-scanner', 'trivy'].map(id => [id, { status: 'PASS', decision: 'RUN', parseValid: true, version: '1.0.0' }]));
  tools.trufflehog = { status: 'MISSING', parseValid: false, version: null };
  const coverage = verificationCoverage(plan, tools, { currentScopeFingerprint: 'unchanged' });
  assert.equal(coverage.complete, false);
  assert.equal(verificationOutcome({ finding, updatedFinding: finding, coverage }).verification, 'VERIFICATION_INCOMPLETE');
});

test('short and non-semver dependency identity survives normalization and historical migration', () => {
  const { adaptScannerOutput } = require('../core/findings');
  const { normalizePersistedFinding } = require('../core/findings/schema');
  for (const version of ['1', '1.0rc1', '2026.10.post1']) {
    const context = { projectId: 'short-version', projectPath: '/tmp/short-version', runId: 'old' };
    const raw = adaptScannerOutput('osv-scanner', JSON.stringify({ results: [{ source: { path: 'requirements.txt' }, packages: [{ package: { name: 'synthetic-package', version }, vulnerabilities: [{ id: 'PYSEC-2026-123', summary: 'command injection' }] }] }] }), context)[0];
    assert.equal(normalizePersistedFinding(raw, context).correlationMetadata.installedVersion, version);
    const legacy = reconcileFindings([], [createFinding({ ...raw, category: 'INJECTION', fingerprint: undefined, id: undefined }, context)], context).findings[0];
    legacy.status = 'FIXED';
    const next = reconcileFindings([legacy], [raw], { ...context, verificationScopeValid: true });
    assert.equal(next.findings.length, 1);
    assert.equal(next.findings[0].id, legacy.id);
    assert.equal(next.findings[0].status, 'OPEN');
  }
});

test('ambiguous legacy dependency identity defers verification instead of proving absence', () => {
  const { adaptScannerOutput } = require('../core/findings');
  const context = { projectId: 'ambiguous-history', projectPath: '/tmp/ambiguous-history', runId: 'old' };
  const raw = adaptScannerOutput('osv-scanner', JSON.stringify({ results: [{ source: { path: 'requirements.txt' }, packages: [{ package: { name: 'synthetic-package', version: '1' }, vulnerabilities: [{ id: 'PYSEC-2026-123', summary: 'command injection' }] }] }] }), context)[0];
  const old = createFinding({ ...raw, correlationMetadata: undefined, category: 'INJECTION', fingerprint: undefined, id: undefined }, context);
  const legacy = reconcileFindings([], [old], context).findings[0];
  legacy.status = 'FIXED';
  const tools = Object.fromEntries(['trivy', 'osv-scanner'].map(id => [id, { status: 'PASS', decision: 'RUN', parseValid: true, version: '1.0.0' }]));
  const next = reconcileFindings([legacy], [raw], { ...context, tools, verificationScopeValid: true });
  assert.equal(next.findings.find(item => item.id === legacy.id).status, 'FIXED');
  assert.deepEqual(next.incompleteFindingIds, [legacy.id]);
  assert.ok(next.findings.some(item => item.id !== legacy.id && item.status === 'OPEN'));
});

test('targeted verification persists unmatched evidence and reports ambiguous history as incomplete', () => {
  const { createMockToolchain, copyFixture } = require('./e2e/harness');
  const report = { source: { path: 'requirements.txt' }, packages: [{ package: { name: 'synthetic-package', version: '1' }, vulnerabilities: [{ id: 'PYSEC-2026-123', summary: 'command injection' }] }] };
  const tools = createMockToolchain({ findings: { 'osv-scanner': [report] } });
  const project = fs.realpathSync(copyFixture('node-api'));
  try {
    fs.writeFileSync(path.join(project, 'requirements.txt'), 'synthetic-package==1\n');
    const server = JSON.stringify(path.join(ROOT, 'server'));
    const invoke = code => JSON.parse(execFileSync(process.execPath, ['-e', code], { env: tools.env, encoding: 'utf8', timeout: 30000 }));
    invoke(`const {createRun,runAudit}=require(${server});const run=createRun({projectPath:${JSON.stringify(project)},mode:'auto',webTarget:null});runAudit(run).then(()=>console.log(JSON.stringify({ok:true})));`);
    const indexFile = path.join(tools.dataDir, 'projects', projectIdentity(project).id, 'findings-index.json');
    const index = JSON.parse(fs.readFileSync(indexFile, 'utf8'));
    const legacy = index.findings.find(f => f.observations.some(o => o.scanner === 'osv-scanner'));
    legacy.id = 'VCG-CORR-00000000000001';
    legacy.category = 'INJECTION';
    legacy.status = 'FIXED';
    for (const observation of legacy.observations) {
      observation.category = 'INJECTION';
      observation.fingerprint = 'legacy-fingerprint';
      observation.identity = { ...observation.identity, kind: 'static', packageName: null, installedVersion: null, vulnerabilityId: null };
    }
    const unrelated = JSON.parse(JSON.stringify(legacy));
    unrelated.id = 'VCG-CORR-00000000000002';
    unrelated.observations.forEach(o => { o.ruleId = 'PYSEC-2026-999'; });
    index.findings.push(unrelated);
    fs.writeFileSync(indexFile, JSON.stringify(index));
    const result = invoke(`const {verifyFinding,hydrateRun}=require(${server});verifyFinding({projectPath:${JSON.stringify(project)},findingId:${JSON.stringify(legacy.id)}}).then(r=>console.log(JSON.stringify({verification:r.verification,findings:r.run.correlatedFindings,stored:hydrateRun(r.run.id).verification})));`);
    assert.equal(result.verification.verification, 'VERIFICATION_INCOMPLETE');
    assert.equal(result.verification.coverage.complete, false);
    assert.deepEqual(result.stored, result.verification);
    const persisted = JSON.parse(fs.readFileSync(indexFile, 'utf8')).findings;
    assert.deepEqual(result.findings, persisted);
    assert.equal(persisted.find(f => f.id === legacy.id).status, 'FIXED');
    assert.equal(persisted.find(f => f.id === unrelated.id).status, 'FIXED');
    assert.ok(persisted.some(f => f.id !== legacy.id && f.status === 'OPEN'));
    const cli = spawnSync(process.execPath, [path.join(ROOT, 'bin/vibe-code-guard.js'), 'verify', legacy.id, project, '--json'], { env: tools.env, encoding: 'utf8', timeout: 30000 });
    assert.equal(cli.status, 2, cli.stderr);
    const cliResult = JSON.parse(cli.stdout);
    assert.equal(cliResult.verification, 'VERIFICATION_INCOMPLETE');
    const repeat = invoke(`const run=require(${server}).hydrateRun(${JSON.stringify(cliResult.runId)});console.log(JSON.stringify({verification:run.verification,findings:run.correlatedFindings}));`);
    assert.equal(repeat.verification.verification, cliResult.verification);
    assert.equal(repeat.findings.find(f => f.id === legacy.id).status, cliResult.lifecycle);
    assert.equal(repeat.verification.verification, 'VERIFICATION_INCOMPLETE');
    assert.equal(repeat.findings.length, persisted.length);
    const newFinding = persisted.find(f => f.status === 'OPEN');
    assert.ok(repeat.findings.find(f => f.id === newFinding.id).observations.length > newFinding.observations.length);
  } finally {
    fs.rmSync(tools.root, { recursive: true, force: true });
    fs.rmSync(path.dirname(project), { recursive: true, force: true });
  }
});

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

test('canonical misconfiguration findings require both configuration scanners', () => {
  for (const scanner of ['checkov', 'trivy']) {
    const finding = { ...syntheticGroup('MISCONFIGURATION', scanner), scopeFingerprint: 'same' };
    const plan = verificationPlan(finding);
    assert.deepEqual(plan.relevantScanners.sort(), ['checkov', 'trivy']);
    const coverage = verificationCoverage(plan, { [scanner]: { status: 'PASS', decision: 'RUN', parseValid: true, version: '1.0.0' } }, { currentScopeFingerprint: 'same' });
    assert.equal(coverage.complete, false);
    assert.equal(verificationOutcome({ finding, updatedFinding: { ...finding, status: 'VERIFIED' }, coverage }).verification, 'VERIFICATION_INCOMPLETE');
  }
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

test('dependency advisory titles cannot substitute Semgrep for required OSV coverage, including historical findings', () => {
  const { adaptScannerOutput } = require('../core/findings');
  const raw = adaptScannerOutput('trivy', JSON.stringify({ Results: [{ Target: 'package-lock.json', Vulnerabilities: [{
    VulnerabilityID: 'CVE-2021-23337', PkgName: 'lodash', InstalledVersion: '4.17.11',
    Title: 'lodash command injection', Severity: 'HIGH',
  }] }] }), { projectPath: '/tmp/synthetic-dependency' })[0];
  assert.equal(raw.category, 'DEPENDENCY_VULNERABILITY');
  const current = reconcileFindings([], [raw], { projectId: 'synthetic-dependency', projectPath: '/tmp/synthetic-dependency', runId: 'synthetic-run' }).findings[0];
  for (const finding of [current, { ...current, category: 'INJECTION' }]) {
    const plan = { ...verificationPlan(finding), baselineScopeFingerprint: 'unchanged-scope' };
    assert.deepEqual(plan.relevantScanners.sort(), ['osv-scanner', 'trivy']);
    const coverage = verificationCoverage(plan, {
      trivy: { status: 'PASS', decision: 'RUN', parseValid: true, version: '0.73.0' },
      semgrep: { status: 'PASS', decision: 'RUN', parseValid: true, version: '1.172.0' },
    }, { currentScopeFingerprint: 'unchanged-scope' });
    assert.equal(coverage.complete, false);
    assert.equal(verificationOutcome({ finding, updatedFinding: { ...finding, status: 'VERIFIED' }, coverage }).verification, 'VERIFICATION_INCOMPLETE');
  }
});

test('dependency category correction preserves historical runtime finding identity', () => {
  const { adaptScannerOutput } = require('../core/findings');
  const context = { projectId: 'runtime-history', projectPath: '/tmp/runtime-history', runId: 'old-run' };
  const raw = adaptScannerOutput('nuclei', JSON.stringify({ 'template-id': 'synthetic-sql-injection', info: { name: 'SQL injection', severity: 'high' }, 'matched-at': 'http://127.0.0.1:3000/example' }), context)[0];
  const legacyRaw = createFinding({ ...raw, category: 'INJECTION', id: undefined, fingerprint: undefined }, context);
  assert.equal(raw.category, legacyRaw.category);
  assert.equal(raw.fingerprint, legacyRaw.fingerprint);
  const legacy = reconcileFindings([], [legacyRaw], context).findings[0];
  legacy.status = 'FIXED';
  const tools = { nuclei: { status: 'PASS', decision: 'RUN', parseValid: true, version: '3.11.1' } };
  const next = reconcileFindings([legacy], [raw], { ...context, tools, verificationScopeValid: true }).findings;
  assert.equal(next.length, 1);
  assert.equal(next[0].id, legacy.id);
  assert.equal(next[0].status, 'OPEN');
  assert.equal(verificationOutcome({ finding: legacy, updatedFinding: next[0], coverage: { complete: true, results: [] } }).verification, 'STILL_DETECTED');
});

test('legacy dependency categories preserve finding identity and never verify a still-detected advisory', () => {
  const { adaptScannerOutput } = require('../core/findings');
  const { compareEvidence } = require('../core/correlation/correlation-key');
  const context = { projectId: 'legacy-dependency', projectPath: '/tmp/synthetic-dependency', runId: 'old-run' };
  const raw = adaptScannerOutput('trivy', JSON.stringify({ Results: [{ Target: 'package-lock.json', Vulnerabilities: [{
    VulnerabilityID: 'CVE-2021-23337', PkgName: 'lodash', InstalledVersion: '4.17.11', Title: 'lodash command injection', Severity: 'HIGH',
  }] }] }), context)[0];
  const oldRaw = createFinding({ ...raw, category: 'INJECTION', id: undefined, fingerprint: undefined }, context);
  assert.notEqual(oldRaw.fingerprint, raw.fingerprint);
  const legacy = reconcileFindings([], [oldRaw], context).findings[0];
  legacy.scopeFingerprint = 'unchanged';
  const tools = Object.fromEntries(['trivy', 'osv-scanner'].map(scanner => [scanner, { status: 'PASS', decision: 'RUN', parseValid: true, version: '1.0.0' }]));
  for (const status of ['FIXED', 'VERIFIED']) {
    const finding = { ...legacy, status };
    const coverage = verificationCoverage(verificationPlan(finding), tools, { currentScopeFingerprint: 'unchanged' });
    const reconciled = reconcileFindings([finding], [raw], { ...context, runId: 'new-run', tools, verificationScopeValid: coverage.complete });
    assert.equal(reconciled.findings.length, 1);
    assert.equal(reconciled.findings[0].id, legacy.id);
    assert.equal(reconciled.findings[0].status, status === 'VERIFIED' ? 'REOPENED' : 'OPEN');
    assert.equal(verificationOutcome({ finding, updatedFinding: reconciled.findings[0], coverage }).verification, 'STILL_DETECTED');
  }
  for (const changed of [
    { packageName: 'another-package' }, { installedVersion: '0.0.1' }, { file: 'other/package-lock.json' }, { ecosystem: 'pypi' },
  ]) {
    const current = reconcileFindings([], [raw], context).findings[0].observations[0];
    assert.equal(compareEvidence({ ...current, identity: { ...current.identity, ...changed } }, legacy.observations[0]), 'NONE');
  }
  const clean = reconcileFindings([{ ...legacy, status: 'FIXED' }], [], { ...context, tools, verificationScopeValid: true });
  assert.equal(clean.findings[0].status, 'VERIFIED');
});

test('legacy OSV advisory IDs retain dependency coverage and still-detected identity', () => {
  const { adaptScannerOutput } = require('../core/findings');
  const context = { projectId: 'legacy-osv', projectPath: '/tmp/legacy-osv', runId: 'old-run' };
  const raw = adaptScannerOutput('osv-scanner', JSON.stringify({ results: [{ source: { path: 'requirements.txt' }, packages: [{ package: { name: 'synthetic-package', version: '1.0.0' }, vulnerabilities: [{ id: 'PYSEC-2026-123', summary: 'command injection' }] }] }] }), context)[0];
  const oldRaw = createFinding({ ...raw, category: 'INJECTION', id: undefined, fingerprint: undefined }, context);
  const legacy = reconcileFindings([], [oldRaw], context).findings[0];
  legacy.status = 'FIXED';
  assert.deepEqual(verificationPlan(legacy).relevantScanners.sort(), ['osv-scanner', 'trivy']);
  const next = reconcileFindings([legacy], [raw], { ...context, verificationScopeValid: true }).findings;
  assert.equal(next.length, 1);
  assert.equal(next[0].id, legacy.id);
  assert.equal(next[0].status, 'OPEN');
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
  for (const invalid of ['null', '{}', '[]', '{"results":[{}]}', '{"results":[null]}']) {
    fs.writeFileSync(path.join(data, 'projects', identity.id, 'findings-index.json'), JSON.stringify({ schemaVersion: '1.0', projectId: identity.id, findings: [initial] }));
    fs.writeFileSync(fakeSemgrep, '#!/bin/sh\nif [ "$1" = "--version" ]; then printf \'1.2.3\\n\'; else printf \'%s\\n\' \'' + invalid + '\'; fi\n');
    const rejected = JSON.parse(execFileSync(process.execPath, ['-e', script], { cwd: ROOT, encoding: 'utf8', env: { ...process.env, SECURITY_TOOLKIT_HOME: toolkit, SECURITY_DASHBOARD_DATA_DIR: data, SECURITY_TOOL_BINARIES: JSON.stringify({ semgrep: fakeSemgrep }) } }));
    assert.equal(rejected.verification, 'VERIFICATION_INCOMPLETE');
    assert.notEqual(rejected.lifecycle, 'VERIFIED');
  }
  fs.rmSync(root, { recursive: true, force: true });
});
