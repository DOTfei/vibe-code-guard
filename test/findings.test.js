const test = require('node:test');
const assert = require('node:assert/strict');
const {
  ADAPTERS,
  CATEGORIES,
  SEVERITIES,
  adaptScannerOutput,
  buildFingerprint,
  createFinding,
  countFindings,
  normalizePersistedFindings,
  normalizeSeverity,
  validateFinding,
} = require('../core/findings');

const context = {
  runId: '20260810000000-abcdef',
  startedAt: '2026-08-10T00:00:00.000Z',
  observedAt: '2026-08-10T00:01:00.000Z',
  projectPath: '/tmp/synthetic-project',
};
const syntheticApiKey = ['sk', 'proj', '1234567890abcdef1234567890'].join('-');

function assertUnified(findings, scannerId, expectedLength = 1) {
  assert.equal(findings.length, expectedLength);
  for (const finding of findings) {
    assert.equal(finding.schemaVersion, '1.0');
    assert.equal(finding.scanner.id, scannerId);
    assert.deepEqual(validateFinding(finding), { valid: true, errors: [] });
    assert.equal(finding.evidence.redacted, true);
    assert.ok(finding.fingerprint);
  }
}

test('creates a stable v1 Unified Finding with the required nested fields', () => {
  const finding = createFinding({
    scanner: { id: 'semgrep', name: 'Semgrep', ruleId: 'javascript.lang.security.audit.test' },
    severity: 'high',
    confidence: 'high',
    category: 'INJECTION',
    title: 'Unsafe synthetic input flow',
    location: { type: 'file', file: 'src/handler.js', line: 12, column: 4 },
    explanation: { technical: 'Synthetic rule evidence.', simple: 'Input is not checked.', whyItMatters: 'The boundary may be crossed.' },
    evidence: 'safe synthetic fixture only',
    remediation: 'Validate input at the boundary.',
  }, context);
  assert.deepEqual(Object.keys(finding), [
    'schemaVersion', 'id', 'fingerprint', 'scanner', 'severity', 'confidence', 'category', 'title',
    'location', 'explanation', 'evidence', 'remediation', 'status', 'firstSeen', 'lastSeen', 'source',
  ]);
  assert.equal(finding.status, 'OPEN');
  assert.equal(finding.location.file, 'src/handler.js');
  assert.equal(finding.source.runId, context.runId);
  assert.deepEqual(validateFinding(finding), { valid: true, errors: [] });
});

test('normalizes severity conservatively and counts all supported severities', () => {
  assert.deepEqual(SEVERITIES, ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNKNOWN']);
  assert.equal(normalizeSeverity('blocker'), 'CRITICAL');
  assert.equal(normalizeSeverity('error'), 'HIGH');
  assert.equal(normalizeSeverity('warning'), 'MEDIUM');
  assert.equal(normalizeSeverity('informational'), 'INFO');
  assert.equal(normalizeSeverity('not supplied'), 'UNKNOWN');
  const findings = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNKNOWN'].map((severity) => createFinding({ severity, title: severity }, context));
  assert.deepEqual(countFindings(findings), { critical: 1, high: 1, medium: 1, low: 1, info: 1, unknown: 1, total: 6 });
});

test('fingerprints do not change with run identifiers or timestamps', () => {
  const stableInput = { ruleId: 'fixture.rule', category: 'INJECTION', title: 'Synthetic issue', location: { file: 'src/app.js', line: 7 } };
  const first = buildFingerprint({ ...stableInput, projectPath: '/tmp/synthetic-project' });
  const second = buildFingerprint({ ...stableInput, projectPath: '/tmp/synthetic-project' });
  const changed = buildFingerprint({ ...stableInput, location: { file: 'src/app.js', line: 8 }, projectPath: '/tmp/synthetic-project' });
  assert.equal(first, second);
  assert.notEqual(first, changed);
});

test('redacts credential-shaped synthetic evidence before persistence', () => {
  const finding = createFinding({
    scanner: 'gitleaks',
    title: 'Synthetic credential pattern',
    evidence: `match=${syntheticApiKey}`,
  }, context);
  const serialized = JSON.stringify(finding);
  assert.equal(finding.evidence.redacted, true);
  assert.equal(serialized.includes(syntheticApiKey), false);
  assert.match(finding.evidence.summary, /REDACTED/);
});

test('redacts JSON-shaped raw and match fields in scanner output', () => {
  const serialized = JSON.stringify({ Raw: syntheticApiKey, Match: syntheticApiKey, value: syntheticApiKey });
  const redacted = require('../core/findings').redact(serialized);
  assert.equal(redacted.includes(syntheticApiKey), false);
});

test('adapts every supported scanner output into Unified Findings', () => {
  const fixtures = {
    gitleaks: JSON.stringify([{ RuleID: 'generic-api-key', Description: 'Synthetic credential', File: 'fixtures/secret.txt', StartLine: 2, StartColumn: 1, Secret: syntheticApiKey }]),
    trufflehog: JSON.stringify({ DetectorName: 'SyntheticDetector', Verified: false, SourceMetadata: { Data: { Filesystem: { file: 'fixtures/secret.txt', line: 2 } } }, Raw: syntheticApiKey }),
    semgrep: JSON.stringify({ results: [{ check_id: 'fixture.sql-injection', path: 'src/query.js', start: { line: 9, col: 3 }, extra: { message: 'Synthetic SQL injection pattern', severity: 'ERROR', metadata: { category: 'INJECTION', fix: 'Use a parameterized query.' } } }] }),
    trivy: JSON.stringify({ Results: [{ Target: 'package-lock.json', Vulnerabilities: [{ VulnerabilityID: 'CVE-2020-SYNTHETIC', PkgName: 'fixture-package', InstalledVersion: '1.0.0', FixedVersion: '1.0.1', Severity: 'HIGH', Title: 'Synthetic dependency issue' }], Misconfigurations: [{ ID: 'DS-SYNTHETIC', Title: 'Synthetic misconfiguration', Severity: 'LOW', Resolution: 'Use a safe fixture setting.' }], Secrets: [{ RuleID: 'synthetic-secret', Title: 'Synthetic secret', StartLine: 3, Severity: 'HIGH', Match: syntheticApiKey }] }] }),
    'osv-scanner': JSON.stringify({ results: [{ source: { path: 'package-lock.json' }, packages: [{ package: { name: 'fixture-package', version: '1.0.0' }, vulnerabilities: [{ id: 'OSV-SYNTHETIC', summary: 'Synthetic dependency issue', database_specific: { severity: 'MEDIUM' } }] }] }] }),
    checkov: JSON.stringify({ results: { failed_checks: [{ check_id: 'CKV_SYNTHETIC_1', check_name: 'Synthetic IaC issue', check_type: 'terraform', file_path: 'main.tf', file_line_range: [4], guideline: 'Set the safe synthetic option.' }] } }),
    zap: JSON.stringify({ site: [{ '@name': 'http://127.0.0.1:4567', alerts: [{ pluginid: '100-SYNTHETIC', alert: 'Synthetic runtime alert', riskcode: '2', confidence: '2', instances: [{ uri: 'http://127.0.0.1:4567/synthetic' }], desc: '<p>Safe local fixture alert.</p>', solution: '<p>Apply the fixture remediation.</p>' }] }] }),
    nuclei: JSON.stringify({ 'template-id': 'synthetic-template', info: { name: 'Synthetic runtime check', severity: 'low', description: 'Safe local fixture result.' }, 'matched-at': 'http://127.0.0.1:4567/synthetic' }),
  };
  for (const [tool, fixture] of Object.entries(fixtures)) {
    const findings = adaptScannerOutput(tool, fixture, context);
    assertUnified(findings, tool === 'osv-scanner' ? 'osv-scanner' : tool, tool === 'trivy' ? 3 : 1);
  }
  assert.deepEqual(Object.keys(ADAPTERS).sort(), ['checkov', 'gitleaks', 'nuclei', 'osv-scanner', 'semgrep', 'trivy', 'trufflehog', 'zap']);
  assert.equal(CATEGORIES.includes('SECRET_EXPOSURE'), true);
});

test('malformed, empty, and unknown scanner output are safe', () => {
  for (const tool of Object.keys(ADAPTERS)) {
    assert.deepEqual(adaptScannerOutput(tool, '', context), []);
    assert.deepEqual(adaptScannerOutput(tool, '{not-json', context), []);
  }
  assert.deepEqual(adaptScannerOutput('not-a-scanner', '{}', context), []);
  const finding = createFinding({ severity: 'future severity', category: 'future category' }, context);
  assert.equal(finding.severity, 'UNKNOWN');
  assert.equal(finding.category, 'UNKNOWN');
});

test('normalizes legacy flat findings into the v1 nested shape', () => {
  const legacy = [{
    id: 'GITLEAKS-legacy',
    scanner: 'gitleaks',
    severity: 'HIGH',
    category: 'Secret exposure',
    title: 'Legacy synthetic finding',
    file: 'fixtures/secret.txt',
    technical: 'Legacy technical text',
    simple: 'Legacy simple text',
    why: 'Legacy reason',
    status: 'OPEN',
    firstSeen: '20260809000000-abcdef',
    lastSeen: '20260809000000-abcdef',
  }];
  const findings = normalizePersistedFindings(legacy, context);
  assertUnified(findings, 'gitleaks');
  assert.equal(findings[0].id, 'GITLEAKS-legacy');
  assert.equal(findings[0].location.file, 'fixtures/secret.txt');
  assert.equal(findings[0].explanation.whyItMatters, 'Legacy reason');
  assert.equal(findings[0].firstSeen, context.startedAt);
});
