const test = require('node:test');
const assert = require('node:assert/strict');
const {
  correlateFindings,
  createFinding,
  explicitLifecycleAction,
  isVerificationEligible,
  normalizePersistedFindings,
  reconcileFindings,
} = require('../core/findings');
const correlation = require('../core/correlation');

const projectPath = '/tmp/vcg-v03-synthetic-project';
const baseContext = { projectId: 'project-synthetic', projectPath, startedAt: '2026-08-10T00:00:00.000Z', observedAt: '2026-08-10T00:01:00.000Z' };

function context(runId, extra = {}) {
  return { ...baseContext, ...extra, runId, startedAt: `${runId.slice(0, 4)}-08-10T00:00:00.000Z`, observedAt: `${runId.slice(0, 4)}-08-10T00:01:00.000Z` };
}

function finding(scanner, input = {}, runId = '2026-08-10-000001') {
  return createFinding({
    scanner: { id: scanner, name: scanner, ruleId: input.ruleId || 'synthetic-rule' },
    severity: input.severity || 'HIGH',
    category: input.category || 'INJECTION',
    title: input.title || 'Synthetic issue',
    location: input.location || { type: 'file', file: 'src/app.js', line: 10 },
    explanation: { technical: 'Synthetic technical evidence.', simple: 'Synthetic simple explanation.', whyItMatters: 'Synthetic impact explanation.' },
    evidence: 'Safe synthetic fixture metadata only.',
    source: { runId },
    ...input,
  }, context(runId));
}

function runTools(status = 'PASS', scanner = 'gitleaks') {
  return { [scanner]: { status, decision: 'RUN' } };
}

test('same scanner fingerprint across runs keeps one correlated finding and two observations', () => {
  const first = finding('gitleaks', { category: 'SECRET_EXPOSURE', ruleId: 'stripe-api-key', title: 'Stripe credential', location: { type: 'file', file: 'src/config.ts', line: 14 } }, '2026-08-10-000001');
  const initial = reconcileFindings([], [first], context('2026-08-10-000001'));
  const second = finding('gitleaks', { category: 'SECRET_EXPOSURE', ruleId: 'stripe-api-key', title: 'Stripe credential', location: { type: 'file', file: 'src/config.ts', line: 14 } }, '2026-08-11-000002');
  const next = reconcileFindings(initial.findings, [second], context('2026-08-11-000002', { tools: runTools() }));
  assert.equal(next.findings.length, 1);
  assert.equal(next.findings[0].observations.length, 2);
  assert.equal(next.findings[0].id, initial.findings[0].id);
}
);

test('Gitleaks and TruffleHog correlate the same secret location without raw values', () => {
  const findings = [
    finding('gitleaks', { category: 'SECRET_EXPOSURE', ruleId: 'stripe-api-key', title: 'Stripe credential', location: { type: 'file', file: 'src/config.ts', line: 14 } }),
    finding('trufflehog', { category: 'SECRET_EXPOSURE', ruleId: 'Stripe', title: 'Stripe credential detected', location: { type: 'file', file: 'src/config.ts', line: 14 } }),
  ];
  const result = correlateFindings(findings, context('2026-08-10-000001'));
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].confidence, 'HIGH');
  assert.deepEqual(result.findings[0].observations.map((item) => item.scanner).sort(), ['gitleaks', 'trufflehog']);
  assert.equal(JSON.stringify(result.findings).includes('syntheticApiKey'), false);
}
);

test('Trivy and OSV correlate the same vulnerability and package', () => {
  const findings = [
    finding('trivy', { category: 'DEPENDENCY_VULNERABILITY', ruleId: 'CVE-2026-0001', title: 'CVE-2026-0001: lodash vulnerability', location: { type: 'file', file: 'package-lock.json' }, explanation: { technical: 'lodash 4.0.0 is associated with CVE-2026-0001.', simple: 'Synthetic dependency issue.', whyItMatters: 'Synthetic impact.' } }),
    finding('osv-scanner', { category: 'DEPENDENCY_VULNERABILITY', ruleId: 'CVE-2026-0001', title: 'CVE-2026-0001: lodash vulnerability', location: { type: 'file', file: 'package-lock.json' }, explanation: { technical: 'lodash 4.0.0 matched CVE-2026-0001.', simple: 'Synthetic dependency issue.', whyItMatters: 'Synthetic impact.' } }),
  ];
  const result = correlateFindings(findings, context('2026-08-10-000001'));
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].confidence, 'HIGH');
}
);

test('same Semgrep rule at different lines stays separate', () => {
  const findings = [
    finding('semgrep', { category: 'INJECTION', ruleId: 'synthetic.sql-injection', title: 'SQL injection', location: { type: 'file', file: 'src/query.js', line: 50 } }),
    finding('semgrep', { category: 'INJECTION', ruleId: 'synthetic.sql-injection', title: 'SQL injection', location: { type: 'file', file: 'src/query.js', line: 80 } }),
  ];
  const result = correlateFindings(findings, context('2026-08-10-000001'));
  assert.equal(result.findings.length, 2);
}
);

test('compatible ZAP and Nuclei runtime observations correlate by endpoint and rule family', () => {
  const findings = [
    finding('zap', { category: 'RUNTIME', ruleId: '10010', title: 'Cross-site scripting', location: { type: 'endpoint', endpoint: 'http://127.0.0.1:4567/api/user' } }),
    finding('nuclei', { category: 'RUNTIME', ruleId: 'xss-reflected', title: 'XSS reflected', location: { type: 'endpoint', endpoint: 'http://127.0.0.1:4567/api/user/' } }),
  ];
  const result = correlateFindings(findings, context('2026-08-10-000001'));
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].confidence, 'HIGH');
}
);

test('unrelated and MEDIUM-confidence findings never auto-merge', () => {
  const findings = [
    finding('semgrep', { category: 'INJECTION', ruleId: 'sql-injection', title: 'SQL injection', location: { type: 'file', file: 'src/query.js', line: 10 } }),
    finding('checkov', { category: 'INJECTION', ruleId: 'unsafe-shell', title: 'Command injection', location: { type: 'file', file: 'src/query.js', line: 10 } }),
  ];
  const result = correlateFindings(findings, context('2026-08-10-000001'));
  assert.equal(result.findings.length, 2);
  assert.equal(result.suggestions.length, 1);
  assert.equal(result.suggestions[0].confidence, 'MEDIUM');
}
);

test('scanner skipped or failed prevents verification', () => {
  const original = finding('gitleaks', { category: 'SECRET_EXPOSURE', ruleId: 'stripe-api-key', title: 'Stripe credential', location: { type: 'file', file: 'src/config.ts', line: 14 } });
  const initial = reconcileFindings([], [original], context('2026-08-10-000001'));
  explicitLifecycleAction(initial.findings[0], 'FIXED', { runId: '2026-08-10-000001', reason: 'Synthetic fix attempted.' });
  const skipped = reconcileFindings(initial.findings, [], context('2026-08-11-000002', { tools: runTools('SKIPPED') }));
  assert.equal(skipped.findings[0].status, 'FIXED');
  assert.ok(skipped.findings[0].history.some((event) => event.event === 'VERIFICATION_DEFERRED'));
  const failed = reconcileFindings(initial.findings, [], context('2026-08-12-000003', { tools: runTools('FAIL') }));
  assert.equal(failed.findings[0].status, 'FIXED');
  assert.equal(isVerificationEligible(initial.findings[0], { tools: runTools('SKIPPED') }), false);
}
);

test('OPEN → FIXED → VERIFIED and VERIFIED → REOPENED are deterministic', () => {
  const original = finding('gitleaks', { category: 'SECRET_EXPOSURE', ruleId: 'stripe-api-key', title: 'Stripe credential', location: { type: 'file', file: 'src/config.ts', line: 14 } });
  const initial = reconcileFindings([], [original], context('2026-08-10-000001'));
  explicitLifecycleAction(initial.findings[0], 'FIXED', { runId: '2026-08-10-000001', reason: 'Synthetic fix attempted.' });
  const verified = reconcileFindings(initial.findings, [], context('2026-08-11-000002', { tools: runTools('PASS') }));
  assert.equal(verified.findings[0].status, 'VERIFIED');
  const returned = finding('gitleaks', { category: 'SECRET_EXPOSURE', ruleId: 'stripe-api-key', title: 'Stripe credential', location: { type: 'file', file: 'src/config.ts', line: 14 } }, '2026-08-12-000003');
  const reopened = reconcileFindings(verified.findings, [returned], context('2026-08-12-000003', { tools: runTools('PASS') }));
  assert.equal(reopened.findings[0].status, 'REOPENED');
  assert.ok(reopened.findings[0].history.some((event) => event.event === 'VERIFIED'));
  assert.ok(reopened.findings[0].history.some((event) => event.event === 'REOPENED'));
}
);

test('FALSE_POSITIVE and ACCEPTED_RISK require reasons and persist explicitly', () => {
  const original = finding('semgrep', { category: 'INJECTION', ruleId: 'synthetic.sql-injection', title: 'SQL injection' });
  const initial = reconcileFindings([], [original], context('2026-08-10-000001'));
  assert.throws(() => explicitLifecycleAction(initial.findings[0], 'FALSE_POSITIVE', { runId: '2026-08-10-000001' }), /requires a reason/);
  explicitLifecycleAction(initial.findings[0], 'FALSE_POSITIVE', { runId: '2026-08-10-000001', reason: 'Synthetic fixture is intentionally insecure.' });
  assert.equal(initial.findings[0].status, 'FALSE_POSITIVE');
  explicitLifecycleAction(initial.findings[0], 'ACCEPTED_RISK', { runId: '2026-08-10-000002', reason: 'Synthetic acceptance test.' });
  assert.equal(initial.findings[0].status, 'ACCEPTED_RISK');
  assert.ok(initial.findings[0].history.some((event) => event.event === 'RISK_ACCEPTED'));
}
);

test('release-gate counts correlated issues, not scanner observations', () => {
  const gitleaksFinding = finding('gitleaks', { category: 'SECRET_EXPOSURE', ruleId: 'stripe-api-key', title: 'Stripe credential' });
  const secondObservation = finding('trufflehog', { category: 'SECRET_EXPOSURE', ruleId: 'Stripe', title: 'Stripe credential detected' });
  const result = correlateFindings([gitleaksFinding, secondObservation], context('2026-08-10-000001'));
  const blocking = correlation.countBlockingCorrelatedFindings(result.findings);
  assert.deepEqual(blocking, { critical: 0, high: 1, total: 1 });
  result.findings[0].status = 'VERIFIED';
  assert.deepEqual(correlation.countBlockingCorrelatedFindings(result.findings), { critical: 0, high: 0, total: 0 });
}
);

test('legacy v0.2 findings derive a safe correlation view without changing the source shape', () => {
  const legacy = [{ id: 'GITLEAKS-legacy', scanner: 'gitleaks', severity: 'HIGH', category: 'Secret exposure', title: 'Legacy synthetic finding', file: 'fixtures/secret.txt', status: 'OPEN' }];
  const normalized = normalizePersistedFindings(legacy, { ...baseContext, runId: '2026-08-10-000001' });
  const result = correlateFindings(normalized, context('2026-08-10-000001'));
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].status, 'OPEN');
  assert.equal(legacy[0].scanner, 'gitleaks');
  assert.equal(legacy[0].schemaVersion, undefined);
}
);
