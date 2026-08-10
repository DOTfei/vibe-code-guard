const test = require('node:test');
const assert = require('node:assert/strict');
const {
  AI_REVIEW_SYSTEM_PROMPT,
  MockProvider,
  buildReviewContext,
  cachedReviewState,
  createProvider,
  generateFindingReview,
  generateSummaryReview,
  summaryContext,
  validateAIReview,
  validateAISummary,
} = require('../core/ai');
const { countBlockingCorrelatedFindings } = require('../core/correlation');
const { explicitLifecycleAction } = require('../core/correlation/lifecycle');

function fixtureFinding() {
  return {
    id: 'VCG-CORR-SYNTHETIC',
    title: 'Synthetic dependency vulnerability',
    severity: 'HIGH',
    category: 'DEPENDENCY_VULNERABILITY',
    confidence: 'HIGH',
    correlationKey: 'dependency|npm|lodash|CVE-2024-1234',
    status: 'OPEN',
    location: { file: 'package-lock.json', line: 12, endpoint: null },
    observations: [{
      scanner: 'trivy',
      scannerFindingId: 'TRIVY-SYNTHETIC',
      fingerprint: 'fingerprint-synthetic',
      ruleId: null,
      severity: 'HIGH',
      category: 'DEPENDENCY_VULNERABILITY',
      location: { file: 'package-lock.json', line: 12 },
      identity: { kind: 'dependency', vulnerabilityId: 'CVE-2024-1234', packageName: 'lodash', ecosystem: 'npm' },
    }],
    history: [],
  };
}

function fixtureContext(overrides = {}) {
  return buildReviewContext({
    finding: fixtureFinding(),
    rawFindings: [{ id: 'TRIVY-SYNTHETIC', scanner: { id: 'trivy' }, title: 'Synthetic dependency vulnerability', severity: 'HIGH', category: 'DEPENDENCY_VULNERABILITY', location: { file: 'package-lock.json', line: 12 }, evidence: { summary: 'CVE-2024-1234 is present in the synthetic fixture.' } }],
    stack: ['Node.js'],
    lifecycleStatus: 'OPEN',
    releaseGate: { label: 'DO NOT DEPLOY', reason: 'One unresolved correlated High finding.' },
    ...overrides,
  });
}

test('AI review schema and mock provider produce advisory output without deterministic fields', async () => {
  const context = fixtureContext();
  const result = await generateFindingReview(context, { provider: new MockProvider() });
  assert.equal(result.status, 'READY');
  assert.equal(result.review.schemaVersion, '1.0');
  assert.equal(result.review.findingId, context.finding.id);
  assert.equal(result.review.priority.suggested, 'P1');
  assert.equal(result.review.falsePositiveAssessment.requiresUserDecision, true);
  assert.equal('status' in result.review, false);
  assert.equal('severity' in result.review, false);
  assert.equal(context.finding.lifecycleStatus, 'OPEN');
});

test('provider abstraction is disabled by default and does not upload code', async () => {
  const context = fixtureContext();
  const result = await generateFindingReview(context, { provider: createProvider({ name: 'disabled' }) });
  assert.equal(result.status, 'NOT_GENERATED');
  assert.match(result.reason, /disabled/i);
  assert.equal(createProvider({ name: 'external' }).name, 'external');
  assert.equal(createProvider({ name: 'local' }).name, 'local');
});

test('invalid AI JSON becomes a review failure, not a finding', async () => {
  const provider = { name: 'fake', model: 'invalid-json', availability: async () => ({ available: true }), reviewFinding: async () => '{not json' };
  const result = await generateFindingReview(fixtureContext(), { provider });
  assert.equal(result.status, 'FAILED');
  assert.match(result.validationErrors[0], /Invalid AI JSON/);
});

test('hallucinated scanner, file, and CVE references are rejected', async () => {
  const provider = new MockProvider();
  provider.reviewFinding = async (context) => ({
    ...(await new MockProvider().reviewFinding(context)),
    summary: 'CVE-2099-99999 is reported by imaginary-scanner in src/does-not-exist.js.',
    evidenceReferences: [{ scanner: 'imaginary-scanner', files: ['src/does-not-exist.js'], vulnerabilityIds: ['CVE-2099-99999'] }],
  });
  const result = await generateFindingReview(fixtureContext(), { provider });
  assert.equal(result.status, 'FAILED');
  assert.ok(result.validationErrors.some((error) => /scanner|file|vulnerability ID/.test(error)));
});

test('redaction and context limits remove secrets before provider input', () => {
  const secret = ['ghp_', '1234567890abcdef1234567890'].join('');
  const context = fixtureContext({ allowCodeSnippet: true, codeFile: 'package-lock.json', codeSnippet: `const token = '${secret}';` });
  assert.equal(context.codeSnippet.includes(secret), false);
  assert.match(context.codeSnippet, /REDACTED/);
  assert.ok(context.metadata.redactionCount >= 1);
  assert.ok(context.metadata.estimatedInputSize < 10000);
  const poisoned = fixtureFinding();
  poisoned.title = `token=${secret}`;
  poisoned.observations[0].ruleId = `token=${secret}`;
  const poisonedContext = fixtureContext({ finding: poisoned });
  assert.equal(JSON.stringify(poisonedContext).includes(secret), false);
});

test('identical evidence is a cache hit and changed evidence becomes STALE', () => {
  const context = fixtureContext();
  const ready = { status: 'READY', findingId: context.finding.id, inputHash: context.inputHash, provider: { provider: 'mock', model: 'synthetic-v0.4' } };
  assert.equal(cachedReviewState(ready, context).cacheHit, true);
  const changed = fixtureContext({ stack: ['Node.js', 'Next.js'] });
  assert.equal(cachedReviewState(ready, changed).status, 'STALE');
});

test('scanner evidence, explicitly supplied snippets, and lifecycle changes invalidate the cache', () => {
  const context = fixtureContext();
  const ready = { status: 'READY', findingId: context.finding.id, inputHash: context.inputHash, provider: { provider: 'mock', model: 'synthetic-v0.4' } };
  const changedFinding = fixtureFinding();
  changedFinding.observations[0].fingerprint = 'changed-fingerprint';
  assert.equal(cachedReviewState(ready, fixtureContext({ finding: changedFinding })).status, 'STALE');
  assert.equal(cachedReviewState(ready, fixtureContext({ allowCodeSnippet: true, codeFile: 'package-lock.json', codeSnippet: 'const version = 2;' })).status, 'STALE');
  assert.equal(cachedReviewState(ready, fixtureContext({ lifecycleStatus: 'FIXED' })).status, 'STALE');
});

test('AI cannot automatically change lifecycle or release-gate state', async () => {
  const context = fixtureContext();
  const beforeGate = countBlockingCorrelatedFindings([context.finding]);
  const result = await generateFindingReview(context, { provider: new MockProvider() });
  assert.equal(result.status, 'READY');
  assert.equal(context.finding.lifecycleStatus, 'OPEN');
  assert.deepEqual(countBlockingCorrelatedFindings([context.finding]), beforeGate);
  explicitLifecycleAction(context.finding, 'ACCEPTED_RISK', { reason: 'User reviewed the synthetic fixture.' });
  assert.equal(context.finding.status, 'ACCEPTED_RISK');
});

test('false-positive suggestions require a user decision', () => {
  const context = fixtureContext();
  const output = {
    schemaVersion: '1.0', findingId: context.finding.id, generatedAt: new Date().toISOString(), model: { provider: 'fake', model: 'fake' },
    summary: 'Possible false positive.', plainLanguageExplanation: 'Advisory only.', whyItMatters: 'Review evidence.',
    impact: { scope: 'local', likelyAffectedAreas: [], confidence: 'LOW' }, priority: { suggested: 'P3', reason: 'Low confidence.' },
    remediation: { recommendedApproach: 'Review.', steps: ['Review evidence.'], verificationAdvice: 'Run the scanner again.' },
    falsePositiveAssessment: { likelihood: 'HIGH', reason: 'Context is incomplete.', requiresUserDecision: false }, uncertainties: [], questions: [],
  };
  const result = validateAIReview(output, context);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((error) => /user-controlled/.test(error)));
});

test('run summary and release review use the same safe provider boundary', async () => {
  const finding = fixtureFinding();
  const context = summaryContext({ mode: 'RUN_SUMMARY', findings: [finding], releaseGate: { label: 'DO NOT DEPLOY' }, stack: ['Node.js'], runId: 'run-synthetic', summary: { high: 1 } });
  const result = await generateSummaryReview(context, { provider: new MockProvider() });
  assert.equal(result.status, 'READY');
  assert.equal(result.summary.mode, 'RUN_SUMMARY');
  assert.equal(result.summary.blockers[0].findingId, finding.id);
  const bad = validateAISummary({ ...result.summary, blockers: [{ findingId: 'UNKNOWN' }] }, context);
  assert.equal(bad.valid, false);
});

test('prompt explicitly keeps AI defensive and advisory', () => {
  assert.match(AI_REVIEW_SYSTEM_PROMPT, /scanner evidence.*authoritative/i);
  assert.match(AI_REVIEW_SYSTEM_PROMPT, /Do not generate exploit payloads/i);
  assert.match(AI_REVIEW_SYSTEM_PROMPT, /100% security/i);
});

test('code snippets require an explicitly reported file and provider output limits are bounded', async () => {
  assert.throws(() => fixtureContext({ allowCodeSnippet: true, codeFile: '../outside.js', codeSnippet: 'safe snippet' }), /explicitly tied/);
  const provider = { name: 'fake', model: 'large', availability: async () => ({ available: true }), reviewFinding: async () => 'x'.repeat(128 * 1024 + 1) };
  const result = await generateFindingReview(fixtureContext(), { provider });
  assert.equal(result.status, 'FAILED');
  assert.match(result.validationErrors[0], /bounded response size/);
});

test('dangerous prototype keys and provider timeouts fail closed', async () => {
  const context = fixtureContext();
  const output = JSON.parse(JSON.stringify(await new MockProvider().reviewFinding(context)));
  output.__proto__ = { polluted: true };
  const polluted = validateAIReview(JSON.parse(`{"__proto__":{"polluted":true},"schemaVersion":"1.0"}`), context);
  assert.equal(polluted.valid, false);
  const provider = { name: 'fake', model: 'timeout', availability: () => new Promise(() => {}) };
  const result = await generateFindingReview(context, { provider, timeoutMs: 5 });
  assert.equal(result.status, 'FAILED');
  assert.match(result.reason, /timed out/);
  assert.equal({}.polluted, undefined);
  assert.equal(output.findingId, context.finding.id);
});
