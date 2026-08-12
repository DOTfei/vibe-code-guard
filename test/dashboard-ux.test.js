'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const viewModel = require('../public/view-model');

const run = {
  status: 'FAIL',
  releaseGate: { label: 'DO NOT DEPLOY', reason: '1 unresolved correlated Critical/High finding.' },
  tools: {
    semgrep: { decision: 'RUN', status: 'PASS' },
    trivy: { decision: 'SKIP', status: 'SKIPPED' },
  },
};

function finding(id, severity, status, title) {
  return {
    id,
    severity,
    status,
    title,
    location: { file: `src/${id}.js` },
    evidence: { summary: 'REDACTED synthetic evidence', redacted: true },
    remediation: { summary: 'Validate the authorization boundary.' },
  };
}

test('friendly lifecycle makes FIXED and VERIFIED visibly different', () => {
  assert.equal(viewModel.friendlyLifecycle('FIXED').label, 'Fix applied · not verified');
  assert.equal(viewModel.friendlyLifecycle('FIXED').tone, 'warning');
  assert.equal(viewModel.friendlyLifecycle('VERIFIED').label, 'Verified fixed');
  assert.equal(viewModel.friendlyLifecycle('VERIFIED').tone, 'pass');
});

test('release decision presents the canonical gate without replacing it', () => {
  const decision = viewModel.releaseDecision(run);
  assert.equal(decision.label, 'DO NOT DEPLOY');
  assert.equal(decision.canonicalLabel, 'DO NOT DEPLOY');
  assert.match(decision.reason, /unresolved/);
  assert.equal(viewModel.releaseDecision({ status: 'PASS', releaseGate: { label: 'READY TO DEPLOY', reason: 'No known Critical/High findings.' } }).label, 'SAFE TO DEPLOY');
});

test('Dashboard and CLI presentation use the same canonical gate, lifecycle, verification, and tool status', () => {
  const canonical = {
    ...run,
    verification: { verification: 'VERIFICATION_INCOMPLETE', reason: 'Semgrep coverage was unavailable.' },
    tools: { semgrep: { decision: 'RUN', status: 'DEGRADED' } },
  };
  assert.equal(viewModel.releaseDecision(canonical).canonicalLabel, canonical.releaseGate.label);
  assert.equal(viewModel.friendlyLifecycle('FIXED').status, 'FIXED');
  assert.equal(viewModel.verificationSummary(canonical).label, 'Verification incomplete');
  assert.equal(viewModel.toolchainSummary({ doctor: { overall: 'DEGRADED', tools: { semgrep: { status: 'DEGRADED' } } } }).label, 'DEGRADED');
});

test('priority issues put unresolved release attention first', () => {
  const ordered = viewModel.priorityFindings([
    finding('low', 'LOW', 'OPEN', 'Low issue'),
    finding('fixed', 'CRITICAL', 'FIXED', 'Critical fixed but unverified'),
    finding('verified', 'HIGH', 'VERIFIED', 'Verified high issue'),
  ], run, 3);
  assert.deepEqual(ordered.map((item) => item.id), ['fixed', 'low', 'verified']);
  assert.equal(ordered[0].releaseBlocking, true);
  assert.equal(ordered[2].lifecycle.label, 'Verified fixed');
});

test('coverage and toolchain states remain visible as degraded instead of green', () => {
  const coverage = viewModel.coverageSummary(run);
  assert.equal(coverage.tone, 'warning');
  assert.match(coverage.detail, /skipped|degraded/i);
  const toolkit = viewModel.toolchainSummary({ doctor: { overall: 'DEGRADED', tools: { trivy: { status: 'DEGRADED' }, semgrep: { status: 'HEALTHY' } } } });
  assert.equal(toolkit.label, 'DEGRADED');
  assert.equal(toolkit.tone, 'warning');
});

test('agent prompt is actionable but excludes scanner evidence and secrets', () => {
  const prompt = viewModel.buildAgentPrompt(run, [finding('VCG-1', 'HIGH', 'OPEN', 'Missing authorization check')]);
  assert.match(prompt, /vibe-code-guard audit/);
  assert.match(prompt, /current release-blocking findings/i);
  assert.match(prompt, /authorize code changes/i);
  assert.match(prompt, /targeted verification/i);
  assert.match(prompt, /do not scrape Dashboard HTML/i);
  assert.match(prompt, /VCG-1/);
  assert.doesNotMatch(prompt, /REDACTED synthetic evidence/);
  assert.doesNotMatch(prompt, /sk_live_|AKIA[0-9A-Z]+/);
  const nonBlocking = viewModel.buildAgentPrompt({ status: 'PASS', releaseGate: { label: 'READY TO DEPLOY', reason: 'No known Critical/High findings.' } }, [finding('VCG-LOW', 'LOW', 'OPEN', 'Low issue')]);
  assert.doesNotMatch(nonBlocking, /current release-blocking findings/);
});

test('Dashboard source-of-truth and historical compatibility surfaces are documented', () => {
  const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf8');
  const app = fs.readFileSync(path.join(__dirname, '..', 'public', 'app.js'), 'utf8');
  assert.match(html, /view-model\.js/);
  assert.match(html, /SAFE TO DEPLOY|decision-label/);
  assert.match(app, /correlatedFindings/);
  assert.match(fs.readFileSync(path.join(__dirname, '..', 'public', 'view-model.js'), 'utf8'), /VERIFICATION_INCOMPLETE|Verification incomplete/);
});
