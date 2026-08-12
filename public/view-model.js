(function attachDashboardViewModel(root, factory) {
  const viewModel = factory();
  if (typeof module === 'object' && module.exports) module.exports = viewModel;
  else root.VCGDashboardViewModel = viewModel;
}(typeof globalThis !== 'undefined' ? globalThis : this, function createDashboardViewModel() {
  'use strict';

  const SEVERITY_WEIGHT = Object.freeze({ CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1, UNKNOWN: 0 });
  const LIFECYCLE_COPY = Object.freeze({
    OPEN: { label: 'Needs fixing', tone: 'fail', detail: 'The issue is still open.' },
    FIXING: { label: 'Fix in progress', tone: 'warning', detail: 'A fix is being worked on; verification is still required.' },
    FIXED: { label: 'Fix applied · not verified', tone: 'warning', detail: 'Code was marked fixed, but the relevant scanners have not verified it yet.' },
    VERIFIED: { label: 'Verified fixed', tone: 'pass', detail: 'Relevant scanner coverage completed successfully after the fix.' },
    STILL_DETECTED: { label: 'Still detected', tone: 'fail', detail: 'The relevant scanner still reported the issue.' },
    VERIFICATION_INCOMPLETE: { label: 'Verification incomplete', tone: 'warning', detail: 'The fix could not be fully verified with the required coverage.' },
    REOPENED: { label: 'Reopened', tone: 'fail', detail: 'The issue returned during a later scan.' },
    FALSE_POSITIVE: { label: 'Marked false positive', tone: 'warning', detail: 'A user marked this finding as a false positive.' },
    ACCEPTED_RISK: { label: 'Accepted risk', tone: 'warning', detail: 'A user accepted this risk; it is not the same as a verified fix.' },
  });

  function canonicalStatus(value) {
    return String(value || '').toUpperCase();
  }

  function friendlyLifecycle(value) {
    const status = canonicalStatus(value);
    return { status, ...(LIFECYCLE_COPY[status] || { label: status || 'Status unavailable', tone: 'neutral', detail: 'Lifecycle state was not supplied.' }) };
  }

  function isResolvedStatus(value) {
    return ['VERIFIED', 'FALSE_POSITIVE', 'ACCEPTED_RISK'].includes(canonicalStatus(value));
  }

  function isUnresolvedStatus(value) {
    return !isResolvedStatus(value);
  }

  function releaseDecision(run) {
    if (!run) return { label: 'NO AUDIT YET', tone: 'neutral', canonicalLabel: null, reason: 'Run a local audit to establish evidence.' };
    if (canonicalStatus(run.status) === 'SCANNING') return { label: 'AUDIT RUNNING', tone: 'running', canonicalLabel: run.releaseGate?.label || null, reason: 'The assessment is still collecting scanner evidence.' };
    const canonicalLabel = String(run.releaseGate?.label || '').toUpperCase();
    const reason = String(run.releaseGate?.reason || 'The release gate did not provide a reason.');
    const lowerReason = reason.toLowerCase();
    if (canonicalLabel === 'READY TO DEPLOY') {
      if (canonicalStatus(run.status) === 'PASS WITH WARNINGS' || lowerReason.includes('warning')) return { label: 'REVIEW REQUIRED', tone: 'warning', canonicalLabel, reason };
      return { label: 'SAFE TO DEPLOY', tone: 'pass', canonicalLabel, reason };
    }
    if (canonicalLabel === 'DO NOT DEPLOY') {
      const incomplete = canonicalStatus(run.verification?.verification || run.verification?.status) === 'VERIFICATION_INCOMPLETE'
        || (canonicalStatus(run.status) === 'PASS WITH WARNINGS' && /coverage|skipped|manual review|incomplete|degraded|not applicable/.test(lowerReason));
      return { label: incomplete ? 'INCOMPLETE SECURITY COVERAGE' : 'DO NOT DEPLOY', tone: incomplete ? 'warning' : 'fail', canonicalLabel, reason };
    }
    if (canonicalLabel === 'REVIEW REQUIRED' || canonicalLabel === 'INCOMPLETE SECURITY COVERAGE') return { label: canonicalLabel, tone: 'warning', canonicalLabel, reason };
    return { label: canonicalLabel || 'REVIEW REQUIRED', tone: 'warning', canonicalLabel: canonicalLabel || null, reason };
  }

  function releaseBlocking(finding, run) {
    const severity = canonicalStatus(finding?.severity);
    // Keep the card badge aligned with the canonical release-gate lifecycle
    // contract. Presentation may explain urgency, but it must not invent a
    // broader blocking rule than the persisted gate uses.
    return Boolean(run?.releaseGate?.label === 'DO NOT DEPLOY' && ['CRITICAL', 'HIGH'].includes(severity) && ['OPEN', 'FIXED', 'REOPENED'].includes(canonicalStatus(finding?.status)));
  }

  function priorityFindings(findings, run, limit = 3) {
    return (Array.isArray(findings) ? findings : [])
      .map((finding) => ({ ...finding, releaseBlocking: releaseBlocking(finding, run), lifecycle: friendlyLifecycle(finding.status) }))
      .sort((left, right) => Number(right.releaseBlocking) - Number(left.releaseBlocking)
        || Number(isUnresolvedStatus(right.status)) - Number(isUnresolvedStatus(left.status))
        || (SEVERITY_WEIGHT[canonicalStatus(right.severity)] || 0) - (SEVERITY_WEIGHT[canonicalStatus(left.severity)] || 0)
        || String(left.title || left.id).localeCompare(String(right.title || right.id)))
      .slice(0, limit);
  }

  function verificationSummary(run) {
    const verification = run?.verification;
    if (!run) return { label: 'Not started', tone: 'neutral', detail: 'A finding can only become verified after a relevant rescan.' };
    if (run.status === 'SCANNING') return { label: 'Collecting evidence', tone: 'running', detail: 'Verification and release readiness are not decided yet.' };
    if (!verification) return { label: 'No targeted verification', tone: 'neutral', detail: 'No fix verification was requested for this run.' };
    const state = canonicalStatus(verification.verification || verification.status);
    if (state === 'PASSED') return { label: 'Verified', tone: 'pass', detail: verification.reason || 'Relevant scanner coverage passed.' };
    if (state === 'STILL_DETECTED') return { label: 'Still detected', tone: 'fail', detail: verification.reason || 'The issue remains present.' };
    if (state === 'VERIFICATION_INCOMPLETE') return { label: 'Verification incomplete', tone: 'warning', detail: verification.reason || 'Required scanner coverage was incomplete.' };
    return { label: state || 'Pending', tone: 'warning', detail: verification.reason || 'Verification state is pending.' };
  }

  function coverageSummary(run) {
    const tools = run?.tools || {};
    const entries = Object.values(tools);
    const ran = entries.filter((tool) => tool.decision === 'RUN' && !['SKIPPED', 'NOT_APPLICABLE'].includes(tool.status));
    const limited = entries.filter((tool) => ['SKIPPED', 'NOT_APPLICABLE', 'DEGRADED', 'FAIL', 'ERROR', 'UNKNOWN'].includes(canonicalStatus(tool.status)) || tool.decision === 'SKIP');
    if (!run) return { label: 'Coverage unavailable', tone: 'neutral', detail: 'Start an audit to see which checks ran and which were skipped.' };
    if (!limited.length) return { label: `${ran.length} checks completed`, tone: 'pass', detail: 'No skipped or degraded scanner coverage was reported for this run.' };
    return { label: `${ran.length} checks ran · ${limited.length} limited`, tone: 'warning', detail: 'Skipped, degraded, failed, and not-applicable checks remain visible; they are not passes.' };
  }

  function toolchainSummary(toolkit) {
    const tools = Object.values(toolkit?.doctor?.tools || {});
    const states = tools.reduce((result, tool) => {
      const state = canonicalStatus(tool.status || 'UNKNOWN');
      result[state] = (result[state] || 0) + 1;
      return result;
    }, {});
    const degraded = ['DEGRADED', 'BROKEN', 'MISSING', 'UNKNOWN'].some((state) => states[state]);
    return {
      label: toolkit?.doctor?.overall || 'UNKNOWN',
      tone: degraded ? 'warning' : 'pass',
      states,
      detail: degraded ? 'One or more local tool or content checks need attention.' : 'The locally reported toolchain is healthy.',
    };
  }

  function promptValue(value, fallback = 'not supplied') {
    return String(value || fallback).replace(/[\r\n]+/g, ' ').slice(0, 180);
  }

  function buildAgentPrompt(run, findings = []) {
    const decision = releaseDecision(run);
    const selected = priorityFindings(findings, run, 5);
    const lines = [
      'Use Vibe Code Guard to review this project using the canonical local workflow.',
      'Read the structured CLI result and Dashboard state; do not invent scanner results or claim 100% security.',
      '',
      `Release decision: ${decision.label}`,
      `Gate reason: ${promptValue(decision.reason)}`,
      'Run: vibe-code-guard audit . --profile auto --json',
      'Dashboard: vibe-code-guard dashboard --json',
    ];
    if (selected.length) {
      lines.push('', 'Prioritize these correlated findings:');
      selected.forEach((finding) => lines.push(`- ${promptValue(finding.id)} · ${promptValue(finding.severity)} · ${promptValue(finding.title)} · ${promptValue(finding.location?.file || finding.location?.endpoint, 'location unavailable')}`));
      lines.push('', 'If I authorize fixes, make the smallest safe change, then run targeted verification. A fix is not verified until the relevant scanner coverage succeeds.');
    } else {
      lines.push('', 'No correlated findings were supplied to this prompt. Report what actually ran, what was skipped, and any degraded toolchain coverage.');
    }
    return lines.join('\n');
  }

  return Object.freeze({
    coverageSummary,
    buildAgentPrompt,
    friendlyLifecycle,
    isResolvedStatus,
    priorityFindings,
    releaseBlocking,
    releaseDecision,
    toolchainSummary,
    verificationSummary,
  });
}));
