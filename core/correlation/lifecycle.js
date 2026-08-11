const LIFECYCLE_STATUSES = Object.freeze(['OPEN', 'FIXING', 'FIXED', 'VERIFIED', 'REOPENED', 'FALSE_POSITIVE', 'ACCEPTED_RISK']);
const ACTION_STATUSES = Object.freeze(['OPEN', 'FIXING', 'FIXED', 'FALSE_POSITIVE', 'ACCEPTED_RISK']);

function normalizeLifecycleStatus(value) {
  const status = String(value || 'OPEN').toUpperCase();
  return LIFECYCLE_STATUSES.includes(status) ? status : 'OPEN';
}

function now(context = {}) {
  return context.timestamp || new Date().toISOString();
}

function appendHistory(finding, { event, runId = null, previousStatus, newStatus, reason = '' }, context = {}) {
  const history = Array.isArray(finding.history) ? finding.history : [];
  history.push({
    event,
    timestamp: now(context),
    runId: runId || context.runId || null,
    previousStatus: previousStatus || null,
    newStatus: newStatus || finding.status,
    reason: String(reason || '').slice(0, 1000),
  });
  finding.history = history;
  return finding;
}

function eventForStatus(status) {
  return {
    OPEN: 'OPENED',
    FIXING: 'FIX_STARTED',
    FIXED: 'FIX_MARKED',
    VERIFIED: 'VERIFIED',
    REOPENED: 'REOPENED',
    FALSE_POSITIVE: 'FALSE_POSITIVE_MARKED',
    ACCEPTED_RISK: 'RISK_ACCEPTED',
  }[status] || 'OBSERVED';
}

function isVerificationEligible(finding, context = {}) {
  const observations = Array.isArray(finding?.observations) ? finding.observations : [];
  if (!observations.length) return false;
  if (context.verificationScopeValid === false) return false;
  const tools = context.tools || {};
  const statuses = context.scannerStatuses || {};
  for (const observation of observations) {
    const scanner = String(observation.scanner || '').toLowerCase();
    const tool = tools[scanner];
    const status = tool?.status || statuses[scanner];
    if (status !== 'PASS') return false;
    if (tool?.decision && tool.decision !== 'RUN') return false;
    if (tool && Object.prototype.hasOwnProperty.call(tool, 'parseValid') && tool.parseValid !== true) return false;
    if (['zap', 'nuclei'].includes(scanner) && (context.stages?.web?.status !== 'PASS' || !context.webTarget)) return false;
  }
  return true;
}

function automaticLifecycle(finding, { observed, verificationEligible = false, runId, timestamp, reason = '' } = {}) {
  const currentStatus = normalizeLifecycleStatus(finding.status);
  finding.status = currentStatus;
  const context = { runId, timestamp };
  if (observed && currentStatus === 'VERIFIED') {
    finding.status = 'REOPENED';
    appendHistory(finding, { event: 'REOPENED', runId, previousStatus: currentStatus, newStatus: 'REOPENED', reason: reason || 'A previously verified finding was observed again.' }, context);
    return finding;
  }
  if (observed && (currentStatus === 'FIXING' || currentStatus === 'FIXED')) {
    finding.status = 'OPEN';
    appendHistory(finding, { event: 'STILL_PRESENT', runId, previousStatus: currentStatus, newStatus: 'OPEN', reason: reason || 'The relevant scanner still reports the finding after the authorized fix attempt.' }, context);
    return finding;
  }
  if (!observed && ['FIXING', 'FIXED'].includes(currentStatus) && verificationEligible) {
    finding.status = 'VERIFIED';
    appendHistory(finding, { event: 'VERIFIED', runId, previousStatus: currentStatus, newStatus: 'VERIFIED', reason: reason || 'The relevant scanner ran successfully and no matching observation was reported.' }, context);
    return finding;
  }
  if (!observed && !verificationEligible && !['FALSE_POSITIVE', 'ACCEPTED_RISK'].includes(currentStatus)) {
    appendHistory(finding, { event: 'VERIFICATION_DEFERRED', runId, previousStatus: currentStatus, newStatus: currentStatus, reason: reason || 'Verification was deferred because relevant scanner coverage was incomplete.' }, context);
    return finding;
  }
  if (observed && !['FALSE_POSITIVE', 'ACCEPTED_RISK'].includes(currentStatus)) {
    appendHistory(finding, { event: 'OBSERVED', runId, previousStatus: currentStatus, newStatus: currentStatus, reason: reason || 'A relevant scanner observed this correlated finding.' }, context);
  }
  return finding;
}

function explicitLifecycleAction(finding, nextStatus, { reason = '', runId, timestamp } = {}) {
  const next = normalizeLifecycleStatus(nextStatus);
  if (!ACTION_STATUSES.includes(next)) throw new Error(`Unsupported lifecycle action: ${next}`);
  if ((next === 'FALSE_POSITIVE' || next === 'ACCEPTED_RISK') && !String(reason).trim()) throw new Error(`${next} requires a reason.`);
  const previous = normalizeLifecycleStatus(finding.status);
  finding.status = next;
  appendHistory(finding, { event: eventForStatus(next), runId, previousStatus: previous, newStatus: next, reason }, { runId, timestamp });
  return finding;
}

module.exports = {
  ACTION_STATUSES,
  LIFECYCLE_STATUSES,
  appendHistory,
  automaticLifecycle,
  eventForStatus,
  explicitLifecycleAction,
  isVerificationEligible,
  normalizeLifecycleStatus,
};
