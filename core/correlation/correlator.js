const crypto = require('node:crypto');
const { buildCorrelationKey, comparable, compareEvidence, deriveIdentity, scannerFingerprintKey } = require('./correlation-key');
const { compareConfidence } = require('./confidence');
const { automaticLifecycle, isVerificationEligible, appendHistory } = require('./lifecycle');
const { normalizeSeverity } = require('../findings/severity');
const { normalizeCategory } = require('../findings/category');

const CORRELATION_SCHEMA_VERSION = '1.0';
const SEVERITY_RANK = Object.freeze({ UNKNOWN: 0, INFO: 1, LOW: 2, MEDIUM: 3, HIGH: 4, CRITICAL: 5 });

function highestSeverity(left, right) {
  const a = normalizeSeverity(left);
  const b = normalizeSeverity(right);
  return SEVERITY_RANK[b] > SEVERITY_RANK[a] ? b : a;
}

function safeLocation(identity) {
  return {
    file: identity.file || null,
    line: identity.line || null,
    endpoint: identity.endpoint || null,
  };
}

function observationFromFinding(finding, context = {}) {
  const identity = deriveIdentity(finding, context);
  return {
    scanner: String(finding.scanner?.id || 'unknown').toLowerCase(),
    scannerFindingId: String(finding.id || '').slice(0, 200),
    fingerprint: String(finding.fingerprint || '').slice(0, 200),
    ruleId: String(finding.scanner?.ruleId || '').slice(0, 200) || null,
    runId: context.runId || finding.source?.runId || null,
    severity: normalizeSeverity(finding.severity),
    category: normalizeCategory(finding.category),
    firstSeen: finding.firstSeen || context.startedAt || null,
    lastSeen: finding.lastSeen || context.observedAt || context.startedAt || null,
    location: safeLocation(identity),
    identity: {
      kind: identity.kind,
      file: identity.file,
      line: identity.line,
      endpoint: identity.endpoint,
      method: identity.method,
      parameter: identity.parameter,
      secretFamily: identity.secretFamily,
      vulnerabilityId: identity.vulnerabilityId,
      packageName: identity.packageName,
      installedVersion: identity.installedVersion,
      ecosystem: identity.ecosystem,
      ruleFamily: identity.ruleFamily,
    },
  };
}

function correlationId(projectId, key) {
  return `VCG-CORR-${crypto.createHash('sha256').update(`${projectId || 'project'}|${key}`).digest('hex').slice(0, 14).toUpperCase()}`;
}

function groupTitle(findings) {
  return findings.find((finding) => finding.title)?.title || 'Correlated security finding';
}

function createGroup(findings, context = {}) {
  const first = findings[0];
  const identity = deriveIdentity(first, context);
  const correlationKey = buildCorrelationKey(first, context);
  const observations = findings.map((finding) => observationFromFinding(finding, context));
  const timestamp = context.observedAt || context.startedAt || new Date().toISOString();
  const preservedStatus = ['FIXED', 'VERIFIED', 'REOPENED', 'FALSE_POSITIVE', 'ACCEPTED_RISK'].includes(first.status) ? first.status : 'OPEN';
  const group = {
    schemaVersion: CORRELATION_SCHEMA_VERSION,
    id: correlationId(context.projectId, correlationKey),
    correlationKey,
    title: groupTitle(findings),
    severity: findings.reduce((value, finding) => highestSeverity(value, finding.severity), 'UNKNOWN'),
    category: normalizeCategory(first.category),
    status: preservedStatus,
    confidence: 'EXACT',
    location: safeLocation(identity),
    observations: [],
    firstSeen: findings.map((finding) => finding.firstSeen).filter(Boolean).sort()[0] || timestamp,
    lastSeen: timestamp,
    history: [],
  };
  appendHistory(group, { event: 'OPENED', runId: context.runId, previousStatus: null, newStatus: preservedStatus, reason: 'A correlated finding was derived from scanner evidence.' }, { runId: context.runId, timestamp });
  for (const observation of observations) addObservation(group, observation);
  appendHistory(group, { event: 'OBSERVED', runId: context.runId, previousStatus: preservedStatus, newStatus: preservedStatus, reason: 'The scanner observation was recorded.' }, { runId: context.runId, timestamp });
  return group;
}

function addObservation(group, observation) {
  const key = `${observation.runId || ''}|${observation.scanner}|${observation.fingerprint || observation.scannerFindingId}`;
  const exists = group.observations.some((item) => `${item.runId || ''}|${item.scanner}|${item.fingerprint || item.scannerFindingId}` === key);
  if (!exists) group.observations.push(observation);
  group.lastSeen = [group.lastSeen, observation.lastSeen].filter(Boolean).sort().at(-1) || group.lastSeen;
  group.firstSeen = [group.firstSeen, observation.firstSeen].filter(Boolean).sort()[0] || group.firstSeen;
  group.severity = highestSeverity(group.severity, observation.severity);
  return group;
}

function bestMatch(finding, groups, context = {}) {
  let best = null;
  for (const group of groups) {
    for (const observation of group.observations || []) {
      const confidence = compareEvidence(finding, observation, context);
      if (!['EXACT', 'HIGH', 'MEDIUM'].includes(confidence)) continue;
      if (!best || compareConfidence(confidence, best.confidence) > 0 || (confidence === best.confidence && group.id < best.group.id)) best = { group, confidence };
    }
  }
  return best;
}

function correlateFindings(findings, context = {}) {
  const groups = [];
  const suggestions = [];
  for (const finding of Array.isArray(findings) ? findings : []) {
    const match = bestMatch(finding, groups, context);
    if (match?.confidence === 'MEDIUM') {
      suggestions.push({ findingId: finding.id, correlatedFindingId: match.group.id, confidence: 'MEDIUM', reason: 'Location and category overlap, but deterministic identity evidence is incomplete.' });
    }
    if (!match || match.confidence === 'MEDIUM') groups.push(createGroup([finding], context));
    else {
      const observation = observationFromFinding(finding, context);
      addObservation(match.group, observation);
      const scanners = new Set(match.group.observations.map((item) => item.scanner));
      match.group.confidence = scanners.size > 1 && match.confidence === 'HIGH'
        ? 'HIGH'
        : compareConfidence(match.confidence, match.group.confidence) > 0 ? match.confidence : match.group.confidence;
      match.group.title = match.group.title || finding.title;
    }
  }
  return { findings: groups, suggestions };
}

function mergeGroup(existing, current, context = {}) {
  const merged = JSON.parse(JSON.stringify(existing));
  const currentObservations = current.observations || [];
  const bestConfidence = currentObservations.reduce((best, observation) => {
    const match = (merged.observations || []).map((old) => compareEvidence(observation, old, context)).sort((a, b) => compareConfidence(b, a))[0] || 'NONE';
    return compareConfidence(match, best) > 0 ? match : best;
  }, 'NONE');
  for (const observation of currentObservations) addObservation(merged, observation);
  if (bestConfidence !== 'NONE') merged.confidence = compareConfidence(bestConfidence, merged.confidence) > 0 ? bestConfidence : merged.confidence;
  if (new Set(merged.observations.map((observation) => observation.scanner)).size > 1 && bestConfidence === 'HIGH') merged.confidence = 'HIGH';
  merged.title = merged.title || current.title;
  merged.category = merged.category || current.category;
  merged.location = merged.location || current.location;
  automaticLifecycle(merged, { observed: true, runId: context.runId, timestamp: context.observedAt, reason: 'A current scan produced a matching observation.' });
  return merged;
}

function reconcileFindings(existingFindings, findings, context = {}) {
  const current = correlateFindings(findings, context);
  const next = (Array.isArray(existingFindings) ? existingFindings : []).map((finding) => JSON.parse(JSON.stringify(finding)));
  const matched = new Set();
  for (const currentGroup of current.findings) {
    let best = null;
    for (const existing of next) {
      for (const currentObservation of currentGroup.observations) {
        for (const oldObservation of existing.observations || []) {
          const confidence = compareEvidence(currentObservation, oldObservation, context);
          if (!['EXACT', 'HIGH'].includes(confidence)) continue;
          if (!best || compareConfidence(confidence, best.confidence) > 0 || (confidence === best.confidence && existing.id < best.finding.id)) best = { finding: existing, confidence };
        }
      }
    }
    if (best) {
      matched.add(best.finding.id);
      const index = next.findIndex((item) => item.id === best.finding.id);
      next[index] = mergeGroup(best.finding, currentGroup, context);
    } else next.push(currentGroup);
  }
  for (const finding of next) {
    if (matched.has(finding.id) || current.findings.some((item) => item.id === finding.id)) continue;
    const eligible = isVerificationEligible(finding, context);
    automaticLifecycle(finding, { observed: false, verificationEligible: eligible, runId: context.runId, timestamp: context.observedAt, reason: eligible ? 'Relevant scanner coverage completed without a matching observation.' : 'Verification deferred because relevant scanner coverage was incomplete.' });
  }
  return { findings: next, currentFindings: current.findings, suggestions: current.suggestions };
}

function countCorrelatedFindings(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0, total: 0, observations: 0 };
  for (const finding of Array.isArray(findings) ? findings : []) {
    const severity = normalizeSeverity(finding.severity).toLowerCase();
    counts[severity] = (counts[severity] || 0) + 1;
    counts.total += 1;
    counts.observations += Array.isArray(finding.observations) ? finding.observations.length : 0;
  }
  return counts;
}

function countBlockingCorrelatedFindings(findings) {
  const blockingStatuses = new Set(['OPEN', 'FIXED', 'REOPENED']);
  const blocking = (Array.isArray(findings) ? findings : []).filter((finding) => blockingStatuses.has(finding.status));
  return {
    critical: blocking.filter((finding) => finding.severity === 'CRITICAL').length,
    high: blocking.filter((finding) => finding.severity === 'HIGH').length,
    total: blocking.length,
  };
}

module.exports = {
  CORRELATION_SCHEMA_VERSION,
  addObservation,
  countBlockingCorrelatedFindings,
  countCorrelatedFindings,
  correlateFindings,
  createGroup,
  mergeGroup,
  observationFromFinding,
  reconcileFindings,
};
