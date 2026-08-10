const { redact, sanitizeText } = require('../findings/sanitize');

const MAX_SNIPPET_LENGTH = 2400;
const MAX_OBSERVATIONS = 20;
const MAX_RAW_FINDINGS = 12;

function truncate(value, limit = MAX_SNIPPET_LENGTH) {
  const text = String(value || '');
  return text.length > limit ? `${text.slice(0, limit)}\n[TRUNCATED]` : text;
}

function safeToken(value, limit, fallback = '') {
  return sanitizeText(value, fallback).slice(0, limit);
}

function safeLocation(location = {}) {
  location = location || {};
  return {
    file: location.file ? sanitizeText(location.file, '').slice(0, 300) : null,
    line: location.line || null,
    endpoint: location.endpoint ? sanitizeText(location.endpoint, '').slice(0, 500) : null,
  };
}

function safeObservation(observation = {}) {
  return {
    scanner: safeToken(observation.scanner || 'unknown', 100, 'unknown'),
    scannerFindingId: safeToken(observation.scannerFindingId || '', 200),
    fingerprint: safeToken(observation.fingerprint || '', 200),
    ruleId: observation.ruleId ? safeToken(observation.ruleId, 200) : null,
    severity: safeToken(observation.severity || 'UNKNOWN', 30, 'UNKNOWN'),
    category: safeToken(observation.category || 'UNKNOWN', 80, 'UNKNOWN'),
    location: safeLocation(observation.location),
    identity: {
      kind: observation.identity?.kind ? safeToken(observation.identity.kind, 80) : null,
      ruleFamily: observation.identity?.ruleFamily ? safeToken(observation.identity.ruleFamily, 120) : null,
      secretFamily: observation.identity?.secretFamily ? safeToken(observation.identity.secretFamily, 120) : null,
      vulnerabilityId: observation.identity?.vulnerabilityId ? safeToken(observation.identity.vulnerabilityId, 120) : null,
      packageName: observation.identity?.packageName ? safeToken(observation.identity.packageName, 160) : null,
      ecosystem: observation.identity?.ecosystem ? safeToken(observation.identity.ecosystem, 80) : null,
    },
  };
}

function safeRawFinding(finding = {}) {
  return {
    id: safeToken(finding.id || '', 200),
    title: sanitizeText(finding.title, 'Scanner finding'),
    severity: safeToken(finding.severity || 'UNKNOWN', 30, 'UNKNOWN'),
    category: safeToken(finding.category || 'UNKNOWN', 80, 'UNKNOWN'),
    scanner: safeToken(finding.scanner?.id || finding.scanner || 'unknown', 100, 'unknown'),
    location: safeLocation(finding.location),
    evidence: { summary: sanitizeText(finding.evidence?.summary || finding.evidence, 'Evidence was redacted before AI review.'), redacted: true },
  };
}

function redactValue(value) {
  if (typeof value === 'string') return redact(value);
  if (Array.isArray(value)) return value.map(redactValue);
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, redactValue(item)]));
  return value;
}

function redactionCount(value) {
  return (JSON.stringify(value).match(/\[(?:REDACTED|TRUNCATED)[^\]]*\]/g) || []).length;
}

module.exports = {
  MAX_OBSERVATIONS,
  MAX_RAW_FINDINGS,
  MAX_SNIPPET_LENGTH,
  redactValue,
  redactionCount,
  safeLocation,
  safeObservation,
  safeRawFinding,
  safeToken,
  truncate,
};
