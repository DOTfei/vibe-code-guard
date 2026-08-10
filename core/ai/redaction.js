const { redact, sanitizeText } = require('../findings/sanitize');

const MAX_SNIPPET_LENGTH = 2400;
const MAX_OBSERVATIONS = 20;
const MAX_RAW_FINDINGS = 12;

function truncate(value, limit = MAX_SNIPPET_LENGTH) {
  const text = String(value || '');
  return text.length > limit ? `${text.slice(0, limit)}\n[TRUNCATED]` : text;
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
    scanner: String(observation.scanner || 'unknown').slice(0, 100),
    scannerFindingId: String(observation.scannerFindingId || '').slice(0, 200),
    fingerprint: String(observation.fingerprint || '').slice(0, 200),
    ruleId: observation.ruleId ? String(observation.ruleId).slice(0, 200) : null,
    severity: String(observation.severity || 'UNKNOWN').slice(0, 30),
    category: String(observation.category || 'UNKNOWN').slice(0, 80),
    location: safeLocation(observation.location),
    identity: {
      kind: observation.identity?.kind || null,
      ruleFamily: observation.identity?.ruleFamily || null,
      secretFamily: observation.identity?.secretFamily || null,
      vulnerabilityId: observation.identity?.vulnerabilityId || null,
      packageName: observation.identity?.packageName || null,
      ecosystem: observation.identity?.ecosystem || null,
    },
  };
}

function safeRawFinding(finding = {}) {
  return {
    id: String(finding.id || '').slice(0, 200),
    title: sanitizeText(finding.title, 'Scanner finding'),
    severity: String(finding.severity || 'UNKNOWN').slice(0, 30),
    category: String(finding.category || 'UNKNOWN').slice(0, 80),
    scanner: String(finding.scanner?.id || finding.scanner || 'unknown').slice(0, 100),
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
  truncate,
};
