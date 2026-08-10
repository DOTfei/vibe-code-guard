const { normalizeCategory } = require('./category');
const { buildFingerprint, buildFindingId, normalizePath } = require('./fingerprint');
const { redact, sanitizeEvidence, sanitizeText } = require('./sanitize');
const { normalizeSeverity } = require('./severity');

const SCHEMA_VERSION = '1.0';
const STATUSES = Object.freeze(['OPEN', 'FIXING', 'FIXED', 'VERIFIED', 'REOPENED', 'FALSE_POSITIVE', 'ACCEPTED_RISK']);

function normalizeStatus(value) {
  const status = String(value || 'OPEN').toUpperCase();
  return STATUSES.includes(status) ? status : 'OPEN';
}

function normalizeConfidence(value) {
  const confidence = String(value || 'MEDIUM').toUpperCase();
  return ['HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'].includes(confidence) ? confidence : 'UNKNOWN';
}

function normalizeLocation(input = {}, context = {}) {
  const rawFile = input.file || '';
  const file = normalizePath(rawFile, context.projectPath);
  const endpoint = sanitizeText(input.endpoint || '');
  const type = input.type || (endpoint ? 'endpoint' : file ? 'file' : 'unknown');
  return {
    type: ['file', 'endpoint', 'unknown'].includes(type) ? type : 'unknown',
    file: file || null,
    line: Number.isInteger(input.line) && input.line > 0 ? input.line : null,
    column: Number.isInteger(input.column) && input.column > 0 ? input.column : null,
    endpoint: endpoint || null,
  };
}

function safeTime(value, fallback) {
  if (typeof value === 'string' && value && !/^\d{14}-[a-f0-9]{6}$/.test(value)) return value;
  return fallback || new Date().toISOString();
}

function createFinding(input = {}, context = {}) {
  const scannerInput = typeof input.scanner === 'string' ? { id: input.scanner, name: input.scanner } : (input.scanner || {});
  const scanner = {
    id: sanitizeText(scannerInput.id || 'unknown').toLowerCase(),
    name: sanitizeText(scannerInput.name || scannerInput.id || 'Unknown scanner'),
    ruleId: sanitizeText(scannerInput.ruleId || input.ruleId || '') || null,
  };
  const location = normalizeLocation(input.location || {
    type: input.endpoint ? 'endpoint' : input.file ? 'file' : 'unknown',
    file: input.file,
    line: input.line,
    column: input.column,
    endpoint: input.endpoint,
  }, context);
  const category = normalizeCategory(input.category, `${input.title || ''} ${scanner.ruleId || ''}`);
  const title = sanitizeText(input.title, 'Security finding');
  const fingerprint = input.fingerprint || buildFingerprint({
    ruleId: scanner.ruleId,
    category,
    title,
    location,
    projectPath: context.projectPath,
  });
  const firstSeen = safeTime(input.firstSeen, context.startedAt);
  const lastSeen = safeTime(input.lastSeen, context.observedAt || context.startedAt || firstSeen);
  const remediationInput = input.remediation;
  const remediationSummary = remediationInput && typeof remediationInput === 'object'
    ? sanitizeText(remediationInput.summary) || null
    : remediationInput
      ? sanitizeText(remediationInput)
      : null;
  return {
    schemaVersion: SCHEMA_VERSION,
    id: sanitizeText(input.id || buildFindingId(scanner.id, fingerprint)),
    fingerprint,
    scanner,
    severity: normalizeSeverity(input.severity),
    confidence: normalizeConfidence(input.confidence),
    category,
    title,
    location,
    explanation: {
      technical: sanitizeText(input.explanation?.technical || input.technical || title),
      simple: sanitizeText(input.explanation?.simple || input.simple || 'This scanner reported a security signal that needs review.'),
      whyItMatters: sanitizeText(input.explanation?.whyItMatters || input.why || 'The issue may increase the risk of unauthorized access, data exposure, or unsafe execution.'),
    },
    evidence: sanitizeEvidence(input.evidence),
    remediation: { summary: remediationSummary },
    status: normalizeStatus(input.status),
    firstSeen,
    lastSeen,
    source: {
      runId: sanitizeText(input.source?.runId || context.runId || '') || null,
      rawResultReference: sanitizeText(input.source?.rawResultReference) || null,
    },
  };
}

function validateFinding(finding) {
  const errors = [];
  if (!finding || typeof finding !== 'object') return { valid: false, errors: ['finding must be an object'] };
  for (const field of ['schemaVersion', 'id', 'fingerprint', 'severity', 'confidence', 'category', 'title', 'status', 'firstSeen', 'lastSeen']) {
    if (!finding[field]) errors.push(`${field} is required`);
  }
  if (finding.schemaVersion !== SCHEMA_VERSION) errors.push(`schemaVersion must be ${SCHEMA_VERSION}`);
  if (!finding.scanner?.id || !finding.scanner?.name) errors.push('scanner.id and scanner.name are required');
  if (!finding.location || !['file', 'endpoint', 'unknown'].includes(finding.location.type)) errors.push('location.type is invalid');
  if (!finding.explanation?.technical || !finding.explanation?.simple || !finding.explanation?.whyItMatters) errors.push('explanation fields are required');
  if (!finding.evidence || finding.evidence.redacted !== true) errors.push('evidence must be marked redacted');
  if (!finding.remediation || !Object.prototype.hasOwnProperty.call(finding.remediation, 'summary')) errors.push('remediation.summary is required');
  if (!finding.source || !Object.prototype.hasOwnProperty.call(finding.source, 'runId')) errors.push('source.runId is required');
  return { valid: errors.length === 0, errors };
}

function assertFinding(finding) {
  const result = validateFinding(finding);
  if (!result.valid) throw new Error(`Invalid Unified Finding: ${result.errors.join('; ')}`);
  return finding;
}

function normalizePersistedFinding(raw, context = {}) {
  if (!raw || typeof raw !== 'object') return null;
  if (raw.schemaVersion === SCHEMA_VERSION && raw.scanner && raw.location && raw.explanation) {
    return createFinding({ ...raw, source: raw.source || { runId: context.runId || null } }, context);
  }
  return createFinding({
    id: raw.id,
    scanner: raw.scanner || 'unknown',
    severity: raw.severity,
    category: raw.category,
    title: raw.title,
    file: raw.file,
    endpoint: raw.endpoint,
    technical: raw.technical,
    simple: raw.simple,
    why: raw.why,
    status: raw.status,
    firstSeen: raw.firstSeen,
    lastSeen: raw.lastSeen,
    source: { runId: context.runId || raw.previousRunId || null },
    evidence: raw.evidence?.summary || raw.title,
  }, context);
}

function normalizePersistedFindings(items, context = {}) {
  return (Array.isArray(items) ? items : []).map((item) => normalizePersistedFinding(item, context)).filter(Boolean);
}

module.exports = {
  SCHEMA_VERSION,
  STATUSES,
  createFinding,
  validateFinding,
  assertFinding,
  normalizeStatus,
  normalizePersistedFinding,
  normalizePersistedFindings,
};
