const { createFinding, assertFinding, normalizePersistedFindings, validateFinding, SCHEMA_VERSION, STATUSES } = require('./schema');
const { CATEGORIES, normalizeCategory } = require('./category');
const { SEVERITIES, normalizeSeverity } = require('./severity');
const { buildFingerprint, buildFindingId } = require('./fingerprint');
const { redact, sanitizeEvidence, sanitizeText } = require('./sanitize');
const { parseJsonLoose, parseJsonLines } = require('./parsing');
const gitleaks = require('./adapters/gitleaks');
const trufflehog = require('./adapters/trufflehog');
const semgrep = require('./adapters/semgrep');
const trivy = require('./adapters/trivy');
const osvScanner = require('./adapters/osv-scanner');
const checkov = require('./adapters/checkov');
const zap = require('./adapters/zap');
const nuclei = require('./adapters/nuclei');
const correlation = require('../correlation');

const ADAPTERS = Object.freeze({ gitleaks, trufflehog, semgrep, trivy, 'osv-scanner': osvScanner, checkov, zap, nuclei });

function adaptScannerOutput(tool, text, context = {}) {
  const adapter = ADAPTERS[tool];
  if (!adapter) return [];
  return adapter(text, context).map((finding) => assertFinding(finding));
}

function countFindings(findings) {
  return (Array.isArray(findings) ? findings : []).reduce((counts, finding) => {
    const key = String(finding.severity || 'UNKNOWN').toLowerCase();
    counts[key] = (counts[key] || 0) + 1;
    counts.total += 1;
    return counts;
  }, { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0, total: 0 });
}

module.exports = {
  ADAPTERS,
  CATEGORIES,
  SCHEMA_VERSION,
  SEVERITIES,
  STATUSES,
  adaptScannerOutput,
  buildFindingId,
  buildFingerprint,
  countFindings,
  createFinding,
  normalizeCategory,
  normalizePersistedFindings,
  normalizeSeverity,
  parseJsonLines,
  parseJsonLoose,
  redact,
  sanitizeEvidence,
  sanitizeText,
  validateFinding,
  correlation,
  ...correlation,
};
