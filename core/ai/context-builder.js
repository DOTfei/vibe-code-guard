const crypto = require('node:crypto');
const { redactValue, redactionCount, safeLocation, safeObservation, safeRawFinding, truncate, MAX_OBSERVATIONS, MAX_RAW_FINDINGS } = require('./redaction');

function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue);
  if (value && typeof value === 'object') return Object.keys(value).sort().reduce((result, key) => {
    result[key] = stableValue(value[key]);
    return result;
  }, {});
  return value;
}

function stableStringify(value) {
  return JSON.stringify(stableValue(value));
}

function buildReviewContext({ finding, rawFindings = [], stack = [], lifecycleStatus, releaseGate = {}, codeSnippet = '', codeFile = '', allowCodeSnippet = false } = {}) {
  if (!finding?.id) throw new Error('A correlated finding is required for AI review.');
  const observations = (finding.observations || []).slice(0, MAX_OBSERVATIONS).map(safeObservation);
  const matchingRawFindings = rawFindings
    .filter((raw) => observations.some((observation) => observation.scannerFindingId === raw.id))
    .slice(0, MAX_RAW_FINDINGS)
    .map(safeRawFinding);
  const filePaths = [...new Set([
    finding.location?.file,
    ...observations.map((observation) => observation.location.file),
    ...matchingRawFindings.map((raw) => raw.location.file),
  ].filter(Boolean))].slice(0, 20);
  const scanners = [...new Set(observations.map((observation) => observation.scanner).filter(Boolean))];
  const vulnerabilityIds = [...new Set(observations.map((observation) => observation.identity.vulnerabilityId).filter(Boolean))];
  const requestedCodeFile = codeFile ? String(codeFile).slice(0, 500) : '';
  const snippetIncluded = Boolean(allowCodeSnippet && codeSnippet);
  if (snippetIncluded && (!requestedCodeFile || !filePaths.includes(requestedCodeFile))) throw new Error('Code snippets must be explicitly tied to a file reported by the finding.');
  const context = {
    finding: {
      id: finding.id,
      title: finding.title || 'Correlated security finding',
      severity: finding.severity || 'UNKNOWN',
      category: finding.category || 'UNKNOWN',
      scannerConfidence: finding.confidence || 'UNKNOWN',
      correlationKey: finding.correlationKey || null,
      location: safeLocation(finding.location),
      lifecycleStatus: lifecycleStatus || finding.status || 'OPEN',
    },
    scannerEvidence: observations,
    redactedFindings: matchingRawFindings,
    project: { stack: [...new Set(stack)].slice(0, 20) },
    releaseGate: {
      label: String(releaseGate.label || 'UNKNOWN').slice(0, 100),
      reason: String(releaseGate.reason || '').slice(0, 1000),
    },
    codeSnippet: snippetIncluded ? truncate(redactValue(codeSnippet)) : null,
    codeSnippetFile: snippetIncluded ? requestedCodeFile : null,
    evidenceBoundary: { scanners, filePaths, vulnerabilityIds },
  };
  const input = stableStringify(context);
  const inputHash = crypto.createHash('sha256').update(input).digest('hex');
  const redactions = redactionCount(context);
  return {
    ...context,
    inputHash,
    metadata: {
      inputHash,
      estimatedInputSize: input.length,
      filesIncluded: filePaths,
      snippetIncluded,
      redactionCount: redactions,
      observationsIncluded: observations.length,
    },
  };
}

module.exports = { buildReviewContext, stableStringify };
