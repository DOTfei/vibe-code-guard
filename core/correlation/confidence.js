const CONFIDENCE_LEVELS = Object.freeze(['EXACT', 'HIGH', 'MEDIUM', 'NONE']);

const CONFIDENCE_RANK = Object.freeze({ NONE: 0, MEDIUM: 1, HIGH: 2, EXACT: 3 });

function normalizeConfidence(value) {
  const normalized = String(value || 'NONE').toUpperCase();
  return CONFIDENCE_LEVELS.includes(normalized) ? normalized : 'NONE';
}

function compareConfidence(left, right) {
  return CONFIDENCE_RANK[normalizeConfidence(left)] - CONFIDENCE_RANK[normalizeConfidence(right)];
}

module.exports = { CONFIDENCE_LEVELS, CONFIDENCE_RANK, normalizeConfidence, compareConfidence };
