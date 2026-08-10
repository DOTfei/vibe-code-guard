const AI_REVIEW_SCHEMA_VERSION = '1.0';
const AI_REVIEW_STATUSES = Object.freeze(['NOT_GENERATED', 'GENERATING', 'READY', 'FAILED', 'STALE']);
const AI_CONFIDENCE = Object.freeze(['HIGH', 'MEDIUM', 'LOW']);
const PRIORITIES = Object.freeze(['P0', 'P1', 'P2', 'P3']);
const FALSE_POSITIVE_LIKELIHOOD = Object.freeze(['LOW', 'MEDIUM', 'HIGH', 'UNKNOWN']);

function modelMetadata(provider, model) {
  return { provider: String(provider || 'unknown').slice(0, 100), model: String(model || 'unknown').slice(0, 160) };
}

module.exports = {
  AI_CONFIDENCE,
  AI_REVIEW_SCHEMA_VERSION,
  AI_REVIEW_STATUSES,
  FALSE_POSITIVE_LIKELIHOOD,
  PRIORITIES,
  modelMetadata,
};
