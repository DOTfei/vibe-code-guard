const { redact } = require('../findings/sanitize');
const { AI_CONFIDENCE, AI_REVIEW_SCHEMA_VERSION, FALSE_POSITIVE_LIKELIHOOD, PRIORITIES } = require('./review-schema');

const FORBIDDEN_KEYS = new Set(['status', 'lifecycle', 'lifecycleStatus', 'severity', 'category', 'fingerprint', 'correlationKey', 'releaseGate', 'verified', 'fixed']);
const DANGEROUS_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const MAX_PROVIDER_RESPONSE_LENGTH = 128 * 1024;
const REVIEW_KEYS = new Set(['schemaVersion', 'findingId', 'generatedAt', 'model', 'summary', 'plainLanguageExplanation', 'whyItMatters', 'impact', 'priority', 'remediation', 'falsePositiveAssessment', 'uncertainties', 'questions', 'evidenceReferences']);
const SUMMARY_KEYS = new Set(['schemaVersion', 'mode', 'generatedAt', 'model', 'summary', 'blockers', 'priorityActions', 'uncertainties', 'questions']);

function sanitizePayload(value, depth = 0) {
  if (depth > 8) return '[TRUNCATED NESTED OUTPUT]';
  if (typeof value === 'string') return redact(value).slice(0, 4000);
  if (Array.isArray(value)) return value.slice(0, 30).map((item) => sanitizePayload(item, depth + 1));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).slice(0, 80).map(([key, item]) => [key, sanitizePayload(item, depth + 1)]));
  return value;
}

function collectStrings(value, result = []) {
  if (typeof value === 'string') result.push(value);
  else if (Array.isArray(value)) value.forEach((item) => collectStrings(item, result));
  else if (value && typeof value === 'object') Object.values(value).forEach((item) => collectStrings(item, result));
  return result;
}

function collectKeys(value, result = []) {
  if (Array.isArray(value)) value.forEach((item) => collectKeys(item, result));
  else if (value && typeof value === 'object') Object.entries(value).forEach(([key, item]) => { result.push(key); collectKeys(item, result); });
  return result;
}

function parseProviderJSON(value) {
  if (value && typeof value === 'object') return value;
  const text = String(value || '').trim().replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/, '');
  if (text.length > MAX_PROVIDER_RESPONSE_LENGTH) throw new Error('AI provider response exceeded the bounded response size.');
  return JSON.parse(text);
}

function validateCommon(review, context, errors) {
  if (!review || typeof review !== 'object' || Array.isArray(review)) return false;
  for (const key of collectKeys(review)) {
    if (FORBIDDEN_KEYS.has(key)) errors.push(`AI output attempted to mutate deterministic field: ${key}`);
    if (DANGEROUS_KEYS.has(key)) errors.push(`AI output contained a blocked object key: ${key}`);
  }
  if (review.schemaVersion !== AI_REVIEW_SCHEMA_VERSION) errors.push('Unsupported AI review schemaVersion.');
  if (review.findingId && review.findingId !== context.finding?.id) errors.push('AI output references a different finding.');
  if (!review.findingId) errors.push('AI output is missing findingId.');
  if (!review.generatedAt || Number.isNaN(Date.parse(review.generatedAt))) errors.push('AI output has an invalid generatedAt.');
  if (!review.model || typeof review.model.provider !== 'string' || typeof review.model.model !== 'string') errors.push('AI output is missing model metadata.');
}

function validateAIReview(rawReview, context = {}) {
  let review;
  try { review = sanitizePayload(parseProviderJSON(rawReview)); } catch (error) { return { valid: false, errors: [`Invalid AI JSON: ${error.message}`], review: null }; }
  const errors = [];
  validateCommon(review, context, errors);
  for (const key of Object.keys(review)) if (!REVIEW_KEYS.has(key)) errors.push(`AI output contained an unexpected field: ${key}`);
  for (const field of ['summary', 'plainLanguageExplanation', 'whyItMatters']) if (typeof review[field] !== 'string' || !review[field].trim()) errors.push(`AI output is missing ${field}.`);
  if (!review.impact || typeof review.impact.scope !== 'string' || !AI_CONFIDENCE.includes(review.impact.confidence)) errors.push('AI output has an invalid impact object.');
  if (!review.priority || !PRIORITIES.includes(review.priority.suggested) || typeof review.priority.reason !== 'string') errors.push('AI output has an invalid priority object.');
  if (!review.remediation || typeof review.remediation.recommendedApproach !== 'string' || !Array.isArray(review.remediation.steps) || typeof review.remediation.verificationAdvice !== 'string') errors.push('AI output has an invalid remediation object.');
  if (!review.falsePositiveAssessment || !FALSE_POSITIVE_LIKELIHOOD.includes(review.falsePositiveAssessment.likelihood) || review.falsePositiveAssessment.requiresUserDecision !== true) errors.push('False-positive assessment must remain user-controlled.');
  if (!Array.isArray(review.uncertainties) || !Array.isArray(review.questions)) errors.push('AI output must include uncertainties and questions arrays.');
  const boundary = context.evidenceBoundary || { scanners: [], filePaths: [], vulnerabilityIds: [] };
  for (const reference of review.evidenceReferences || []) {
    if (!boundary.scanners.includes(reference.scanner)) errors.push(`AI output referenced scanner without evidence: ${reference.scanner}`);
    for (const file of reference.files || []) if (!boundary.filePaths.includes(file)) errors.push(`AI output referenced file without evidence: ${file}`);
    for (const vulnerabilityId of reference.vulnerabilityIds || []) if (!boundary.vulnerabilityIds.includes(vulnerabilityId)) errors.push(`AI output invented vulnerability ID: ${vulnerabilityId}`);
  }
  const allowedCves = new Set(boundary.vulnerabilityIds || []);
  for (const cve of collectStrings(review).join('\n').match(/CVE-\d{4}-\d{4,}/gi) || []) if (![...allowedCves].some((id) => id.toUpperCase() === cve.toUpperCase())) errors.push(`AI output invented vulnerability ID: ${cve}`);
  const fileCandidates = collectStrings(review).join('\n').match(/\b(?:[A-Za-z0-9_.-]+\/)+[A-Za-z0-9_.-]+\.(?:c|cc|cpp|go|html|java|js|json|jsx|md|php|py|rb|rs|tf|ts|tsx|yaml|yml)\b/g) || [];
  for (const file of fileCandidates) if (!boundary.filePaths.includes(file)) errors.push(`AI output referenced file without evidence: ${file}`);
  if (errors.length) return { valid: false, errors, review };
  return { valid: true, errors: [], review };
}

function validateAISummary(rawSummary, context = {}) {
  let summary;
  try { summary = sanitizePayload(parseProviderJSON(rawSummary)); } catch (error) { return { valid: false, errors: [`Invalid AI JSON: ${error.message}`], summary: null }; }
  const errors = [];
  for (const key of Object.keys(summary)) if (!SUMMARY_KEYS.has(key)) errors.push(`AI summary contained an unexpected field: ${key}`);
  if (summary.schemaVersion !== AI_REVIEW_SCHEMA_VERSION) errors.push('Unsupported AI summary schemaVersion.');
  if (!['RUN_SUMMARY', 'RELEASE_REVIEW'].includes(summary.mode)) errors.push('Invalid AI summary mode.');
  if (!summary.generatedAt || Number.isNaN(Date.parse(summary.generatedAt))) errors.push('AI summary has an invalid generatedAt.');
  if (!summary.model || typeof summary.model.provider !== 'string' || typeof summary.model.model !== 'string') errors.push('AI summary is missing model metadata.');
  if (typeof summary.summary !== 'string' || !summary.summary.trim()) errors.push('AI summary is missing summary text.');
  if (!Array.isArray(summary.blockers) || !Array.isArray(summary.priorityActions) || !Array.isArray(summary.uncertainties) || !Array.isArray(summary.questions)) errors.push('AI summary arrays are missing.');
  const findingIds = new Set((context.findings || []).map((finding) => finding.id));
  for (const item of [...(summary.blockers || []), ...(summary.priorityActions || [])]) if (item.findingId && !findingIds.has(item.findingId)) errors.push(`AI summary referenced unknown finding: ${item.findingId}`);
  for (const key of collectKeys(summary)) {
    if (FORBIDDEN_KEYS.has(key)) errors.push(`AI summary attempted to mutate deterministic field: ${key}`);
    if (DANGEROUS_KEYS.has(key)) errors.push(`AI summary contained a blocked object key: ${key}`);
  }
  if (errors.length) return { valid: false, errors, summary };
  return { valid: true, errors: [], summary };
}

module.exports = { parseProviderJSON, sanitizePayload, validateAIReview, validateAISummary };
