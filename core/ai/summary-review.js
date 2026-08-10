const { createProvider } = require('./provider');
const { validateAISummary } = require('./validation');
const { AI_REVIEW_SCHEMA_VERSION } = require('./review-schema');

async function generateSummaryReview(context, { provider = createProvider(), timeoutMs = 8000 } = {}) {
  const availability = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`AI provider timed out after ${timeoutMs}ms.`)), timeoutMs);
    Promise.resolve(provider.availability()).then((value) => { clearTimeout(timer); resolve(value); }, (error) => { clearTimeout(timer); reject(error); });
  }).catch((error) => ({ available: false, reason: error.message }));
  if (!availability.available) return { status: provider.name === 'disabled' ? 'NOT_GENERATED' : 'FAILED', mode: context.mode, inputHash: context.inputHash, provider: { provider: provider.name, model: provider.model }, reason: availability.reason, updatedAt: new Date().toISOString() };
  try {
    const raw = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`AI provider timed out after ${timeoutMs}ms.`)), timeoutMs);
      Promise.resolve(provider.reviewRunSummary(context)).then((value) => { clearTimeout(timer); resolve(value); }, (error) => { clearTimeout(timer); reject(error); });
    });
    const validation = validateAISummary(raw, context);
    if (!validation.valid) return { status: 'FAILED', mode: context.mode, inputHash: context.inputHash, provider: { provider: provider.name, model: provider.model }, reason: 'AI summary failed validation.', validationErrors: validation.errors, updatedAt: new Date().toISOString() };
    return { status: 'READY', mode: context.mode, inputHash: context.inputHash, provider: { provider: provider.name, model: provider.model }, summary: validation.summary, updatedAt: new Date().toISOString() };
  } catch (error) {
    return { status: 'FAILED', mode: context.mode, inputHash: context.inputHash, provider: { provider: provider.name, model: provider.model }, reason: error.message || 'AI provider failed.', validationErrors: [], updatedAt: new Date().toISOString() };
  }
}

function summaryContext({ mode, findings = [], releaseGate = {}, stack = [], runId, summary = {} } = {}) {
  const safeFindings = findings.slice(0, 50).map((finding) => ({ id: finding.id, title: finding.title, severity: finding.severity, status: finding.status, category: finding.category, confidence: finding.confidence }));
  const input = JSON.stringify({ mode, findings: safeFindings, releaseGate, stack, runId, summary });
  const crypto = require('node:crypto');
  return { mode, findings: safeFindings, releaseGate, stack, runId, summary, inputHash: crypto.createHash('sha256').update(input).digest('hex') };
}

module.exports = { generateSummaryReview, summaryContext, AI_REVIEW_SCHEMA_VERSION };
