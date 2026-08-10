const { createProvider } = require('./provider');
const { validateAIReview } = require('./validation');

const DEFAULT_TIMEOUT_MS = 8000;

function withTimeout(promise, timeoutMs) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`AI provider timed out after ${timeoutMs}ms.`)), timeoutMs);
    Promise.resolve(promise).then((value) => { clearTimeout(timer); resolve(value); }, (error) => { clearTimeout(timer); reject(error); });
  });
}

function providerMetadata(provider) {
  return { provider: provider.name || 'unknown', model: provider.model || 'unknown' };
}

function unavailableRecord(context, provider, status, reason) {
  return {
    status,
    findingId: context.finding.id,
    inputHash: context.inputHash,
    provider: providerMetadata(provider),
    reason,
    context: context.metadata,
    updatedAt: new Date().toISOString(),
  };
}

async function generateFindingReview(context, { provider = createProvider(), timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  let availability;
  try {
    availability = await withTimeout(provider.availability(), timeoutMs);
  } catch (error) {
    return unavailableRecord(context, provider, 'FAILED', error.message || 'AI provider availability check failed.');
  }
  if (!availability.available) return unavailableRecord(context, provider, provider.name === 'disabled' ? 'NOT_GENERATED' : 'FAILED', availability.reason);
  try {
    const raw = await withTimeout(provider.reviewFinding(context), timeoutMs);
    const validation = validateAIReview(raw, context);
    if (!validation.valid) return { ...unavailableRecord(context, provider, 'FAILED', 'AI output failed validation.'), validationErrors: validation.errors };
    return { status: 'READY', findingId: context.finding.id, inputHash: context.inputHash, provider: providerMetadata(provider), review: validation.review, context: context.metadata, updatedAt: new Date().toISOString() };
  } catch (error) {
    return { ...unavailableRecord(context, provider, 'FAILED', error.message || 'AI provider failed.'), validationErrors: [] };
  }
}

function cachedReviewState(previous, context) {
  if (!previous) return { status: 'NOT_GENERATED', findingId: context.finding.id, inputHash: context.inputHash };
  if (previous.inputHash === context.inputHash) return { ...previous, cacheHit: true };
  return { ...previous, status: 'STALE', staleBecause: 'Relevant deterministic finding evidence changed.', cacheHit: false };
}

module.exports = { DEFAULT_TIMEOUT_MS, cachedReviewState, generateFindingReview };
