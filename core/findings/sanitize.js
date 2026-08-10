const MAX_TEXT_LENGTH = 4000;

function redact(value) {
  return String(value ?? '')
    .replace(/-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----/gi, '[REDACTED PRIVATE KEY]')
    .replace(/(sk-(?:proj-)?)[A-Za-z0-9_-]{10,}/g, '$1…[REDACTED]')
    .replace(/(AKIA)[A-Z0-9]{12,}/g, '$1…[REDACTED]')
    .replace(/(xox[baprs]-)[A-Za-z0-9-]{10,}/g, '$1…[REDACTED]')
    .replace(/(gh[pousr]_[A-Za-z0-9_]{8,})/g, 'gh_…[REDACTED]')
    .replace(/(Bearer\s+)[A-Za-z0-9._~+/=-]{12,}/gi, '$1[REDACTED]')
    .replace(/((?:["']?(?:password|secret|token|api[_-]?key|private[_-]?key|authorization|credential|match|raw|value)["']?\s*[:=]\s*["']?))[^\s"',}\]]{8,}/gi, '$1[REDACTED]');
}

function sanitizeText(value, fallback = '') {
  const text = redact(value);
  return (text || fallback).slice(0, MAX_TEXT_LENGTH);
}

function sanitizeEvidence(value) {
  const summary = typeof value === 'object' && value !== null ? value.summary : value;
  return { summary: sanitizeText(summary, 'Scanner reported a matching security signal.'), redacted: true };
}

module.exports = { MAX_TEXT_LENGTH, redact, sanitizeText, sanitizeEvidence };
