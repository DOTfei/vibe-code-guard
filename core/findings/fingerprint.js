const crypto = require('node:crypto');
const path = require('node:path');

function normalizePath(value, projectPath) {
  if (!value) return '';
  let result = String(value).replaceAll('\\', '/').trim();
  if (projectPath && path.isAbsolute(result)) {
    const relative = path.relative(projectPath, result);
    if (relative && !relative.startsWith('..')) result = relative;
  }
  return result.replace(/^\.\//, '').replace(/\/+/g, '/').toLowerCase();
}

function normalizeText(value) {
  return String(value || '').toLowerCase().replace(/\s+/g, ' ').trim();
}

function buildFingerprint({ ruleId, category, title, location, projectPath }) {
  const stable = [
    normalizeText(ruleId),
    normalizeText(category),
    normalizePath(location?.file, projectPath),
    normalizeText(location?.endpoint),
    location?.line ?? '',
    normalizeText(title),
  ].join('|');
  return crypto.createHash('sha256').update(stable).digest('hex');
}

function buildFindingId(scannerId, fingerprint) {
  const scanner = String(scannerId || 'unknown').replace(/[^a-z0-9]+/gi, '-').toUpperCase();
  const scoped = crypto.createHash('sha256').update(`${scanner}|${fingerprint}`).digest('hex').slice(0, 12).toUpperCase();
  return `VCG-${scanner}-${scoped}`;
}

module.exports = { normalizePath, normalizeText, buildFingerprint, buildFindingId };
