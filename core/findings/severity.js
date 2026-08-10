const SEVERITIES = Object.freeze(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNKNOWN']);

function normalizeSeverity(value, fallback = 'UNKNOWN') {
  if (value === null || value === undefined || value === '') return fallback;
  const raw = String(value).trim().toUpperCase();
  if (SEVERITIES.includes(raw)) return raw;
  if (raw.includes('CRITICAL') || raw === 'BLOCKER' || raw === '9' || raw === '10') return 'CRITICAL';
  if (raw.includes('HIGH') || raw === 'ERROR' || raw === 'SEVERE') return 'HIGH';
  if (raw.includes('MEDIUM') || raw === 'WARNING' || raw === 'WARN' || raw === 'MODERATE') return 'MEDIUM';
  if (raw.includes('LOW') || raw === 'MINOR') return 'LOW';
  if (raw.includes('INFO') || raw === 'INFORMATIONAL' || raw === 'NOTE') return 'INFO';
  const score = Number.parseFloat(raw);
  if (Number.isFinite(score)) {
    if (score >= 9) return 'CRITICAL';
    if (score >= 7) return 'HIGH';
    if (score >= 4) return 'MEDIUM';
    if (score > 0) return 'LOW';
    if (score === 0) return 'INFO';
  }
  return fallback;
}

module.exports = { SEVERITIES, normalizeSeverity };
