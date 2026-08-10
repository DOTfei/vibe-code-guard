const { parseJsonLoose } = require('../parsing');
const { createFinding } = require('../schema');

function zapSeverity(value) {
  const text = String(value || '').toLowerCase();
  if (text.startsWith('3')) return 'HIGH';
  if (text.startsWith('2')) return 'MEDIUM';
  if (text.startsWith('1')) return 'LOW';
  if (text.startsWith('0')) return 'INFO';
  if (text.includes('high')) return 'HIGH';
  if (text.includes('medium')) return 'MEDIUM';
  if (text.includes('low')) return 'LOW';
  return 'INFO';
}

function plainText(value) {
  return String(value || '').replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
}

function parseZap(text, context) {
  const data = parseJsonLoose(text);
  const alerts = Array.isArray(data?.alerts) ? data.alerts : Array.isArray(data?.site?.[0]?.alerts) ? data.site[0].alerts : [];
  return alerts.map((item) => createFinding({
    scanner: { id: 'zap', name: 'OWASP ZAP', ruleId: item.pluginid || item.alertRef || item.id },
    severity: zapSeverity(item.riskcode || item.riskdesc || item.risk),
    confidence: item.confidence || item.confidenceDesc,
    category: item.name || item.alert || 'RUNTIME',
    title: item.name || item.alert || item.pluginid || 'OWASP ZAP alert',
    location: { type: 'endpoint', endpoint: item.url || item.uri || item['matched-at'] || item.instances?.[0]?.uri || 'authorized local target' },
    explanation: { technical: plainText(item.description || item.desc || item.name || 'OWASP ZAP reported a runtime alert.'), simple: 'A local runtime check found a web behavior worth reviewing.', whyItMatters: plainText(item.solution || item.otherinfo || 'Runtime evidence can reveal issues that source-only scanners do not see.') },
    evidence: `OWASP ZAP reported ${item.name || item.alert || 'a sanitized alert'} with ${item.confidenceDesc || item.confidence || 'unspecified'} confidence.`,
    remediation: plainText(item.solution) || null,
  }, context));
}

module.exports = parseZap;
