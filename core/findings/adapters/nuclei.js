const { parseJsonLines } = require('../parsing');
const { createFinding } = require('../schema');

function parseNuclei(text, context) {
  return parseJsonLines(text).filter((item) => item.info).map((item) => createFinding({
    scanner: { id: 'nuclei', name: 'Nuclei', ruleId: item['template-id'] },
    severity: item.info.severity,
    confidence: 'MEDIUM',
    category: 'RUNTIME',
    title: item.info.name || item['template-id'] || 'Nuclei detection',
    location: { type: 'endpoint', endpoint: item['matched-at'] || item.host || 'authorized local target' },
    explanation: { technical: `${item['template-id'] || 'Nuclei template'} matched the authorized local target.`, simple: 'A runtime check found a web behavior worth reviewing on the local test target.', whyItMatters: item.info.description || 'Runtime findings can reveal issues that source-only scanners do not see.' },
    evidence: `Nuclei template ${item['template-id'] || 'matched'} reported a sanitized runtime result.`,
    remediation: item.info.remediation || item.info.solution || null,
  }, context));
}

module.exports = parseNuclei;
