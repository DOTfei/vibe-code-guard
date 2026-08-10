const { parseJsonLoose } = require('../parsing');
const { createFinding } = require('../schema');

function parseCheckov(text, context) {
  const data = parseJsonLoose(text);
  const failed = data?.results?.failed_checks || [];
  return failed.map((item) => createFinding({
    scanner: { id: 'checkov', name: 'Checkov', ruleId: item.check_id },
    severity: item.severity,
    category: item.check_type || 'INFRASTRUCTURE',
    title: `${item.check_id || 'IaC check'}: ${item.check_name || 'Configuration issue'}`,
    location: { type: 'file', file: item.file_path || 'infrastructure', line: Array.isArray(item.file_line_range) ? item.file_line_range[0] : null },
    explanation: { technical: item.check_name || 'Checkov reported a failed infrastructure security check.', simple: 'A deployment or infrastructure setting may be more exposed than intended.', whyItMatters: item.guideline || 'Infrastructure defaults can turn a small application mistake into a broad exposure.' },
    evidence: `Checkov check ${item.check_id || 'failed'} reported a sanitized configuration result.`,
    remediation: item.guideline || null,
  }, context));
}

module.exports = parseCheckov;
