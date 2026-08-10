const { parseJsonLoose } = require('../parsing');
const { createFinding } = require('../schema');

function parseGitleaks(text, context) {
  const data = parseJsonLoose(text);
  if (!Array.isArray(data)) return [];
  return data.map((item) => createFinding({
    scanner: { id: 'gitleaks', name: 'Gitleaks', ruleId: item.RuleID },
    severity: 'HIGH',
    confidence: 'HIGH',
    category: 'SECRET_EXPOSURE',
    title: item.Description || item.RuleID || 'Potential secret detected',
    location: { type: 'file', file: item.File || 'unknown', line: item.StartLine, column: item.StartColumn },
    explanation: {
      technical: `Secret detector rule ${item.RuleID || 'matched'} reported a credential-like value. The value is intentionally redacted.`,
      simple: 'A credential-like value may be inside the project and could be reused by someone who gets the code.',
      whyItMatters: 'Secrets committed to source or build output may grant access to external services. Rotate real credentials if this is not synthetic.',
    },
    evidence: `Gitleaks rule ${item.RuleID || 'matched'} reported a redacted match.`,
  }, context));
}

module.exports = parseGitleaks;
