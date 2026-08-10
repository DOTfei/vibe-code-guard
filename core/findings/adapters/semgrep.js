const { parseJsonLoose } = require('../parsing');
const { createFinding } = require('../schema');

function parseSemgrep(text, context) {
  const data = parseJsonLoose(text);
  const results = Array.isArray(data?.results) ? data.results : [];
  return results.map((item) => {
    const message = item.extra?.message || item.check_id || 'Potential insecure code pattern';
    return createFinding({
      scanner: { id: 'semgrep', name: 'Semgrep', ruleId: item.check_id },
      severity: item.extra?.severity,
      confidence: 'MEDIUM',
      category: item.extra?.metadata?.category || item.extra?.metadata?.cwe || message,
      title: message,
      location: { type: 'file', file: item.path || 'unknown', line: item.start?.line, column: item.start?.col },
      explanation: {
        technical: `${item.check_id || 'Semgrep rule'}: ${message}`,
        simple: 'A code pattern may let untrusted input cross a security boundary without enough checking.',
        whyItMatters: 'The actual impact depends on reachability and data flow, so this needs review and a focused fix or documented false-positive decision.',
      },
      evidence: `Semgrep rule ${item.check_id || 'matched'} reported: ${message}`,
      remediation: item.extra?.metadata?.fix || null,
    }, context);
  });
}

module.exports = parseSemgrep;
