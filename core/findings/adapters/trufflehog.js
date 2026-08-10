const { parseJsonLines } = require('../parsing');
const { createFinding } = require('../schema');

function parseTruffleHog(text, context) {
  return parseJsonLines(text).filter((item) => item.DetectorName).map((item) => {
    const filesystem = item.SourceMetadata?.Data?.Filesystem || {};
    return createFinding({
      scanner: { id: 'trufflehog', name: 'TruffleHog', ruleId: item.DetectorName },
      severity: 'HIGH',
      confidence: item.Verified ? 'HIGH' : 'MEDIUM',
      category: 'SECRET_EXPOSURE',
      title: `${item.DetectorName} credential detected`,
      location: { type: 'file', file: filesystem.file || 'unknown', line: filesystem.line },
      explanation: {
        technical: `TruffleHog identified a ${item.DetectorName} detector match. The credential value is redacted.`,
        simple: 'This file looks like it contains a credential that should not be reachable by the project.',
        whyItMatters: 'A valid credential can allow unauthorized access. Treat real matches as incidents and rotate them.',
      },
      evidence: `TruffleHog detector ${item.DetectorName} reported a redacted match${item.Verified ? ' with verification metadata' : ''}.`,
    }, context);
  });
}

module.exports = parseTruffleHog;
