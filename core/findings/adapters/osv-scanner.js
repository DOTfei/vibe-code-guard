const { parseJsonLoose } = require('../parsing');
const { createFinding } = require('../schema');

function parseOsvScanner(text, context) {
  const data = parseJsonLoose(text);
  const findings = [];
  for (const result of data?.results || []) {
    for (const pkg of result.packages || []) {
      for (const vuln of pkg.vulnerabilities || []) findings.push(createFinding({
        scanner: { id: 'osv-scanner', name: 'OSV-Scanner', ruleId: vuln.id },
        severity: vuln.database_specific?.severity || vuln.severity?.[0]?.score,
        category: 'DEPENDENCY_VULNERABILITY',
        title: `${vuln.id || 'OSV finding'}: ${vuln.summary || 'Known dependency vulnerability'}`,
        location: { type: 'file', file: result.source?.path || pkg.package?.name || 'dependency manifest' },
        explanation: { technical: `${pkg.package?.name || 'Package'} ${pkg.package?.version || ''} matched ${vuln.id || 'an OSV advisory'}.`, simple: 'The project uses a dependency version that a public vulnerability database has flagged.', whyItMatters: 'Independent dependency evidence helps confirm whether an upgrade or compensating control is needed.' },
        evidence: `OSV-Scanner matched ${vuln.id || 'an advisory'} for ${pkg.package?.name || 'a dependency'}.`,
      }, context));
    }
  }
  return findings;
}

module.exports = parseOsvScanner;
