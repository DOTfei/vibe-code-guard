const { parseJsonLoose } = require('../parsing');
const { createFinding } = require('../schema');

function parseTrivy(text, context) {
  const data = parseJsonLoose(text);
  const findings = [];
  for (const result of data?.Results || []) {
    for (const item of result.Vulnerabilities || []) findings.push(createFinding({
      scanner: { id: 'trivy', name: 'Trivy', ruleId: item.VulnerabilityID },
      severity: item.Severity,
      category: 'DEPENDENCY_VULNERABILITY',
      title: `${item.VulnerabilityID || 'Vulnerability'}: ${item.Title || item.PkgName || 'vulnerable dependency'}`,
      location: { type: 'file', file: result.Target || item.PkgName || 'dependency manifest' },
      explanation: {
        technical: `${item.PkgName || 'Package'} ${item.InstalledVersion || ''} is associated with ${item.VulnerabilityID || 'a known vulnerability'}${item.FixedVersion ? `; fixed in ${item.FixedVersion}` : ''}.`,
        simple: 'A third-party component used by this project has a published security issue.',
        whyItMatters: item.FixedVersion ? `Upgrade or otherwise remove the affected path. A fixed version is available: ${item.FixedVersion}.` : 'Check the advisory and determine whether this component is reachable in the shipped artifact.',
      },
      evidence: `Trivy matched ${item.VulnerabilityID || 'a vulnerability'} in ${item.PkgName || 'a dependency'}.`,
      remediation: item.FixedVersion ? `Upgrade to ${item.FixedVersion} or a later fixed version.` : null,
    }, context));
    for (const item of result.Misconfigurations || []) findings.push(createFinding({
      scanner: { id: 'trivy', name: 'Trivy', ruleId: item.ID },
      severity: item.Severity,
      category: 'MISCONFIGURATION',
      title: `${item.ID || 'Configuration check'}: ${item.Title || 'Configuration issue'}`,
      location: { type: 'file', file: result.Target || 'configuration' },
      explanation: { technical: item.Description || item.Title || 'Trivy reported a configuration issue.', simple: 'A configuration setting may be more exposed than intended.', whyItMatters: item.Resolution || 'Secure configuration reduces unnecessary attack surface.' },
      evidence: `Trivy configuration check ${item.ID || 'matched'} reported a sanitized result.`,
      remediation: item.Resolution || null,
    }, context));
    for (const item of result.Secrets || []) findings.push(createFinding({
      scanner: { id: 'trivy', name: 'Trivy', ruleId: item.RuleID },
      severity: item.Severity || 'HIGH',
      category: 'SECRET_EXPOSURE',
      title: item.Title || item.RuleID || 'Potential secret detected',
      location: { type: 'file', file: result.Target || 'unknown', line: item.StartLine },
      explanation: { technical: `Trivy secret rule ${item.RuleID || 'matched'} reported a credential-like value. The matched value is redacted.`, simple: 'A file may contain a credential that should not be committed.', whyItMatters: 'Exposed credentials can grant unauthorized access to external services.' },
      evidence: `Trivy secret rule ${item.RuleID || 'matched'} reported a redacted result.`,
    }, context));
  }
  return findings;
}

module.exports = parseTrivy;
