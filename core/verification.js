const SCANNER_FAMILIES = Object.freeze({
  SECRET_EXPOSURE: ['gitleaks', 'trufflehog'],
  DEPENDENCY_VULNERABILITY: ['osv-scanner', 'trivy'],
  INJECTION: ['semgrep'],
  AUTHORIZATION: ['semgrep'],
  CONFIGURATION: ['checkov', 'trivy'],
  INFRASTRUCTURE: ['checkov', 'trivy'],
  RUNTIME: ['zap', 'nuclei'],
});

const KNOWN_SCANNERS = new Set(['gitleaks', 'trufflehog', 'semgrep', 'trivy', 'osv-scanner', 'checkov', 'zap', 'nuclei']);

function familyForFinding(finding) {
  const category = String(finding?.category || '').toUpperCase().replaceAll(' ', '_');
  if (SCANNER_FAMILIES[category]) return SCANNER_FAMILIES[category];
  const text = `${finding?.title || ''} ${finding?.category || ''}`.toLowerCase();
  if (/secret|credential|token|key/.test(text)) return SCANNER_FAMILIES.SECRET_EXPOSURE;
  if (/cve|dependency|package|library|vulnerability/.test(text)) return SCANNER_FAMILIES.DEPENDENCY_VULNERABILITY;
  if (/terraform|docker|iac|infrastructure|configuration/.test(text)) return SCANNER_FAMILIES.CONFIGURATION;
  if (/endpoint|runtime|web|http/.test(text)) return SCANNER_FAMILIES.RUNTIME;
  return [...new Set((finding?.observations || []).map((item) => item.scanner).filter((item) => KNOWN_SCANNERS.has(item)))];
}

function relevantScanners(finding) {
  const observed = (finding?.observations || []).map((item) => String(item.scanner || '').toLowerCase()).filter((item) => KNOWN_SCANNERS.has(item));
  const family = familyForFinding(finding);
  const scanners = [...new Set([...observed, ...family])].filter((item) => KNOWN_SCANNERS.has(item));
  return scanners.length ? scanners : ['semgrep'];
}

function verificationPlan(finding, { webTarget = null } = {}) {
  const scanners = relevantScanners(finding);
  const runtime = scanners.some((scanner) => ['zap', 'nuclei'].includes(scanner));
  return {
    findingId: finding?.id || null,
    relevantScanners: scanners,
    target: runtime ? webTarget : null,
    scope: runtime && !webTarget ? 'OUT_OF_SCOPE' : 'LOCAL_PROJECT',
    authorizationRequired: runtime && !webTarget,
    reason: runtime && !webTarget ? 'Runtime verification requires an authorized localhost or explicitly allowlisted test target.' : 'The plan runs only scanners relevant to the correlated finding family.',
  };
}

function verificationCoverage(plan, tools, { webTarget = null } = {}) {
  const results = plan.relevantScanners.map((scanner) => ({
    scanner,
    status: tools?.[scanner]?.status || 'MISSING',
    decision: tools?.[scanner]?.decision || 'RUN',
    exitCode: tools?.[scanner]?.exitCode ?? null,
    findingsCount: tools?.[scanner]?.findingsCount ?? null,
    reason: tools?.[scanner]?.error || tools?.[scanner]?.decisionReason || null,
  }));
  const targetRequired = plan.relevantScanners.some((scanner) => ['zap', 'nuclei'].includes(scanner));
  const inScope = !targetRequired || Boolean(webTarget);
  const complete = inScope && results.length > 0 && results.every((result) => result.status === 'PASS' && result.decision === 'RUN');
  return { complete, inScope, results, reason: !inScope ? 'The required runtime target was not authorized or supplied.' : complete ? 'All relevant scanners completed successfully.' : 'One or more relevant scanners were skipped, failed, degraded, or missing.' };
}

function verificationOutcome({ finding, updatedFinding, coverage }) {
  if (!coverage.complete) return { verification: 'VERIFICATION_INCOMPLETE', lifecycle: updatedFinding?.status || finding?.status || 'OPEN', reason: coverage.reason };
  if (updatedFinding?.status === 'VERIFIED') return { verification: 'PASSED', lifecycle: 'VERIFIED', reason: 'The relevant scanners completed successfully and did not report the correlated finding.' };
  return { verification: 'STILL_DETECTED', lifecycle: updatedFinding?.status || 'OPEN', reason: 'The relevant scanners completed successfully but reported the correlated finding again.' };
}

module.exports = {
  KNOWN_SCANNERS,
  SCANNER_FAMILIES,
  familyForFinding,
  relevantScanners,
  verificationCoverage,
  verificationOutcome,
  verificationPlan,
};
