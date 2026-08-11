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

const SCOPE_CONTROL_FILES = Object.freeze([
  '.vibe-code-guard.json',
  '.gitleaks.toml',
  '.gitleaksignore',
  '.semgrepignore',
  '.semgrep.yaml',
  '.semgrep.yml',
  'semgrep.yaml',
  'semgrep.yml',
  '.trivy.yaml',
  'trivy.yaml',
  '.trivyignore',
  '.trivyignore.yaml',
  '.checkov.yaml',
  '.checkov.yml',
  '.nuclei-ignore',
  'nuclei-ignore',
  '.osv-scanner.toml',
  'osv-scanner.toml',
]);

function projectScopeFingerprint(projectPath, targetFile = null, runtimeTarget = null) {
  const root = path.resolve(projectPath);
  const hash = crypto.createHash('sha256');
  for (const relative of SCOPE_CONTROL_FILES) {
    const absolute = path.join(root, relative);
    try {
      const stat = fs.lstatSync(absolute);
      if (stat.isSymbolicLink() || !stat.isFile() || stat.size > 1024 * 1024) return null;
      hash.update(`${relative}:FILE:${stat.size}:`);
      hash.update(fs.readFileSync(absolute));
      hash.update('\n');
    } catch (error) {
      if (error.code !== 'ENOENT') return null;
      hash.update(`${relative}:ABSENT\n`);
    }
  }
  if (targetFile) {
    const normalized = String(targetFile).replaceAll('\\', '/');
    const absolute = path.resolve(root, normalized);
    const inside = absolute !== root && absolute.startsWith(`${root}${path.sep}`);
    if (!inside) return null;
    try {
      const stat = fs.lstatSync(absolute);
      if (stat.isSymbolicLink() || !stat.isFile()) return null;
      hash.update(`target:${normalized}:FILE\n`);
    } catch { return null; }
  }
  hash.update(`runtime-target:${runtimeTarget || 'NONE'}\n`);
  return hash.digest('hex');
}

function familyForFinding(finding) {
  const category = String(finding?.category || '').toUpperCase().replaceAll(' ', '_');
  if (SCANNER_FAMILIES[category]) return SCANNER_FAMILIES[category];
  return [...new Set((finding?.observations || []).map((item) => item.scanner).filter((item) => KNOWN_SCANNERS.has(item)))];
}

function relevantScanners(finding) {
  const observed = (finding?.observations || []).map((item) => String(item.scanner || '').toLowerCase()).filter((item) => KNOWN_SCANNERS.has(item));
  const family = familyForFinding(finding);
  const scanners = [...new Set([...observed, ...family])].filter((item) => KNOWN_SCANNERS.has(item));
  return scanners;
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
    baselineScopeFingerprint: finding?.scopeFingerprint || null,
    manualReviewRequired: scanners.length === 0,
    reason: runtime && !webTarget ? 'Runtime verification requires an authorized localhost or explicitly allowlisted test target.' : scanners.length === 0 ? 'No deterministic scanner mapping exists for this finding; manual review is required.' : 'The plan runs only scanners relevant to the correlated finding family.',
  };
}

function verificationCoverage(plan, tools, { webTarget = null, currentScopeFingerprint = null } = {}) {
  const results = plan.relevantScanners.map((scanner) => ({
    scanner,
    status: tools?.[scanner]?.status || 'MISSING',
    decision: tools?.[scanner]?.decision || 'RUN',
    exitCode: tools?.[scanner]?.exitCode ?? null,
    findingsCount: tools?.[scanner]?.findingsCount ?? null,
    version: tools?.[scanner]?.version || null,
    versionKnown: Boolean(tools?.[scanner]?.version),
    parseValid: tools?.[scanner]?.parseValid === true,
    reason: tools?.[scanner]?.error || tools?.[scanner]?.decisionReason || null,
  }));
  const targetRequired = plan.relevantScanners.some((scanner) => ['zap', 'nuclei'].includes(scanner));
  const inScope = !targetRequired || Boolean(webTarget);
  const targetMatches = !targetRequired || plan.target === webTarget;
  const scopeBaselineAvailable = Boolean(plan.baselineScopeFingerprint);
  const scopeUnchanged = scopeBaselineAvailable && Boolean(currentScopeFingerprint) && plan.baselineScopeFingerprint === currentScopeFingerprint;
  const complete = inScope && targetMatches && !plan.manualReviewRequired && scopeUnchanged && results.length > 0 && results.every((result) => result.status === 'PASS' && result.decision === 'RUN' && result.parseValid && result.versionKnown);
  const reason = !inScope
    ? 'The required runtime target was not authorized or supplied.'
    : !targetMatches
      ? 'The runtime target changed after the verification plan was created.'
    : !scopeBaselineAvailable
      ? 'The finding has no baseline scanner-scope fingerprint; verification is incomplete.'
      : !scopeUnchanged
        ? 'Scanner configuration, ignore scope, or the target file changed since the finding was recorded.'
        : complete ? 'All relevant scanners completed successfully with known versions, valid structured output, and unchanged scope.' : 'One or more relevant scanners were skipped, failed, degraded, malformed, missing, or did not report a version.';
  return { complete, inScope, targetMatches, scopeBaselineAvailable, scopeUnchanged, results, reason };
}

function verificationOutcome({ finding, updatedFinding, coverage }) {
  const verifiedWithVersions = Object.fromEntries((coverage.results || []).map((result) => [result.scanner, result.version]));
  if (!coverage.complete) return { verification: 'VERIFICATION_INCOMPLETE', lifecycle: updatedFinding?.status || finding?.status || 'OPEN', verifiedWithVersions, reason: coverage.reason };
  if (updatedFinding?.status === 'VERIFIED') return { verification: 'PASSED', lifecycle: 'VERIFIED', verifiedWithVersions, reason: 'The relevant scanners completed successfully and did not report the correlated finding.' };
  return { verification: 'STILL_DETECTED', lifecycle: updatedFinding?.status || 'OPEN', verifiedWithVersions, reason: 'The relevant scanners completed successfully but reported the correlated finding again.' };
}

module.exports = {
  KNOWN_SCANNERS,
  SCANNER_FAMILIES,
  familyForFinding,
  projectScopeFingerprint,
  relevantScanners,
  verificationCoverage,
  verificationOutcome,
  verificationPlan,
};
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
