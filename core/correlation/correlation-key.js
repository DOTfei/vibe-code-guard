const crypto = require('node:crypto');
const { normalizeCategory } = require('../findings/category');
const { normalizePath } = require('../findings/fingerprint');
const { normalizeText } = require('../findings/fingerprint');

const KNOWN_SECRET_FAMILIES = [
  ['stripe', /stripe|sk_(?:live|test)|publishable[_ -]?key/i],
  ['aws', /aws|access[_ -]?key|secret[_ -]?access/i],
  ['github', /github|gh[pousr]_/i],
  ['slack', /slack|xox[baprs]-/i],
  ['google', /google|gcp|AIza/i],
  ['azure', /azure/i],
  ['private-key', /private[_ -]?key|pem|rsa|openssh/i],
  ['generic', /generic|credential|secret|token|api[_ -]?key|password/i],
];

const KNOWN_RULE_FAMILIES = [
  ['sql-injection', /sql[_ -]?injection|sqli/i],
  ['command-injection', /command[_ -]?injection|os[._ -]?system|shell/i],
  ['xss', /cross[_ -]?site[_ -]?scripting|\bxss\b/i],
  ['ssrf', /\bssrf\b|server[_ -]?side[_ -]?request/i],
  ['csrf', /\bcsrf\b|cross[_ -]?site[_ -]?request[_ -]?forgery/i],
  ['auth', /auth(?:entication|orization)|idor|access[_ -]?control|ownership/i],
  ['tls', /tls|ssl|certificate/i],
];

function normalizeEndpoint(value) {
  if (!value) return '';
  try {
    const parsed = new URL(String(value));
    const pathname = parsed.pathname.replace(/\/+/g, '/').replace(/\/$/, '') || '/';
    const parameters = [...new Set([...parsed.searchParams.keys()].map((key) => normalizeText(key)).filter(Boolean))].sort();
    return `${parsed.hostname.toLowerCase()}${pathname.toLowerCase()}${parameters.length ? `?${parameters.join('&')}` : ''}`;
  } catch {
    return normalizeText(value).replace(/\/$/, '');
  }
}

function extractIdentifier(values) {
  const text = values.filter(Boolean).join(' ');
  const matches = text.match(/\b(?:CVE-\d{4}-[A-Z0-9-]+|GHSA-[A-Z0-9-]+|OSV-[A-Z0-9-]+)\b/ig) || [];
  return matches.map((value) => value.toUpperCase())[0] || null;
}

function extractPackageName(finding, values) {
  const explicit = finding.packageName || finding.package || finding.metadata?.packageName || finding.correlationMetadata?.packageName;
  if (explicit) return normalizeText(explicit);
  const text = values.filter(Boolean).join(' ');
  const labelled = text.match(/(?:package|pkg(?:name)?|dependency)\s*[:=/]\s*([@a-z0-9][a-z0-9._/@-]*)/i);
  if (labelled) return normalizeText(labelled[1]);
  const versioned = text.match(/\b([@a-z0-9][a-z0-9._/@-]*)\s+v?\d+\.\d+(?:\.\d+)?\b/i);
  return versioned ? normalizeText(versioned[1]) : null;
}

function extractPackageVersion(finding, values) {
  const explicit = finding.installedVersion || finding.version || finding.metadata?.installedVersion || finding.correlationMetadata?.installedVersion;
  if (explicit) return normalizeText(explicit);
  const text = values.filter(Boolean).join(' ');
  const versioned = text.match(/\b(?:[@a-z0-9][a-z0-9._/@-]*)\s+v?(\d+\.\d+(?:\.\d+)?)\b/i);
  return versioned ? normalizeText(versioned[1]) : null;
}

function inferEcosystem(finding, file) {
  const explicit = finding.ecosystem || finding.metadata?.ecosystem || finding.correlationMetadata?.ecosystem;
  if (explicit) return normalizeText(explicit);
  if (/package(-lock)?\.json|yarn\.lock|pnpm-lock\.yaml/.test(file || '')) return 'npm';
  if (/requirements\.txt|pyproject\.toml|poetry\.lock/.test(file || '')) return 'pypi';
  if (/go\.sum|go\.mod/.test(file || '')) return 'go';
  if (/cargo\.lock|cargo\.toml/.test(file || '')) return 'crates.io';
  return null;
}

function deriveSecretFamily(finding, values) {
  const explicit = finding.secretType || finding.metadata?.secretType || finding.correlationMetadata?.secretType;
  const text = [explicit, finding.scanner?.ruleId, finding.title].filter(Boolean).join(' ');
  for (const [family, pattern] of KNOWN_SECRET_FAMILIES) if (pattern.test(text)) return family;
  return normalizeText(explicit || finding.scanner?.ruleId || finding.title).replace(/[^a-z0-9]+/g, '-') || 'unknown';
}

function deriveRuleFamily(finding, values) {
  const explicit = finding.ruleFamily || finding.metadata?.ruleFamily || finding.correlationMetadata?.ruleFamily;
  const text = [explicit, finding.scanner?.ruleId, finding.title].filter(Boolean).join(' ');
  for (const [family, pattern] of KNOWN_RULE_FAMILIES) if (pattern.test(text)) return family;
  return normalizeText(explicit || finding.scanner?.ruleId || finding.title).replace(/[^a-z0-9]+/g, '-') || 'unknown';
}

function deriveIdentity(finding = {}, context = {}) {
  const location = finding.location || {};
  const category = normalizeCategory(finding.category, `${finding.title || ''} ${finding.scanner?.ruleId || ''}`);
  const values = [finding.title, finding.explanation?.technical, finding.explanation?.simple, finding.scanner?.ruleId];
  const file = normalizePath(location.file || '', context.projectPath);
  const endpoint = normalizeEndpoint(location.endpoint || '');
  const line = Number.isInteger(location.line) && location.line > 0 ? location.line : null;
  const scanner = String(finding.scanner?.id || 'unknown').toLowerCase();
  const vulnerabilityId = finding.vulnerabilityId || finding.metadata?.vulnerabilityId || finding.correlationMetadata?.vulnerabilityId || extractIdentifier(values);
  const packageName = extractPackageName(finding, values);
  const installedVersion = extractPackageVersion(finding, values);
  let kind = 'generic';
  if (category === 'SECRET_EXPOSURE') kind = 'secret';
  else if (category === 'DEPENDENCY_VULNERABILITY') kind = 'dependency';
  else if (endpoint || category === 'RUNTIME' || ['zap', 'nuclei'].includes(scanner)) kind = 'runtime';
  else if (['semgrep', 'checkov'].includes(scanner) || file) kind = 'static';
  return {
    kind,
    category,
    file: file || null,
    line,
    endpoint: endpoint || null,
    method: normalizeText(finding.method || finding.metadata?.method || finding.correlationMetadata?.method) || null,
    parameter: normalizeText(finding.parameter || finding.metadata?.parameter || finding.correlationMetadata?.parameter) || null,
    secretFamily: kind === 'secret' ? deriveSecretFamily(finding, values) : null,
    vulnerabilityId: vulnerabilityId ? normalizeText(vulnerabilityId).toUpperCase() : null,
    packageName: packageName || null,
    installedVersion: installedVersion || null,
    ecosystem: kind === 'dependency' ? inferEcosystem(finding, file) : null,
    ruleFamily: deriveRuleFamily(finding, values),
  };
}

function locationMatches(left, right) {
  if (left.endpoint || right.endpoint) return Boolean(left.endpoint && right.endpoint && left.endpoint === right.endpoint && (!left.method || !right.method || left.method === right.method) && (!left.parameter || !right.parameter || left.parameter === right.parameter));
  if (!left.file || !right.file || left.file !== right.file) return false;
  return !left.line || !right.line || left.line === right.line;
}

function secretFamiliesCompatible(left, right) {
  if (!left || !right) return false;
  return left === right || left === 'generic' || right === 'generic';
}

function comparable(input = {}, context = {}) {
  if (input.identity) {
    return {
      scannerId: String(input.scannerId || input.scanner?.id || input.scanner || 'unknown').toLowerCase(),
      fingerprint: input.fingerprint || null,
      ruleId: normalizeText(input.ruleId || input.scanner?.ruleId || ''),
      category: normalizeCategory(input.category, ''),
      identity: input.identity,
    };
  }
  return {
    scannerId: String(input.scanner?.id || input.scanner || 'unknown').toLowerCase(),
    fingerprint: input.fingerprint || null,
    ruleId: normalizeText(input.scanner?.ruleId || input.ruleId || ''),
    category: normalizeCategory(input.category, `${input.title || ''} ${input.scanner?.ruleId || ''}`),
    identity: deriveIdentity(input, context),
  };
}

function compareEvidence(leftInput, rightInput, context = {}) {
  const left = comparable(leftInput, context);
  const right = comparable(rightInput, context);
  if (left.scannerId === right.scannerId && left.fingerprint && left.fingerprint === right.fingerprint) return 'EXACT';
  if (left.category !== right.category) return 'NONE';
  if (left.identity.kind === 'dependency' && right.identity.kind === 'dependency') {
    const ecosystemMatches = !left.identity.ecosystem || !right.identity.ecosystem || left.identity.ecosystem === right.identity.ecosystem;
    const versionMatches = !left.identity.installedVersion || !right.identity.installedVersion || left.identity.installedVersion === right.identity.installedVersion;
    if (left.identity.vulnerabilityId && right.identity.vulnerabilityId && left.identity.vulnerabilityId === right.identity.vulnerabilityId && left.identity.packageName && right.identity.packageName && left.identity.packageName === right.identity.packageName && ecosystemMatches && versionMatches) return 'HIGH';
    return 'MEDIUM';
  }
  if (!locationMatches(left.identity, right.identity)) return 'NONE';
  if (left.identity.kind === 'secret' && right.identity.kind === 'secret') {
    if (secretFamiliesCompatible(left.identity.secretFamily, right.identity.secretFamily) && (!left.identity.line || !right.identity.line || left.identity.line === right.identity.line)) return 'HIGH';
    return 'MEDIUM';
  }
  if (left.identity.kind === 'static' && right.identity.kind === 'static') {
    if (left.identity.ruleFamily !== 'unknown' && left.identity.ruleFamily === right.identity.ruleFamily && left.identity.line && right.identity.line && left.identity.line === right.identity.line) return 'HIGH';
    return 'MEDIUM';
  }
  if (left.identity.kind === 'runtime' && right.identity.kind === 'runtime') {
    if (left.identity.ruleFamily !== 'unknown' && left.identity.ruleFamily === right.identity.ruleFamily) return 'HIGH';
    return 'MEDIUM';
  }
  if (left.identity.ruleFamily !== 'unknown' && left.identity.ruleFamily === right.identity.ruleFamily) return 'HIGH';
  return 'MEDIUM';
}

function buildCorrelationKey(finding, context = {}) {
  const identity = deriveIdentity(finding, context);
  const stable = [identity.kind, identity.category, identity.file || '', identity.line || '', identity.endpoint || '', identity.method || '', identity.parameter || '', identity.secretFamily || '', identity.vulnerabilityId || '', identity.packageName || '', identity.installedVersion || '', identity.ecosystem || '', identity.ruleFamily || ''].join('|');
  return crypto.createHash('sha256').update(stable).digest('hex');
}

function scannerFingerprintKey(finding) {
  return `${String(finding.scanner?.id || 'unknown').toLowerCase()}|${finding.fingerprint || ''}`;
}

module.exports = {
  buildCorrelationKey,
  comparable,
  compareEvidence,
  deriveIdentity,
  extractIdentifier,
  extractPackageName,
  extractPackageVersion,
  normalizeEndpoint,
  locationMatches,
  scannerFingerprintKey,
};
