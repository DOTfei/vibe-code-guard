const POLICIES = [
  { id: 'BASELINE-001', when: ['*'], require: ['gitleaks'], reason: 'Secret detection is mandatory for every automatic checkpoint.' },
  { id: 'UI-001', when: ['UI_CHANGE'], require: ['semgrep'], reason: 'Changed UI/source files receive lightweight static analysis.' },
  { id: 'DEP-001', when: ['DEPENDENCY_CHANGE'], require: ['osv-scanner', 'trivy'], reason: 'The dependency graph changed.' },
  { id: 'AUTH-001', when: ['AUTH_CHANGE'], require: ['gitleaks', 'semgrep'], reason: 'Authentication-sensitive code changed.' },
  { id: 'API-001', when: ['API_CHANGE'], require: ['semgrep'], reason: 'An API or request-handling surface changed.' },
  { id: 'DB-001', when: ['DATABASE_CHANGE'], require: ['gitleaks', 'semgrep'], reason: 'Database schema, migration, or authorization policy changed.' },
  { id: 'PAY-001', when: ['PAYMENT_CHANGE'], require: ['gitleaks', 'semgrep'], reason: 'Payment or billing logic changed.' },
  { id: 'CONTAINER-001', when: ['CONTAINER_CHANGE'], require: ['trivy'], reason: 'Container configuration changed.' },
  { id: 'IAC-001', when: ['IAC_CHANGE'], require: ['checkov', 'trivy'], reason: 'Infrastructure-as-code changed.' },
  { id: 'CONFIG-001', when: ['CONFIG_CHANGE'], require: ['gitleaks'], reason: 'Configuration or environment-sensitive files changed.' },
  { id: 'CI-001', when: ['CI_CD_CHANGE'], require: ['gitleaks', 'semgrep'], reason: 'CI/CD automation changed.' },
];

function evaluatePolicies(classification) {
  const categories = new Set(classification.categories || []);
  const fired = POLICIES.filter((policy) => policy.when.includes('*') || policy.when.some((category) => categories.has(category)));
  const requiredTools = [...new Set(fired.flatMap((policy) => policy.require))];
  return { fired, requiredTools };
}

module.exports = { POLICIES, evaluatePolicies };
