const TOOL_ORDER = ['gitleaks', 'trufflehog', 'semgrep', 'osv-scanner', 'trivy', 'checkov', 'zap', 'nuclei', 'strix'];

function isLocalTarget(value) {
  if (!value) return false;
  try {
    const url = new URL(value);
    return url.protocol === 'http:' && ['localhost', '127.0.0.1', '0.0.0.0'].includes(url.hostname);
  } catch { return false; }
}

function selectTools({ categories, risk, requiredTools, webTarget }) {
  const values = new Set(categories || []);
  const decisions = new Map();
  const add = (tool, decision, reason) => {
    const current = decisions.get(tool);
    const rank = { NOT_APPLICABLE: 0, SKIPPED: 1, RECOMMENDED: 2, RUN: 3, BLOCKED: 4 };
    if (!current || rank[decision] > rank[current.decision]) decisions.set(tool, { tool, decision, reason });
  };

  for (const tool of requiredTools) add(tool, 'RUN', 'Required by a mandatory policy.');
  if (values.has('UI_CHANGE') || values.has('GENERAL_BACKEND_CHANGE') || values.has('UNKNOWN_CHANGE')) add('semgrep', 'RUN', 'Source code changed; static analysis is relevant.');
  if (risk === 'HIGH') add('trufflehog', 'RUN', 'High-risk change receives a second secret detector.');
  if (values.has('DEPENDENCY_CHANGE')) { add('osv-scanner', 'RUN', 'Dependency manifest or lockfile changed.'); add('trivy', 'RUN', 'Dependency graph changed; filesystem vulnerability scan is relevant.'); }
  if (values.has('CONTAINER_CHANGE')) add('trivy', 'RUN', 'Container configuration changed.');
  if (values.has('IAC_CHANGE')) add('checkov', 'RUN', 'Infrastructure-as-code changed.');

  const runtimeRelevant = ['AUTH_CHANGE', 'API_CHANGE', 'DATABASE_CHANGE', 'PAYMENT_CHANGE', 'GENERAL_BACKEND_CHANGE'].some((category) => values.has(category));
  if (runtimeRelevant && isLocalTarget(webTarget)) {
    add('zap', 'RUN', `Authorized local runtime target available: ${webTarget}`);
    add('nuclei', 'RUN', `Authorized local runtime target available: ${webTarget}`);
  } else if (runtimeRelevant) {
    add('zap', 'SKIPPED', 'No authorized localhost runtime target is available.');
    add('nuclei', 'SKIPPED', 'No authorized localhost runtime target is available.');
  } else {
    add('zap', 'NOT_APPLICABLE', 'No runtime-relevant change was detected.');
    add('nuclei', 'NOT_APPLICABLE', 'No runtime-relevant change was detected.');
  }

  if (risk === 'HIGH') add('strix', 'RECOMMENDED', 'High-risk change may benefit from deep agentic validation; explicit authorization is still required.');
  else add('strix', 'SKIPPED', 'Deep agentic penetration testing is not required for this checkpoint.');

  for (const tool of TOOL_ORDER) {
    if (decisions.has(tool)) continue;
    if (tool === 'trufflehog') add(tool, 'SKIPPED', 'The second secret detector is reserved for high-risk automatic plans.');
    else if (tool === 'osv-scanner') add(tool, 'NOT_APPLICABLE', 'No dependency manifest or lockfile changed.');
    else if (tool === 'trivy') add(tool, 'NOT_APPLICABLE', 'No dependency, container, or IaC change was detected.');
    else if (tool === 'checkov') add(tool, 'NOT_APPLICABLE', 'No supported IaC change was detected.');
    else if (tool === 'semgrep') add(tool, 'RUN', 'Baseline source review for the automatic checkpoint.');
    else if (tool === 'gitleaks') add(tool, 'RUN', 'Mandatory secret baseline.');
  }
  return TOOL_ORDER.map((tool) => decisions.get(tool));
}

module.exports = { TOOL_ORDER, isLocalTarget, selectTools };
