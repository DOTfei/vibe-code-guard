const RISK_ORDER = ['LOW', 'MEDIUM', 'HIGH'];
const RISK_RULES = {
  HIGH: new Set(['AUTH_CHANGE', 'PAYMENT_CHANGE', 'DATABASE_CHANGE', 'CONFIG_CHANGE']),
  MEDIUM: new Set(['DEPENDENCY_CHANGE', 'API_CHANGE', 'CONTAINER_CHANGE', 'IAC_CHANGE', 'CI_CD_CHANGE', 'GENERAL_BACKEND_CHANGE', 'UNKNOWN_CHANGE']),
  LOW: new Set(['UI_CHANGE']),
};

function classifyRisk(categories) {
  const values = new Set(categories || []);
  for (const risk of [...RISK_ORDER].reverse()) {
    if ([...RISK_RULES[risk]].some((category) => values.has(category))) return risk;
  }
  return 'MEDIUM';
}

module.exports = { RISK_ORDER, RISK_RULES, classifyRisk };
