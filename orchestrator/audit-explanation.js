function buildAuditExplanation(plan) {
  const lines = [];
  lines.push(`${plan.risk} change risk: ${plan.categories.join(', ')}.`);
  lines.push(`Change source: ${plan.changeSet.source}. ${plan.changeSet.note}`);
  for (const policy of plan.policies) lines.push(`${policy.id} fired: ${policy.reason}`);
  for (const item of plan.tools) {
    if (item.decision === 'RUN') lines.push(`${item.tool} selected: ${item.reason}`);
    else if (item.decision === 'RECOMMENDED') lines.push(`${item.tool} recommended but not executed: ${item.reason}`);
    else lines.push(`${item.tool} ${item.decision.toLowerCase()}: ${item.reason}`);
  }
  return lines;
}

module.exports = { buildAuditExplanation };
