const { detectChanges } = require('./change-detector');
const { classifyChanges } = require('./change-classifier');
const { evaluatePolicies } = require('./policy-engine');
const { classifyRisk } = require('./risk-engine');
const { selectTools } = require('./tool-selector');
const { buildAuditExplanation } = require('./audit-explanation');

function buildExecutionPlan({ projectPath, webTarget = null, detectedChanges = null }) {
  const changeSet = detectedChanges || detectChanges(projectPath);
  const classification = classifyChanges(changeSet);
  const policyResult = evaluatePolicies(classification);
  const risk = classifyRisk(classification.categories);
  const tools = selectTools({
    categories: classification.categories,
    risk,
    requiredTools: policyResult.requiredTools,
    webTarget,
  });
  const plan = {
    version: '1.0.0',
    projectPath,
    generatedAt: new Date().toISOString(),
    changeSet,
    categories: classification.categories,
    fileClassifications: classification.fileClassifications,
    risk,
    policies: policyResult.fired,
    tools,
    summary: {
      selected: tools.filter((tool) => tool.decision === 'RUN').length,
      skipped: tools.filter((tool) => tool.decision === 'SKIPPED').length,
      notApplicable: tools.filter((tool) => tool.decision === 'NOT_APPLICABLE').length,
      recommended: tools.filter((tool) => tool.decision === 'RECOMMENDED').length,
      blocked: tools.filter((tool) => tool.decision === 'BLOCKED').length,
    },
    webTarget,
  };
  plan.explanation = buildAuditExplanation(plan);
  return plan;
}

module.exports = { buildExecutionPlan };
