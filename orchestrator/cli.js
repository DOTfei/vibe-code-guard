#!/usr/bin/env node

const path = require('node:path');
const { buildExecutionPlan } = require('./index');
const { runAIReviewCLI } = require('./ai-review-cli');

function parseArgs(argv) {
  const options = { target: '.', webTarget: null, json: false };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--target' || arg === '-t') options.target = argv[++index];
    else if (arg === '--web-target') options.webTarget = argv[++index];
    else if (arg === '--json') options.json = true;
    else if (arg === '--help' || arg === '-h') options.help = true;
  }
  return options;
}

function humanPlan(plan) {
  const lines = [
    'Vibe Code Guard v0.4.0-alpha',
    `Target: ${plan.projectPath}`,
    `Change source: ${plan.changeSet.source}`,
    `Categories: ${plan.categories.join(', ')}`,
    `Risk: ${plan.risk}`,
    `Tools: ${plan.summary.selected} selected, ${plan.summary.skipped} skipped, ${plan.summary.notApplicable} not applicable, ${plan.summary.recommended} recommended`,
    '',
    'Policies:',
    ...plan.policies.map((policy) => `- ${policy.id}: ${policy.reason}`),
    '',
    'Tool decisions:',
    ...plan.tools.map((tool) => `- ${tool.tool}: ${tool.decision} — ${tool.reason}`),
    '',
    'Explanation:',
    ...plan.explanation.map((line) => `- ${line}`),
  ];
  return lines.join('\n');
}

function main() {
  const argv = process.argv.slice(2);
  if (argv[0] === 'ai-review') return runAIReviewCLI(argv.slice(1));
  const options = parseArgs(argv);
  if (options.help) {
    console.log('Usage: node orchestrator/cli.js --target <project> [--web-target http://127.0.0.1:3000] [--json]');
    return 0;
  }
  const target = path.resolve(options.target || '.');
  const plan = buildExecutionPlan({ projectPath: target, webTarget: options.webTarget });
  console.log(options.json ? JSON.stringify(plan, null, 2) : humanPlan(plan));
  return 0;
}

try {
  const result = main();
  if (result && typeof result.then === 'function') {
    result.then((code) => { process.exitCode = code; }).catch((error) => {
      console.error(`Unable to build security plan: ${error.message}`);
      process.exitCode = 1;
    });
  } else process.exitCode = result;
} catch (error) {
  console.error(`Unable to build security plan: ${error.message}`);
  process.exitCode = 1;
}
