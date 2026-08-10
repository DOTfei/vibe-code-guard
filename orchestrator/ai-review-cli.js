#!/usr/bin/env node

const fs = require('node:fs');
const path = require('node:path');
const { normalizePersistedFindings } = require('../core/findings');
const { reconcileFindings } = require('../core/correlation');
const { buildReviewContext, createProvider, generateFindingReview } = require('../core/ai');

function parseArgs(argv) {
  const options = { json: false, runDir: null, findingId: null, allowCodeSnippet: false, codeSnippet: '' };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--run-dir') options.runDir = argv[++index];
    else if (arg === '--finding') options.findingId = argv[++index];
    else if (arg === '--json') options.json = true;
    else if (arg === '--allow-code-snippet') options.allowCodeSnippet = true;
    else if (arg === '--code-snippet') options.codeSnippet = argv[++index] || '';
    else if (arg === '--help' || arg === '-h') options.help = true;
  }
  return options;
}

function readJSON(filePath) {
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

async function runAIReviewCLI(argv = []) {
  const options = parseArgs(argv);
  if (options.help || !options.runDir || !options.findingId) {
    console.log('Usage: node orchestrator/cli.js ai-review --run-dir <run-directory> --finding <finding-id> [--json] [--allow-code-snippet --code-snippet <text>]');
    return options.help ? 0 : 1;
  }
  const runDir = path.resolve(options.runDir);
  try {
    const metadata = readJSON(path.join(runDir, 'metadata.json'));
    const raw = readJSON(path.join(runDir, 'findings.json'));
    const findings = normalizePersistedFindings(raw, {
      runId: metadata.id || path.basename(runDir),
      projectPath: metadata.projectPath,
      startedAt: metadata.startedAt,
      observedAt: metadata.finishedAt || metadata.startedAt,
    });
    let correlation;
    try { correlation = readJSON(path.join(runDir, 'correlation.json')); } catch { correlation = reconcileFindings([], findings, { projectId: metadata.projectId, projectPath: metadata.projectPath, runId: metadata.id, startedAt: metadata.startedAt, observedAt: metadata.finishedAt }); }
    const correlatedFindings = correlation.findings || [];
    const finding = correlatedFindings.find((item) => item.id === options.findingId);
    if (!finding) throw new Error(`Correlated finding not found: ${options.findingId}`);
    const context = buildReviewContext({
      finding,
      rawFindings: findings,
      stack: metadata.stack || [],
      lifecycleStatus: finding.status,
      releaseGate: metadata.releaseGate || {},
      allowCodeSnippet: options.allowCodeSnippet,
      codeSnippet: options.codeSnippet,
    });
    const result = await generateFindingReview(context, { provider: createProvider() });
    if (options.json) console.log(JSON.stringify(result, null, 2));
    else {
      console.log(`AI Review: ${result.status}`);
      console.log(`Finding: ${result.findingId}`);
      console.log(`Provider: ${result.provider?.provider || 'unknown'} (${result.provider?.model || 'unknown'})`);
      if (result.review) console.log(`\n${result.review.summary}\n\n${result.review.plainLanguageExplanation}`);
      if (result.reason) console.log(`Reason: ${result.reason}`);
    }
    return result.status === 'FAILED' ? 1 : 0;
  } catch (error) {
    if (options.json) console.log(JSON.stringify({ status: 'FAILED', reason: error.message }, null, 2));
    else console.error(`AI review failed: ${error.message}`);
    return 1;
  }
}

if (require.main === module) runAIReviewCLI(process.argv.slice(2)).then((code) => { process.exitCode = code; });

module.exports = { parseArgs, runAIReviewCLI };
