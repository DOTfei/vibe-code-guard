#!/usr/bin/env node

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { normalizePersistedFindings } = require('../core/findings');
const { reconcileFindings } = require('../core/correlation');
const { buildReviewContext, createProvider, generateFindingReview } = require('../core/ai');

function parseArgs(argv) {
  const options = { json: false, runDir: null, findingId: null, allowCodeSnippet: false, codeSnippet: '', codeFile: '' };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--run-dir') options.runDir = argv[++index];
    else if (arg === '--finding') options.findingId = argv[++index];
    else if (arg === '--json') options.json = true;
    else if (arg === '--allow-code-snippet') options.allowCodeSnippet = true;
    else if (arg === '--code-snippet') options.codeSnippet = argv[++index] || '';
    else if (arg === '--code-file') options.codeFile = argv[++index] || '';
    else if (arg === '--help' || arg === '-h') options.help = true;
  }
  return options;
}

function safeRunDirectory(input) {
  if (typeof input !== 'string' || !input.trim() || input.includes('\0') || input.includes('://')) throw new Error('Run directory must be a local path.');
  const root = path.resolve(process.env.SECURITY_DASHBOARD_DATA_DIR || path.join(process.env.SECURITY_TOOLKIT_HOME || path.join(os.homedir(), 'security-toolkit'), 'runs'));
  const realRoot = fs.realpathSync(root);
  const candidate = path.resolve(input);
  if (!/^[0-9]{14}-[a-f0-9]{6}$/.test(path.basename(candidate)) || path.dirname(candidate) !== root) throw new Error('Run directory must be a direct child run of the configured dashboard data directory.');
  const stat = fs.lstatSync(candidate);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('Run directory must be a real local directory.');
  const realCandidate = fs.realpathSync(candidate);
  if (path.dirname(realCandidate) !== realRoot) throw new Error('Run directory symlink escape was rejected.');
  return realCandidate;
}

function safeFindingId(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_.:-]{1,200}$/.test(value)) throw new Error('Finding ID is invalid.');
  return value;
}

function validateProjectMetadata(metadata) {
  if (typeof metadata.projectPath !== 'string' || !metadata.projectPath || metadata.projectPath.includes('\0') || metadata.projectPath.includes('://') || !path.isAbsolute(metadata.projectPath)) throw new Error('Stored project path is invalid.');
}

function readJSON(filePath) {
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

async function runAIReviewCLI(argv = []) {
  const options = parseArgs(argv);
  if (options.help || !options.runDir || !options.findingId) {
    console.log('Usage: node orchestrator/cli.js ai-review --run-dir <run-directory> --finding <finding-id> [--json] [--allow-code-snippet --code-file <reported-file> --code-snippet <text>]');
    return options.help ? 0 : 1;
  }
  try {
    const runDir = safeRunDirectory(options.runDir);
    const metadata = readJSON(path.join(runDir, 'metadata.json'));
    validateProjectMetadata(metadata);
    if (metadata.id && metadata.id !== path.basename(runDir)) throw new Error('Run metadata ID does not match the run directory.');
    const findingId = safeFindingId(options.findingId);
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
    const finding = correlatedFindings.find((item) => item.id === findingId);
    if (!finding) throw new Error(`Correlated finding not found: ${findingId}`);
    const context = buildReviewContext({
      finding,
      rawFindings: findings,
      stack: metadata.stack || [],
      lifecycleStatus: finding.status,
      releaseGate: metadata.releaseGate || {},
      allowCodeSnippet: options.allowCodeSnippet,
      codeSnippet: options.codeSnippet,
      codeFile: options.codeFile,
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

module.exports = { parseArgs, runAIReviewCLI, safeFindingId, safeRunDirectory, validateProjectMetadata };
