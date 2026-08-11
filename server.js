#!/usr/bin/env node

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const net = require('node:net');
const { spawn } = require('node:child_process');
const { buildExecutionPlan } = require('./orchestrator');
const {
  SCHEMA_VERSION,
  adaptScannerOutput,
  countFindings,
  normalizePersistedFindings,
  parseJsonLoose,
  redact,
} = require('./core/findings');
const {
  CORRELATION_SCHEMA_VERSION,
  appendHistory,
  countBlockingCorrelatedFindings,
  countCorrelatedFindings,
  explicitLifecycleAction,
  projectIdentity,
  reconcileFindings,
} = require('./core/correlation');
const {
  projectScopeFingerprint,
  verificationCoverage,
  verificationOutcome,
  verificationPlan,
} = require('./core/verification');
const {
  checkUpdates,
  lifecycleStatus,
  refreshContent,
  updateTool,
  withToolLock,
} = require('./core/agent/tool-lifecycle');
const {
  AI_REVIEW_SCHEMA_VERSION,
  buildReviewContext,
  cachedReviewState,
  createProvider,
  generateFindingReview,
  generateSummaryReview,
  summaryContext,
} = require('./core/ai');

const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, 'public');
const TOOLKIT_HOME = process.env.SECURITY_TOOLKIT_HOME || path.join(os.homedir(), 'security-toolkit');
const HOST = '127.0.0.1';
const PORT = Number(process.env.PORT || 4567);

const TOOL_META = {
  gitleaks: { label: 'Gitleaks', purpose: 'Secret scanner', command: 'gitleaks' },
  trufflehog: { label: 'TruffleHog', purpose: 'Credential detector', command: 'trufflehog' },
  semgrep: { label: 'Semgrep', purpose: 'Source code security', command: 'semgrep' },
  trivy: { label: 'Trivy', purpose: 'Dependencies + config', command: 'trivy' },
  'osv-scanner': { label: 'OSV-Scanner', purpose: 'Dependency intelligence', command: 'osv-scanner' },
  checkov: { label: 'Checkov', purpose: 'Infrastructure config', command: 'checkov' },
  zap: { label: 'OWASP ZAP', purpose: 'Local web runtime', command: 'zap' },
  nuclei: { label: 'Nuclei', purpose: 'Authorized web templates', command: 'nuclei' },
};

const STAGE_META = [
  { id: 'discovery', label: 'Project discovery', description: 'Identify stack, manifests, entry points' },
  { id: 'threat-model', label: 'Threat model', description: 'Record trust boundaries and sensitive actions' },
  { id: 'secrets', label: 'Secrets', description: 'Find credentials without exposing them' },
  { id: 'static', label: 'Static analysis', description: 'Review dangerous code patterns' },
  { id: 'dependencies', label: 'Dependencies', description: 'Check known vulnerable components' },
  { id: 'infrastructure', label: 'Infrastructure', description: 'Inspect IaC and container configuration' },
  { id: 'web', label: 'Web / runtime', description: 'Scan only an authorized local target' },
  { id: 'manual', label: 'Manual security review', description: 'Human reasoning still required' },
  { id: 'fix', label: 'Fix', description: 'Apply and document root-cause fixes' },
  { id: 'rescan', label: 'Re-scan', description: 'Run the relevant scanner again' },
  { id: 'decision', label: 'Final decision', description: 'Release gate based on performed evidence' },
];

const COMMAND_ENV = {
  ...process.env,
  ...(process.env.SECURITY_TOOL_PATHS
    ? { PATH: `${process.env.SECURITY_TOOL_PATHS}${path.delimiter}${process.env.PATH || ''}` }
    : {}),
  SEMGREP_SEND_METRICS: 'off',
  SEMGREP_ENABLE_VERSION_CHECK: '0',
  DO_NOT_TRACK: '1',
  CI: '1',
};

function ensureDirectory(dir) {
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function writableDirectory(preferred, fallback) {
  try {
    ensureDirectory(preferred);
    fs.accessSync(preferred, fs.constants.W_OK);
    return preferred;
  } catch {
    ensureDirectory(fallback);
    return fallback;
  }
}

const DATA_DIR = writableDirectory(
  process.env.SECURITY_DASHBOARD_DATA_DIR || path.join(TOOLKIT_HOME, 'runs'),
  path.join(ROOT, 'runs'),
);
const PROJECT_INDEX_DIR = ensureDirectory(path.join(DATA_DIR, 'projects'));

const runs = new Map();
const subscribers = new Map();

function isoNow() {
  return new Date().toISOString();
}

function atomicWrite(filePath, value) {
  const temporary = `${filePath}.${process.pid}.tmp`;
  fs.writeFileSync(temporary, value, 'utf8');
  fs.renameSync(temporary, filePath);
}

function projectIndexPath(projectId) {
  return path.join(PROJECT_INDEX_DIR, projectId, 'findings-index.json');
}

function readProjectIndex(projectId) {
  try {
    const index = JSON.parse(fs.readFileSync(projectIndexPath(projectId), 'utf8'));
    return {
      schemaVersion: index.schemaVersion || CORRELATION_SCHEMA_VERSION,
      projectId,
      findings: Array.isArray(index.findings) ? index.findings : [],
    };
  } catch {
    return { schemaVersion: CORRELATION_SCHEMA_VERSION, projectId, findings: [] };
  }
}

function saveProjectIndex(index) {
  const filePath = projectIndexPath(index.projectId);
  ensureDirectory(path.dirname(filePath));
  atomicWrite(filePath, `${JSON.stringify({
    schemaVersion: CORRELATION_SCHEMA_VERSION,
    projectId: index.projectId,
    findings: index.findings,
  }, null, 2)}\n`);
}

function aiReviewStorePath(projectId) {
  return path.join(PROJECT_INDEX_DIR, projectId, 'ai-reviews.json');
}

function readAIReviewStore(projectId) {
  try {
    const stored = JSON.parse(fs.readFileSync(aiReviewStorePath(projectId), 'utf8'));
    return {
      schemaVersion: stored.schemaVersion || AI_REVIEW_SCHEMA_VERSION,
      projectId,
      reviews: stored.reviews && typeof stored.reviews === 'object' ? stored.reviews : {},
      summaries: stored.summaries && typeof stored.summaries === 'object' ? stored.summaries : {},
    };
  } catch {
    return { schemaVersion: AI_REVIEW_SCHEMA_VERSION, projectId, reviews: {}, summaries: {} };
  }
}

function saveAIReviewStore(store) {
  const filePath = aiReviewStorePath(store.projectId);
  ensureDirectory(path.dirname(filePath));
  atomicWrite(filePath, `${JSON.stringify({
    schemaVersion: AI_REVIEW_SCHEMA_VERSION,
    projectId: store.projectId,
    reviews: store.reviews,
    summaries: store.summaries,
  }, null, 2)}\n`);
}

function aiPrivacy() {
  const provider = createProvider();
  const external = provider.name === 'external';
  if (provider.name === 'mock') return {
    provider: provider.name,
    model: provider.model,
    externalProvider: false,
    notice: 'Mock / Test provider. Output is synthetic advisory text, not security evidence or a real AI assessment.',
  };
  return {
    provider: provider.name,
    model: provider.model,
    externalProvider: external,
    notice: external
      ? 'AI review uses an external provider. Only selected redacted security context/code snippets may leave this machine.'
      : 'AI review is local-first. No source code is uploaded while the provider is disabled or unavailable.',
  };
}

function rawFindingsForRun(run) {
  return [...(run.findings || []), ...(run.resolvedFindings || [])];
}

function findingReviewContext(run, finding, options = {}) {
  return buildReviewContext({
    finding,
    rawFindings: rawFindingsForRun(run),
    stack: run.stack || [],
    lifecycleStatus: finding.status,
    releaseGate: run.releaseGate,
    codeSnippet: options.codeSnippet,
    codeFile: options.codeFile,
    allowCodeSnippet: options.allowCodeSnippet === true,
  });
}

function aiReviewStateForFinding(run, finding, store = readAIReviewStore(run.projectId)) {
  const context = findingReviewContext(run, finding);
  const state = cachedReviewState(store.reviews[finding.id], context);
  return {
    status: state.status,
    findingId: finding.id,
    inputHash: context.inputHash,
    review: state.review || null,
    provider: state.provider || { provider: createProvider().name, model: createProvider().model },
    reason: state.reason || state.staleBecause || null,
    validationErrors: state.validationErrors || [],
    context: state.context || context.metadata,
    cacheHit: Boolean(state.cacheHit),
    privacy: aiPrivacy(),
  };
}

function aiReviewSummariesForRun(run) {
  const store = readAIReviewStore(run.projectId);
  return Object.fromEntries((run.correlatedFindings || []).map((finding) => [finding.id, aiReviewStateForFinding(run, finding, store)]));
}

function aiSummaryContextForRun(run, mode) {
  return summaryContext({
    mode,
    findings: run.correlatedFindings || [],
    releaseGate: run.releaseGate,
    stack: run.stack || [],
    runId: run.id,
    summary: run.summary,
  });
}

function aiSummaryStatesForRun(run) {
  const store = readAIReviewStore(run.projectId);
  return Object.fromEntries(['RUN_SUMMARY', 'RELEASE_REVIEW'].map((mode) => {
    const context = aiSummaryContextForRun(run, mode);
    const previous = store.summaries[mode];
    const state = previous && previous.inputHash === context.inputHash ? { ...previous, cacheHit: true } : previous ? { ...previous, status: 'STALE', staleBecause: 'Relevant deterministic run evidence changed.', cacheHit: false } : { status: 'NOT_GENERATED', mode, inputHash: context.inputHash };
    return [mode, { ...state, privacy: aiPrivacy() }];
  }));
}

function writeEvent(run, event) {
  const safeEvent = {
    schemaVersion: SCHEMA_VERSION,
    timestamp: isoNow(),
    ...event,
    message: redact(event.message || ''),
  };
  run.events.push(safeEvent);
  fs.appendFileSync(path.join(run.dir, 'events.jsonl'), `${JSON.stringify(safeEvent)}\n`, 'utf8');
  const listeners = subscribers.get(run.id) || [];
  for (const listener of listeners) listener(safeEvent);
}

function saveRun(run) {
  const persistedFindings = [...run.findings, ...run.resolvedFindings];
  const metadata = {
    schemaVersion: SCHEMA_VERSION,
    id: run.id,
    projectName: run.projectName,
    projectPath: run.projectPath,
    mode: run.mode,
    webTarget: run.webTarget || null,
    status: run.status,
    startedAt: run.startedAt,
    finishedAt: run.finishedAt || null,
    currentStage: run.currentStage,
    stages: run.stages,
    tools: run.tools,
    stack: run.stack,
    orchestration: run.orchestration || null,
    summary: run.summary,
    observationSummary: run.observationSummary || countFindings(run.findings),
    projectId: run.projectId,
    verification: run.verification || null,
    correlationSchemaVersion: CORRELATION_SCHEMA_VERSION,
    correlatedSummary: run.correlatedSummary || countCorrelatedFindings(run.correlatedFindings),
    releaseGate: run.releaseGate,
    dataDir: DATA_DIR,
  };
  atomicWrite(path.join(run.dir, 'metadata.json'), `${JSON.stringify(metadata, null, 2)}\n`);
  atomicWrite(path.join(run.dir, 'findings.json'), `${JSON.stringify(persistedFindings, null, 2)}\n`);
  atomicWrite(path.join(run.dir, 'correlation.json'), `${JSON.stringify({
    schemaVersion: CORRELATION_SCHEMA_VERSION,
    projectId: run.projectId,
    findings: run.correlatedFindings || [],
    suggestions: run.correlationSuggestions || [],
    summary: run.correlatedSummary || countCorrelatedFindings(run.correlatedFindings),
  }, null, 2)}\n`);
  atomicWrite(path.join(run.dir, 'tool-status.json'), `${JSON.stringify({ schemaVersion: SCHEMA_VERSION, tools: run.tools }, null, 2)}\n`);
  atomicWrite(path.join(run.dir, 'summary.json'), `${JSON.stringify({ schemaVersion: SCHEMA_VERSION, summary: run.summary, releaseGate: run.releaseGate, status: run.status }, null, 2)}\n`);
}

function createStages() {
  return STAGE_META.reduce((stages, stage) => {
    stages[stage.id] = {
      id: stage.id,
      label: stage.label,
      description: stage.description,
      status: 'WAITING',
      startedAt: null,
      finishedAt: null,
      note: '',
    };
    return stages;
  }, {});
}

function createTools() {
  return Object.entries(TOOL_META).reduce((tools, [id, meta]) => {
    tools[id] = {
      id,
      label: meta.label,
      purpose: meta.purpose,
      status: 'WAITING',
      version: null,
      startedAt: null,
      finishedAt: null,
      durationMs: null,
      findingsCount: 0,
      decision: 'RUN',
      decisionReason: '',
      exitCode: null,
      error: null,
    };
    return tools;
  }, {});
}

function createRun({ projectPath, mode, webTarget, verification = null }) {
  const orchestration = mode === 'auto' ? buildExecutionPlan({ projectPath, webTarget }) : null;
  const id = `${new Date().toISOString().replace(/[-:.TZ]/g, '').slice(0, 14)}-${crypto.randomBytes(3).toString('hex')}`;
  const dir = ensureDirectory(path.join(DATA_DIR, id));
  const tools = createTools();
  const project = projectIdentity(projectPath);
  try {
    const lock = JSON.parse(fs.readFileSync(path.join(TOOLKIT_HOME, 'security-toolchain.lock'), 'utf8'));
    for (const [toolId, tool] of Object.entries(lock.tools || {})) if (tools[toolId]) tools[toolId].version = tool.version || null;
  } catch { /* the toolkit health page reports missing lock data separately */ }
  if (orchestration) {
    for (const decision of orchestration.tools) {
      if (!tools[decision.tool]) continue;
      tools[decision.tool].decision = decision.decision;
      tools[decision.tool].decisionReason = decision.reason;
      if (decision.decision !== 'RUN') tools[decision.tool].status = decision.decision;
    }
  }
  const run = {
    id,
    projectId: project.id,
    dir,
    projectPath,
    projectName: path.basename(projectPath) || projectPath,
    mode,
    webTarget: webTarget || null,
    verification,
    status: 'SCANNING',
    startedAt: isoNow(),
    finishedAt: null,
    currentStage: 'discovery',
    stages: createStages(),
    tools,
    orchestration,
    stack: [],
    findings: [],
    resolvedFindings: [],
    correlatedFindings: [],
    correlationSuggestions: [],
    events: [],
    summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0, total: 0 },
    observationSummary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0, total: 0 },
    correlatedSummary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0, total: 0, observations: 0 },
    releaseGate: { label: 'DO NOT DEPLOY', reason: 'Assessment is still running.' },
    aiReviews: {},
    aiSummaryReviews: {},
    processes: new Set(),
    abortRequested: false,
  };
  runs.set(id, run);
  fs.writeFileSync(path.join(dir, 'events.jsonl'), '', 'utf8');
  saveRun(run);
  writeEvent(run, { kind: 'scan-started', message: `Scan started: ${run.mode} audit for ${run.projectName}` });
  return run;
}

function stageStart(run, stageId) {
  run.currentStage = stageId;
  const stage = run.stages[stageId];
  stage.status = 'RUNNING';
  stage.startedAt = isoNow();
  stage.finishedAt = null;
  writeEvent(run, { kind: 'stage-started', stage: stageId, message: `${stage.label} started` });
  saveRun(run);
}

function stageFinish(run, stageId, status, note = '') {
  const stage = run.stages[stageId];
  stage.status = status;
  stage.finishedAt = isoNow();
  stage.note = redact(note);
  writeEvent(run, { kind: 'stage-finished', stage: stageId, status, message: `${stage.label}: ${status}${note ? ` — ${note}` : ''}` });
  saveRun(run);
}

function skipStage(run, stageId, note) {
  run.stages[stageId].status = 'SKIPPED';
  run.stages[stageId].note = note;
  const stageTools = {
    secrets: ['gitleaks', 'trufflehog'],
    static: ['semgrep'],
    dependencies: ['osv-scanner', 'trivy'],
    infrastructure: ['checkov', 'trivy'],
    web: ['nuclei', 'zap'],
  }[stageId] || [];
  for (const toolId of stageTools) {
    const tool = run.tools[toolId];
    if (!tool || tool.status !== 'WAITING') continue;
    tool.status = 'SKIPPED';
    tool.decision = 'SKIP';
    tool.decisionReason = note;
  }
  writeEvent(run, { kind: 'stage-skipped', stage: stageId, status: 'SKIPPED', message: `${run.stages[stageId].label}: skipped — ${note}` });
  saveRun(run);
}

function resolveBinary(name) {
  let configured = {};
  try {
    configured = JSON.parse(process.env.SECURITY_TOOL_BINARIES || '{}');
  } catch {
    configured = {};
  }
  if (typeof configured[name] === 'string' && configured[name].trim()) return configured[name].trim();
  if (name === 'zap') {
    const macPath = '/Applications/ZAP.app/Contents/Java/zap.sh';
    if (fs.existsSync(macPath)) return macPath;
  }
  return name;
}

function parserFor(tool) {
  return (text, run) => adaptScannerOutput(tool, text, {
    runId: run.id,
    startedAt: run.startedAt,
    observedAt: run.finishedAt || isoNow(),
    projectPath: run.projectPath,
  });
}

function gitleaksArgs(projectPath, reportPath) {
  const args = ['detect', '--source', projectPath, '--no-git', '--redact', '--report-format', 'json', '--report-path', reportPath];
  const configured = String(process.env.VCG_GITLEAKS_CONFIG || '').trim();
  if (configured && !configured.includes('\0') && !/^https?:\/\//i.test(configured)) {
    const resolved = path.resolve(configured);
    try {
      const stat = fs.statSync(resolved);
      if (stat.isFile() && stat.size <= 1024 * 1024) args.splice(1, 0, '--config', resolved);
    } catch { /* fall back to Gitleaks' normal configuration discovery */ }
  }
  return args;
}

function semgrepArgs(projectPath) {
  const configured = String(process.env.VCG_SEMGREP_CONFIG || '').trim();
  if (configured && !configured.includes('\0') && !/^https?:\/\//i.test(configured)) {
    const resolved = path.resolve(configured);
    try {
      const stat = fs.statSync(resolved);
      if (stat.isFile() && stat.size <= 1024 * 1024) return ['scan', '--config', resolved, projectPath, '--json'];
    } catch { /* fall back to the normal upstream rule source */ }
  }
  return ['scan', '--config=p/security-audit', projectPath, '--json'];
}

function updateToolVersion(tool) {
  const commands = {
    gitleaks: ['version'],
    trufflehog: ['--version'],
    semgrep: ['--version'],
    trivy: ['--version'],
    'osv-scanner': ['--version'],
    checkov: ['--version'],
    zap: ['-version'],
    nuclei: ['-version'],
  };
  return new Promise((resolve) => {
    const command = resolveBinary(tool);
    const child = spawn(command, commands[tool] || ['--version'], { env: COMMAND_ENV });
    let output = '';
    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(value);
    };
    const append = (chunk) => { output = `${output}${chunk}`.slice(-8192); };
    child.stdout.on('data', append);
    child.stderr.on('data', append);
    const timer = setTimeout(() => { child.kill('SIGTERM'); finish(null); }, 5000);
    child.on('close', () => {
      const match = redact(output).match(/(?:^|[^0-9A-Za-z.])v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)((?:[-+][0-9A-Za-z.-]+)?)(?:$|[^0-9A-Za-z.])/);
      finish(match ? `${match[1]}.${match[2]}.${match[3]}${match[4]}` : null);
    });
    child.on('error', () => finish(null));
  });
}

function validateScannerOutput(tool, text) {
  const value = String(text || '').trim();
  const jsonLines = new Set(['trufflehog', 'nuclei']);
  if (jsonLines.has(tool)) {
    if (!value) return { valid: true };
    const invalid = value.split('\n').some((line) => {
      try { JSON.parse(line); return false; } catch { return true; }
    });
    return invalid ? { valid: false, reason: `${tool} emitted malformed JSONL output.` } : { valid: true };
  }
  if (!value) return { valid: false, reason: `${tool} emitted no structured output.` };
  try { JSON.parse(value); return { valid: true }; } catch { return { valid: false, reason: `${tool} emitted malformed JSON output.` }; }
}

function runtimeTargetReachable(target, timeoutMs = 3000) {
  if (!target) return Promise.resolve(false);
  let parsed;
  try { parsed = new URL(target); } catch { return Promise.resolve(false); }
  const port = parsed.port ? Number(parsed.port) : parsed.protocol === 'https:' ? 443 : 80;
  return new Promise((resolve) => {
    let settled = false;
    const socket = net.connect({ host: parsed.hostname, port });
    const finish = (reachable) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(reachable);
    };
    socket.setTimeout(timeoutMs, () => finish(false));
    socket.once('connect', () => finish(true));
    socket.once('error', () => finish(false));
  });
}

async function executeScanner(run, { tool, stage, args, outputName, parser, reportPath }) {
  if (run.abortRequested) {
    const meta = run.tools[tool];
    meta.status = 'STOPPED';
    meta.decision = meta.decision || 'RUN';
    meta.decisionReason = 'The audit was stopped before this scanner started.';
    writeEvent(run, { kind: 'tool-stopped', stage, tool, status: 'STOPPED', message: `${meta.label} was not started because the audit was stopped.` });
    saveRun(run);
    return { status: 'STOPPED', findings: [] };
  }
  const detectedVersion = await updateToolVersion(tool);
  if (run.abortRequested) {
    const meta = run.tools[tool];
    meta.status = 'STOPPED';
    meta.decision = meta.decision || 'RUN';
    meta.decisionReason = 'The audit was stopped before this scanner started.';
    writeEvent(run, { kind: 'tool-stopped', stage, tool, status: 'STOPPED', message: `${meta.label} was not started because the audit was stopped.` });
    saveRun(run);
    return { status: 'STOPPED', findings: [] };
  }
  return new Promise((resolve) => {
    const meta = run.tools[tool];
    const started = Date.now();
    meta.status = 'RUNNING';
    meta.version = detectedVersion || meta.version || null;
    meta.startedAt = isoNow();
    writeEvent(run, { kind: 'tool-started', stage, tool, message: `${meta.label} started` });
    saveRun(run);

    const child = spawn(resolveBinary(tool), args, { cwd: run.projectPath, env: COMMAND_ENV, stdio: ['ignore', 'pipe', 'pipe'] });
    run.processes.add(child);
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk.toString(); });
    child.stderr.on('data', (chunk) => { stderr += chunk.toString(); });
    const finish = (exitCode, error) => {
      if (!run.processes.has(child)) return;
      run.processes.delete(child);
      let parserInput = stdout;
      if (reportPath && fs.existsSync(reportPath)) {
        parserInput = fs.readFileSync(reportPath, 'utf8');
      }
      const safeStdout = redact(stdout);
      const safeStderr = redact(stderr);
      const output = `${safeStdout}${safeStderr ? `\n${safeStderr}` : ''}`;
      if (outputName) atomicWrite(path.join(run.dir, outputName), output);
      if (reportPath && fs.existsSync(reportPath)) atomicWrite(reportPath, redact(parserInput));
      const parseCheck = validateScannerOutput(tool, parserInput);
      const findings = parseCheck.valid ? (parser || parserFor(tool))(parserInput, run) : [];
      run.findings.push(...findings);
      run.summary = countFindings(run.findings);
      meta.findingsCount = findings.length;
      meta.exitCode = exitCode;
      meta.durationMs = Date.now() - started;
      meta.finishedAt = isoNow();
      meta.version = meta.version || null;
      meta.parseValid = parseCheck.valid;
      meta.parseError = parseCheck.valid ? null : parseCheck.reason;
      if (run.abortRequested || error?.code === 'ABORT_ERR') meta.status = 'STOPPED';
      else if (error || exitCode === null) { meta.status = 'ERROR'; meta.error = redact(error?.message || 'Process failed to start'); }
      else if (!parseCheck.valid) { meta.status = 'FAIL'; meta.error = parseCheck.reason; }
      else if (exitCode > 1) { meta.status = 'FAIL'; meta.error = `Scanner exited with code ${exitCode}.`; }
      else meta.status = 'PASS';
      writeEvent(run, {
        kind: 'tool-finished', stage, tool, status: meta.status, exitCode,
        message: `${meta.label} ${meta.status}${findings.length ? ` — ${findings.length} finding${findings.length === 1 ? '' : 's'}` : ''}`,
      });
      saveRun(run);
      resolve({ status: meta.status, findings });
    };
    child.on('error', (error) => finish(null, error));
    child.on('close', (code) => finish(code, null));
  });
}

function targetedScannerSpec(tool, run, finding = null) {
  const report = (name) => path.join(run.dir, name);
  const category = String(finding?.category || '').toUpperCase();
  const trivyScanner = ['CONFIGURATION', 'INFRASTRUCTURE', 'MISCONFIGURATION'].includes(category) ? 'config' : 'vuln';
  const specs = {
    gitleaks: { stage: 'rescan', args: gitleaksArgs(run.projectPath, report('gitleaks-report.json')), outputName: 'gitleaks-output.txt', reportPath: report('gitleaks-report.json') },
    trufflehog: { stage: 'rescan', args: ['filesystem', run.projectPath, '--no-verification', '--no-update', '--no-color', '--json'], outputName: 'trufflehog-output.jsonl' },
    semgrep: { stage: 'rescan', args: semgrepArgs(run.projectPath), outputName: 'semgrep-output.json' },
    'osv-scanner': { stage: 'rescan', args: ['scan', 'source', '--recursive', '--format', 'json', run.projectPath], outputName: 'osv-output.json' },
    trivy: { stage: 'rescan', args: ['fs', '--scanners', trivyScanner, '--skip-db-update', '--format', 'json', run.projectPath], outputName: 'trivy-output.json' },
    checkov: { stage: 'rescan', args: ['-d', run.projectPath, '--output', 'json'], outputName: 'checkov-output.json' },
    nuclei: { stage: 'web', args: ['-u', run.webTarget, '-tags', 'tech', '-jsonl', '-silent'], outputName: 'nuclei-output.jsonl' },
    zap: { stage: 'web', args: ['-cmd', '-quickurl', run.webTarget, '-quickout', report('zap-report.json'), '-quickprogress'], outputName: 'zap-output.txt', reportPath: report('zap-report.json') },
  };
  return specs[tool] || null;
}

function verificationFinding(projectPath, findingId) {
  const project = projectIdentity(projectPath);
  const index = readProjectIndex(project.id);
  if (!/^VCG-CORR-[A-F0-9]{14}$/.test(String(findingId || ''))) return { project, index, finding: null, invalidReason: 'Finding id is not a valid correlated finding id.' };
  const finding = index.findings.find((item) => item.id === findingId) || null;
  if (!finding) return { project, index, finding: null, invalidReason: `Correlated finding ${findingId} was not found for this project.` };
  const historyValid = (finding.observations || []).length > 0 && finding.observations.every((observation) => {
    if (!isValidRunId(observation.runId)) return false;
    try {
      const metadata = JSON.parse(fs.readFileSync(path.join(DATA_DIR, observation.runId, 'metadata.json'), 'utf8'));
      return projectIdentity(metadata.projectPath || '').id === project.id && (!metadata.projectId || metadata.projectId === project.id);
    } catch { return false; }
  });
  return { project, index, finding: historyValid ? finding : null, invalidReason: historyValid ? null : 'Finding history is missing, invalid, or belongs to a different project.' };
}

function createVerificationRun({ projectPath, findingId, webTarget }) {
  const authorizedWebTarget = webTarget ? safeWebTarget(webTarget) : null;
  if (webTarget && !authorizedWebTarget) throw new Error('Runtime verification target is not localhost or explicitly authorized.');
  const located = verificationFinding(projectPath, findingId);
  if (!located.finding) throw new Error(located.invalidReason || `Correlated finding ${findingId} was not found for this project.`);
  if (['FALSE_POSITIVE', 'ACCEPTED_RISK'].includes(located.finding.status)) throw new Error('User-controlled FALSE_POSITIVE and ACCEPTED_RISK findings cannot be automatically verified.');
  if (located.finding.status === 'OPEN') throw new Error('Mark the finding FIXING or FIXED after an authorized external fix before targeted verification.');
  const plan = verificationPlan(located.finding, { webTarget: authorizedWebTarget });
  if (plan.authorizationRequired) throw new Error(plan.reason);
  const run = createRun({ projectPath, mode: 'verify', webTarget: authorizedWebTarget, verification: { findingId, plan, status: 'STARTING' } });
  const current = readProjectIndex(located.project.id);
  const target = current.findings.find((item) => item.id === findingId);
  appendHistory(target, { event: 'VERIFICATION_STARTED', runId: run.id, previousStatus: target.status, newStatus: target.status, reason: 'Targeted verification was requested after an authorized external fix attempt.' }, { runId: run.id, timestamp: isoNow() });
  saveProjectIndex(current);
  run.correlatedFindings = current.findings;
  run.correlatedSummary = countCorrelatedFindings(run.correlatedFindings);
  run.summary = run.correlatedSummary;
  saveRun(run);
  return { run, target, plan };
}

async function runTargetedVerification(run) {
  const located = verificationFinding(run.projectPath, run.verification.findingId);
  if (!located.finding) throw new Error(`Correlated finding ${run.verification.findingId} disappeared before verification started.`);
  const plan = verificationPlan(located.finding, { webTarget: run.webTarget });
  run.verification.plan = plan;
  const initialScopeFingerprint = projectScopeFingerprint(run.projectPath, located.finding.location?.file || null, run.webTarget);
  stageStart(run, 'discovery');
  const discovery = detectStack(run.projectPath);
  run.stack = discovery.stack;
  stageFinish(run, 'discovery', 'PASS', `${discovery.files.length} relevant project signals found`);
  skipStage(run, 'threat-model', 'Threat modeling remains the external agent and developer responsibility.');
  for (const [toolId, tool] of Object.entries(run.tools)) {
    if (!plan.relevantScanners.includes(toolId)) {
      tool.status = 'NOT_APPLICABLE';
      tool.decision = 'NOT_APPLICABLE';
      tool.decisionReason = 'Not relevant to the selected correlated finding.';
    }
  }
  stageStart(run, 'rescan');
  const runtimeScanners = plan.relevantScanners.filter((item) => ['zap', 'nuclei'].includes(item));
  const runtimeReachable = runtimeScanners.length === 0 || await runtimeTargetReachable(run.webTarget);
  for (const toolId of plan.relevantScanners) {
    if (runtimeScanners.includes(toolId) && !runtimeReachable) {
      run.tools[toolId].status = 'SKIPPED';
      run.tools[toolId].decision = 'SKIP';
      run.tools[toolId].decisionReason = 'The authorized runtime target was not reachable before active verification.';
      continue;
    }
    const spec = targetedScannerSpec(toolId, run, located.finding);
    if (!spec) {
      run.tools[toolId].status = 'SKIPPED';
      run.tools[toolId].decision = 'SKIP';
      run.tools[toolId].decisionReason = 'No safe targeted adapter is configured.';
      continue;
    }
    if (spec.stage === 'web' && run.stages.web.status !== 'RUNNING') stageStart(run, 'web');
    await executeScanner(run, { tool: toolId, ...spec, parser: null });
  }
  if (runtimeScanners.length && run.stages.web.status === 'WAITING') stageStart(run, 'web');
  if (run.stages.web.status === 'RUNNING') stageFinish(run, 'web', runtimeScanners.every((item) => run.tools[item].status === 'PASS') ? 'PASS' : 'FAIL', runtimeReachable ? `Authorized target: ${run.webTarget || 'none'}` : 'Authorized runtime target was unreachable.');
  const currentScopeFingerprint = projectScopeFingerprint(run.projectPath, located.finding.location?.file || null, run.webTarget);
  const stableScopeFingerprint = initialScopeFingerprint && initialScopeFingerprint === currentScopeFingerprint ? currentScopeFingerprint : null;
  const coverage = verificationCoverage(plan, run.tools, { webTarget: run.webTarget, currentScopeFingerprint: stableScopeFingerprint });
  stageFinish(run, 'rescan', coverage.complete ? 'PASS' : 'FAIL', coverage.reason);
  skipStage(run, 'manual', 'Manual security review is not part of targeted scanner verification.');
  skipStage(run, 'fix', 'The external coding agent owns code changes; Vibe Code Guard only verifies them.');
  const current = readProjectIndex(located.project.id);
  const existing = current.findings.find((item) => item.id === run.verification.findingId);
  const reconciled = reconcileFindings([existing], run.findings, {
    projectId: located.project.id,
    projectPath: run.projectPath,
    runId: run.id,
    startedAt: run.startedAt,
    observedAt: isoNow(),
    tools: run.tools,
    stages: run.stages,
    webTarget: run.webTarget,
    verificationScopeValid: coverage.complete,
  });
  const updatedFinding = reconciled.findings[0] || existing;
  current.findings = current.findings.map((item) => item.id === run.verification.findingId ? updatedFinding : item);
  saveProjectIndex(current);
  const outcome = verificationOutcome({ finding: existing, updatedFinding, coverage });
  run.verification = { ...run.verification, plan, coverage, initialScopeFingerprint, currentScopeFingerprint, scopeStableDuringScan: Boolean(stableScopeFingerprint), runtimeReachable, ...outcome, completedAt: isoNow() };
  run.correlatedFindings = current.findings;
  run.correlatedSummary = countCorrelatedFindings(run.correlatedFindings);
  run.summary = run.correlatedSummary;
  run.observationSummary = countFindings(run.findings);
  run.finishedAt = isoNow();
  run.status = outcome.verification === 'PASSED' ? 'PASS' : outcome.verification === 'VERIFICATION_INCOMPLETE' ? 'PASS WITH WARNINGS' : 'FAIL';
  run.releaseGate = { label: 'DO NOT DEPLOY', reason: outcome.verification === 'PASSED' ? 'Targeted verification passed, but a complete release assessment is still required.' : outcome.reason };
  run.currentStage = 'decision';
  run.stages.decision.status = run.status === 'PASS' ? 'PASS' : 'WARNING';
  run.stages.decision.finishedAt = run.finishedAt;
  run.aiReviews = aiReviewSummariesForRun(run);
  run.aiSummaryReviews = aiSummaryStatesForRun(run);
  atomicWrite(path.join(run.dir, 'summary.json'), `${JSON.stringify({ summary: run.summary, releaseGate: run.releaseGate, status: run.status, verification: run.verification }, null, 2)}\n`);
  atomicWrite(path.join(run.dir, 'security-report.md'), buildReport(run));
  saveRun(run);
  writeEvent(run, { kind: 'verification-finished', stage: 'decision', status: run.status, verification: outcome.verification, findingId: run.verification.findingId, message: `Targeted verification ${outcome.verification}: ${outcome.reason}` });
  saveRun(run);
  return { run, finding: updatedFinding, verification: run.verification };
}

async function verifyFinding({ projectPath, findingId, webTarget = null }) {
  const authorizedProjectPath = safeProjectPath(projectPath);
  if (!authorizedProjectPath) throw new Error('Verification target must be a safe existing local project directory.');
  projectPath = authorizedProjectPath;
  const active = [...runs.values()].find((run) => run.projectPath === projectPath && run.status === 'SCANNING');
  if (active) throw new Error(`A scan is already running for this project: ${active.id}`);
  const created = createVerificationRun({ projectPath, findingId, webTarget });
  try {
    return await withToolLock(TOOLKIT_HOME, `verify:${created.run.id}`, () => runTargetedVerification(created.run));
  } catch (error) {
    created.run.status = 'FAIL';
    created.run.finishedAt = isoNow();
    if (created.run.stages.rescan.status === 'RUNNING') stageFinish(created.run, 'rescan', 'FAIL', error.message || 'Targeted verification failed.');
    if (created.run.stages.decision.status === 'WAITING') {
      created.run.currentStage = 'decision';
      created.run.stages.decision.status = 'FAIL';
      created.run.stages.decision.finishedAt = created.run.finishedAt;
    }
    created.run.verification = { ...created.run.verification, verification: 'VERIFICATION_INCOMPLETE', lifecycle: created.target.status, reason: redact(error.message || 'Targeted verification failed.'), completedAt: isoNow() };
    created.run.releaseGate = { label: 'DO NOT DEPLOY', reason: created.run.verification.reason };
    saveRun(created.run);
    writeEvent(created.run, { kind: 'verification-error', stage: 'rescan', status: 'FAIL', findingId, message: created.run.verification.reason });
    saveRun(created.run);
    throw error;
  }
}

function safeProjectPath(input) {
  if (typeof input !== 'string' || !input.trim() || input.includes('\0') || input.includes('://')) return null;
  const resolved = path.resolve(input.trim());
  try {
    const real = fs.realpathSync(resolved);
    const stats = fs.statSync(real);
    const within = (candidate, parent) => candidate === parent || candidate.startsWith(`${parent}${path.sep}`);
    const root = path.parse(real).root;
    const home = fs.realpathSync(os.homedir());
    const toolkit = fs.existsSync(TOOLKIT_HOME) ? fs.realpathSync(TOOLKIT_HOME) : path.resolve(TOOLKIT_HOME);
    const data = fs.existsSync(DATA_DIR) ? fs.realpathSync(DATA_DIR) : path.resolve(DATA_DIR);
    if (real === root || real === home || within(real, toolkit) || within(real, data)) return null;
    return stats.isDirectory() ? real : null;
  } catch {
    return null;
  }
}

function safeWebTarget(input) {
  if (!input) return null;
  try {
    const parsed = new URL(input);
    if (!['http:', 'https:'].includes(parsed.protocol)) return null;
    const hostname = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase();
    const allowed = new Set(['localhost', '127.0.0.1', '::1']);
    const configured = [process.env.SECURITY_AUTHORIZED_TARGETS, process.env.VIBE_CODE_GUARD_AUTHORIZED_TARGETS]
      .flatMap((value) => String(value || '').split(','))
      .map((item) => item.trim())
      .map((item) => item.replace(/\/$/, ''))
      .filter(Boolean);
    const normalized = parsed.toString().replace(/\/$/, '');
    return allowed.has(hostname) || configured.includes(normalized) ? normalized : null;
  } catch {
    return null;
  }
}

function detectStack(projectPath) {
  const names = new Set();
  const stack = [];
  const add = (label) => { if (!stack.includes(label)) stack.push(label); };
  const files = new Set();
  const visit = (dir, depth = 0) => {
    if (depth > 2) return;
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (['.git', 'node_modules', '.next', 'dist', 'build', '.venv', '__pycache__'].includes(entry.name)) continue;
      files.add(entry.name);
      if (entry.isDirectory()) visit(path.join(dir, entry.name), depth + 1);
    }
  };
  visit(projectPath);
  const packagePath = path.join(projectPath, 'package.json');
  let packageData = {};
  try { packageData = JSON.parse(fs.readFileSync(packagePath, 'utf8')); } catch { /* no package manifest */ }
  const deps = { ...(packageData.dependencies || {}), ...(packageData.devDependencies || {}) };
  if (files.has('package.json')) add('Node.js');
  if (deps.react) add('React');
  if (deps.next) add('Next.js');
  if (deps.vite) add('Vite');
  if (deps.vue) add('Vue');
  if (files.has('requirements.txt') || files.has('pyproject.toml')) add('Python');
  if (files.has('manage.py') || deps.django) add('Django');
  if (files.has('Dockerfile') || files.has('docker-compose.yml') || files.has('compose.yml')) add('Docker');
  if ([...files].some((file) => file.endsWith('.tf'))) add('Terraform');
  if ([...files].some((file) => file.endsWith('.yaml') || file.endsWith('.yml'))) add('YAML / CI');
  if (files.has('supabase') || files.has('supabase')) add('Supabase');
  if (!stack.length) add('Unclassified project');
  names.add(...stack);
  return { stack, files: [...names] };
}

function hasInfrastructure(projectPath) {
  const candidates = ['Dockerfile', 'docker-compose.yml', 'compose.yml', 'template.yaml', 'serverless.yml'];
  if (candidates.some((file) => fs.existsSync(path.join(projectPath, file)))) return true;
  try {
    return fs.readdirSync(projectPath).some((file) => file.endsWith('.tf') || file === 'k8s' || file === 'kubernetes');
  } catch { return false; }
}

function readPreviousFindings(projectPath, currentId) {
  const all = [];
  for (const entry of fs.readdirSync(DATA_DIR, { withFileTypes: true })) {
    if (!entry.isDirectory() || entry.name === currentId) continue;
    try {
      const metadata = JSON.parse(fs.readFileSync(path.join(DATA_DIR, entry.name, 'metadata.json'), 'utf8'));
      if (metadata.projectPath !== projectPath) continue;
      const rawFindings = JSON.parse(fs.readFileSync(path.join(DATA_DIR, entry.name, 'findings.json'), 'utf8'));
      all.push(...normalizePersistedFindings(rawFindings, {
        runId: entry.name,
        projectPath,
        startedAt: metadata.startedAt,
        observedAt: metadata.finishedAt || metadata.startedAt,
      }));
    } catch { /* ignore incomplete prior runs */ }
  }
  return all;
}

function isValidRunId(id) {
  return /^[0-9]{14}-[a-f0-9]{6}$/.test(String(id || ''));
}

function finalizeFindings(run) {
  const unique = new Map();
  for (const finding of run.findings) {
    if (!unique.has(finding.id)) unique.set(finding.id, finding);
  }
  run.findings = [...unique.values()];
  const index = readProjectIndex(run.projectId);
  const result = reconcileFindings(index.findings, run.findings, {
    projectId: run.projectId,
    projectPath: run.projectPath,
    runId: run.id,
    startedAt: run.startedAt,
    observedAt: run.finishedAt || isoNow(),
    tools: run.tools,
    stages: run.stages,
    webTarget: run.webTarget,
  });
  index.findings = result.findings;
  saveProjectIndex(index);
  run.correlatedFindings = index.findings;
  run.correlationSuggestions = result.suggestions;
  run.observationSummary = countFindings(run.findings);
  run.correlatedSummary = countCorrelatedFindings(run.correlatedFindings);
  run.summary = run.correlatedSummary;
}

function buildReport(run) {
  const all = run.correlatedFindings || [];
  const overallRisk = run.summary.critical || run.summary.high
    ? 'HIGH'
    : run.summary.medium
      ? 'MEDIUM'
      : run.summary.low
        ? 'LOW'
        : run.summary.unknown
          ? 'UNKNOWN'
          : run.summary.info
            ? 'INFO'
            : 'LOW';
  const lines = [
    '# Security Assessment', '',
    '## Executive Summary', '',
    `- Project: ${redact(run.projectName)}`,
    `- Path: ${redact(run.projectPath)}`,
    `- Date: ${run.startedAt}`,
    `- Unified Finding Schema: ${SCHEMA_VERSION}`,
    `- Correlation Schema: ${CORRELATION_SCHEMA_VERSION}`,
    `- Scan Mode: ${run.mode}`,
    `- Stack: ${run.stack.join(', ') || 'Unknown'}`,
    `- Overall Risk: ${overallRisk}`,
    `- Release Decision: ${run.releaseGate.label}`,
    `- Correlated Findings: ${run.summary.total}`,
    `- Scanner Observations: ${run.observationSummary?.total || 0}`,
    '', '## Scanner Status', '',
    '| Tool | Status | Findings | Exit code |', '| --- | --- | ---: | ---: |',
  ];
  for (const tool of Object.values(run.tools)) lines.push(`| ${tool.label} | ${tool.status} | ${tool.findingsCount ?? '—'} | ${tool.exitCode ?? '—'} |`);
  lines.push('', '## Findings', '');
  if (!all.length) lines.push('No findings were parsed from the scanners that ran.', '');
  for (const finding of all) {
    lines.push(`### ${finding.id} — ${finding.severity}`, '',
      `- Detected by: ${(finding.observations || []).map((observation) => observation.scanner).join(', ') || 'No scanner observation'}`,
      `- Category: ${finding.category}`,
      `- Location: ${finding.location?.file || finding.location?.endpoint || 'Not specified'}`,
      `- Title: ${finding.title}`,
      `- Observations: ${(finding.observations || []).length}`,
      `- Status: ${finding.status}`, '');
  }
  lines.push('## Remaining Risks', '', '- Manual security review is not automated by this dashboard.', '- A clean scanner result does not prove the project is perfectly secure.', '');
  return `${redact(lines.join('\n'))}\n`;
}

function updateReleaseGate(run) {
  const blockingSummary = countBlockingCorrelatedFindings(run.correlatedFindings);
  const blockingFindings = (run.correlatedFindings || []).filter((finding) => ['OPEN', 'FIXED', 'REOPENED'].includes(finding.status));
  const unresolvedHigh = blockingSummary.critical + blockingSummary.high;
  run.finishedAt = run.finishedAt || isoNow();
  const toolErrors = Object.values(run.tools).filter((tool) => tool.status === 'ERROR' || (tool.status === 'FAIL' && tool.findingsCount === 0 && (tool.exitCode || 0) > 1)).length;
  const manualSkipped = run.stages.manual.status === 'SKIPPED';
  const incompleteAssessment = run.mode !== 'full' || manualSkipped || run.stages.web.status === 'SKIPPED';
  if (run.abortRequested) run.releaseGate = { label: 'DO NOT DEPLOY', reason: 'The scan was stopped before the assessment completed.' };
  else if (unresolvedHigh > 0) run.releaseGate = { label: 'DO NOT DEPLOY', reason: `${unresolvedHigh} unresolved correlated Critical/High finding${unresolvedHigh === 1 ? '' : 's'}.` };
  else if (toolErrors > 0) run.releaseGate = { label: 'DO NOT DEPLOY', reason: `${toolErrors} scanner${toolErrors === 1 ? '' : 's'} failed to execute.` };
  else if (incompleteAssessment) run.releaseGate = { label: 'DO NOT DEPLOY', reason: 'The performed assessment still has skipped runtime or manual review stages.' };
  else run.releaseGate = { label: 'READY TO DEPLOY', reason: 'No known Critical/High findings detected by the performed assessment.' };
  run.status = run.abortRequested ? 'STOPPED' : unresolvedHigh > 0 || toolErrors > 0 ? 'FAIL' : incompleteAssessment || blockingFindings.length > 0 || run.correlatedFindings.some((finding) => finding.status === 'ACCEPTED_RISK') ? 'PASS WITH WARNINGS' : 'PASS';
  run.currentStage = 'decision';
  run.stages.decision.status = run.status === 'FAIL' ? 'FAIL' : run.status === 'PASS' ? 'PASS' : 'WARNING';
  run.stages.decision.finishedAt = run.finishedAt;
}

function finishRun(run) {
  run.finishedAt = run.finishedAt || isoNow();
  finalizeFindings(run);
  updateReleaseGate(run);
  run.aiReviews = aiReviewSummariesForRun(run);
  run.aiSummaryReviews = aiSummaryStatesForRun(run);
  atomicWrite(path.join(run.dir, 'summary.json'), `${JSON.stringify({ summary: run.summary, releaseGate: run.releaseGate, status: run.status }, null, 2)}\n`);
  atomicWrite(path.join(run.dir, 'security-report.md'), buildReport(run));
  saveRun(run);
  writeEvent(run, { kind: 'scan-finished', stage: 'decision', status: run.status, message: `Scan finished: ${run.status}. ${run.releaseGate.reason}` });
  saveRun(run);
}

function planDecision(run, tool) {
  return run.orchestration?.tools?.find((item) => item.tool === tool) || { tool, decision: 'RUN', reason: 'Legacy scan mode.' };
}

function plannedToolIds(run, toolIds) {
  return toolIds.filter((tool) => planDecision(run, tool).decision === 'RUN');
}

function plannedStageNote(run, toolIds) {
  return toolIds.map((tool) => {
    const item = planDecision(run, tool);
    return `${tool}: ${item.decision} — ${item.reason}`;
  }).join(' ');
}

function plannedStageStatus(run, toolIds) {
  return toolIds.some((tool) => ['ERROR', 'FAIL'].includes(run.tools[tool]?.status)) ? 'FAIL' : 'PASS';
}

async function runPlannedAudit(run) {
  stageStart(run, 'discovery');
  const discovery = detectStack(run.projectPath);
  run.stack = discovery.stack;
  writeEvent(run, {
    kind: 'stack-detected',
    stage: 'discovery',
    message: `Stack detected: ${run.stack.join(' + ')}`,
  });
  stageFinish(run, 'discovery', 'PASS', `${discovery.files.length} relevant project signals found`);
  writeEvent(run, {
    kind: 'orchestration-planned',
    stage: 'discovery',
    message: `${run.orchestration.risk} risk: ${run.orchestration.summary.selected} selected, ${run.orchestration.summary.skipped} skipped, ${run.orchestration.summary.recommended} recommended`,
  });

  skipStage(run, 'threat-model', 'Not automated; record or review the project threat model before release.');

  const executeStage = async (stage, specs, note = '') => {
    const selected = plannedToolIds(run, specs.map((spec) => spec.tool));
    if (!selected.length) {
      skipStage(run, stage, note || plannedStageNote(run, specs.map((spec) => spec.tool)));
      return;
    }
    stageStart(run, stage);
    for (const spec of specs) {
      if (!selected.includes(spec.tool)) continue;
      await executeScanner(run, { ...spec, stage });
    }
    stageFinish(run, stage, plannedStageStatus(run, selected), plannedStageNote(run, specs.map((spec) => spec.tool)));
  };

  await executeStage('secrets', [
    { tool: 'gitleaks', args: gitleaksArgs(run.projectPath, path.join(run.dir, 'gitleaks-report.json')), outputName: 'gitleaks-output.txt', parser: null, reportPath: path.join(run.dir, 'gitleaks-report.json') },
    { tool: 'trufflehog', args: ['filesystem', run.projectPath, '--no-verification', '--json'], outputName: 'trufflehog-output.jsonl', parser: null },
  ]);
  await executeStage('static', [
    { tool: 'semgrep', args: semgrepArgs(run.projectPath), outputName: 'semgrep-output.json', parser: null },
  ]);

  const categories = new Set(run.orchestration.categories);
  if (categories.has('DEPENDENCY_CHANGE')) {
    await executeStage('dependencies', [
      { tool: 'osv-scanner', args: ['scan', 'source', '--recursive', '--format', 'json', run.projectPath], outputName: 'osv-output.json', parser: null },
      { tool: 'trivy', args: ['fs', '--scanners', 'vuln', '--skip-db-update', '--format', 'json', run.projectPath], outputName: 'trivy-output.json', parser: null },
    ]);
  } else {
    skipStage(run, 'dependencies', plannedStageNote(run, ['osv-scanner', 'trivy']));
  }

  if (categories.has('IAC_CHANGE') || categories.has('CONTAINER_CHANGE')) {
    await executeStage('infrastructure', [
      { tool: 'checkov', args: ['-d', run.projectPath, '--output', 'json'], outputName: 'checkov-output.json', parser: null },
      { tool: 'trivy', args: ['fs', '--scanners', 'config', '--skip-db-update', '--format', 'json', run.projectPath], outputName: 'trivy-config-output.json', parser: null },
    ]);
  } else {
    skipStage(run, 'infrastructure', plannedStageNote(run, ['checkov', 'trivy']));
  }

  const webTools = plannedToolIds(run, ['nuclei', 'zap']);
  if (webTools.length) {
    const target = safeWebTarget(run.webTarget);
    if (!target) skipStage(run, 'web', 'The automatic plan selected runtime checks, but no authorized localhost target is available.');
    else {
      stageStart(run, 'web');
      if (webTools.includes('nuclei')) await executeScanner(run, { tool: 'nuclei', stage: 'web', args: ['-u', target, '-tags', 'tech', '-jsonl', '-silent'], outputName: 'nuclei-output.jsonl', parser: null });
      if (webTools.includes('zap')) {
        const zapPath = resolveBinary('zap');
        if (zapPath !== 'zap' && fs.existsSync(zapPath)) await executeScanner(run, { tool: 'zap', stage: 'web', args: ['-cmd', '-quickurl', target, '-quickout', path.join(run.dir, 'zap-report.json'), '-quickprogress'], outputName: 'zap-output.txt', parser: null, reportPath: path.join(run.dir, 'zap-report.json') });
        else {
          run.tools.zap.status = 'SKIPPED';
          writeEvent(run, { kind: 'tool-skipped', stage: 'web', tool: 'zap', message: 'OWASP ZAP binary was not found.' });
        }
      }
      stageFinish(run, 'web', plannedStageStatus(run, webTools), `Authorized target: ${target}`);
    }
  } else {
    skipStage(run, 'web', plannedStageNote(run, ['zap', 'nuclei']));
  }

  skipStage(run, 'manual', 'Manual security review belongs to Codex and the developer; the dashboard cannot pretend to perform it.');
  skipStage(run, 'fix', 'No automatic fixes are executed by the observability layer.');
  skipStage(run, 'rescan', 'A rescan is a separate run so history stays append-only.');
  stageStart(run, 'decision');
  finishRun(run);
}

async function runAudit(run) {
  try {
    if (run.mode === 'auto') {
      await runPlannedAudit(run);
      return;
    }
    stageStart(run, 'discovery');
    const discovery = detectStack(run.projectPath);
    run.stack = discovery.stack;
    writeEvent(run, { kind: 'stack-detected', stage: 'discovery', message: `Stack detected: ${run.stack.join(' + ')}` });
    stageFinish(run, 'discovery', 'PASS', `${discovery.files.length} relevant project signals found`);

    skipStage(run, 'threat-model', 'Not automated; record or review the project threat model before release.');
    stageStart(run, 'secrets');
    await executeScanner(run, {
      tool: 'gitleaks', stage: 'secrets',
      args: gitleaksArgs(run.projectPath, path.join(run.dir, 'gitleaks-report.json')),
      outputName: 'gitleaks-output.txt', parser: null, reportPath: path.join(run.dir, 'gitleaks-report.json'),
    });
    await executeScanner(run, {
      tool: 'trufflehog', stage: 'secrets',
      args: ['filesystem', run.projectPath, '--no-verification', '--json'],
      outputName: 'trufflehog-output.jsonl', parser: null,
    });
    stageFinish(run, 'secrets', [run.tools.gitleaks, run.tools.trufflehog].some((tool) => tool.status === 'ERROR' || tool.status === 'FAIL') ? 'FAIL' : 'PASS');

    stageStart(run, 'static');
    await executeScanner(run, {
      tool: 'semgrep', stage: 'static',
      args: semgrepArgs(run.projectPath),
      outputName: 'semgrep-output.json', parser: null,
    });
    stageFinish(run, 'static', run.tools.semgrep.status === 'ERROR' || run.tools.semgrep.status === 'FAIL' ? 'FAIL' : 'PASS');

    stageStart(run, 'dependencies');
    await executeScanner(run, {
      tool: 'osv-scanner', stage: 'dependencies',
      args: ['scan', 'source', '--recursive', '--format', 'json', run.projectPath],
      outputName: 'osv-output.json', parser: null,
    });
    await executeScanner(run, {
      tool: 'trivy', stage: 'dependencies',
      args: ['fs', '--scanners', 'vuln', '--skip-db-update', '--format', 'json', run.projectPath],
      outputName: 'trivy-output.json', parser: null,
    });
    stageFinish(run, 'dependencies', [run.tools['osv-scanner'], run.tools.trivy].some((tool) => tool.status === 'ERROR' || tool.status === 'FAIL') ? 'FAIL' : 'PASS');

    if (run.mode === 'full' && hasInfrastructure(run.projectPath)) {
      stageStart(run, 'infrastructure');
      await executeScanner(run, {
        tool: 'checkov', stage: 'infrastructure',
        args: ['-d', run.projectPath, '--output', 'json'],
        outputName: 'checkov-output.json', parser: null,
      });
      await executeScanner(run, {
        tool: 'trivy', stage: 'infrastructure',
        args: ['fs', '--scanners', 'config', '--skip-db-update', '--format', 'json', run.projectPath],
        outputName: 'trivy-config-output.json', parser: null,
      });
      stageFinish(run, 'infrastructure', [run.tools.checkov, run.tools.trivy].some((tool) => tool.status === 'ERROR' || tool.status === 'FAIL') ? 'FAIL' : 'PASS');
    } else skipStage(run, 'infrastructure', run.mode === 'quick' ? 'Quick mode keeps infrastructure scanning out of the frequent loop.' : 'No supported infrastructure files detected.');

    const target = safeWebTarget(run.webTarget);
    if (run.mode === 'full' && target) {
      stageStart(run, 'web');
      await executeScanner(run, {
        tool: 'nuclei', stage: 'web',
        args: ['-u', target, '-tags', 'tech', '-jsonl', '-silent'],
        outputName: 'nuclei-output.jsonl', parser: null,
      });
      const zapPath = resolveBinary('zap');
      if (zapPath !== 'zap' && fs.existsSync(zapPath)) {
        await executeScanner(run, {
          tool: 'zap', stage: 'web',
          args: ['-cmd', '-quickurl', target, '-quickout', path.join(run.dir, 'zap-report.json'), '-quickprogress'],
          outputName: 'zap-output.txt', parser: null, reportPath: path.join(run.dir, 'zap-report.json'),
        });
      } else {
        run.tools.zap.status = 'SKIPPED';
        writeEvent(run, { kind: 'tool-skipped', stage: 'web', tool: 'zap', message: 'OWASP ZAP binary was not found.' });
      }
      stageFinish(run, 'web', [run.tools.nuclei, run.tools.zap].some((tool) => tool.status === 'ERROR' || tool.status === 'FAIL') ? 'FAIL' : 'PASS', `Authorized target: ${target}`);
    } else skipStage(run, 'web', run.mode === 'quick' ? 'Quick mode does not run active web scanners.' : 'No authorized localhost/test target was supplied.');

    skipStage(run, 'manual', 'Manual security review belongs to Codex and the developer; the dashboard cannot pretend to perform it.');
    skipStage(run, 'fix', 'No automatic fixes are executed by the observability layer.');
    skipStage(run, 'rescan', 'A rescan is a separate run so history stays append-only.');
    stageStart(run, 'decision');
    finishRun(run);
  } catch (error) {
    run.status = 'FAIL';
    run.releaseGate = { label: 'DO NOT DEPLOY', reason: redact(error.message || 'Unexpected dashboard error') };
    writeEvent(run, { kind: 'scan-error', stage: run.currentStage, status: 'FAIL', message: run.releaseGate.reason });
    finishRun(run);
  }
}

function readRuns() {
  const result = [];
  for (const entry of fs.readdirSync(DATA_DIR, { withFileTypes: true })) {
    if (!entry.isDirectory() || entry.isSymbolicLink()) continue;
    try {
      const metadata = JSON.parse(fs.readFileSync(path.join(DATA_DIR, entry.name, 'metadata.json'), 'utf8'));
      result.push(metadata);
    } catch { /* ignore incomplete atomic writes */ }
  }
  return result.sort((a, b) => String(b.startedAt).localeCompare(String(a.startedAt)));
}

function hydrateRun(id) {
  if (!isValidRunId(id)) return null;
  if (runs.has(id)) return runs.get(id);
  let dir;
  try {
    const root = fs.realpathSync(DATA_DIR);
    const candidate = path.join(DATA_DIR, id);
    const stat = fs.lstatSync(candidate);
    if (!stat.isDirectory() || stat.isSymbolicLink()) return null;
    dir = fs.realpathSync(candidate);
    if (path.dirname(dir) !== root) return null;
  } catch {
    return null;
  }
  try {
    const metadata = JSON.parse(fs.readFileSync(path.join(dir, 'metadata.json'), 'utf8'));
    const rawFindings = JSON.parse(fs.readFileSync(path.join(dir, 'findings.json'), 'utf8'));
    const persistedFindings = normalizePersistedFindings(rawFindings, {
      runId: id,
      projectPath: metadata.projectPath,
      startedAt: metadata.startedAt,
      observedAt: metadata.finishedAt || metadata.startedAt,
    });
    const events = fs.readFileSync(path.join(dir, 'events.jsonl'), 'utf8').split('\n').filter(Boolean).map((line) => ({ schemaVersion: SCHEMA_VERSION, ...JSON.parse(line) }));
    const findings = persistedFindings.filter((item) => item.status !== 'VERIFIED');
    const resolvedFindings = persistedFindings.filter((item) => item.status === 'VERIFIED');
    const project = projectIdentity(metadata.projectPath);
    let correlation = null;
    try { correlation = JSON.parse(fs.readFileSync(path.join(dir, 'correlation.json'), 'utf8')); } catch { /* v0.2 run without correlation data */ }
    const derived = correlation?.findings ? correlation : reconcileFindings([], persistedFindings, {
      projectId: metadata.projectId || project.id,
      projectPath: metadata.projectPath,
      runId: id,
      startedAt: metadata.startedAt,
      observedAt: metadata.finishedAt || metadata.startedAt,
    });
    const correlatedFindings = correlation?.findings || derived.findings;
    const correlatedSummary = correlation?.summary || countCorrelatedFindings(correlatedFindings);
  const run = {
      ...metadata,
      schemaVersion: metadata.schemaVersion || SCHEMA_VERSION,
      projectId: metadata.projectId || project.id,
      dir,
      findings,
      resolvedFindings,
      correlatedFindings,
      correlationSuggestions: correlation?.suggestions || derived.suggestions || [],
      correlatedSummary,
      observationSummary: metadata.observationSummary || countFindings(findings),
      summary: correlation ? (metadata.summary || correlatedSummary) : countFindings(findings),
      events,
      processes: new Set(),
      abortRequested: false,
    };
    run.aiReviews = aiReviewSummariesForRun(run);
    run.aiSummaryReviews = aiSummaryStatesForRun(run);
    try {
      const lock = JSON.parse(fs.readFileSync(path.join(TOOLKIT_HOME, 'security-toolchain.lock'), 'utf8'));
      for (const [toolId, tool] of Object.entries(lock.tools || {})) if (run.tools?.[toolId] && !run.tools[toolId].version) run.tools[toolId].version = tool.version || null;
    } catch { /* health view reports missing lock data */ }
    runs.set(id, run);
    return run;
  } catch {
    return null;
  }
}

function parseDoctor(output) {
  const tools = {};
  for (const line of String(output || '').split('\n')) {
    const match = line.match(/^\[OK\]\s+(\S+):\s+INSTALLED\s+\(([^)]+)\)\s*-\s*(.*)$/);
    if (!match) continue;
    const id = match[1] === 'zap' ? 'zap' : match[1];
    tools[id] = { id, label: TOOL_META[id]?.label || id, status: 'HEALTHY', path: match[2], version: redact(match[3]) };
  }
  const zap = String(output || '').match(/^\[OK\]\s+zap: INSTALLED \(([^)]+)\)/m);
  if (zap) tools.zap = { id: 'zap', label: 'OWASP ZAP', status: 'HEALTHY', path: zap[1], version: 'Installed' };
  for (const id of Object.keys(TOOL_META)) if (!tools[id]) tools[id] = { id, label: TOOL_META[id].label, status: 'BROKEN', path: null, version: null };
  const overall = String(output || '').match(/OVERALL TOOLCHAIN HEALTH:\s+(HEALTHY|DEGRADED|BROKEN)/)?.[1] || 'UNKNOWN';
  return { overall, tools, checkedAt: isoNow() };
}

function parseToolchainLock(output) {
  const data = parseJsonLoose(output);
  return {
    tools: data?.tools || {},
    optionalTools: data?.optional_tools || {},
  };
}

function runFixedCommand(tool, args = []) {
  return new Promise((resolve) => {
    const child = spawn(resolveBinary(tool), args, { env: COMMAND_ENV, cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'] });
    let output = '';
    child.stdout.on('data', (chunk) => { output += chunk; });
    child.stderr.on('data', (chunk) => { output += chunk; });
    child.on('close', (code) => resolve({ code, output: redact(output) }));
    child.on('error', (error) => resolve({ code: null, output: redact(error.message) }));
  });
}

async function toolkitHealth() {
  const [doctor, status] = await Promise.all([
    runFixedCommand('security-tools', ['doctor']),
    runFixedCommand('security-tools', ['status']),
  ]);
  const parsedDoctor = parseDoctor(doctor.output);
  const lockTools = parseToolchainLock(status.output);
  for (const [id, tool] of Object.entries(parsedDoctor.tools)) {
    if (lockTools.tools[id]) {
      tool.version = lockTools.tools[id].version || tool.version;
      tool.path = lockTools.tools[id].binary || tool.path;
      tool.installMethod = lockTools.tools[id].install_method || null;
      tool.lastSelfTest = lockTools.tools[id].last_self_test || null;
    }
  }
  let lifecycle = null;
  try { lifecycle = await lifecycleStatus(); } catch (error) { lifecycle = { overall: 'DEGRADED', error: redact(error.message) }; }
  return {
    doctor: parsedDoctor,
    optionalTools: lockTools.optionalTools,
    lifecycle,
    statusOutput: status.output,
    doctorOutput: doctor.output,
  };
}

async function readBody(request) {
  let body = '';
  for await (const chunk of request) {
    body += chunk;
    if (body.length > 1024 * 1024) throw new Error('Request body too large');
  }
  return body ? JSON.parse(body) : {};
}

function localMutationAuthorized(request) {
  const contentType = String(request.headers['content-type'] || '').toLowerCase();
  if (!contentType.startsWith('application/json')) return false;
  if (request.headers['x-vibe-code-guard-action'] !== 'confirmed') return false;
  const origin = request.headers.origin;
  if (!origin) return true;
  try {
    const parsed = new URL(origin);
    const host = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase();
    return ['127.0.0.1', 'localhost', '::1'].includes(host);
  } catch { return false; }
}

function sendJson(response, statusCode, payload) {
  const data = payload && typeof payload === 'object' && !Array.isArray(payload) && !payload.schemaVersion
    ? { schemaVersion: SCHEMA_VERSION, ...payload }
    : payload;
  const body = JSON.stringify(data);
  response.writeHead(statusCode, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  response.end(body);
}

function sendText(response, statusCode, body, contentType = 'text/plain; charset=utf-8') {
  response.writeHead(statusCode, { 'Content-Type': contentType, 'Cache-Control': 'no-store' });
  response.end(body);
}

function publicFile(requestPath, response) {
  const requested = requestPath === '/' ? '/index.html' : requestPath;
  const filePath = path.resolve(PUBLIC_DIR, `.${requested}`);
  if (!filePath.startsWith(`${PUBLIC_DIR}${path.sep}`)) return sendText(response, 403, 'Forbidden');
  const contentTypes = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.json': 'application/json; charset=utf-8' };
  fs.readFile(filePath, (error, data) => {
    if (error) return sendText(response, 404, 'Not found');
    response.writeHead(200, {
      'Content-Type': contentTypes[path.extname(filePath)] || 'application/octet-stream',
      'Cache-Control': 'no-cache',
      'Content-Security-Policy': "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'",
    });
    response.end(data);
  });
}

function openEventStream(request, response, run) {
  response.writeHead(200, {
    'Content-Type': 'text/event-stream; charset=utf-8',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  response.write(`event: snapshot\ndata: ${JSON.stringify({ run })}\n\n`);
  const listeners = subscribers.get(run.id) || [];
  const listener = (event) => response.write(`event: activity\ndata: ${JSON.stringify(event)}\n\n`);
  listeners.push(listener);
  subscribers.set(run.id, listeners);
  request.on('close', () => {
    const current = subscribers.get(run.id) || [];
    subscribers.set(run.id, current.filter((item) => item !== listener));
  });
}

function findCorrelatedFinding(run, findingId) {
  return (run.correlatedFindings || []).find((finding) => finding.id === findingId) || null;
}

function storedProviderMatches(record, provider) {
  return record?.provider?.provider === provider.name && record?.provider?.model === provider.model;
}

async function generateStoredFindingReview(run, finding, body = {}) {
  const store = readAIReviewStore(run.projectId);
  const context = findingReviewContext(run, finding, {
    allowCodeSnippet: body.allowCodeSnippet === true,
    codeSnippet: typeof body.codeSnippet === 'string' ? body.codeSnippet : '',
    codeFile: typeof body.codeFile === 'string' ? body.codeFile : '',
  });
  const provider = createProvider();
  const previous = store.reviews[finding.id];
  if (previous?.inputHash === context.inputHash && previous.status === 'READY' && storedProviderMatches(previous, provider)) {
    return { ...previous, cacheHit: true, privacy: aiPrivacy() };
  }
  store.reviews[finding.id] = {
    status: 'GENERATING',
    findingId: finding.id,
    inputHash: context.inputHash,
    provider: { provider: provider.name, model: provider.model },
    context: context.metadata,
    updatedAt: isoNow(),
  };
  saveAIReviewStore(store);
  const result = await generateFindingReview(context, { provider });
  store.reviews[finding.id] = result;
  saveAIReviewStore(store);
  run.aiReviews = aiReviewSummariesForRun(run);
  saveRun(run);
  return { ...result, privacy: aiPrivacy() };
}

async function generateStoredSummaryReview(run, mode) {
  const store = readAIReviewStore(run.projectId);
  const context = aiSummaryContextForRun(run, mode);
  const provider = createProvider();
  const previous = store.summaries[mode];
  if (previous?.inputHash === context.inputHash && previous.status === 'READY' && storedProviderMatches(previous, provider)) return { ...previous, cacheHit: true, privacy: aiPrivacy() };
  store.summaries[mode] = { status: 'GENERATING', mode, inputHash: context.inputHash, provider: { provider: provider.name, model: provider.model }, updatedAt: isoNow() };
  saveAIReviewStore(store);
  const result = await generateSummaryReview(context, { provider });
  store.summaries[mode] = result;
  saveAIReviewStore(store);
  run.aiSummaryReviews = aiSummaryStatesForRun(run);
  saveRun(run);
  return { ...result, privacy: aiPrivacy() };
}

const server = http.createServer(async (request, response) => {
  response.setHeader('X-Content-Type-Options', 'nosniff');
  response.setHeader('Referrer-Policy', 'no-referrer');
  response.setHeader('X-Frame-Options', 'DENY');
  const parsed = new URL(request.url, `http://${HOST}:${PORT}`);
  const pathname = parsed.pathname;

  try {
    if (request.method === 'GET' && pathname === '/api/health') return sendJson(response, 200, { ok: true, host: HOST, port: PORT, dataDir: DATA_DIR, localOnly: true });
    if (request.method === 'GET' && pathname === '/api/runs') return sendJson(response, 200, { runs: readRuns() });
    if (request.method === 'GET' && pathname === '/api/state') {
      const history = readRuns();
      const latest = history[0] ? hydrateRun(history[0].id) : null;
      return sendJson(response, 200, { latest, runs: history });
    }
    if (request.method === 'GET' && pathname === '/api/toolkit') return sendJson(response, 200, await toolkitHealth());
    if (request.method === 'GET' && pathname.startsWith('/api/runs/') && pathname.endsWith('/events')) {
      const id = pathname.split('/')[3];
      const run = hydrateRun(id);
      if (!run) return sendJson(response, 404, { error: 'Run not found' });
      return openEventStream(request, response, run);
    }
    if (request.method === 'GET' && pathname.startsWith('/api/runs/') && pathname.endsWith('/report')) {
      const id = pathname.split('/')[3];
      const run = hydrateRun(id);
      if (!run) return sendJson(response, 404, { error: 'Run not found' });
      let report = '';
      try { report = fs.readFileSync(path.join(run.dir, 'security-report.md'), 'utf8'); } catch { report = 'Report is not ready yet.'; }
      return sendText(response, 200, redact(report), 'text/markdown; charset=utf-8');
    }
    if (request.method === 'GET' && /^\/api\/runs\/[^/]+\/findings\/[^/]+\/ai-review$/.test(pathname)) {
      const parts = pathname.split('/');
      const run = hydrateRun(decodeURIComponent(parts[3]));
      if (!run) return sendJson(response, 404, { error: 'Run not found' });
      const finding = findCorrelatedFinding(run, decodeURIComponent(parts[5]));
      if (!finding) return sendJson(response, 404, { error: 'Correlated finding not found' });
      return sendJson(response, 200, aiReviewStateForFinding(run, finding));
    }
    if (request.method === 'POST' && /^\/api\/runs\/[^/]+\/findings\/[^/]+\/ai-review$/.test(pathname)) {
      const parts = pathname.split('/');
      const run = hydrateRun(decodeURIComponent(parts[3]));
      if (!run) return sendJson(response, 404, { error: 'Run not found' });
      const finding = findCorrelatedFinding(run, decodeURIComponent(parts[5]));
      if (!finding) return sendJson(response, 404, { error: 'Correlated finding not found' });
      const body = await readBody(request);
      try {
        const result = await generateStoredFindingReview(run, finding, body);
        return sendJson(response, 200, result);
      } catch (error) {
        if (/Code snippets must be explicitly tied/.test(error.message)) return sendJson(response, 400, { error: redact(error.message) });
        throw error;
      }
    }
    if (request.method === 'POST' && /^\/api\/runs\/[^/]+\/ai-review\/summary$/.test(pathname)) {
      const parts = pathname.split('/');
      const run = hydrateRun(decodeURIComponent(parts[3]));
      if (!run) return sendJson(response, 404, { error: 'Run not found' });
      const body = await readBody(request);
      const mode = body.mode === 'RELEASE_REVIEW' ? 'RELEASE_REVIEW' : 'RUN_SUMMARY';
      return sendJson(response, 200, await generateStoredSummaryReview(run, mode));
    }
    if (request.method === 'GET' && pathname.startsWith('/api/runs/')) {
      const id = pathname.split('/')[3];
      const run = hydrateRun(id);
      if (!run) return sendJson(response, 404, { error: 'Run not found' });
      return sendJson(response, 200, { run });
    }
    if (request.method === 'POST' && pathname === '/api/scans') {
      const body = await readBody(request);
      const projectPath = safeProjectPath(body.projectPath);
      const mode = ['auto', 'full', 'quick'].includes(body.mode) ? body.mode : null;
      if (!projectPath || !mode) return sendJson(response, 400, { error: 'Use an existing local project directory and auto/quick/full mode.' });
      const webTarget = body.webTarget ? safeWebTarget(body.webTarget) : null;
      if (body.webTarget && !webTarget) return sendJson(response, 400, { error: 'Web targets must be authorized localhost or an explicitly configured test target.' });
      const active = [...runs.values()].find((run) => run.status === 'SCANNING');
      if (active) return sendJson(response, 409, { error: `A scan is already running: ${active.id}` });
      const run = createRun({ projectPath, mode, webTarget });
      void runAudit(run);
      return sendJson(response, 202, { runId: run.id });
    }
    if (request.method === 'POST' && /^\/api\/runs\/[^/]+\/findings\/[^/]+\/(?:verify|rescan)$/.test(pathname)) {
      const parts = pathname.split('/');
      const run = hydrateRun(decodeURIComponent(parts[3]));
      if (!run) return sendJson(response, 404, { error: 'Run not found' });
      const findingId = decodeURIComponent(parts[5]);
      const body = await readBody(request);
      const requestedTarget = body.webTarget || run.webTarget || null;
      const webTarget = requestedTarget ? safeWebTarget(requestedTarget) : null;
      if (requestedTarget && !webTarget) return sendJson(response, 400, { error: 'Web targets must be authorized localhost or an explicitly configured test target.' });
      try {
        const result = await verifyFinding({ projectPath: run.projectPath, findingId, webTarget });
        return sendJson(response, 200, result);
      } catch (error) {
        return sendJson(response, 409, { error: redact(error.message) });
      }
    }
    if (request.method === 'POST' && pathname.startsWith('/api/runs/') && pathname.endsWith('/stop')) {
      const id = pathname.split('/')[3];
      const run = hydrateRun(id);
      if (!run) return sendJson(response, 404, { error: 'Run not found' });
      run.abortRequested = true;
      for (const child of run.processes) child.kill('SIGTERM');
      writeEvent(run, { kind: 'scan-stop-requested', message: 'Stop requested; waiting for the active scanner to exit.' });
      return sendJson(response, 202, { ok: true });
    }
    if (request.method === 'POST' && /^\/api\/runs\/[^/]+\/findings\/[^/]+\/status$/.test(pathname)) {
      const parts = pathname.split('/');
      const run = hydrateRun(decodeURIComponent(parts[3]));
      if (!run) return sendJson(response, 404, { error: 'Run not found' });
      const findingId = decodeURIComponent(parts[5]);
      const body = await readBody(request);
      const index = readProjectIndex(run.projectId);
      const finding = index.findings.find((item) => item.id === findingId);
      if (!finding) return sendJson(response, 404, { error: 'Correlated finding not found' });
      try {
        explicitLifecycleAction(finding, body.status, { reason: redact(body.reason || ''), runId: run.id, timestamp: isoNow() });
      } catch (error) {
        return sendJson(response, 400, { error: redact(error.message) });
      }
      saveProjectIndex(index);
      run.correlatedFindings = index.findings;
      run.correlatedSummary = countCorrelatedFindings(run.correlatedFindings);
      run.summary = run.correlatedSummary;
      updateReleaseGate(run);
      run.aiReviews = aiReviewSummariesForRun(run);
      run.aiSummaryReviews = aiSummaryStatesForRun(run);
      atomicWrite(path.join(run.dir, 'summary.json'), `${JSON.stringify({ summary: run.summary, releaseGate: run.releaseGate, status: run.status }, null, 2)}\n`);
      atomicWrite(path.join(run.dir, 'security-report.md'), buildReport(run));
      saveRun(run);
      writeEvent(run, { kind: 'finding-lifecycle', findingId, status: finding.status, message: `${finding.id} marked ${finding.status}${body.reason ? ` — ${redact(body.reason)}` : ''}` });
      saveRun(run);
      return sendJson(response, 200, { finding, run });
    }
    if (request.method === 'POST' && pathname === '/api/toolkit/doctor') return sendJson(response, 200, await toolkitHealth());
    if (request.method === 'GET' && pathname === '/api/toolkit/lifecycle') return sendJson(response, 200, await lifecycleStatus());
    if (request.method === 'POST' && pathname === '/api/toolkit/check-updates') return sendJson(response, 200, await checkUpdates());
    if (request.method === 'POST' && pathname === '/api/toolkit/update') {
      if (!localMutationAuthorized(request)) return sendJson(response, 403, { error: 'Local lifecycle mutation requires JSON and the explicit X-Vibe-Code-Guard-Action confirmation header.' });
      const body = await readBody(request);
      if (typeof body.scanner !== 'string' || !body.scanner.trim()) return sendJson(response, 400, { error: 'Specify one scanner.' });
      return sendJson(response, 200, await updateTool(body.scanner, { dryRun: body.dryRun !== false, yes: body.confirm === true, securityReviewed: body.securityReviewed === true }));
    }
    if (request.method === 'POST' && pathname === '/api/toolkit/refresh-data') {
      if (!localMutationAuthorized(request)) return sendJson(response, 403, { error: 'Local lifecycle mutation requires JSON and the explicit X-Vibe-Code-Guard-Action confirmation header.' });
      const body = await readBody(request);
      if (typeof body.scanner !== 'string' || !body.scanner.trim()) return sendJson(response, 400, { error: 'Specify one scanner.' });
      return sendJson(response, 200, await refreshContent(body.scanner, { dryRun: body.dryRun !== false, yes: body.confirm === true, securityReviewed: body.securityReviewed === true }));
    }
    if (request.method === 'POST' && pathname === '/api/toolkit/self-test') {
      const result = await runFixedCommand('security-tools', ['self-test']);
      return sendJson(response, 200, { code: result.code, output: result.output, healthy: result.code === 0 && /ALL PASSED/.test(result.output) });
    }
    if (request.method === 'GET') return publicFile(pathname, response);
    return sendJson(response, 405, { error: 'Method not allowed' });
  } catch (error) {
    return sendJson(response, 500, { error: redact(error.message || 'Unexpected dashboard error') });
  }
});

if (require.main === module) {
  server.listen(PORT, HOST, () => {
    console.log(`Local Security Dashboard listening on http://${HOST}:${PORT}`);
    console.log(`Run data directory: ${DATA_DIR}`);
  });
}

module.exports = { server, createRun, runAudit, verifyFinding, hydrateRun, readRuns, safeProjectPath, safeWebTarget, detectStack };
