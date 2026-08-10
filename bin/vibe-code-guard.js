#!/usr/bin/env node

const fs = require('node:fs');
const http = require('node:http');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { buildExecutionPlan } = require('../orchestrator');
const {
  ROOT,
  TOOLKIT_HOME,
  doctor,
  extractJson,
  installLocalEntrypoints,
  installPlan,
  readProjectConfig,
  runFile,
  toolkitSelfTest,
  uninstallLocalEntrypoints,
  validateRuntimeTarget,
} = require('../core/agent');

const VERSION = require('../package.json').version;
const PROFILES = new Set(['auto', 'quick', 'full', 'release']);

function usage() {
  return `Vibe Code Guard ${VERSION}\n\nUsage:\n  vibe-code-guard install [--dry-run] [--yes] [--json]\n  vibe-code-guard doctor [--json]\n  vibe-code-guard audit [project] [--profile auto|quick|full|release] [--json]\n  vibe-code-guard dashboard [--port PORT] [--json] [--dry-run]\n  vibe-code-guard update [--check] [--yes] [--json]\n  vibe-code-guard uninstall [--dry-run] [--yes] [--json]\n  vibe-code-guard version\n\nAliases:\n  security-check audit .\n\nInstallation never changes shell startup files and never removes upstream scanners.`;
}

function parseArgs(argv) {
  const options = { json: false, dryRun: false, yes: false, check: false, profile: null, target: '.', port: null, webTarget: null };
  const positionals = [];
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--json') options.json = true;
    else if (arg === '--dry-run' || arg === '--plan') options.dryRun = true;
    else if (arg === '--yes' || arg === '-y') options.yes = true;
    else if (arg === '--check') options.check = true;
    else if (arg === '--profile' || arg === '-p') options.profile = argv[++index];
    else if (arg === '--target' || arg === '-t') options.target = argv[++index];
    else if (arg === '--web-target') options.webTarget = argv[++index];
    else if (arg === '--port') options.port = argv[++index];
    else if (arg === '--help' || arg === '-h') options.help = true;
    else if (!arg.startsWith('-')) positionals.push(arg);
    else throw new Error(`Unknown option: ${arg}`);
  }
  if (positionals[0] && options.target === '.') options.target = positionals[0];
  return options;
}

function emit(payload, human) {
  if (payload.json) console.log(JSON.stringify(payload.data, null, 2));
  else console.log(human);
  return payload.code ?? 0;
}

function humanDoctor(result) {
  const lines = [`Vibe Code Guard ${result.version}`, `Overall: ${result.status}`, '', 'Security toolchain:'];
  for (const tool of Object.values(result.toolchain)) lines.push(`- ${tool.displayName}: ${tool.status}${tool.version ? ` — ${tool.version}` : ''}${tool.reason ? ` — ${tool.reason}` : ''}`);
  lines.push('', `Dashboard: ${result.dashboard.status} (${result.dashboard.host} only)`, `Workflow: ${result.workflowVersion}`);
  if (result.wrapper?.status === 'DEGRADED') lines.push('Note: the global security-tools wrapper reported a degraded external dependency.');
  return lines.join('\n');
}

async function commandDoctor(options) {
  const result = await doctor();
  return emit({ json: options.json, data: result, code: result.status === 'BROKEN' ? 1 : result.status === 'DEGRADED' ? 2 : 0 }, humanDoctor(result));
}

async function commandInstall(options) {
  const plan = await installPlan();
  const local = installLocalEntrypoints({ dryRun: true });
  const data = { status: options.dryRun || !options.yes ? 'PLAN_ONLY' : 'INSTALLING', plan, localEntrypoints: local, upstreamTools: 'independently installed; never bundled by this repository' };
  if (!options.yes && !options.dryRun) data.nextAction = 'Review this plan, then rerun with --yes to apply only these planned actions.';
  if (options.dryRun) return emit({ json: options.json, data, code: 0 }, renderInstall(data));
  if (!options.yes) return emit({ json: options.json, data, code: 0 }, renderInstall(data));
  const executed = [];
  const failures = [];
  for (const action of plan.actions) {
    const result = await runFile(action.command, action.args, { timeoutMs: 10 * 60 * 1000 });
    executed.push({ ...action, exitCode: result.code, output: result.output.slice(-2000) });
    if (result.code !== 0) failures.push({ id: action.id, reason: `Installer exited with code ${result.code}.` });
  }
  let localInstall = null;
  try { localInstall = installLocalEntrypoints(); } catch (error) { failures.push({ id: 'vibe-code-guard', reason: error.message }); }
  const health = await doctor();
  const selfTest = await toolkitSelfTest();
  const status = failures.length || health.status === 'BROKEN' ? 'FAILED' : health.status === 'DEGRADED' || selfTest.overall === 'DEGRADED' ? 'DEGRADED' : 'READY';
  const result = { status, plan, executed, failures, localEntrypoints: localInstall, doctor: health, selfTest: summarizeSelfTest(selfTest) };
  return emit({ json: options.json, data: result, code: status === 'FAILED' ? 1 : status === 'DEGRADED' ? 2 : 0 }, renderInstall(result));
}

function renderInstall(data) {
  const lines = [`Vibe Code Guard install: ${data.status}`];
  const plan = data.plan;
  if (plan) {
    lines.push(`Platform: ${plan.platform}/${plan.architecture}`, `Planned tool actions: ${plan.actions.length}`);
    for (const action of plan.actions) lines.push(`- ${action.id}: ${action.command} ${action.args.join(' ')}`);
    for (const note of plan.notes) lines.push(`- NOTE: ${note}`);
  }
  if (data.nextAction) lines.push(data.nextAction);
  if (data.doctor) lines.push(`Doctor: ${data.doctor.status}`, `Self-test: ${data.selfTest?.overall || 'UNKNOWN'}`);
  return lines.join('\n');
}

function summarizeSelfTest(result) {
  if (!result) return null;
  const { raw, ...summary } = result;
  return summary;
}

function safeProjectRoot(input) {
  if (typeof input !== 'string' || !input.trim() || input.includes('\0') || input.includes('://')) throw new Error('Audit target must be an existing local directory path.');
  const resolved = path.resolve(input);
  const home = os.homedir();
  const toolkit = TOOLKIT_HOME();
  if ([path.parse(resolved).root, home, toolkit].includes(resolved)) throw new Error('Refusing to audit a filesystem root, home directory, or security-toolkit directory.');
  const stat = fs.statSync(resolved);
  if (!stat.isDirectory()) throw new Error('Audit target must be a directory.');
  return resolved;
}

function selectRuntimeTarget(configTargets, explicit) {
  const candidate = explicit || configTargets[0] || null;
  if (!candidate) return null;
  const result = validateRuntimeTarget(candidate);
  if (!result.allowed) throw new Error(result.reason);
  return result.target;
}

function dashboardState() {
  const statePath = path.join(TOOLKIT_HOME(), 'vibe-code-guard', 'dashboard.json');
  try {
    const state = JSON.parse(fs.readFileSync(statePath, 'utf8'));
    return state.dashboardUrl ? state : null;
  } catch {
    return null;
  }
}

async function commandAudit(options) {
  const projectPath = safeProjectRoot(options.target || '.');
  const projectConfig = readProjectConfig(projectPath);
  const profile = options.profile || projectConfig.config.profile || 'auto';
  if (!PROFILES.has(profile)) throw new Error(`Unsupported audit profile: ${profile}`);
  const webTarget = selectRuntimeTarget(projectConfig.config.runtimeTargets, options.webTarget);
  const mode = profile === 'release' ? 'full' : profile;
  if (options.dryRun) {
    const plan = buildExecutionPlan({ projectPath, webTarget });
    const data = { status: 'PLANNED', profile, project: projectPath, config: projectConfig, plan, dashboardUrl: dashboardState()?.dashboardUrl || null };
    return emit({ json: options.json, data, code: 0 }, `Audit plan for ${projectPath}\nProfile: ${profile}\n${plan.explanation.join('\n')}`);
  }
  const health = await doctor();
  if (health.status === 'BROKEN') {
    const data = { status: 'BLOCKED', profile, project: projectPath, reason: 'Vibe Code Guard toolchain is BROKEN; no scan was started.', doctor: health, dashboardUrl: dashboardState()?.dashboardUrl || null };
    return emit({ json: options.json, data, code: 1 }, 'Audit blocked: the Vibe Code Guard toolchain is BROKEN. Run vibe-code-guard doctor.');
  }
  const { createRun, runAudit } = require('../server');
  const run = createRun({ projectPath, mode, webTarget });
  await runAudit(run);
  const data = {
    status: run.status === 'FAIL' ? 'FAILED' : 'COMPLETED',
    profile,
    runId: run.id,
    project: run.projectPath,
    stack: run.stack,
    releaseGate: run.releaseGate,
    issues: run.summary,
    correlatedFindings: run.correlatedFindings || [],
    scannerObservations: run.observationSummary,
    doctor: health,
    dashboardUrl: dashboardState()?.dashboardUrl || null,
    dashboardCommand: 'vibe-code-guard dashboard',
    config: projectConfig.config,
  };
  const human = [`Audit ${data.status}: ${data.project}`, `Profile: ${profile}`, `Run: ${data.runId}`, `Release gate: ${data.releaseGate.label}`, `Issues: ${data.issues.total} correlated (${data.issues.critical} critical, ${data.issues.high} high, ${data.issues.medium} medium, ${data.issues.low} low)`, data.dashboardUrl ? `Dashboard: ${data.dashboardUrl}` : 'Dashboard: run `vibe-code-guard dashboard` to open local history.'];
  return emit({ json: options.json, data, code: data.status === 'FAILED' ? 1 : 0 }, human.join('\n'));
}

function findPort(preferred) {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', reject);
    server.listen(preferred || 0, '127.0.0.1', () => {
      const port = server.address().port;
      server.close(() => resolve(port));
    });
  });
}

function getJson(url) {
  return new Promise((resolve, reject) => {
    const request = http.get(url, (response) => {
      let body = '';
      response.setEncoding('utf8');
      response.on('data', (chunk) => { body += chunk; });
      response.on('end', () => resolve({ statusCode: response.statusCode, body }));
    });
    request.setTimeout(300, () => request.destroy(new Error('timeout')));
    request.on('error', reject);
  });
}

async function waitForHealth(url) {
  for (let attempt = 0; attempt < 15; attempt += 1) {
    try {
      const response = await getJson(`${url}/api/health`);
      if (response.statusCode === 200) return JSON.parse(response.body);
    } catch { /* retry while the local child starts */ }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  return null;
}

async function commandDashboard(options) {
  const hasRequestedPort = options.port !== null || Boolean(process.env.PORT);
  const requestedPort = options.port !== null ? Number(options.port) : Number(process.env.PORT || 0);
  if (hasRequestedPort && (!Number.isInteger(requestedPort) || requestedPort < 0 || requestedPort > 65535)) throw new Error('Dashboard port must be 0 (auto) or an integer between 1 and 65535.');
  const port = await findPort(requestedPort);
  const url = `http://127.0.0.1:${port}`;
  const dataDir = process.env.SECURITY_DASHBOARD_DATA_DIR || path.join(TOOLKIT_HOME(), 'runs');
  if (options.dryRun) return emit({ json: options.json, data: { status: 'PLANNED', host: '127.0.0.1', port, dashboardUrl: url, localOnly: true, dataDir }, code: 0 }, `Dashboard plan: ${url} (127.0.0.1 only)`);
  const child = spawn(process.execPath, [path.join(ROOT, 'server.js')], {
    detached: true,
    stdio: 'ignore',
    env: { ...process.env, PORT: String(port), SECURITY_DASHBOARD_DATA_DIR: dataDir },
  });
  child.unref();
  const health = await waitForHealth(url);
  if (!health) return emit({ json: options.json, data: { status: 'FAILED', dashboardUrl: url, reason: 'Local Dashboard did not become healthy within the startup window.' }, code: 1 }, 'Dashboard failed to start.');
  const stateDir = path.join(TOOLKIT_HOME(), 'vibe-code-guard');
  fs.mkdirSync(stateDir, { recursive: true, mode: 0o755 });
  fs.writeFileSync(path.join(stateDir, 'dashboard.json'), `${JSON.stringify({ dashboardUrl: url, pid: child.pid, dataDir, startedAt: new Date().toISOString(), localOnly: true }, null, 2)}\n`, { mode: 0o600 });
  return emit({ json: options.json, data: { status: 'READY', dashboardUrl: url, host: '127.0.0.1', port, pid: child.pid, dataDir, localOnly: true }, code: 0 }, `Dashboard ready: ${url}\nLocal-only binding: 127.0.0.1`);
}

async function commandUpdate(options) {
  const plan = installLocalEntrypoints({ dryRun: true });
  const manifestPath = path.join(TOOLKIT_HOME(), 'vibe-code-guard', 'installation.json');
  let installed = null;
  try { installed = JSON.parse(fs.readFileSync(manifestPath, 'utf8')); } catch { /* not installed */ }
  const data = { status: installed ? 'CHECKED' : 'NOT_INSTALLED', productVersion: VERSION, installedVersion: installed?.productVersion || null, scannerUpdates: 'NOT_TOUCHED', plan };
  if (options.check || options.dryRun || !options.yes) return emit({ json: options.json, data, code: installed && installed.productVersion !== VERSION ? 2 : 0 }, `Vibe Code Guard update check: ${data.status}\nInstalled: ${data.installedVersion || 'not installed'}\nCurrent checkout: ${VERSION}\nScanner updates: not touched`);
  const updated = installLocalEntrypoints();
  return emit({ json: options.json, data: { ...data, status: 'UPDATED', localEntrypoints: updated }, code: 0 }, `Vibe Code Guard updated to ${VERSION}. Scanner updates were not touched.`);
}

async function commandUninstall(options) {
  const preview = uninstallLocalEntrypoints({ dryRun: true });
  if (options.dryRun || !options.yes) return emit({ json: options.json, data: { ...preview, status: 'PLAN_ONLY', upstreamTools: 'preserved' }, code: 0 }, `Uninstall plan: remove ${preview.removed.length} Vibe Code Guard-owned file(s); preserve upstream scanners.`);
  const result = uninstallLocalEntrypoints();
  return emit({ json: options.json, data: { ...result, upstreamTools: 'preserved' }, code: result.status === 'DEGRADED' ? 2 : 0 }, `Uninstall: ${result.status}\nRemoved: ${result.removed.join(', ') || 'none'}\nUpstream scanners were preserved.`);
}

async function main() {
  const argv = process.argv.slice(2);
  if (argv[0] === '--version' || argv[0] === '-v') { console.log(VERSION); return 0; }
  const command = argv[0] && !argv[0].startsWith('-') ? argv.shift() : 'help';
  const options = parseArgs(argv);
  if (options.help || command === 'help') { console.log(usage()); return 0; }
  if (command === 'version' || command === '--version') { console.log(VERSION); return 0; }
  if (command === 'doctor') return commandDoctor(options);
  if (command === 'install') return commandInstall(options);
  if (command === 'audit') return commandAudit(options);
  if (command === 'dashboard') return commandDashboard(options);
  if (command === 'update') return commandUpdate(options);
  if (command === 'uninstall') return commandUninstall(options);
  throw new Error(`Unknown command: ${command}`);
}

main().then((code) => { process.exitCode = code; }).catch((error) => {
  console.error(`Vibe Code Guard error: ${error.message}`);
  process.exitCode = 1;
});
