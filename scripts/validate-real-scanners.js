#!/usr/bin/env node
'use strict';

// Opt-in evidence harness. Generated projects and scanner reports never share a directory.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const { adaptScannerOutput, redact } = require('../core/findings');
const ROOT = path.resolve(__dirname, '..');
const MANIFEST = require('../config/toolchain.json');
const active = new Set();
const LIMIT = 8 * 1024 * 1024;

function kill(child, signal = 'SIGTERM') {
  try { process.kill(-child.pid, signal); } catch { try { child.kill(signal); } catch {} }
}
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => {
  for (const child of active) kill(child, 'SIGKILL');
  process.exit(2);
});

function runProcess(binary, args, env, timeoutMs = 45000, cwd = ROOT) {
  return new Promise((resolve) => {
    const started = Date.now();
    const child = spawn(binary, args, { env, cwd, detached: true, stdio: ['ignore', 'pipe', 'pipe'], shell: false });
    active.add(child);
    let stdout = '', stderr = '', timedOut = false, overflow = false, error = null, escalation;
    const stop = () => { kill(child); escalation = setTimeout(() => kill(child, 'SIGKILL'), 1000); };
    const timer = setTimeout(() => { timedOut = true; stop(); }, timeoutMs);
    const append = (key, bytes) => {
      if (key === 'stdout') stdout += bytes;
      else stderr += bytes;
      if (!overflow && Buffer.byteLength(stdout) + Buffer.byteLength(stderr) > LIMIT) { overflow = true; stop(); }
      stdout = stdout.slice(0, LIMIT); stderr = stderr.slice(0, LIMIT);
    };
    child.stdout.on('data', (bytes) => append('stdout', bytes));
    child.stderr.on('data', (bytes) => append('stderr', bytes));
    child.on('error', (value) => { error = value.message; });
    child.on('close', (code, signal) => {
      clearTimeout(timer); clearTimeout(escalation); active.delete(child);
      resolve({ binary, args, exitCode: code, signal, durationMs: Date.now() - started, timedOut, overflow, error, stdout, stderr });
    });
  });
}

function summaryExit(results) {
  if (!results.length) return 1;
  if (results.some((item) => item.failure)) return 1;
  return results.every((item) => item.status === 'REAL_VALIDATED') ? 0 : 2;
}

function installedVersion(tool, command) {
  if (command.exitCode !== 0) return null;
  const text = `${command.stdout}\n${command.stderr}`;
  const pattern = tool.versionPattern ? new RegExp(tool.versionPattern) : /(?:^|[^0-9A-Za-z.])v?(\d+\.\d+\.\d+)(?:$|[^0-9A-Za-z.])/;
  return text.match(pattern)?.[1] || (tool.id === 'zap' ? text.match(/^\s*v?(\d+\.\d+\.\d+)\s*$/m)?.[1] : null) || null;
}

function safeEvidence(value, root = '', home = '') {
  if (typeof value === 'string') {
    let text = redact(value).replace(/VCG_SYNTHETIC_CREDENTIAL_[A-Z0-9]+/g, '[SYNTHETIC REDACTED]')
      .replace(/sk_live_[0-9a-f]{32}/g, '[SYNTHETIC REDACTED]');
    if (root) text = text.split(root).join('$VALIDATION');
    if (home) text = text.split(home).join('$HOME');
    return text;
  }
  if (Array.isArray(value)) return value.map((item) => safeEvidence(item, root, home));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, safeEvidence(item, root, home)]));
  return value;
}

function writeJson(file, value) { fs.writeFileSync(file, JSON.stringify(value, null, 2) + '\n', { mode: 0o600 }); }
function hash(file) { try { return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex'); } catch { return null; } }
function findBinary(tool) {
  for (const candidate of tool.candidates) {
    const paths = path.isAbsolute(candidate) ? [candidate] : (process.env.PATH || '').split(path.delimiter).map((dir) => path.join(dir, candidate));
    for (const file of paths) { try { if (fs.statSync(file).isFile()) { fs.accessSync(file, fs.constants.X_OK); return fs.realpathSync(file); } } catch {} }
  }
  return null;
}

// These launchers execute installed binaries unchanged; they add timeout/evidence capture only.
async function executeLauncher(id, args) {
  const context = JSON.parse(fs.readFileSync(process.env.VCG_VALIDATION_CONTEXT, 'utf8'));
  const result = await runProcess(context.binaries[id] || path.join(context.root, 'missing', id), args, process.env, id === 'zap' ? 60000 : 45000, process.cwd());
  const trace = path.join(context.root, 'traces', `${Date.now()}-${process.pid}-${id}.json`);
  writeJson(trace, safeEvidence({ tool: id, ...result }, context.root, context.originalHome));
  process.stdout.write(result.stdout); process.stderr.write(result.stderr);
  process.exitCode = result.timedOut || result.overflow ? 124 : result.exitCode ?? 127;
}

async function chainWorker(kind, project) {
  const context = JSON.parse(fs.readFileSync(process.env.VCG_VALIDATION_CONTEXT, 'utf8'));
  assert.ok(['secret', 'static', 'container', 'dependencies'].includes(kind));
  assert.match(path.basename(context.root), /^vcg-real-validation-/);
  assert.equal(fs.realpathSync(project), path.join(fs.realpathSync(context.root), 'projects', kind));
  const { server, createRun, runAudit } = require('../server');
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const url = `http://127.0.0.1:${server.address().port}`;
  const checks = [];
  const run = createRun({ projectPath: fs.realpathSync(project), mode: kind === 'container' ? 'full' : 'auto', webTarget: null });
  try {
    await runAudit(run);
    const scanner = kind === 'static' ? 'semgrep' : kind === 'container' ? 'checkov' : kind === 'dependencies' ? 'trivy' : 'gitleaks';
    const candidates = run.correlatedFindings.filter((item) => item.observations.some((o) => o.scanner === scanner));
    const finding = kind === 'dependencies' ? candidates.find((item) => /CVE-2021-23337/.test(JSON.stringify(item))) : candidates[0];
    if (!finding) return { status: run.tools[scanner].status === 'PASS' ? 'REAL_PARTIAL' : 'BLOCKED_BY_ENVIRONMENT', failure: run.tools[scanner].status === 'PASS', reason: 'Expected initial finding was unavailable.', tools: run.tools, initialRunId: run.id };
    if (kind === 'dependencies' && ['trivy', 'osv-scanner'].some((id) => run.tools[id].status !== 'PASS')) return { status: 'BLOCKED_BY_ENVIRONMENT', reason: 'Both dependency scanners must execute before a dependency remediation chain can be claimed.', tools: run.tools, initialRunId: run.id };
    const initialVersions = Object.fromEntries(Object.entries(run.tools).map(([id, tool]) => [id, tool.version]));
    const file = path.join(project, kind === 'container' ? 'Dockerfile' : kind === 'static' ? 'src/routes/auth.js' : kind === 'dependencies' ? 'package-lock.json' : 'src/config.js');
    const original = fs.readFileSync(file, 'utf8');
    const fixed = kind === 'container' ? 'FROM node:20-alpine\nUSER node\nHEALTHCHECK CMD node -e "process.exit(0)"\nCMD ["node", "app.js"]\n'
      : kind === 'static' ? 'module.exports = () => null;\n' : kind === 'dependencies' ? original.replaceAll('4.17.11', '4.17.21') : 'module.exports = { synthetic: true };\n';
    const markFixed = async () => {
      const response = await fetch(`${url}/api/runs/${run.id}/findings/${finding.id}/status`, {
        method: 'POST', headers: { 'content-type': 'application/json', 'x-vibe-code-guard-action': 'confirmed' },
        body: JSON.stringify({ status: 'FIXED', reason: 'Authorized disposable synthetic remediation.' }),
      });
      assert.equal(response.status, 200);
    };
    const verify = async (expected, overrides = {}) => {
      const command = await runProcess(process.execPath, [path.join(ROOT, 'bin/vibe-code-guard.js'), 'verify', finding.id, project, '--json'], { ...process.env, ...overrides }, 120000);
      assert.equal(command.timedOut, false);
      const data = JSON.parse(command.stdout);
      assert.equal(data.verification, expected);
      if (kind === 'dependencies') assert.ok(['trivy', 'osv-scanner'].every((id) => data.relevantScanners.includes(id)), 'Dependency verification must retain both scanners.');
      assert.equal(command.exitCode, expected === 'PASSED' ? 0 : expected === 'STILL_DETECTED' ? 1 : 2);
      const response = await fetch(`${url}/api/runs/${data.runId}`);
      const { run: dashboard } = await response.json();
      assert.equal(dashboard.verification.verification, data.verification);
      assert.equal(dashboard.correlatedFindings.find((item) => item.id === finding.id).status, data.lifecycle);
      assert.deepEqual(dashboard.releaseGate, data.releaseGate);
      if (expected === 'PASSED') assert.ok(data.coverage.results.every((item) => item.version));
      else assert.notEqual(data.lifecycle, 'VERIFIED');
      checks.push({ expected, cliExitCode: command.exitCode, ...data, dashboardAgrees: true });
    };
    await markFixed(); await verify('STILL_DETECTED');
    fs.writeFileSync(file, fixed); await markFixed(); await verify('PASSED');
    fs.writeFileSync(file, original); await markFixed(); await verify('STILL_DETECTED');
    fs.writeFileSync(file, fixed);
    fs.writeFileSync(path.join(project, '.semgrepignore'), 'src/\n');
    await markFixed(); await verify('VERIFICATION_INCOMPLETE');
    fs.unlinkSync(path.join(project, '.semgrepignore'));
    const configured = JSON.parse(process.env.SECURITY_TOOL_BINARIES);
    await markFixed(); await verify('VERIFICATION_INCOMPLETE', { SECURITY_TOOL_BINARIES: JSON.stringify({ ...configured, [kind === 'dependencies' ? 'osv-scanner' : scanner]: path.join(project, 'absent-scanner') }) });
    return { status: 'REAL_VALIDATED', initialRunId: run.id, findingId: finding.id, initialVersions, tools: run.tools, checks };
  } finally {
    for (const child of run.processes) child.kill('SIGKILL');
    await new Promise((resolve) => server.close(resolve));
  }
}

async function main() {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'vcg-real-validation-')));
  const originalHome = os.homedir();
  for (const dir of ['home', 'toolkit', 'runs', 'traces', 'bin', 'projects', 'cache']) fs.mkdirSync(path.join(root, dir), { mode: 0o700 });
  const context = { root, originalHome, binaries: Object.fromEntries(MANIFEST.tools.map((tool) => [tool.id, findBinary(tool)])) };
  const contextFile = path.join(root, 'context.json'); writeJson(contextFile, context);
  const wrappers = {};
  for (const tool of MANIFEST.tools) {
    const launcher = path.join(root, 'bin', tool.id); wrappers[tool.id] = launcher;
    fs.writeFileSync(launcher, `#!${process.execPath}\nrequire(${JSON.stringify(__filename)}).executeLauncher(${JSON.stringify(tool.id)}, process.argv.slice(2)).catch(e => { console.error(e.message); process.exit(1); });\n`, { mode: 0o700 });
  }
  const cache = process.platform === 'darwin' ? path.join(originalHome, 'Library/Caches/trivy') : path.join(originalHome, '.cache/trivy');
  const metadataFile = path.join(cache, 'db/metadata.json');
  const templates = path.join(originalHome, 'nuclei-templates');
  const template = path.join(templates, 'http/exposures/configs/git-config.yaml');
  const trackedFiles = [metadataFile, path.join(cache, 'db/trivy.db'), template, ...Object.values(context.binaries).filter(Boolean)];
  // Metadata/stats catch host writes without hashing a gigabyte database on each invocation.
  const snapshot = () => trackedFiles.map((file) => {
    try { const stat = fs.statSync(file); return { file, size: stat.size, mtimeMs: stat.mtimeMs, hash: stat.size < LIMIT ? hash(file) : null }; }
    catch { return { file, missing: true }; }
  });
  const before = snapshot();
  for (const dir of ['db', 'policy']) {
    if (fs.existsSync(path.join(cache, dir))) fs.cpSync(path.join(cache, dir), path.join(root, 'cache', dir), { recursive: true, mode: fs.constants.COPYFILE_FICLONE });
  }
  const env = {
    ...process.env, HOME: path.join(root, 'home'), XDG_CACHE_HOME: path.join(root, 'cache'), XDG_CONFIG_HOME: path.join(root, 'home/.config'),
    SECURITY_TOOLKIT_HOME: path.join(root, 'toolkit'), SECURITY_DASHBOARD_DATA_DIR: path.join(root, 'runs'),
    SECURITY_TOOL_BINARIES: JSON.stringify(wrappers), VCG_VALIDATION_CONTEXT: contextFile,
    VCG_SEMGREP_CONFIG: '', VCG_GITLEAKS_CONFIG: '', SECURITY_AI_PROVIDER: 'disabled',
    SEMGREP_SEND_METRICS: 'off', SEMGREP_ENABLE_VERSION_CHECK: '0', DO_NOT_TRACK: '1', CI: '1',
    TRIVY_CACHE_DIR: path.join(root, 'cache'), TRIVY_SKIP_DB_UPDATE: 'true', TRIVY_SKIP_JAVA_DB_UPDATE: 'true',
    TRIVY_SKIP_CHECK_UPDATE: 'true', TRIVY_SKIP_VERSION_CHECK: 'true', TRIVY_OFFLINE_SCAN: 'true',
  };
  const rule = path.join(root, 'local-semgrep.yml');
  fs.copyFileSync(path.join(ROOT, 'test/real-scanner/semgrep/vcg-real-static.yml'), rule);
  env.VCG_SEMGREP_CONFIG = rule;
  const results = [], inventory = {};
  const add = (id, status, reason, extra = {}) => results.push({ id, status, reason, ...extra });
  const project = (name) => { const dir = path.join(root, 'projects', name); fs.mkdirSync(path.join(dir, 'src/routes'), { recursive: true }); return dir; };
  for (const tool of MANIFEST.tools) {
    const version = await runProcess(wrappers[tool.id], tool.versionArgs, env, 30000);
    inventory[tool.id] = { binary: context.binaries[tool.id], officialRepository: tool.upstream.officialRepository, provenance: 'Resolved installed path; no installation or release authentication performed.', version: installedVersion(tool, version), command: version };
  }
  for (const kind of ['secret', 'static', 'container', 'dependencies']) {
    const dir = project(kind);
    if (kind === 'secret') {
      fs.writeFileSync(path.join(dir, 'src/config.js'), `module.exports = { token: '${'VCG_SYNTHETIC_CREDENTIAL_' + 'A1B2C3D4'.repeat(3)}' };\n`);
      const config = path.join(dir, '.gitleaks.toml');
      fs.writeFileSync(config, 'title = "VCG safe synthetic validation"\n[[rules]]\nid = "vcg-synthetic-credential"\ndescription = "Synthetic credential only"\nregex = "VCG_SYNTHETIC_CREDENTIAL_[A-Z0-9]{24}"\n');
      env.VCG_GITLEAKS_CONFIG = config;
    } else { env.VCG_GITLEAKS_CONFIG = ''; }
    if (kind === 'static') fs.writeFileSync(path.join(dir, 'src/routes/auth.js'), 'module.exports = request => request.headers.authorization;\n');
    if (kind === 'container') {
      fs.writeFileSync(path.join(dir, 'Dockerfile'), 'FROM node:20-alpine\nCMD ["node", "app.js"]\n');
      fs.writeFileSync(path.join(dir, 'app.js'), 'console.log("Disposable example; never started");\n');
      fs.writeFileSync(path.join(dir, '.checkov.yaml'), 'skip-download: true\n');
    }
    if (kind === 'dependencies') fs.copyFileSync(path.join(ROOT, 'test/e2e/fixtures/node-api/package-lock.json'), path.join(dir, 'package-lock.json'));
    process.stderr.write(`Validating ${kind} discovery and targeted verification...\n`);
    const command = await runProcess(process.execPath, [__filename, '--chain', kind, dir], env, 600000);
    let data;
    try { data = JSON.parse(command.stdout); } catch { data = null; }
    if (command.exitCode === 0 && data) add(`${kind}-workflow`, data.status, data.reason || 'Real audit, fix, targeted verification and negative cases completed.', { failure: !!data.failure, evidence: data });
    else add(`${kind}-workflow`, command.timedOut ? 'BLOCKED_BY_ENVIRONMENT' : 'REAL_PARTIAL', 'Workflow did not complete.', { failure: !command.timedOut, command });
  }
  env.VCG_GITLEAKS_CONFIG = '';
  const secret = project('trufflehog-detection');
  fs.writeFileSync(path.join(secret, 'sample.txt'), 'Synthetic noncredential stripe fixture: ' + 'sk_' + 'live_' + '0123456789abcdef'.repeat(2) + '\n');
  const th = await runProcess(wrappers.trufflehog, ['filesystem', secret, '--no-verification', '--no-update', '--no-color', '--json'], env);
  try {
    const findings = adaptScannerOutput('trufflehog', th.stdout, { projectPath: secret });
    const valid = th.stdout.trim().split('\n').filter(Boolean).every((line) => { JSON.parse(line); return true; });
    add('trufflehog-detection', th.exitCode === 0 && valid && findings.length && inventory.trufflehog.version ? 'REAL_VALIDATED' : th.exitCode === 0 ? 'REAL_PARTIAL' : 'BLOCKED_BY_ENVIRONMENT', 'Synthetic unverified pattern; no credential verification. This is detector/adapter evidence, not a targeted remediation chain.', { findingCount: findings.length, command: th });
  } catch (error) { add('trufflehog-detection', 'REAL_PARTIAL', error.message, { failure: true, command: th }); }
  const dependencies = project('dependencies');
  fs.copyFileSync(path.join(ROOT, 'test/e2e/fixtures/node-api/package-lock.json'), path.join(dependencies, 'package-lock.json'));
  for (const id of ['trivy', 'osv-scanner']) {
    const args = id === 'trivy' ? ['fs', '--scanners', 'vuln', '--skip-db-update', '--skip-java-db-update', '--skip-check-update', '--offline-scan', '--format', 'json', path.join(dependencies, 'package-lock.json')]
      : ['scan', 'source', '--recursive', '--format', 'json', dependencies];
    const command = await runProcess(wrappers[id], args, env, 60000);
    let findings = [], failure = false, parsed = null;
    try { parsed = JSON.parse(command.stdout); findings = adaptScannerOutput(id, command.stdout, { projectPath: dependencies }); }
    catch { failure = command.exitCode === 0; }
    const expected = findings.some((item) => /lodash/i.test(item.title + item.explanation.technical) && /CVE-|GHSA-/i.test(item.title + item.explanation.technical));
    failure ||= !!parsed && [0, 1].includes(command.exitCode) && !expected;
    add(`${id}-dependencies`, failure ? 'REAL_PARTIAL' : expected && inventory[id].version && [0, 1].includes(command.exitCode) && !command.timedOut && !command.overflow ? 'REAL_VALIDATED' : 'BLOCKED_BY_ENVIRONMENT', expected ? 'Historical dependency detection/normalization; see the separate dependencies-workflow for remediation evidence.' : 'Dependency intelligence unavailable or expected dependency not detected.', { failure, expectedFixtureDetected: expected, findingCount: findings.length, metadata: id === 'trivy' && fs.existsSync(metadataFile) ? JSON.parse(fs.readFileSync(metadataFile)) : null, structuredOutput: !!parsed, command });
  }
  if (fs.existsSync(metadataFile)) {
    const metadata = JSON.parse(fs.readFileSync(metadataFile));
    const next = Date.parse(metadata.NextUpdate);
    const expired = !Number.isFinite(next) || next <= Date.now();
    add('trivy-db-freshness', expired ? 'REAL_PARTIAL' : 'REAL_VALIDATED', expired ? 'Existing usable DB is expired or its freshness is unknown. No refresh attempted.' : 'Existing DB metadata is current.', { schemaVersion: metadata.Version, expired, nextUpdate: metadata.NextUpdate });
  } else add('trivy-db-freshness', 'BLOCKED_BY_ENVIRONMENT', 'Required local DB metadata is missing.');
  let exposed = true;
  const app = http.createServer((request, response) => {
    if (request.url === '/.git/config' && exposed) { response.writeHead(200, { 'Content-Type': 'text/plain' }); response.end('[core]\nrepositoryformatversion = 0\n'); }
    else if (request.url === '/') { response.writeHead(200, { 'Content-Type': 'text/html' }); response.end('<!doctype html><html><head><title>Disposable localhost fixture</title></head><body>Safe validation page</body></html>'); }
    else { response.writeHead(404); response.end('Not found'); }
  });
  await new Promise((resolve) => app.listen(0, '127.0.0.1', resolve));
  const target = `http://127.0.0.1:${app.address().port}`;
  try {
    if (fs.existsSync(template) && /# digest:/.test(fs.readFileSync(template, 'utf8'))) {
      const args = ['-u', target, '-t', template, '-dut', '-ni', '-duc', '-jsonl', '-silent', '-timeout', '3', '-retries', '0'];
      const command = await runProcess(wrappers.nuclei, args, env);
      const parseLines = (text) => text.split('\n').filter((line) => line.trim()).map((line) => JSON.parse(line));
      parseLines(command.stdout);
      const findings = adaptScannerOutput('nuclei', command.stdout, { projectPath: root });
      const detected = findings.some((item) => item.scanner.ruleId === 'git-config');
      exposed = false;
      const fixed = await runProcess(wrappers.nuclei, args, env);
      parseLines(fixed.stdout);
      const clean = !adaptScannerOutput('nuclei', fixed.stdout, { projectPath: root }).some((item) => item.scanner.ruleId === 'git-config');
      const valid = command.exitCode === 0 && fixed.exitCode === 0 && detected && clean && inventory.nuclei.version;
      const failure = (command.exitCode === 0 && !detected) || (fixed.exitCode === 0 && !clean);
      add('nuclei-runtime', failure ? 'REAL_PARTIAL' : valid ? 'REAL_VALIDATED' : 'BLOCKED_BY_ENVIRONMENT', 'Existing signed official git-config template against localhost only; direct finding/fix/rescan, not VCG runtime-family verification.', { command, fixed, detected, failure, templateHash: hash(template), upstream: 'https://github.com/projectdiscovery/nuclei-templates', vcgRuntimeVerification: 'NOT_TESTED' });
    } else add('nuclei-runtime', 'NOT_TESTED', 'Reviewed signed official git-config template is unavailable. No download attempted.');
    const report = path.join(root, 'zap-report.json');
    const command = await runProcess(wrappers.zap, ['-dir', path.join(root, 'home/zap'), '-cmd', '-config', 'autoupdate.checkOnStart=false', '-config', 'autoupdate.downloadNewRelease=false', '-quickurl', target, '-quickout', report, '-quickprogress'], env, 90000);
    let findings = [], failure = false;
    if (fs.existsSync(report)) {
      try { const text = fs.readFileSync(report, 'utf8'); JSON.parse(text); findings = adaptScannerOutput('zap', text, { projectPath: root }); }
      catch { failure = command.exitCode === 0; }
    }
    const detected = findings.some((item) => ['10020', '10038'].includes(String(item.scanner.ruleId)));
    failure ||= command.exitCode === 0 && !detected;
    add('zap-runtime', failure ? 'REAL_PARTIAL' : detected && command.exitCode === 0 && inventory.zap.version ? 'REAL_VALIDATED' : 'BLOCKED_BY_ENVIRONMENT', 'Expected missing clickjacking/CSP header on a disposable local page. Direct detection/normalization only; targeted runtime verification NOT_TESTED.', { failure, detected, findingCount: findings.length, command, vcgRuntimeVerification: 'NOT_TESTED' });
  } finally { app.closeAllConnections?.(); await new Promise((resolve) => app.close(resolve)); }
  // Explicit unperformed dimensions prevent a successful direct scan from promoting the whole matrix.
  add('trufflehog-remediation-chain', 'NOT_TESTED', 'Detector execution does not establish a TruffleHog-originated VCG remediation chain.');
  add('runtime-family-verification', 'NOT_TESTED', 'The default VCG runtime profile uses tech templates, not this exposure template; no selection redesign or false VERIFIED claim.');
  const unchanged = JSON.stringify(before) === JSON.stringify(snapshot());
  if (!unchanged) add('host-preservation', 'REAL_PARTIAL', 'A monitored host binary/content file changed during validation.', { failure: true });
  const exitCode = summaryExit(results);
  const output = safeEvidence({ schemaVersion: '1.0', checkedAt: new Date().toISOString(), baseline: 'Real execution evidence; not a security certification.', exitCode, hostMonitoredFilesUnchanged: unchanged, inventory, results, traces: fs.readdirSync(path.join(root, 'traces')).map((file) => JSON.parse(fs.readFileSync(path.join(root, 'traces', file)))) }, root, originalHome);
  writeJson(path.join(root, 'summary.json'), output);
  if (process.argv.includes('--json')) console.log(JSON.stringify(output));
  else for (const item of results) console.log(`${item.id}: ${item.status}${item.failure ? ' (ASSERTION/EXECUTION FAILURE)' : ''} — ${item.reason}`);
  process.stderr.write(`Sanitized evidence: ${path.join(root, 'summary.json')}\n`);
  process.exitCode = exitCode;
}

module.exports = { summaryExit, safeEvidence, runProcess, executeLauncher, installedVersion };
if (require.main === module) {
  const task = process.argv[2] === '--chain' ? chainWorker(process.argv[3], process.argv[4]).then((result) => console.log(JSON.stringify(result))) : main();
  task.catch((error) => {
    if (process.argv.includes('--json')) console.log(JSON.stringify({ schemaVersion: '1.0', exitCode: 1, error: redact(error.message) }));
    console.error(redact(error.stack)); process.exitCode = 1;
  });
}
