const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');

const ROOT = path.resolve(__dirname, '../..');
const MANIFEST_PATH = path.join(ROOT, 'config', 'toolchain.json');
const TOOLKIT_HOME = () => process.env.SECURITY_TOOLKIT_HOME || path.join(os.homedir(), 'security-toolkit');
const OUTPUT_LIMIT = 32 * 1024;

function safeToolkitHome(input = TOOLKIT_HOME()) {
  const resolved = path.resolve(String(input || ''));
  const home = path.resolve(os.homedir());
  if (!resolved || resolved === path.parse(resolved).root || resolved === home) throw new Error('SECURITY_TOOLKIT_HOME must not be a filesystem root or the home directory itself.');
  let cursor = resolved;
  while (cursor !== path.dirname(cursor)) {
    try {
      if (fs.lstatSync(cursor).isSymbolicLink()) {
        const real = fs.realpathSync(cursor);
        const trustedMacAlias = (cursor === '/var' || cursor === '/tmp') && real === `/private${cursor}`;
        if (!trustedMacAlias) throw new Error(`SECURITY_TOOLKIT_HOME path must not traverse a symbolic link: ${cursor}`);
      }
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    cursor = path.dirname(cursor);
  }
  return resolved;
}

function loadManifest() {
  return JSON.parse(fs.readFileSync(MANIFEST_PATH, 'utf8'));
}

function candidatePaths(tool) {
  const configured = String(process.env.SECURITY_TOOL_PATHS || '').split(path.delimiter).filter(Boolean);
  const candidates = [];
  for (const candidate of tool.candidates || []) {
    if (path.isAbsolute(candidate)) candidates.push(candidate);
    else for (const directory of configured) candidates.push(path.join(directory, candidate));
    candidates.push(candidate);
  }
  return candidates;
}

function isExecutable(filePath) {
  try {
    return fs.statSync(filePath).isFile() && (process.platform === 'win32' || (fs.statSync(filePath).mode & 0o111) !== 0);
  } catch {
    return false;
  }
}

async function which(candidate) {
  const result = await runFile('which', [candidate], { timeoutMs: 2000 });
  const resolved = result.stdout.trim().split('\n').find(Boolean);
  return resolved && isExecutable(resolved) ? resolved : null;
}

async function resolveTool(tool) {
  for (const candidate of candidatePaths(tool)) {
    if (path.isAbsolute(candidate) && isExecutable(candidate)) return candidate;
    if (!path.isAbsolute(candidate)) {
      const resolved = await which(candidate);
      if (resolved) return resolved;
    }
  }
  return null;
}

function runFile(file, args = [], options = {}) {
  const timeoutMs = options.timeoutMs || 10000;
  const cwd = options.cwd || ROOT;
  return new Promise((resolve) => {
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    let settled = false;
    const child = spawn(file, args, { cwd, env: options.env || process.env, shell: false, stdio: ['ignore', 'pipe', 'pipe'] });
    const append = (key, chunk) => {
      if (settled) return;
      const value = String(chunk);
      if (key === 'stdout') stdout = `${stdout}${value}`.slice(-OUTPUT_LIMIT);
      else stderr = `${stderr}${value}`.slice(-OUTPUT_LIMIT);
    };
    child.stdout.on('data', (chunk) => append('stdout', chunk));
    child.stderr.on('data', (chunk) => append('stderr', chunk));
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGTERM');
    }, timeoutMs);
    const finish = (code, error = null) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ code, stdout, stderr, output: `${stdout}${stderr}`, timedOut, error: error ? error.message : null });
    };
    child.once('error', (error) => finish(null, error));
    child.once('close', (code) => finish(code));
  });
}

function statusFromWrapper(output) {
  const overall = String(output || '').match(/OVERALL TOOLCHAIN HEALTH:\s+(HEALTHY|DEGRADED|BROKEN)/)?.[1];
  return overall === 'HEALTHY' ? 'READY' : overall === 'DEGRADED' ? 'DEGRADED' : overall === 'BROKEN' ? 'BROKEN' : null;
}

function versionText(result) {
  return String(result.output || '').replace(/\u001b\[[0-?]*[ -/]*[@-~]/g, '').replace(/\s+/g, ' ').trim().slice(0, 240) || null;
}

function parseVersion(value, pattern = null) {
  const text = String(value || '');
  if (text.length > 1024) return null;
  const match = pattern
    ? text.match(new RegExp(pattern))
    : text.match(/(?:^|[^0-9A-Za-z.])v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:$|[^0-9A-Za-z.+-])/);
  if (pattern && !match) return null;
  if (pattern) return parseVersion(match[1]);
  if (!match) return null;
  const parsed = [Number(match[1]), Number(match[2]), Number(match[3])];
  return parsed.every(Number.isSafeInteger) ? parsed : null;
}

function minimumVersion(range) {
  const match = String(range || '').match(/^>=\s*(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/);
  if (!match) return null;
  const parsed = [Number(match[1]), Number(match[2]), Number(match[3])];
  return parsed.every(Number.isSafeInteger) ? parsed : null;
}

function compareVersions(left, right) {
  for (let index = 0; index < 3; index += 1) {
    if (left[index] !== right[index]) return left[index] - right[index];
  }
  return 0;
}

async function inspectTool(tool) {
  const binaryPath = await resolveTool(tool);
  const base = {
    id: tool.id,
    displayName: tool.displayName,
    required: tool.required !== false,
    doctorCheck: tool.doctorCheck || 'binary-and-version',
    selfTest: tool.selfTest || null,
    supportedVersionRange: tool.supportedVersionRange || null,
    installMethod: tool.install?.type || 'manual',
    officialSource: tool.install?.official || null,
    binaryPath,
    version: null,
    status: 'NOT_INSTALLED',
    reason: null,
  };
  if (!binaryPath) {
    base.reason = 'No supported executable was found on PATH or SECURITY_TOOL_PATHS.';
    return base;
  }
  const version = await runFile(binaryPath, tool.versionArgs || ['--version'], { timeoutMs: 5000 });
  base.version = versionText(version);
  const parsedVersion = parseVersion(base.version, tool.versionPattern);
  base.versionVerified = Boolean(parsedVersion);
  base.versionNumber = parsedVersion ? parsedVersion.join('.') : null;
  if (version.code === 0 || (version.code === 1 && base.version)) {
    base.status = 'READY';
    if (!parsedVersion) {
      base.status = 'DEGRADED';
      base.reason = 'Version command completed but no semantic version could be verified.';
    } else {
      const minimum = minimumVersion(tool.supportedVersionRange);
      if (minimum && compareVersions(parsedVersion, minimum) < 0) {
        base.status = 'DEGRADED';
        base.reason = `Detected version ${base.versionNumber} is below the supported range ${tool.supportedVersionRange}; no automatic downgrade or replacement will be attempted.`;
      }
    }
  }
  else if (/ca-certs|trust anchors|certificate|dns|network|registry|not writable|permission denied/i.test(version.output || '')) {
    base.status = 'DEGRADED';
    base.reason = 'Version command was affected by an environment or network trust dependency.';
  }
  else {
    base.status = 'BROKEN';
    base.reason = version.timedOut ? 'Version command timed out.' : `Version command failed with exit ${version.code}.`;
  }
  return base;
}

function dashboardStatus() {
  return {
    status: fs.existsSync(path.join(ROOT, 'server.js')) ? 'READY' : 'BROKEN',
    host: '127.0.0.1',
    localOnly: true,
    command: 'vibe-code-guard dashboard',
  };
}

async function doctor() {
  const manifest = loadManifest();
  const tools = {};
  for (const tool of manifest.tools) tools[tool.id] = await inspectTool(tool);
  let wrapperStatus = null;
  const wrapper = await which('security-tools');
  if (wrapper) wrapperStatus = statusFromWrapper((await runFile(wrapper, ['doctor'], { timeoutMs: 15000 })).output);
  const toolValues = Object.values(tools);
  let status = toolValues.some((tool) => tool.status === 'BROKEN' || (tool.required && tool.status === 'NOT_INSTALLED')) ? 'BROKEN' : 'READY';
  if (toolValues.some((tool) => tool.status === 'DEGRADED') || wrapperStatus === 'DEGRADED') status = 'DEGRADED';
  if (wrapperStatus === 'BROKEN') status = 'BROKEN';
  return {
    status,
    version: require(path.join(ROOT, 'package.json')).version,
    workflowVersion: manifest.workflowVersion,
    manifestVersion: manifest.manifestVersion,
    toolchain: tools,
    dashboard: dashboardStatus(),
    capabilities: {
      audit: 'READY',
      profiles: ['auto', 'quick', 'full', 'release'],
      structuredOutput: 'READY',
      correlation: 'READY',
      lifecycle: 'READY',
      activeRuntimeScanning: 'AUTHORIZED_TARGET_REQUIRED',
      externalAI: 'NOT_INCLUDED',
    },
    wrapper: wrapper ? { path: wrapper, status: wrapperStatus || 'UNKNOWN' } : { path: null, status: 'NOT_INSTALLED' },
    checkedAt: new Date().toISOString(),
  };
}

function extractJson(output) {
  const text = String(output || '').trim();
  for (let index = text.lastIndexOf('{'); index >= 0; index = text.lastIndexOf('{', index - 1)) {
    try {
      const parsed = JSON.parse(text.slice(index));
      if (parsed && typeof parsed === 'object') return parsed;
    } catch { /* try an earlier opening brace */ }
  }
  return null;
}

async function toolkitSelfTest() {
  const binary = await which('security-tools');
  if (!binary) return { overall: 'FAIL', exitCode: 1, reason: 'security-tools wrapper was not found.', raw: '' };
  const result = await runFile(binary, ['self-test', '--json'], { timeoutMs: 120000 });
  const parsed = extractJson(result.output);
  const overall = parsed?.overall || (result.code === 0 ? 'PASS' : result.code === 2 ? 'DEGRADED' : 'FAIL');
  return { ...parsed, overall, exitCode: result.code, raw: result.output };
}

async function commandExists(command) {
  return Boolean(await which(command));
}

async function installPlan({ includeTools = true, inspect = inspectTool, commandExistsFn = commandExists } = {}) {
  const manifest = loadManifest();
  const inspected = {};
  for (const tool of manifest.tools) inspected[tool.id] = await inspect(tool);
  const actions = [];
  const notes = [];
  const brew = await commandExistsFn('brew');
  const pipx = await commandExistsFn('pipx');
  const python = await commandExistsFn('python3');
  if (includeTools) {
    for (const tool of manifest.tools) {
      if (inspected[tool.id].status !== 'NOT_INSTALLED') {
        if (inspected[tool.id].status !== 'READY') notes.push(`${tool.displayName}: ${inspected[tool.id].status}; no automatic reinstall or downgrade will be attempted.`);
        continue;
      }
      const spec = tool.install || {};
      if ((spec.type === 'brew' || spec.type === 'brew-cask') && brew) {
        actions.push({ id: tool.id, command: 'brew', args: spec.type === 'brew-cask' ? ['install', '--cask', spec.cask] : ['install', spec.formula], source: spec.official, reason: 'Install missing tool from the official Homebrew channel.' });
      } else if (spec.type === 'pipx' && pipx) {
        actions.push({ id: tool.id, command: 'pipx', args: ['install', spec.package], source: spec.official, reason: 'Install missing Python tool in an isolated pipx environment.' });
      } else if (spec.type === 'pipx' && python) {
        notes.push(`${tool.displayName}: pipx is unavailable; no automatic pip fallback is planned. Install pipx and rerun.`);
      } else {
        notes.push(`${tool.displayName}: no supported official installer is available on this machine.`);
      }
    }
  }
  return { platform: process.platform, architecture: process.arch, brewAvailable: brew, pipxAvailable: pipx, python3Available: python, inspected, actions, notes };
}

function shellQuote(value) {
  return `'${String(value).replace(/'/g, `'\\''`)}'`;
}

function managedLauncher(sourceRoot) {
  return `#!/bin/sh\n# VIBE_CODE_GUARD_MANAGED=1\nexec /usr/bin/env node ${shellQuote(path.join(sourceRoot, 'bin', 'vibe-code-guard.js'))} "$@"\n`;
}

function ownershipPath(filePath, sourceRoot) {
  try {
    if (fs.lstatSync(filePath).isSymbolicLink()) return false;
    const current = fs.readFileSync(filePath, 'utf8');
    return current.includes('VIBE_CODE_GUARD_MANAGED=1') && current.includes(path.join(sourceRoot, 'bin', 'vibe-code-guard.js'));
  } catch {
    return false;
  }
}

function installLocalEntrypoints({ sourceRoot = ROOT, toolkitHome = TOOLKIT_HOME(), dryRun = false } = {}) {
  const safeHome = safeToolkitHome(toolkitHome);
  const binDir = path.join(safeHome, 'bin');
  const ownedDir = path.join(safeHome, 'vibe-code-guard');
  for (const directory of [binDir, ownedDir]) {
    try { if (fs.lstatSync(directory).isSymbolicLink()) throw new Error(`Refusing to follow symbolic-link directory: ${directory}`); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
  const files = [path.join(binDir, 'vibe-code-guard'), path.join(binDir, 'security-check')];
  const conflicts = files.filter((filePath) => fs.existsSync(filePath) && !ownershipPath(filePath, sourceRoot));
  if (dryRun) return { files, ownedDir, binDir, pathHint: binDir, changed: false, conflicts };
  fs.mkdirSync(binDir, { recursive: true, mode: 0o755 });
  fs.mkdirSync(ownedDir, { recursive: true, mode: 0o755 });
  const launcher = managedLauncher(sourceRoot);
  const installedFiles = files.filter((filePath) => !conflicts.includes(filePath));
  for (const filePath of installedFiles) {
    fs.writeFileSync(filePath, launcher, { mode: 0o755 });
    fs.chmodSync(filePath, 0o755);
  }
  const manifest = { manifestVersion: '1.0', productVersion: require(path.join(sourceRoot, 'package.json')).version, sourceRoot, files: installedFiles, preservedConflicts: conflicts, ownedDir, installedAt: new Date().toISOString() };
  fs.writeFileSync(path.join(ownedDir, 'installation.json'), `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600 });
  return { files: installedFiles, ownedDir, binDir, pathHint: binDir, changed: installedFiles.length > 0, conflicts };
}

function uninstallLocalEntrypoints({ toolkitHome = TOOLKIT_HOME(), dryRun = false } = {}) {
  const safeHome = safeToolkitHome(toolkitHome);
  const binDir = path.join(safeHome, 'bin');
  const ownedDir = path.join(safeHome, 'vibe-code-guard');
  const manifestPath = path.join(ownedDir, 'installation.json');
  if (!fs.existsSync(manifestPath)) return { status: 'NOT_INSTALLED', removed: [], preserved: [] };
  let manifest;
  try { manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8')); } catch { throw new Error('Vibe Code Guard installation manifest is unreadable; refusing cleanup.'); }
  const removed = [];
  const preserved = [];
  const allowedFiles = new Set([path.join(binDir, 'vibe-code-guard'), path.join(binDir, 'security-check')]);
  for (const filePath of Array.isArray(manifest.files) ? manifest.files : []) {
    if (!allowedFiles.has(filePath) || !ownershipPath(filePath, manifest.sourceRoot)) { preserved.push(filePath); continue; }
    if (!dryRun) fs.rmSync(filePath, { force: true });
    removed.push(filePath);
  }
  if (!dryRun && preserved.length === 0) {
    fs.rmSync(manifestPath, { force: true });
    try { fs.rmdirSync(ownedDir); } catch { /* leave non-empty owned directory */ }
  }
  return { status: preserved.length ? 'DEGRADED' : 'REMOVED', removed, preserved };
}

module.exports = {
  ROOT,
  MANIFEST_PATH,
  loadManifest,
  runFile,
  resolveTool,
  inspectTool,
  parseVersion,
  compareVersions,
  doctor,
  toolkitSelfTest,
  installPlan,
  installLocalEntrypoints,
  uninstallLocalEntrypoints,
  safeToolkitHome,
  extractJson,
  TOOLKIT_HOME,
};
