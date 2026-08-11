const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const {
  TOOLKIT_HOME,
  inspectTool,
  loadManifest,
  runFile,
  safeToolkitHome,
} = require('./toolchain');

const STATE_FILENAME = 'security-toolchain.state.json';
const DEFAULT_CACHE_TTL_MS = 6 * 60 * 60 * 1000;
const RELEASE_API_BASE = 'https://api.github.com/repos/';

function nowIso(now = () => new Date().toISOString()) {
  return now();
}

function statePath(toolkitHome = TOOLKIT_HOME()) {
  const safeHome = safeToolkitHome(toolkitHome);
  return path.join(safeHome, 'vibe-code-guard', STATE_FILENAME);
}

function readState(toolkitHome = TOOLKIT_HOME()) {
  try {
    const value = JSON.parse(fs.readFileSync(statePath(toolkitHome), 'utf8'));
    if (!value || typeof value !== 'object' || Array.isArray(value)) return { schemaVersion: '1.0', tools: {} };
    const tools = Object.create(null);
    if (value.tools && typeof value.tools === 'object' && !Array.isArray(value.tools)) {
      for (const [toolId, record] of Object.entries(value.tools)) {
        if (['__proto__', 'prototype', 'constructor'].includes(toolId)) continue;
        if (record && typeof record === 'object' && !Array.isArray(record)) tools[toolId] = record;
      }
    }
    return { schemaVersion: '1.0', ...value, tools };
  } catch {
    return { schemaVersion: '1.0', tools: {} };
  }
}

function writeState(state, toolkitHome = TOOLKIT_HOME()) {
  const filePath = statePath(toolkitHome);
  fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o755 });
  const temporary = `${filePath}.${process.pid}.tmp`;
  fs.writeFileSync(temporary, `${JSON.stringify({ schemaVersion: '1.0', ...state }, null, 2)}\n`, { mode: 0o600 });
  fs.renameSync(temporary, filePath);
  return filePath;
}

function operationLockPath(toolkitHome = TOOLKIT_HOME()) {
  return path.join(path.dirname(statePath(toolkitHome)), 'scanner-operation.lock');
}

function processIsAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try { process.kill(pid, 0); return true; } catch (error) { return error.code === 'EPERM'; }
}

function acquireToolLock(toolkitHome = TOOLKIT_HOME(), purpose = 'scanner-operation') {
  const filePath = operationLockPath(toolkitHome);
  fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o755 });
  try {
    const descriptor = fs.openSync(filePath, 'wx', 0o600);
    fs.writeFileSync(descriptor, `${JSON.stringify({ pid: process.pid, purpose, startedAt: new Date().toISOString() })}\n`);
    fs.closeSync(descriptor);
    return { filePath, release: () => { try { fs.unlinkSync(filePath); } catch { /* another owner or already released */ } } };
  } catch (error) {
    if (error.code !== 'EEXIST') throw error;
    let owner = null;
    try { owner = JSON.parse(fs.readFileSync(filePath, 'utf8')); } catch { /* fail closed for a corrupt live lock */ }
    const lockAge = owner?.startedAt ? Date.now() - new Date(owner.startedAt).getTime() : 0;
    if (owner && !processIsAlive(Number(owner.pid)) && lockAge > 60 * 60 * 1000) {
      try { fs.unlinkSync(filePath); } catch { /* another process owns the race */ }
      return acquireToolLock(toolkitHome, purpose);
    }
    const busy = new Error(`Scanner lifecycle is busy: ${owner?.purpose || 'another scanner operation is active'}.`);
    busy.code = 'TOOL_LIFECYCLE_BUSY';
    throw busy;
  }
}

async function withToolLock(toolkitHome, purpose, operation) {
  const lock = acquireToolLock(toolkitHome, purpose);
  try { return await operation(); } finally { lock.release(); }
}

function parseVersion(value) {
  const text = String(value || '');
  if (text.length > 1024) return null;
  const match = text.match(/(?:^|[^0-9A-Za-z.])v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?(?:$|[^0-9A-Za-z.])/);
  if (!match) return null;
  const numbers = [match[1], match[2], match[3]].map(Number);
  if (!numbers.every(Number.isSafeInteger)) return null;
  return {
    major: numbers[0],
    minor: numbers[1],
    patch: numbers[2],
    prerelease: match[4] || null,
    value: `${match[1]}.${match[2]}.${match[3]}`,
  };
}

function parseStableReleaseVersion(value) {
  const text = String(value || '').trim();
  if (text.length > 64) return null;
  if (!/^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(text)) return null;
  return parseVersion(text);
}

function compareVersions(left, right) {
  const a = typeof left === 'string' ? parseVersion(left) : left;
  const b = typeof right === 'string' ? parseVersion(right) : right;
  if (!a || !b) return null;
  for (const key of ['major', 'minor', 'patch']) {
    if (a[key] !== b[key]) return a[key] - b[key];
  }
  return 0;
}

function isStableRelease(release) {
  if (!release || release.draft === true || release.prerelease === true) return false;
  const tag = release.tag_name || release.name || '';
  return Boolean(parseStableReleaseVersion(tag));
}

function officialReleaseApi(tool) {
  const repository = tool.upstream?.officialRepository || tool.install?.official;
  if (!repository || !repository.startsWith('https://github.com/')) return null;
  const parsed = new URL(repository);
  const parts = parsed.pathname.split('/').filter(Boolean);
  if (parts.length < 2) return null;
  return `${RELEASE_API_BASE}${parts[0]}/${parts[1]}/releases?per_page=30`;
}

function validatedReleaseUrl(tool, candidate) {
  if (!candidate) return null;
  try {
    const repository = new URL(tool.upstream?.officialRepository || tool.install?.official);
    const release = new URL(candidate);
    const repositoryPath = repository.pathname.replace(/\/$/, '');
    return release.protocol === 'https:' && release.hostname === 'github.com' && release.pathname.startsWith(`${repositoryPath}/releases/`)
      ? release.toString()
      : null;
  } catch { return null; }
}

async function defaultFetchJson(url, { timeoutMs = 5000 } = {}) {
  if (typeof fetch !== 'function') throw new Error('The Node runtime does not provide fetch.');
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      signal: controller.signal,
      redirect: 'error',
      headers: { Accept: 'application/vnd.github+json', 'User-Agent': 'vibe-code-guard-tool-lifecycle' },
    });
    if (!response.ok) throw new Error(`Official release source returned HTTP ${response.status}.`);
    if (response.url && response.url !== url) throw new Error('Official release source redirected unexpectedly.');
    return response.json();
  } finally {
    clearTimeout(timer);
  }
}

async function discoverLatestStable(tool, { fetchJson = defaultFetchJson } = {}) {
  const url = officialReleaseApi(tool);
  if (!url) return { latestStableVersion: null, source: 'OFFICIAL_SOURCE_UNAVAILABLE', state: 'UPDATE_CHECK_UNAVAILABLE', reason: 'No fixed official release API is configured for this tool.' };
  try {
    const releases = await fetchJson(url);
    const stable = (Array.isArray(releases) ? releases : [])
      .filter(isStableRelease)
      .map((release) => ({ release, version: parseStableReleaseVersion(release.tag_name || release.name) }))
      .filter((entry) => entry.version)
      .sort((left, right) => compareVersions(right.version, left.version));
    if (!stable.length) return { latestStableVersion: null, source: 'OFFICIAL', state: 'UPDATE_CHECK_UNAVAILABLE', reason: 'The official source returned no stable semantic release.' };
    const selected = stable[0];
    return {
      latestStableVersion: selected.version.value,
      source: 'OFFICIAL',
      state: 'CHECKED',
      releaseUrl: validatedReleaseUrl(tool, selected.release.html_url),
      checkedAt: new Date().toISOString(),
    };
  } catch (error) {
    return { latestStableVersion: null, source: 'OFFICIAL', state: 'UPDATE_CHECK_UNAVAILABLE', reason: String(error.message || error).slice(0, 500) };
  }
}

function provenanceFor(binaryPath, tool, previous = {}) {
  const value = String(binaryPath || '');
  if (!value) return { method: 'unknown', source: 'UNKNOWN' };
  let resolved = value;
  try { resolved = fs.realpathSync(value); } catch { /* preserve the reported executable path */ }
  const paths = [value, resolved];
  if (tool.install?.type === 'brew-cask' && paths.some((item) => item.includes('/Applications/ZAP.app/'))) return { method: 'brew-cask', source: 'OFFICIAL' };
  if (paths.some((item) => item.includes('/Cellar/') || item.includes('/opt/homebrew/') || item.includes('/homebrew/'))) return { method: 'brew', source: 'OFFICIAL' };
  if (paths.some((item) => item.includes('/pipx/'))) return { method: 'pipx', source: 'OFFICIAL' };
  if (paths.some((item) => item.includes('/.local/share/uv/') || item.includes('/.cache/uv/'))) return { method: 'uv', source: 'OFFICIAL' };
  return { method: 'unknown', source: 'UNKNOWN' };
}

function trivyMetadataCandidates() {
  const cacheRoot = process.env.TRIVY_CACHE_DIR;
  const roots = cacheRoot
    ? [cacheRoot]
    : [path.join(os.homedir(), 'Library', 'Caches', 'trivy'), path.join(os.homedir(), '.cache', 'trivy')];
  return roots.map((root) => path.join(root, 'db', 'metadata.json'));
}

function findExisting(paths) {
  return paths.find((candidate) => {
    try { return fs.statSync(candidate).isFile(); } catch { return false; }
  }) || null;
}

function contentState(tool, { now = () => Date.now() } = {}) {
  const spec = tool.contentUpdates || {};
  const base = {
    supported: spec.supported === true,
    model: spec.state || (spec.supported ? 'INDEPENDENT' : 'ENGINE_COUPLED'),
    state: spec.supported ? 'UNKNOWN' : spec.state || 'ENGINE_COUPLED',
    source: spec.officialSource || tool.upstream?.officialRepository || tool.install?.official || null,
    method: spec.method || null,
    updatedAt: null,
    nextUpdate: null,
    expired: null,
    reason: spec.reason || (spec.supported ? 'Freshness metadata is not available locally.' : 'This tool ships its detection content with the engine.'),
  };
  if (tool.id === 'trivy') {
    const metadataPath = findExisting(trivyMetadataCandidates());
    if (!metadataPath) return { ...base, state: 'MISSING', reason: 'Trivy vulnerability database metadata was not found.' };
    try {
      const metadata = JSON.parse(fs.readFileSync(metadataPath, 'utf8'));
      const next = metadata.NextUpdate || metadata.nextUpdate || null;
      const updated = metadata.UpdatedAt || metadata.updatedAt || null;
      const schemaVersion = Number(metadata.Version ?? metadata.version);
      const nextMs = next ? new Date(next).getTime() : NaN;
      const updatedMs = updated ? new Date(updated).getTime() : NaN;
      if (schemaVersion !== 2) return { ...base, state: 'BROKEN', metadataPath, schemaVersion: Number.isFinite(schemaVersion) ? schemaVersion : null, reason: 'Trivy vulnerability database schema is missing or unsupported.' };
      if (!Number.isFinite(nextMs) || !Number.isFinite(updatedMs)) return { ...base, state: 'BROKEN', metadataPath, schemaVersion, reason: 'Trivy vulnerability database freshness metadata is missing or invalid.' };
      const expired = nextMs < now();
      return {
        ...base,
        state: expired === true ? 'STALE' : 'CURRENT',
        metadataPath,
        schemaVersion,
        updatedAt: updated,
        nextUpdate: next,
        expired,
        reason: expired ? 'Trivy vulnerability database exists but its freshness window has expired.' : 'Trivy vulnerability database metadata is readable and within its freshness window.',
      };
    } catch (error) {
      return { ...base, state: 'BROKEN', metadataPath, reason: `Trivy vulnerability database metadata is unreadable: ${error.message}` };
    }
  }
  if (tool.id === 'nuclei') {
    const candidates = [
      process.env.NUCLEI_TEMPLATES_DIR,
      path.join(os.homedir(), 'Library', 'Application Support', 'nuclei'),
      path.join(os.homedir(), 'Library', 'Caches', 'nuclei'),
      path.join(os.homedir(), '.config', 'nuclei-templates'),
      path.join(os.homedir(), '.local', 'nuclei-templates'),
      path.join(os.homedir(), '.config', 'nuclei'),
      path.join(os.homedir(), '.cache', 'nuclei'),
    ].filter(Boolean);
    const directory = candidates.find((candidate) => {
      try { return fs.statSync(candidate).isDirectory(); } catch { return false; }
    });
    return directory
      ? { ...base, state: 'PRESENT_FRESHNESS_UNKNOWN', path: directory, reason: 'Official Nuclei template directory exists; local freshness metadata is not portable.' }
      : { ...base, state: 'MISSING', reason: 'Official Nuclei template directory was not found.' };
  }
  return base;
}

function actionFor(tool, item, action = 'update') {
  const spec = tool.update || {};
  const contentSpec = tool.contentUpdates || {};
  const install = tool.install || {};
  if (action === 'refresh-data') {
    if (contentSpec.supported !== true) return null;
    const command = typeof item?.binaryPath === 'string' && item.binaryPath ? item.binaryPath : null;
    if (!command) return null;
    if (tool.id === 'trivy' && contentSpec.method === 'trivy-db') return { command, args: ['fs', '--download-db-only'], source: contentSpec.officialSource, method: 'official Trivy vulnerability DB refresh' };
    if (tool.id === 'nuclei' && contentSpec.method === 'nuclei-templates') return { command, args: ['-update-templates'], source: contentSpec.officialSource, method: 'official Nuclei template refresh with upstream verification controls' };
    if (tool.id === 'zap' && contentSpec.method === 'zap-addons') return { command, args: ['-cmd', '-addonupdate'], source: contentSpec.officialSource, method: 'official ZAP add-on refresh' };
    return null;
  }
  const detectedMethod = item?.installMethod || 'unknown';
  if (detectedMethod === 'unknown') return null;
  if (spec.method === 'preserve-provenance' && Array.isArray(spec.supportedMethods) && !spec.supportedMethods.includes(detectedMethod)) return null;
  if (spec.method !== 'preserve-provenance' && spec.method && detectedMethod !== spec.method) return null;
  const method = spec.method === 'preserve-provenance' ? detectedMethod : spec.method;
  if (method === 'brew' || (!method && install.type === 'brew')) return { command: 'brew', args: ['upgrade', install.formula], source: spec.officialSource || install.official, method: 'homebrew' };
  if (method === 'brew-cask' || (!method && install.type === 'brew-cask')) return { command: 'brew', args: ['upgrade', '--cask', install.cask], source: spec.officialSource || install.official, method: 'homebrew cask' };
  if (method === 'pipx' || (!method && install.type === 'pipx')) return { command: 'pipx', args: ['upgrade', install.package], source: spec.officialSource || install.official, method: 'pipx' };
  if (method === 'uv') return { command: 'uv', args: ['tool', 'upgrade', install.package || tool.id], source: spec.officialSource || install.official, method: 'uv' };
  if (method === 'pip') return { command: 'python3', args: ['-m', 'pip', 'install', '--user', '--upgrade', install.package], source: spec.officialSource || install.official, method: 'pip' };
  return null;
}

function summarizeTool(tool, inspection, previous, latest, content, checkedAt) {
  const installed = inspection.versionNumber || null;
  const comparison = installed && latest.latestStableVersion ? compareVersions(latest.latestStableVersion, installed) : null;
  const minimum = parseVersion(tool.supportedVersionRange);
  const latestCompatibility = latest.latestStableVersion && minimum && compareVersions(latest.latestStableVersion, minimum) < 0 ? 'INCOMPATIBLE' : inspection.status === 'READY' ? 'COMPATIBLE' : 'REVIEW_REQUIRED';
  const provenance = provenanceFor(inspection.binaryPath, tool, previous);
  const engineUpdateAvailable = comparison !== null ? comparison > 0 : null;
  const state = ['BROKEN', 'NOT_INSTALLED'].includes(inspection.status)
    ? inspection.status
    : ['BROKEN', 'MISSING'].includes(content.state)
      ? 'BROKEN'
      : inspection.status === 'DEGRADED' ? 'DEGRADED' : 'READY';
  return {
    id: tool.id,
    displayName: tool.displayName,
    required: tool.required !== false,
    state,
    installedVersion: installed,
    versionText: inspection.version,
    binaryPath: inspection.binaryPath || null,
    installMethod: provenance.method,
    provenance: provenance.source,
    latestStableVersion: latest.latestStableVersion || previous.latestStableVersion || null,
    updateCheck: latest.state || previous.updateCheck || 'NOT_CHECKED',
    updateCheckReason: latest.reason || previous.updateCheckReason || null,
    updateAvailable: engineUpdateAvailable,
    compatibility: latestCompatibility,
    source: latest.source || previous.source || 'UNKNOWN',
    releaseUrl: latest.releaseUrl || previous.releaseUrl || null,
    content,
    lastUpdateAttempt: previous.lastUpdateAttempt || null,
    lastSuccessfulValidation: previous.lastSuccessfulValidation || null,
    selfTest: previous.selfTest || null,
    checkedAt,
  };
}

function parseWrapperJson(output) {
  const text = String(output || '').trim();
  for (let index = text.lastIndexOf('{'); index >= 0; index = text.lastIndexOf('{', index - 1)) {
    try {
      const value = JSON.parse(text.slice(index));
      if (value && typeof value === 'object') return value;
    } catch { /* try an earlier JSON object */ }
  }
  return null;
}

async function runToolSelfTest(toolId, { runCommand = runFile } = {}) {
  const result = await runCommand('security-tools', ['self-test', '--json'], { timeoutMs: 120000 });
  const parsed = parseWrapperJson(result.output || `${result.stdout || ''}${result.stderr || ''}`);
  const tool = parsed?.tools?.[toolId];
  const status = tool?.status || (result.code === 0 ? 'PASS' : result.code === 2 ? 'DEGRADED' : 'FAIL');
  return { status, exitCode: result.code, reason: tool?.reason || null };
}

async function lifecycleStatus({ toolkitHome = TOOLKIT_HOME(), checkUpdates = false, persist = true, fetchJson = defaultFetchJson, inspect = inspectTool, now = () => Date.now() } = {}) {
  const manifest = loadManifest();
  const state = readState(toolkitHome);
  const checkedAt = new Date(now()).toISOString();
  const tools = {};
  for (const tool of manifest.tools) {
    const inspection = await inspect(tool);
    const previous = state.tools[tool.id] || {};
    const lastCheckedMs = previous.lastChecked ? new Date(previous.lastChecked).getTime() : null;
    const cacheStale = !checkUpdates && Boolean(previous.lastChecked) && (!Number.isFinite(lastCheckedMs) || now() - lastCheckedMs > DEFAULT_CACHE_TTL_MS);
    const latest = checkUpdates
      ? await discoverLatestStable(tool, { fetchJson })
      : { latestStableVersion: previous.latestStableVersion || null, source: previous.source || 'UNKNOWN', state: cacheStale ? 'CACHE_STALE' : previous.updateCheck || 'NOT_CHECKED', reason: cacheStale ? 'Cached release metadata exceeded its TTL; run a manual official update check.' : previous.updateCheckReason || null, releaseUrl: previous.releaseUrl || null };
    const item = summarizeTool(tool, inspection, previous, latest, contentState(tool, { now }), checkedAt);
    tools[tool.id] = item;
    if (checkUpdates) state.tools[tool.id] = {
      ...previous,
      latestStableVersion: item.latestStableVersion,
      updateCheck: item.updateCheck,
      updateCheckReason: item.updateCheckReason,
      source: item.source,
      releaseUrl: item.releaseUrl,
      lastChecked: checkedAt,
    };
  }
  if (checkUpdates && persist) writeState({ ...state, checkedAt }, toolkitHome);
  const values = Object.values(tools);
  const overall = values.some((tool) => tool.required && ['BROKEN', 'NOT_INSTALLED'].includes(tool.state)) ? 'BROKEN' : values.some((tool) => tool.state === 'DEGRADED' || ['UPDATE_CHECK_UNAVAILABLE', 'CACHE_STALE'].includes(tool.updateCheck) || (tool.content.supported && ['STALE', 'UNKNOWN', 'PRESENT_FRESHNESS_UNKNOWN'].includes(tool.content.state))) ? 'DEGRADED' : 'READY';
  return { schemaVersion: '1.0', checkedAt, cacheTtlMs: DEFAULT_CACHE_TTL_MS, overall, tools, statePath: statePath(toolkitHome) };
}

async function checkUpdates(options = {}) {
  return lifecycleStatus({ ...options, checkUpdates: true });
}

async function updateTool(toolId, { toolkitHome = TOOLKIT_HOME(), dryRun = true, yes = false, securityReviewed = false, inspect = inspectTool, runCommand = runFile, fetchJson = defaultFetchJson, now = () => Date.now() } = {}) {
  const manifest = loadManifest();
  const tool = manifest.tools.find((item) => item.id === toolId);
  if (!tool) throw new Error(`Unknown upstream tool: ${toolId}`);
  const status = await lifecycleStatus({ toolkitHome, checkUpdates: true, persist: Boolean(yes && !dryRun), inspect, fetchJson, now });
  const item = status.tools[toolId];
  const action = actionFor(tool, item, 'update');
  const base = { scanner: toolId, installed: item.installedVersion, latestStable: item.latestStableVersion, installMethod: item.installMethod, source: item.source, compatibility: item.compatibility, securityReview: securityReviewed ? 'ACKNOWLEDGED' : 'REQUIRED', action: action ? 'UPDATE_AVAILABLE' : 'UPDATE_UNSUPPORTED', updateAvailable: item.updateAvailable, plan: action };
  if (item.state === 'BROKEN' || item.state === 'NOT_INSTALLED') return { ...base, state: 'BROKEN', reason: 'The scanner is not in a safe state for an update.' };
  if (item.updateCheck === 'UPDATE_CHECK_UNAVAILABLE' || !item.latestStableVersion) return { ...base, state: 'UPDATE_CHECK_UNAVAILABLE', reason: item.updateCheckReason || 'Official latest stable release could not be checked.' };
  if (item.compatibility === 'INCOMPATIBLE') return { ...base, state: 'MANUAL_REVIEW_REQUIRED', reason: 'The discovered release is outside the repository-controlled compatibility policy.' };
  if (item.updateAvailable !== true) return { ...base, state: 'CURRENT', reason: 'Installed version is current or is newer than the latest stable release observed.' };
  if (!action) return { ...base, state: 'MANUAL_REVIEW_REQUIRED', reason: 'Installation provenance is unknown or unsupported; no destructive update method will be guessed.' };
  if (!securityReviewed && yes && !dryRun) return { ...base, state: 'SECURITY_REVIEW_REQUIRED', reason: 'Review the official release notes and security advisories for this exact release, then rerun with --security-reviewed. No mutation was performed.' };
  if (dryRun || !yes) return { ...base, state: 'PLAN_ONLY', reason: 'No mutation was performed. Review official release notes/security advisories, then rerun one-tool update with explicit confirmation.' };
  let lock;
  try { lock = acquireToolLock(toolkitHome, `update:${toolId}`); } catch (error) {
    if (error.code === 'TOOL_LIFECYCLE_BUSY') return { ...base, state: 'BUSY', reason: error.message };
    throw error;
  }
  try {
    const before = item.installedVersion;
    const result = await runCommand(action.command, action.args, { timeoutMs: 10 * 60 * 1000 });
    const afterInspection = await inspect(tool);
    const versionMatchesPlan = afterInspection.versionNumber && compareVersions(afterInspection.versionNumber, item.latestStableVersion) === 0;
    const validation = afterInspection.status === 'READY' && versionMatchesPlan && compareVersions(afterInspection.versionNumber, before) >= 0;
    const selfTest = validation && result.code === 0 ? await runToolSelfTest(toolId, { runCommand }) : { status: 'NOT_RUN', exitCode: null, reason: 'Binary/version validation did not pass.' };
    const promoted = validation && result.code === 0 && selfTest.status === 'PASS';
    const record = {
      ...base,
      before,
      after: afterInspection.versionNumber || null,
      commandExitCode: result.code,
      selfTest,
      rollback: { state: 'UNAVAILABLE', reason: 'This installation method has no reliable version-pinned rollback configured; previous known-good metadata was preserved.' },
      state: promoted ? 'READY' : validation && result.code === 0 ? (selfTest.status === 'DEGRADED' ? 'DEGRADED' : 'BROKEN') : 'BROKEN',
      reason: promoted ? 'Binary, expected version, and tool-specific self-test passed; the new version is promoted as known-good.' : validation && result.code === 0 ? `Self-test did not pass (${selfTest.status}); the update was not promoted.` : `Update or expected-version validation failed (exit ${result.code}).`,
    };
    const current = readState(toolkitHome);
    current.tools[toolId] = {
      ...(current.tools[toolId] || {}),
      lastUpdateAttempt: { at: new Date(now()).toISOString(), before, after: record.after, state: record.state },
      selfTest: record.selfTest,
      ...(promoted ? { lastSuccessfulValidation: new Date(now()).toISOString(), knownGoodVersion: record.after } : {}),
    };
    writeState({ ...current, checkedAt: new Date(now()).toISOString() }, toolkitHome);
    return record;
  } finally { lock.release(); }
}

async function refreshContent(toolId, { toolkitHome = TOOLKIT_HOME(), dryRun = true, yes = false, securityReviewed = false, inspect = inspectTool, runCommand = runFile, now = () => Date.now() } = {}) {
  const manifest = loadManifest();
  const tool = manifest.tools.find((item) => item.id === toolId);
  if (!tool) throw new Error(`Unknown upstream tool: ${toolId}`);
  const inspection = await inspect(tool);
  const action = actionFor(tool, inspection, 'refresh-data');
  const before = contentState(tool, { now });
  const base = { scanner: toolId, content: before, source: action?.source || before.source, plan: action, securityReview: securityReviewed ? 'ACKNOWLEDGED' : 'REQUIRED', state: action ? 'PLAN_ONLY' : 'UNSUPPORTED' };
  if (inspection.status === 'BROKEN' || inspection.status === 'NOT_INSTALLED') return { ...base, state: 'BROKEN', reason: 'The scanner binary is unavailable or broken; content refresh was not attempted.' };
  if (!action) return { ...base, reason: 'No independent content refresh is configured for this tool.' };
  if (!securityReviewed && yes && !dryRun) return { ...base, state: 'SECURITY_REVIEW_REQUIRED', reason: 'Review the official content source and trust policy, then rerun with --security-reviewed. No mutation was performed.' };
  if (dryRun || !yes) return { ...base, reason: 'No mutation was performed. Review the official content refresh plan.' };
  let lock;
  try { lock = acquireToolLock(toolkitHome, `refresh-data:${toolId}`); } catch (error) {
    if (error.code === 'TOOL_LIFECYCLE_BUSY') return { ...base, state: 'BUSY', reason: error.message };
    throw error;
  }
  try {
    const result = await runCommand(action.command, action.args, { timeoutMs: 10 * 60 * 1000 });
    const after = contentState(tool, { now });
    const state = result.code === 0 && after.state === 'CURRENT' ? 'REFRESHED' : 'DEGRADED';
    const current = readState(toolkitHome);
    current.tools[toolId] = { ...(current.tools[toolId] || {}), content: after, lastContentRefresh: { at: new Date(now()).toISOString(), state } };
    writeState({ ...current, checkedAt: new Date(now()).toISOString() }, toolkitHome);
    return { ...base, content: after, commandExitCode: result.code, state, reason: state === 'REFRESHED' ? 'Official content refresh completed.' : 'Content refresh did not produce a usable local content state.' };
  } finally { lock.release(); }
}

module.exports = {
  acquireToolLock,
  DEFAULT_CACHE_TTL_MS,
  STATE_FILENAME,
  actionFor,
  checkUpdates,
  compareVersions,
  contentState,
  defaultFetchJson,
  discoverLatestStable,
  isStableRelease,
  lifecycleStatus,
  officialReleaseApi,
  parseVersion,
  parseStableReleaseVersion,
  provenanceFor,
  readState,
  refreshContent,
  statePath,
  updateTool,
  withToolLock,
  writeState,
};
