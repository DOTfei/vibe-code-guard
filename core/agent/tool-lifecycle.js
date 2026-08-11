const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const {
  TOOLKIT_HOME,
  inspectTool,
  loadManifest,
  runFile,
  safeToolkitHome,
  resolveTool,
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
    return value && typeof value === 'object'
      ? { schemaVersion: '1.0', tools: {}, ...value, tools: value.tools && typeof value.tools === 'object' ? value.tools : {} }
      : { schemaVersion: '1.0', tools: {} };
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

function parseVersion(value) {
  const match = String(value || '').match(/(?:^|[^0-9])v?(\d+)\.(\d+)(?:\.(\d+))?(?:[-+._]([0-9A-Za-z.-]+))?/);
  if (!match) return null;
  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3] || 0),
    prerelease: match[4] || null,
    value: `${match[1]}.${match[2]}.${match[3] || 0}`,
  };
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
  return Boolean(parseVersion(tag) && !/(?:alpha|beta|rc|nightly|dev|snapshot|canary|preview)/i.test(tag));
}

function officialReleaseApi(tool) {
  const repository = tool.upstream?.officialRepository || tool.install?.official;
  if (!repository || !repository.startsWith('https://github.com/')) return null;
  const parsed = new URL(repository);
  const parts = parsed.pathname.split('/').filter(Boolean);
  if (parts.length < 2) return null;
  return `${RELEASE_API_BASE}${parts[0]}/${parts[1]}/releases?per_page=30`;
}

async function defaultFetchJson(url, { timeoutMs = 5000 } = {}) {
  if (typeof fetch !== 'function') throw new Error('The Node runtime does not provide fetch.');
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      signal: controller.signal,
      headers: { Accept: 'application/vnd.github+json', 'User-Agent': 'vibe-code-guard-tool-lifecycle' },
    });
    if (!response.ok) throw new Error(`Official release source returned HTTP ${response.status}.`);
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
      .map((release) => ({ release, version: parseVersion(release.tag_name || release.name) }))
      .filter((entry) => entry.version)
      .sort((left, right) => compareVersions(right.version, left.version));
    if (!stable.length) return { latestStableVersion: null, source: 'OFFICIAL', state: 'UPDATE_CHECK_UNAVAILABLE', reason: 'The official source returned no stable semantic release.' };
    const selected = stable[0];
    return {
      latestStableVersion: selected.version.value,
      source: 'OFFICIAL',
      state: 'CHECKED',
      releaseUrl: selected.release.html_url || null,
      checkedAt: new Date().toISOString(),
    };
  } catch (error) {
    return { latestStableVersion: null, source: 'OFFICIAL', state: 'UPDATE_CHECK_UNAVAILABLE', reason: String(error.message || error).slice(0, 500) };
  }
}

function provenanceFor(binaryPath, tool, previous = {}) {
  const value = String(binaryPath || '');
  if (!value) return { method: previous.installMethod || 'unknown', source: previous.source || 'UNKNOWN' };
  if (tool.install?.type === 'brew-cask' || value.includes('/Applications/ZAP.app/')) return { method: 'brew-cask', source: 'OFFICIAL' };
  if (value.includes('/Cellar/') || value.includes('/opt/homebrew/') || value.includes('/homebrew/')) return { method: 'brew', source: 'OFFICIAL' };
  if (value.includes('/pipx/') || value.includes('/.local/bin/')) return { method: 'pipx', source: 'OFFICIAL' };
  return { method: previous.installMethod || 'unknown', source: previous.source || 'UNKNOWN' };
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
    state: spec.supported ? 'UNKNOWN' : 'ENGINE_COUPLED',
    source: spec.officialSource || tool.upstream?.officialRepository || tool.install?.official || null,
    method: spec.method || null,
    updatedAt: null,
    nextUpdate: null,
    expired: null,
    reason: spec.supported ? 'Freshness metadata is not available locally.' : 'This tool ships its detection content with the engine.',
  };
  if (tool.id === 'trivy') {
    const metadataPath = findExisting(trivyMetadataCandidates());
    if (!metadataPath) return { ...base, state: 'MISSING', reason: 'Trivy vulnerability database metadata was not found.' };
    try {
      const metadata = JSON.parse(fs.readFileSync(metadataPath, 'utf8'));
      const next = metadata.NextUpdate || metadata.nextUpdate || null;
      const updated = metadata.UpdatedAt || metadata.updatedAt || null;
      const expired = next ? new Date(next).getTime() < now() : null;
      return {
        ...base,
        state: expired === true ? 'STALE' : 'CURRENT',
        metadataPath,
        schemaVersion: metadata.Version || metadata.version || null,
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
  const install = tool.install || {};
  if (action === 'refresh-data') {
    if (tool.id === 'trivy') return { command: resolveTool('trivy'), args: ['fs', '--download-db-only'], source: spec.officialSource || install.official, method: 'official Trivy vulnerability DB refresh' };
    if (tool.id === 'nuclei') return { command: resolveTool('nuclei'), args: ['-update-templates'], source: spec.officialSource || install.official, method: 'official Nuclei template refresh with upstream verification controls' };
    if (tool.id === 'zap') return { command: resolveTool('zap'), args: ['-cmd', '-addonupdate'], source: spec.officialSource || install.official, method: 'official ZAP add-on refresh' };
    return null;
  }
  const method = spec.method === 'preserve-provenance' ? item?.installMethod : spec.method;
  if (method === 'brew' || (!method && install.type === 'brew')) return { command: 'brew', args: ['upgrade', install.formula], source: spec.officialSource || install.official, method: 'homebrew' };
  if (method === 'brew-cask' || (!method && install.type === 'brew-cask')) return { command: 'brew', args: ['upgrade', '--cask', install.cask], source: spec.officialSource || install.official, method: 'homebrew cask' };
  if (method === 'pipx' || (!method && install.type === 'pipx')) return { command: 'pipx', args: ['upgrade', install.package], source: spec.officialSource || install.official, method: 'pipx' };
  if (method === 'pip') return { command: 'python3', args: ['-m', 'pip', 'install', '--user', '--upgrade', install.package], source: spec.officialSource || install.official, method: 'pip' };
  return null;
}

function summarizeTool(tool, inspection, previous, latest, content, checkedAt) {
  const installed = inspection.versionNumber || parseVersion(inspection.version)?.value || null;
  const comparison = installed && latest.latestStableVersion ? compareVersions(latest.latestStableVersion, installed) : null;
  const minimum = parseVersion(tool.supportedVersionRange);
  const latestCompatibility = latest.latestStableVersion && minimum && compareVersions(latest.latestStableVersion, minimum) < 0 ? 'INCOMPATIBLE' : inspection.status === 'READY' ? 'COMPATIBLE' : 'REVIEW_REQUIRED';
  const provenance = provenanceFor(inspection.binaryPath, tool, previous);
  const engineUpdateAvailable = comparison !== null ? comparison > 0 : null;
  const state = inspection.status === 'BROKEN' || inspection.status === 'NOT_INSTALLED'
    ? inspection.status
    : inspection.status === 'DEGRADED' || content.state === 'BROKEN' || content.state === 'MISSING'
      ? 'DEGRADED'
      : 'READY';
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

async function lifecycleStatus({ toolkitHome = TOOLKIT_HOME(), checkUpdates = false, fetchJson = defaultFetchJson, inspect = inspectTool, now = () => Date.now() } = {}) {
  const manifest = loadManifest();
  const state = readState(toolkitHome);
  const checkedAt = new Date(now()).toISOString();
  const tools = {};
  for (const tool of manifest.tools) {
    const inspection = await inspect(tool);
    const previous = state.tools[tool.id] || {};
    const latest = checkUpdates
      ? await discoverLatestStable(tool, { fetchJson })
      : { latestStableVersion: previous.latestStableVersion || null, source: previous.source || 'UNKNOWN', state: previous.updateCheck || 'NOT_CHECKED', reason: previous.updateCheckReason || null, releaseUrl: previous.releaseUrl || null };
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
  if (checkUpdates) writeState({ ...state, checkedAt }, toolkitHome);
  const values = Object.values(tools);
  const overall = values.some((tool) => tool.state === 'BROKEN') ? 'BROKEN' : values.some((tool) => tool.state === 'DEGRADED' || tool.updateCheck === 'UPDATE_CHECK_UNAVAILABLE' || tool.content.state === 'STALE') ? 'DEGRADED' : 'READY';
  return { schemaVersion: '1.0', checkedAt, cacheTtlMs: DEFAULT_CACHE_TTL_MS, overall, tools, statePath: statePath(toolkitHome) };
}

async function checkUpdates(options = {}) {
  return lifecycleStatus({ ...options, checkUpdates: true });
}

async function updateTool(toolId, { toolkitHome = TOOLKIT_HOME(), dryRun = true, yes = false, securityReviewed = false, inspect = inspectTool, runCommand = runFile, fetchJson = defaultFetchJson, now = () => Date.now() } = {}) {
  const manifest = loadManifest();
  const tool = manifest.tools.find((item) => item.id === toolId);
  if (!tool) throw new Error(`Unknown upstream tool: ${toolId}`);
  const status = await lifecycleStatus({ toolkitHome, checkUpdates: true, inspect, fetchJson, now });
  const item = status.tools[toolId];
  const action = actionFor(tool, item, 'update');
  const base = { scanner: toolId, installed: item.installedVersion, latestStable: item.latestStableVersion, installMethod: item.installMethod, source: item.source, compatibility: item.compatibility, securityReview: securityReviewed ? 'ACKNOWLEDGED' : 'REQUIRED', action: action ? 'UPDATE_AVAILABLE' : 'UPDATE_UNSUPPORTED', updateAvailable: item.updateAvailable, plan: action };
  if (item.state === 'BROKEN' || item.state === 'NOT_INSTALLED') return { ...base, state: 'BROKEN', reason: 'The scanner is not in a safe state for an update.' };
  if (item.updateCheck === 'UPDATE_CHECK_UNAVAILABLE' || !item.latestStableVersion) return { ...base, state: 'UPDATE_CHECK_UNAVAILABLE', reason: item.updateCheckReason || 'Official latest stable release could not be checked.' };
  if (item.updateAvailable !== true) return { ...base, state: 'CURRENT', reason: 'Installed version is current or is newer than the latest stable release observed.' };
  if (!action) return { ...base, state: 'DEGRADED', reason: 'No official update method is configured for this installation provenance.' };
  if (!securityReviewed && yes && !dryRun) return { ...base, state: 'SECURITY_REVIEW_REQUIRED', reason: 'Review the official release notes and security advisories for this exact release, then rerun with --security-reviewed. No mutation was performed.' };
  if (dryRun || !yes) return { ...base, state: 'PLAN_ONLY', reason: 'No mutation was performed. Review official release notes/security advisories, then rerun one-tool update with explicit confirmation.' };
  const before = item.installedVersion;
  const result = await runCommand(action.command, action.args, { timeoutMs: 10 * 60 * 1000 });
  const afterInspection = await inspect(tool);
  const validation = afterInspection.status === 'READY' && afterInspection.versionNumber && compareVersions(afterInspection.versionNumber, before) >= 0;
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
    reason: promoted ? 'Binary, version, and tool-specific self-test passed; the new version is promoted as known-good.' : validation && result.code === 0 ? `Self-test did not pass (${selfTest.status}); the update was not promoted.` : `Update or binary validation failed (exit ${result.code}).`,
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
}

async function refreshContent(toolId, { toolkitHome = TOOLKIT_HOME(), dryRun = true, yes = false, runCommand = runFile, now = () => Date.now() } = {}) {
  const manifest = loadManifest();
  const tool = manifest.tools.find((item) => item.id === toolId);
  if (!tool) throw new Error(`Unknown upstream tool: ${toolId}`);
  const action = actionFor(tool, {}, 'refresh-data');
  const before = contentState(tool, { now });
  const base = { scanner: toolId, content: before, source: action?.source || before.source, plan: action, state: action ? 'PLAN_ONLY' : 'UNSUPPORTED' };
  if (!action) return { ...base, reason: 'No independent content refresh is configured for this tool.' };
  if (dryRun || !yes) return { ...base, reason: 'No mutation was performed. Review the official content refresh plan.' };
  const result = await runCommand(action.command, action.args, { timeoutMs: 10 * 60 * 1000 });
  const after = contentState(tool, { now });
  const state = result.code === 0 && !['BROKEN', 'MISSING'].includes(after.state) ? 'REFRESHED' : 'DEGRADED';
  const current = readState(toolkitHome);
  current.tools[toolId] = { ...(current.tools[toolId] || {}), content: after, lastContentRefresh: { at: new Date(now()).toISOString(), state } };
  writeState({ ...current, checkedAt: new Date(now()).toISOString() }, toolkitHome);
  return { ...base, content: after, commandExitCode: result.code, state, reason: state === 'REFRESHED' ? 'Official content refresh completed.' : 'Content refresh did not produce a usable local content state.' };
}

module.exports = {
  DEFAULT_CACHE_TTL_MS,
  STATE_FILENAME,
  actionFor,
  checkUpdates,
  compareVersions,
  contentState,
  discoverLatestStable,
  isStableRelease,
  lifecycleStatus,
  officialReleaseApi,
  parseVersion,
  provenanceFor,
  readState,
  refreshContent,
  statePath,
  updateTool,
  writeState,
};
