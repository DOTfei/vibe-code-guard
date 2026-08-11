const fs = require('node:fs');
const path = require('node:path');

const CONFIG_FILE = '.vibe-code-guard.json';
const PROFILES = Object.freeze(['auto', 'quick', 'full', 'release']);
const MAX_RUNTIME_TARGETS = 10;
const MAX_IGNORED_PATHS = 100;

function defaultConfig() {
  return { profile: 'auto', runtimeTargets: [], ignoredPaths: [] };
}

function authorizedTargets() {
  return new Set(String(process.env.VIBE_CODE_GUARD_AUTHORIZED_TARGETS || '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean));
}

function validateRuntimeTarget(value) {
  if (typeof value !== 'string' || !value.trim() || value.length > 2048) return { target: value, allowed: false, reason: 'Runtime target must be a non-empty URL of at most 2048 characters.' };
  try {
    const parsed = new URL(value);
    if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password) return { target: value, allowed: false, reason: 'Only credential-free HTTP(S) targets are supported.' };
    const hostname = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase();
    const localHost = ['localhost', '127.0.0.1', '::1'].includes(hostname);
    const exactAuthorized = authorizedTargets().has(value) || authorizedTargets().has(parsed.toString().replace(/\/$/, ''));
    if (!localHost && !exactAuthorized) return { target: value, allowed: false, reason: 'Active runtime scanning requires localhost or an exact explicitly authorized target.' };
    return { target: parsed.toString().replace(/\/$/, ''), allowed: true, reason: localHost ? 'Localhost target allowed.' : 'Exact target is explicitly authorized by VIBE_CODE_GUARD_AUTHORIZED_TARGETS.' };
  } catch {
    return { target: value, allowed: false, reason: 'Runtime target must be a valid HTTP(S) URL.' };
  }
}

function validateConfig(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error(`${CONFIG_FILE} must contain a JSON object.`);
  const config = defaultConfig();
  if (input.profile !== undefined) {
    if (typeof input.profile !== 'string' || !PROFILES.includes(input.profile)) throw new Error(`profile must be one of: ${PROFILES.join(', ')}.`);
    config.profile = input.profile;
  }
  if (input.runtimeTargets !== undefined) {
    if (!Array.isArray(input.runtimeTargets) || input.runtimeTargets.length > MAX_RUNTIME_TARGETS) throw new Error(`runtimeTargets must be an array with at most ${MAX_RUNTIME_TARGETS} entries.`);
    config.runtimeTargets = input.runtimeTargets.map(validateRuntimeTarget);
    const rejected = config.runtimeTargets.filter((item) => !item.allowed);
    if (rejected.length) throw new Error(`runtimeTargets rejected: ${rejected.map((item) => item.reason).join(' ')}`);
    config.runtimeTargets = config.runtimeTargets.map((item) => item.target);
  }
  if (input.ignoredPaths !== undefined) {
    if (!Array.isArray(input.ignoredPaths) || input.ignoredPaths.length > MAX_IGNORED_PATHS) throw new Error(`ignoredPaths must be an array with at most ${MAX_IGNORED_PATHS} entries.`);
    for (const item of input.ignoredPaths) {
      if (typeof item !== 'string' || !item || item.length > 1024 || /[\0\r\n;&|$`()<>`!]/.test(item) || path.isAbsolute(item) || item.split(/[\\/]/).includes('..')) throw new Error('ignoredPaths must contain safe relative paths of at most 1024 characters without traversal or shell metacharacters.');
    }
    config.ignoredPaths = [...new Set(input.ignoredPaths)];
  }
  const unknownKeys = Object.keys(input).filter((key) => !['profile', 'runtimeTargets', 'ignoredPaths'].includes(key));
  if (unknownKeys.length) throw new Error(`Unsupported config field(s): ${unknownKeys.join(', ')}.`);
  return config;
}

function readProjectConfig(projectRoot) {
  const configPath = path.join(projectRoot, CONFIG_FILE);
  if (!fs.existsSync(configPath)) return { path: configPath, source: 'default', config: defaultConfig() };
  let data;
  try {
    data = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  } catch (error) {
    throw new Error(`Unable to parse ${CONFIG_FILE}: ${error.message}`);
  }
  return { path: configPath, source: 'project', config: validateConfig(data) };
}

module.exports = {
  CONFIG_FILE,
  PROFILES,
  defaultConfig,
  validateConfig,
  validateRuntimeTarget,
  readProjectConfig,
};
