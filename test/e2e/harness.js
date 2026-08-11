'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const http = require('node:http');

const ROOT = path.resolve(__dirname, '../..');
const BIN = path.join(ROOT, 'bin', 'vibe-code-guard.js');
const FIXTURES = path.join(__dirname, 'fixtures');

function tempDir(prefix = 'vcg-v07-e2e-') {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function fixturePath(name) {
  const directory = path.join(FIXTURES, name);
  if (!fs.existsSync(path.join(directory, 'expected-results.json'))) throw new Error(`Missing fixture manifest: ${name}`);
  return directory;
}

function fixtureManifest(name) {
  return JSON.parse(fs.readFileSync(path.join(fixturePath(name), 'expected-results.json'), 'utf8'));
}

function copyFixture(name, destinationRoot = tempDir('vcg-v07-project-')) {
  const destination = path.join(destinationRoot, name);
  fs.cpSync(fixturePath(name), destination, { recursive: true });
  return destination;
}

function writeExecutable(filePath, source) {
  fs.writeFileSync(filePath, source, { mode: 0o755 });
  fs.chmodSync(filePath, 0o755);
  return filePath;
}

function mockScannerSource() {
  return `#!/usr/bin/env node
const fs = require('node:fs');
const path = require('node:path');
const tool = path.basename(process.argv[1]);
const args = process.argv.slice(2);
const versions = { gitleaks: '8.18.4', trufflehog: '3.82.13', semgrep: '1.99.0', trivy: '0.56.2', 'osv-scanner': '2.0.2', checkov: '3.2.0', zap: '2.15.0', nuclei: '3.3.0' };
if (args.includes('--version') || args.includes('-version') || args.includes('version')) {
  process.stdout.write(tool === 'zap' ? 'ZAP ' + versions[tool] + '\\n' : versions[tool] + '\\n');
  process.exit(0);
}
const all = JSON.parse(process.env.VCG_E2E_FINDINGS || '{}');
let items = Array.isArray(all[tool]) ? all[tool] : [];
if (process.env.VCG_E2E_VERIFY_MODE === 'clean' && tool === 'semgrep') items = [];
const reportArgument = (flag) => { const index = args.indexOf(flag); return index >= 0 ? args[index + 1] : null; };
const emitResults = () => {
if (tool === 'gitleaks') {
  const report = reportArgument('--report-path');
  if (report) fs.writeFileSync(report, JSON.stringify(items));
  process.exit(0);
}
if (tool === 'trufflehog' || tool === 'nuclei') {
  for (const item of items) process.stdout.write(JSON.stringify(item) + '\\n');
  process.exit(0);
}
if (tool === 'semgrep') process.stdout.write(JSON.stringify({ results: items }) + '\\n');
else if (tool === 'osv-scanner') process.stdout.write(JSON.stringify({ results: items }) + '\\n');
else if (tool === 'trivy') process.stdout.write(JSON.stringify({ Results: items }) + '\\n');
else if (tool === 'checkov') process.stdout.write(JSON.stringify({ results: { failed_checks: items } }) + '\\n');
else if (tool === 'zap') {
  const report = reportArgument('-quickout');
  const output = JSON.stringify({ alerts: items });
  if (report) fs.writeFileSync(report, output); else process.stdout.write(output + '\\n');
}
process.exit(0);
};
const delay = Number(process.env.VCG_E2E_SLEEP_MS || 0);
if (delay > 0) setTimeout(emitResults, delay); else emitResults();
`;
}

function createMockToolchain({ findings = {}, verificationMode = null, sleepMs = 0 } = {}) {
  const root = tempDir('vcg-v07-tools-');
  const binDir = path.join(root, 'bin');
  const toolkitHome = path.join(root, 'toolkit');
  const dataDir = path.join(root, 'runs');
  fs.mkdirSync(binDir, { recursive: true });
  fs.mkdirSync(toolkitHome, { recursive: true });
  fs.mkdirSync(dataDir, { recursive: true });
  const source = mockScannerSource();
  const tools = ['gitleaks', 'trufflehog', 'semgrep', 'trivy', 'osv-scanner', 'checkov', 'zap', 'nuclei'];
  const paths = Object.fromEntries(tools.map((tool) => [tool, writeExecutable(path.join(binDir, tool), source)]));
  writeExecutable(path.join(binDir, 'security-tools'), '#!/bin/sh\nprintf "OVERALL TOOLCHAIN HEALTH: HEALTHY\\n"\n');
  const env = {
    ...process.env,
    PATH: `${binDir}${path.delimiter}${process.env.PATH || ''}`,
    SECURITY_TOOL_PATHS: binDir,
    SECURITY_TOOL_BINARIES: JSON.stringify(paths),
    SECURITY_TOOLKIT_HOME: toolkitHome,
    SECURITY_DASHBOARD_DATA_DIR: dataDir,
    VCG_E2E_FINDINGS: JSON.stringify(findings),
    VCG_E2E_SLEEP_MS: String(sleepMs),
    ...(verificationMode ? { VCG_E2E_VERIFY_MODE: verificationMode } : {}),
  };
  return { root, binDir, toolkitHome, dataDir, paths, env };
}

function runCli(args, env, options = {}) {
  const result = spawnSync(process.execPath, [BIN, ...args], {
    cwd: options.cwd || ROOT,
    env,
    encoding: 'utf8',
    maxBuffer: 8 * 1024 * 1024,
    timeout: options.timeout || 120000,
  });
  const output = `${result.stdout || ''}${result.stderr || ''}`;
  let json = null;
  if (options.json !== false) {
    try { json = JSON.parse(result.stdout || ''); } catch { /* caller can inspect raw output */ }
  }
  return { ...result, output, json };
}

function requestJson(url, options = {}) {
  return new Promise((resolve, reject) => {
    const request = http.request(url, { method: options.method || 'GET', headers: options.headers || {} }, (response) => {
      let body = '';
      response.setEncoding('utf8');
      response.on('data', (chunk) => { body += chunk; });
      response.on('end', () => {
        let json = null;
        try { json = JSON.parse(body); } catch { /* non-JSON response */ }
        resolve({ statusCode: response.statusCode, body, json });
      });
    });
    request.on('error', reject);
    if (options.body) request.write(options.body);
    request.end();
  });
}

function assertSuccessfulJson(result) {
  assert.equal(result.status, 0, result.output);
  assert.ok(result.json, result.output);
  assert.equal(result.json.schemaVersion, '1.0');
  return result.json;
}

function readRun(dataDir, runId) {
  return JSON.parse(fs.readFileSync(path.join(dataDir, runId, 'metadata.json'), 'utf8'));
}

module.exports = {
  ROOT,
  BIN,
  FIXTURES,
  tempDir,
  fixturePath,
  fixtureManifest,
  copyFixture,
  createMockToolchain,
  runCli,
  requestJson,
  assertSuccessfulJson,
  readRun,
};
