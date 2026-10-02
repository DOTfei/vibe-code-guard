'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const http = require('node:http');
const { once } = require('node:events');
const { execFileSync, spawn } = require('node:child_process');
const { summaryExit, safeEvidence, runProcess, installedVersion, isolatedEnvironment, parseDependencyOutput } = require('../scripts/validate-real-scanners');
const { ROOT, copyFixture, createMockToolchain } = require('./e2e/harness');

test('real validation never promotes partial, missing, or failed evidence to exit zero', () => {
  assert.equal(summaryExit([]), 1);
  assert.equal(summaryExit([{ status: 'REAL_VALIDATED' }]), 0);
  for (const status of ['REAL_PARTIAL', 'NOT_TESTED', 'BLOCKED_BY_ENVIRONMENT']) assert.equal(summaryExit([{ status }]), 2);
  assert.equal(summaryExit([{ status: 'REAL_VALIDATED', failure: true }, { status: 'NOT_TESTED' }]), 1);
  const token = 'VCG_SYNTHETIC_CREDENTIAL_' + 'A1B2C3D4'.repeat(3);
  const safe = safeEvidence({ args: ['/private/tmp/example/file'], stdout: `token=${token}`, nested: [{ reason: '/Users/example/cache' }] }, '/private/tmp/example', '/Users/example');
  assert.equal(JSON.stringify(safe).includes(token), false);
  assert.equal(safe.args[0], '$VALIDATION/file');
  assert.equal(safe.nested[0].reason, '$HOME/cache');
  const zap = require('../config/toolchain.json').tools.find(tool => tool.id === 'zap');
  assert.equal(installedVersion(zap, { exitCode: 0, stdout: 'Found Java version 17.0.17\nZAP 2.17.0', stderr: '' }), '2.17.0');
  assert.equal(installedVersion(zap, { exitCode: 0, stdout: 'Found Java version 17.0.17\n2.17.0\n', stderr: '' }), '2.17.0');
  assert.equal(installedVersion(zap, { exitCode: 0, stdout: 'Found Java version 17.0.17', stderr: '' }), null);
  assert.equal(installedVersion({}, { exitCode: 0, stdout: '', stderr: 'Nuclei Engine Version: v3.11.1' }), '3.11.1');
});

test('real validation bounds a stalled subprocess', async () => {
  const result = await runProcess(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], process.env, 100);
  assert.equal(result.timedOut, true);
  assert.ok(result.durationMs < 3000);
});

test('real validation isolates inherited Semgrep paths and treats malformed OSV exit-one output as failure', () => {
  const inherited = { SEMGREP_SETTINGS_FILE: '/host/settings', SEMGREP_LOG_FILE: '/host/log', SEMGREP_VERSION_CACHE_PATH: '/host/cache', PATH: '/usr/bin' };
  const env = isolatedEnvironment('/tmp/isolated', inherited);
  for (const key of ['SEMGREP_SETTINGS_FILE', 'SEMGREP_LOG_FILE', 'SEMGREP_VERSION_CACHE_PATH']) assert.ok(env[key].startsWith('/tmp/isolated/'));
  assert.equal(inherited.SEMGREP_SETTINGS_FILE, '/host/settings');
  assert.equal(env.PATH, inherited.PATH);
  for (const exitCode of [0, 1]) {
    for (const stdout of ['not JSON', 'null', '{}', '[]']) {
      const result = parseDependencyOutput('osv-scanner', { exitCode, stdout }, '/tmp/fixture');
      assert.equal(result.failure, true);
      assert.equal(summaryExit([{ status: 'REAL_PARTIAL', failure: result.failure }]), 1);
    }
  }
  assert.equal(parseDependencyOutput('osv-scanner', { exitCode: 1, stdout: '{"results":[]}' }, '/tmp/fixture').failure, false);
  assert.equal(parseDependencyOutput('osv-scanner', { exitCode: 127, stdout: '' }, '/tmp/fixture').failure, false);
});

test('interrupting nested validation wrappers terminates even a scanner that ignores SIGTERM', { timeout: 15000 }, async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vcg-cancel-test-'));
  fs.mkdirSync(path.join(root, 'traces'));
  const contextFile = path.join(root, 'context.json');
  fs.writeFileSync(contextFile, JSON.stringify({ root, originalHome: os.homedir(), binaries: { fake: process.execPath } }));
  const harness = path.join(ROOT, 'scripts/validate-real-scanners.js');
  let leafPid, parent;
  let ready;
  const leafReady = new Promise(resolve => { ready = resolve; });
  const observer = http.createServer((request, response) => { leafPid = Number(request.url.slice(1)); response.end('ok'); ready(); });
  await new Promise(resolve => observer.listen(0, '127.0.0.1', resolve));
  try {
    const leaf = `process.on('SIGTERM',()=>{});require('node:http').get('http://127.0.0.1:${observer.address().port}/'+process.pid);setInterval(()=>{},1000);`;
    const launcher = `require(${JSON.stringify(harness)}).executeLauncher('fake',['-e',${JSON.stringify(leaf)}]);`;
    const worker = `require(${JSON.stringify(harness)}).runProcess(process.execPath,['-e',${JSON.stringify(launcher)}],process.env,8000);`;
    const outer = `require(${JSON.stringify(harness)}).runProcess(process.execPath,['-e',${JSON.stringify(worker)}],process.env,8000);`;
    parent = spawn(process.execPath, ['-e', outer], { env: { ...process.env, VCG_VALIDATION_CONTEXT: contextFile }, stdio: 'ignore' });
    await Promise.race([leafReady, new Promise((_, reject) => setTimeout(() => reject(new Error('Synthetic scanner did not start')), 5000).unref())]);
    const exited = once(parent, 'close', { signal: AbortSignal.timeout(5000) });
    parent.kill('SIGTERM');
    const [exitCode] = await exited;
    assert.equal(exitCode, 2);
    assert.throws(() => process.kill(leafPid, 0), { code: 'ESRCH' });
  } finally {
    parent?.kill('SIGTERM');
    if (leafPid) { try { process.kill(-leafPid, 'SIGKILL'); } catch {} }
    observer.closeAllConnections?.();
    await new Promise(resolve => observer.close(resolve));
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('ordinary and automatic audits send offline safety flags to actual scanner invocations', () => {
  const tools = createMockToolchain();
  const project = copyFixture('node-api');
  try {
    for (const mode of ['auto', 'full']) {
      const source = `const { createRun, runAudit } = require(${JSON.stringify(path.join(ROOT, 'server.js'))});
        const run = createRun({ projectPath: ${JSON.stringify(project)}, mode: ${JSON.stringify(mode)}, webTarget: 'http://127.0.0.1:12345' });
        runAudit(run).then(() => console.log(JSON.stringify({ th: run.tools.trufflehog.status, nuclei: run.tools.nuclei.status })));`;
      const result = JSON.parse(execFileSync(process.execPath, ['-e', source], { env: { ...tools.env, VCG_E2E_ASSERT_OFFLINE: '1' }, encoding: 'utf8', timeout: 30000 }));
      assert.deepEqual(result, { th: 'PASS', nuclei: 'PASS' });
    }
  } finally {
    fs.rmSync(tools.root, { recursive: true, force: true });
    fs.rmSync(project, { recursive: true, force: true });
  }
});
