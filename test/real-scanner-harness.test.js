'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { summaryExit, safeEvidence, runProcess, installedVersion } = require('../scripts/validate-real-scanners');
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
