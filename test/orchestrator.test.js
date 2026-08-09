const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { buildExecutionPlan, detectChanges, parsePorcelainStatus } = require('../orchestrator');

function planFor(paths) {
  return buildExecutionPlan({
    projectPath: '/tmp/example-project',
    detectedChanges: {
      source: 'git',
      root: '/tmp/example-project',
      base: 'working-tree',
      files: paths.map((path) => ({ path, status: 'modified' })),
      note: 'fixture change set',
    },
  });
}

function decision(plan, tool) { return plan.tools.find((item) => item.tool === tool); }

test('parses git status records including renames', () => {
  assert.deepEqual(parsePorcelainStatus(' M src/app.ts\0R  old.ts\0new.ts\0?? .env.example\0'), [
    { path: 'src/app.ts', status: 'modified' },
    { path: 'new.ts', previousPath: 'old.ts', status: 'renamed' },
    { path: '.env.example', status: 'untracked' },
  ]);
});

test('scopes git changes to a repository subdirectory', () => {
  const directory = path.resolve(__dirname, '..', 'orchestrator');
  const changes = detectChanges(directory);
  assert.equal(changes.source, 'git');
  assert.equal(changes.files.some((file) => file.path === 'package.json'), false);
  assert.equal(changes.files.every((file) => !file.path.startsWith('..')), true);
});

test('UI-only changes stay low risk and avoid runtime/deep testing', () => {
  const plan = planFor(['src/components/Button.tsx', 'src/styles.css']);
  assert.deepEqual(plan.categories, ['UI_CHANGE']);
  assert.equal(plan.risk, 'LOW');
  assert.equal(decision(plan, 'gitleaks').decision, 'RUN');
  assert.equal(decision(plan, 'semgrep').decision, 'RUN');
  assert.equal(decision(plan, 'zap').decision, 'NOT_APPLICABLE');
  assert.equal(decision(plan, 'strix').decision, 'SKIPPED');
});

test('dependency changes require OSV-Scanner and Trivy', () => {
  const plan = planFor(['package.json', 'package-lock.json']);
  assert.equal(plan.risk, 'MEDIUM');
  assert.equal(decision(plan, 'osv-scanner').decision, 'RUN');
  assert.equal(decision(plan, 'trivy').decision, 'RUN');
});

test('authentication changes are high risk and recommend Strix without executing it', () => {
  const plan = planFor(['src/auth/session.ts']);
  assert.equal(plan.risk, 'HIGH');
  assert.equal(decision(plan, 'gitleaks').decision, 'RUN');
  assert.equal(decision(plan, 'semgrep').decision, 'RUN');
  assert.equal(decision(plan, 'trufflehog').decision, 'RUN');
  assert.equal(decision(plan, 'strix').decision, 'RECOMMENDED');
});

test('database, Docker, and Terraform signals select their relevant tools', () => {
  const database = planFor(['supabase/migrations/001.sql']);
  const docker = planFor(['Dockerfile']);
  const terraform = planFor(['terraform/main.tf']);
  assert.equal(database.risk, 'HIGH');
  assert.equal(decision(database, 'semgrep').decision, 'RUN');
  assert.equal(decision(docker, 'trivy').decision, 'RUN');
  assert.equal(decision(terraform, 'checkov').decision, 'RUN');
});

test('runtime tools are skipped when no authorized localhost target exists', () => {
  const plan = planFor(['src/api/search.ts']);
  assert.equal(decision(plan, 'zap').decision, 'SKIPPED');
  assert.equal(decision(plan, 'nuclei').decision, 'SKIPPED');
  assert.match(decision(plan, 'zap').reason, /localhost/);
});
