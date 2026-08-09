const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const IGNORED_DIRECTORIES = new Set([
  '.git', 'node_modules', '.venv', 'venv', '__pycache__', '.pytest_cache',
  'dist', 'build', 'coverage', '.next', '.turbo', 'target',
]);

function runGit(projectPath, args) {
  const result = spawnSync('git', args, {
    cwd: projectPath,
    encoding: 'utf8',
    maxBuffer: 2 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  return {
    code: result.status,
    stdout: result.stdout || '',
    stderr: result.stderr || '',
  };
}

function statusName(code) {
  if (code.includes('??')) return 'untracked';
  if (code.includes('A')) return 'added';
  if (code.includes('D')) return 'deleted';
  if (code.includes('R')) return 'renamed';
  if (code.includes('C')) return 'copied';
  return 'modified';
}

function parsePorcelainStatus(output) {
  const records = String(output || '').split('\0').filter(Boolean);
  const files = [];
  for (let index = 0; index < records.length; index += 1) {
    const record = records[index];
    const code = record.slice(0, 2);
    const firstPath = record.slice(3);
    if (!firstPath) continue;
    const status = statusName(code);
    if ((status === 'renamed' || status === 'copied') && records[index + 1]) {
      files.push({ path: records[index + 1], previousPath: firstPath, status });
      index += 1;
    } else {
      files.push({ path: firstPath, status });
    }
  }
  return files;
}

function walkFiles(root, current = root, result = [], limit = 5000) {
  if (result.length >= limit) return result;
  let entries = [];
  try { entries = fs.readdirSync(current, { withFileTypes: true }); } catch { return result; }
  for (const entry of entries) {
    if (result.length >= limit || IGNORED_DIRECTORIES.has(entry.name)) continue;
    const absolute = path.join(current, entry.name);
    if (entry.isDirectory()) walkFiles(root, absolute, result, limit);
    else if (entry.isFile()) result.push({ path: path.relative(root, absolute), status: 'unknown' });
  }
  return result;
}

function detectChanges(projectPath) {
  const repo = runGit(projectPath, ['rev-parse', '--show-toplevel']);
  if (repo.code === 0 && repo.stdout.trim()) {
    const root = path.resolve(repo.stdout.trim());
    const target = path.resolve(projectPath);
    const scope = path.relative(root, target);
    const statusArgs = ['status', '--porcelain=v1', '-z', '--untracked-files=all'];
    if (scope && !scope.startsWith('..') && !path.isAbsolute(scope)) statusArgs.push('--', scope);
    const status = runGit(root, statusArgs);
    if (status.code === 0) {
      const scopedFiles = parsePorcelainStatus(status.stdout).map((file) => ({
        ...file,
        path: path.relative(target, path.resolve(root, file.path)),
        ...(file.previousPath ? { previousPath: path.relative(target, path.resolve(root, file.previousPath)) } : {}),
      }));
      return {
        source: 'git',
        root,
        base: 'working-tree',
        files: scopedFiles.filter((file) => file.path && !file.path.startsWith('..')),
        note: scope ? `Working-tree changes from git status scoped to ${scope}.` : 'Working-tree changes from git status, including untracked files.',
      };
    }
  }

  return {
    source: 'filesystem',
    root: projectPath,
    base: null,
    files: walkFiles(projectPath),
    note: 'Git was unavailable; the relevant local file tree was used as a graceful fallback.',
  };
}

module.exports = { detectChanges, parsePorcelainStatus, walkFiles };
