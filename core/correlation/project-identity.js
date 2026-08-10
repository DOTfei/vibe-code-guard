const crypto = require('node:crypto');
const path = require('node:path');

function normalizeProjectPath(projectPath) {
  return path.resolve(String(projectPath || '')).replaceAll('\\', '/').toLowerCase();
}

function projectIdentity(projectPath, remoteUrl = '') {
  const normalized = `${normalizeProjectPath(projectPath)}|${String(remoteUrl || '').trim().toLowerCase()}`;
  const id = crypto.createHash('sha256').update(normalized).digest('hex').slice(0, 24);
  return { id: `project-${id}`, normalizedPath: normalizeProjectPath(projectPath), remoteUrl: remoteUrl || null };
}

module.exports = { normalizeProjectPath, projectIdentity };
