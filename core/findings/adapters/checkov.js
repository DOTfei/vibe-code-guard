const fs = require('node:fs');
const path = require('node:path');
const { parseJsonLoose } = require('../parsing');
const { createFinding } = require('../schema');

function normalizeCheckovFile(rawFile, projectPath) {
  const value = String(rawFile || '').trim();
  if (!value || !projectPath || !path.isAbsolute(value)) return value;
  const root = path.resolve(projectPath);
  const direct = path.resolve(value);
  const directRelative = path.relative(root, direct);
  if (directRelative && !directRelative.startsWith('..') && !path.isAbsolute(directRelative)) return directRelative;

  // Checkov can emit a project-relative file with a leading slash (for
  // example `/Dockerfile`). Resolve that form only when the resulting regular
  // file is inside the authorized project root; never reinterpret arbitrary
  // outside paths as project files.
  const projectRelative = path.resolve(root, value.replace(/^[/\\]+/, ''));
  const relative = path.relative(root, projectRelative);
  if (!relative || relative.startsWith('..') || path.isAbsolute(relative)) return value;
  try {
    const stat = fs.lstatSync(projectRelative);
    if (stat.isFile() && !stat.isSymbolicLink()) return relative;
  } catch { /* preserve the original path when it cannot be proven safe */ }
  return value;
}

function parseCheckov(text, context) {
  const data = parseJsonLoose(text);
  const failed = data?.results?.failed_checks || [];
  return failed.map((item) => createFinding({
    scanner: { id: 'checkov', name: 'Checkov', ruleId: item.check_id },
    severity: item.severity,
    category: item.check_type || 'INFRASTRUCTURE',
    title: `${item.check_id || 'IaC check'}: ${item.check_name || 'Configuration issue'}`,
    location: { type: 'file', file: normalizeCheckovFile(item.file_path || 'infrastructure', context?.projectPath), line: Array.isArray(item.file_line_range) ? item.file_line_range[0] : null },
    explanation: { technical: item.check_name || 'Checkov reported a failed infrastructure security check.', simple: 'A deployment or infrastructure setting may be more exposed than intended.', whyItMatters: item.guideline || 'Infrastructure defaults can turn a small application mistake into a broad exposure.' },
    evidence: `Checkov check ${item.check_id || 'failed'} reported a sanitized configuration result.`,
    remediation: item.guideline || null,
  }, context));
}

module.exports = parseCheckov;
