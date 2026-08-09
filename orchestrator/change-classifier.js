const CATEGORIES = [
  'UI_CHANGE', 'DEPENDENCY_CHANGE', 'AUTH_CHANGE', 'API_CHANGE', 'DATABASE_CHANGE',
  'PAYMENT_CHANGE', 'CONTAINER_CHANGE', 'IAC_CHANGE', 'CONFIG_CHANGE', 'CI_CD_CHANGE',
  'GENERAL_BACKEND_CHANGE', 'UNKNOWN_CHANGE',
];

const SOURCE_EXTENSIONS = new Set([
  '.js', '.jsx', '.ts', '.tsx', '.py', '.rb', '.php', '.java', '.kt', '.go', '.rs',
  '.cs', '.c', '.cpp', '.swift', '.scala', '.sql',
]);

function lower(value) { return String(value || '').toLowerCase().replaceAll('\\', '/'); }

function classifyFile(filePath) {
  const file = lower(filePath);
  const name = file.split('/').pop() || file;
  const extension = name.includes('.') ? `.${name.split('.').pop()}` : '';
  const categories = new Set();

  if (file.startsWith('.github/workflows/') || file === '.gitlab-ci.yml' || file === '.gitlab-ci.yaml' || name === 'jenkinsfile') {
    categories.add('CI_CD_CHANGE');
  }
  if (/dockerfile(?:\.|$)/.test(name) || file.includes('docker-compose') || file.includes('/container/')) {
    categories.add('CONTAINER_CHANGE');
  }
  if (extension === '.tf' || extension === '.tfvars' || file.includes('/terraform/') || file.includes('/k8s/') || file.includes('/kubernetes/') || file.includes('/helm/') || file.includes('cloudformation') || file.includes('pulumi')) {
    categories.add('IAC_CHANGE');
  }
  if (/package\.json$|package-lock\.json$|yarn\.lock$|pnpm-lock\.yaml$|requirements(?:\.txt|\.in)$|pyproject\.toml$|poetry\.lock$|pipfile(?:\.lock)?$|go\.mod$|go\.sum$|cargo\.toml$|cargo\.lock$|pom\.xml$|build\.gradle(?:\.kts)?$|gemfile(?:\.lock)?$|composer\.json$/.test(name)) {
    categories.add('DEPENDENCY_CHANGE');
  }
  if (/(^|\/)(auth|authentication|authorize|authorization|session|login|logout|oauth|oidc|sso|jwt|passport|identity|permissions?)(\/|\.|$)/.test(file) || /(callback|middleware)/.test(name)) {
    categories.add('AUTH_CHANGE');
  }
  if (/(^|\/)(api|routes?|controllers?|handlers?|endpoints?)(\/|\.|$)/.test(file) || /openapi|swagger|webhook/.test(name)) {
    categories.add('API_CHANGE');
  }
  if (file.includes('/migrations/') || file.includes('/supabase/') || file.includes('/prisma/') || file.includes('/drizzle/') || /(^|\/)(schema|rls|database|db)(\/|\.|$)/.test(file) || extension === '.sql') {
    categories.add('DATABASE_CHANGE');
  }
  if (/payment|billing|checkout|stripe|paypal|paddle/.test(file)) categories.add('PAYMENT_CHANGE');
  if (name.startsWith('.env') || file.includes('/config/') || /(^|\/)(config|settings)(\.|\/|$)/.test(file) ||
    (!categories.has('DEPENDENCY_CHANGE') && !categories.has('CI_CD_CHANGE') && !categories.has('IAC_CHANGE') && !categories.has('CONTAINER_CHANGE') && /\.(ya?ml|json|toml|ini|conf)$/.test(name))) {
    categories.add('CONFIG_CHANGE');
  }

  const isUi = extension === '.css' || extension === '.scss' || extension === '.less' || extension === '.html' ||
    (['.jsx', '.tsx'].includes(extension) && /(components?|views?|pages?|ui|styles?)/.test(file));
  if (isUi) categories.add('UI_CHANGE');

  if (!categories.size && SOURCE_EXTENSIONS.has(extension)) categories.add('GENERAL_BACKEND_CHANGE');
  if (!categories.size) categories.add('UNKNOWN_CHANGE');
  return [...categories];
}

function classifyChanges(changeSet) {
  const fileClassifications = (changeSet.files || []).map((file) => ({
    ...file,
    categories: classifyFile(file.path),
  }));
  const categories = [...new Set(fileClassifications.flatMap((file) => file.categories))];
  if (!categories.length) categories.push('UNKNOWN_CHANGE');
  return {
    categories,
    fileClassifications,
    hasChanges: fileClassifications.length > 0,
    note: changeSet.note,
  };
}

module.exports = { CATEGORIES, classifyFile, classifyChanges };
