const CATEGORIES = Object.freeze([
  'SECRET_EXPOSURE',
  'INJECTION',
  'ACCESS_CONTROL',
  'AUTHENTICATION',
  'DEPENDENCY_VULNERABILITY',
  'MISCONFIGURATION',
  'CRYPTOGRAPHY',
  'DATA_EXPOSURE',
  'XSS',
  'SSRF',
  'FILE_UPLOAD',
  'INFRASTRUCTURE',
  'RUNTIME',
  'UNKNOWN',
]);

function normalizeCategory(value, hints = '') {
  const raw = `${value || ''} ${hints || ''}`.trim().toUpperCase();
  if (CATEGORIES.includes(raw)) return raw;
  const text = raw.replace(/[_-]+/g, ' ');
  if (/SECRET|CREDENTIAL|API KEY|PASSWORD|TOKEN/.test(text)) return 'SECRET_EXPOSURE';
  if (/SQL INJECTION|COMMAND INJECTION|CODE INJECTION|INJECTION/.test(text)) return 'INJECTION';
  if (/ACCESS CONTROL|AUTHORIZATION|IDOR|OWNERSHIP/.test(text)) return 'ACCESS_CONTROL';
  if (/AUTHENTICATION|SESSION|LOGIN|OAUTH|MFA/.test(text)) return 'AUTHENTICATION';
  if (/DEPENDENCY|VULNERABILITY|CVE|OSV|PACKAGE/.test(text)) return 'DEPENDENCY_VULNERABILITY';
  if (/MISCONFIG|CONFIGURATION|POLICY/.test(text)) return 'MISCONFIGURATION';
  if (/CRYPTO|TLS|CERTIFICATE|HASH/.test(text)) return 'CRYPTOGRAPHY';
  if (/DATA EXPOSURE|SENSITIVE DATA|PII|DISCLOSURE/.test(text)) return 'DATA_EXPOSURE';
  if (/XSS|CROSS.?SITE SCRIPT/.test(text)) return 'XSS';
  if (/SSRF|SERVER.?SIDE REQUEST/.test(text)) return 'SSRF';
  if (/FILE UPLOAD|UNRESTRICTED UPLOAD/.test(text)) return 'FILE_UPLOAD';
  if (/INFRA|IAC|DOCKER|KUBERNETES|TERRAFORM/.test(text)) return 'INFRASTRUCTURE';
  if (/RUNTIME|WEB|HTTP|ENDPOINT|DAST/.test(text)) return 'RUNTIME';
  return 'UNKNOWN';
}

module.exports = { CATEGORIES, normalizeCategory };
