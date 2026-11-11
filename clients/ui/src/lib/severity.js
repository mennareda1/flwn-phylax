// What a finding looks like, by meaning: pastel by severity, plain labels, never a status colour that is not in the palette.
export const CARD_FILL = {
  critical: 'bg-pastel-salmon',
  high: 'bg-pastel-salmon',
  medium: 'bg-pastel-gold',
  low: 'bg-pastel-blue',
  info: 'bg-pastel-blue',
};

export const SEVERITY_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };

const TYPE_LABELS = {
  command_injection: 'Command injection',
  sql_injection: 'SQL injection',
  code_injection: 'Code injection',
  insecure_deserialization: 'Insecure deserialization',
  weak_crypto: 'Weak cryptography',
  insecure_random: 'Weak randomness',
  path_traversal: 'Path traversal',
  ssrf: 'Server-side request forgery',
  xss_or_template_injection: 'XSS or template injection',
  tls_verification_disabled: 'TLS checks switched off',
  debug_enabled: 'Debug mode on',
  insecure_temp_file: 'Unsafe temporary file',
  hardcoded_credentials: 'Hardcoded secret',
  other: 'Other',
};

export const typeLabel = (type) => TYPE_LABELS[type] ?? String(type).replace(/_/g, ' ').replace(/^./, (c) => c.toUpperCase());

const RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
export const bySeverity = (a, b) => (RANK[b.severity] ?? 0) - (RANK[a.severity] ?? 0) || String(a.path).localeCompare(String(b.path)) || (a.line ?? 0) - (b.line ?? 0);
