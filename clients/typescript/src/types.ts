/**
 * src/types.ts
 *
 * The Phylax HTTP API, as TypeScript types. They mirror openapi.yaml (contract 1.3.0); only the fields a client uses are named, and anything the
 * service adds later is tolerated (additive changes never break a client).
 */

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type Confidence = 'low' | 'medium' | 'high';
export type Decision = 'pass' | 'review_required' | 'block' | 'scan_failed';
export type JobStatus = 'queued' | 'running' | 'completed' | 'failed';

/** Whether a correction is offered for a finding by default, and why. Set by the service from the finding alone, never from the decision. */
export interface FixEligibility {
  eligible: boolean;
  reason: string;
}

export interface Finding {
  id: string;
  path: string | null;
  vulnerability_type: string;
  severity: Severity;
  confidence: Confidence;
  evidence_tier: string;
  sources: string[];
  rule_id: string | null;
  cwe: string | null;
  line: number | null;
  evidence: string;
  description: string;
  recommendation: string;
  reference: string | null;
  fix: FixEligibility;
}

export interface ScannedFile {
  path: string;
  sha256: string;
}

export interface SkippedFile {
  path: string;
  reason: 'unsupported_language' | 'file_too_large' | 'binary_or_invalid' | 'empty';
  blocks_pass: boolean;
}

export interface Coverage {
  languages: string[];
  files_scanned: string[];
  scanned_files: ScannedFile[];
  skipped_files: SkippedFile[];
  analyzers_run: string[];
  analyzers_failed: Record<string, string>;
  not_assessable: string[];
}

export interface ScanReport {
  status: 'completed' | 'failed';
  decision: Decision;
  risk_level: string;
  findings: Finding[];
  decision_reasons: string[];
  coverage: Coverage;
  duration_ms: number;
  [more: string]: unknown;
}

export interface Scan {
  id: string;
  status: JobStatus;
  report: ScanReport | null;
  [more: string]: unknown;
}

export interface Patch {
  path: string;
  finding_ids: string[];
  unified_diff: string;
  explanation: string;
  /** SHA-256 of the file text that was scanned and patched: the hash the file must still have for the patch to apply. */
  base_sha256: string;
  /** The whole file after the patch, with the original line endings. */
  corrected_content: string;
  /** SHA-256 of corrected_content: the hash the file has after it is applied. */
  corrected_sha256: string;
}

export interface VerificationCheck {
  name: 'syntax' | 'rescan' | 'patch_size' | 'scope';
  result: 'pass' | 'fail' | 'skipped';
  detail: string;
}

export interface Verification {
  id: string;
  scan_id: string;
  status: JobStatus;
  outcome: 'passed' | 'failed' | 'inconclusive' | null;
  checks: VerificationCheck[];
  new_findings: Finding[];
  resolved_finding_ids: string[];
  [more: string]: unknown;
}

export interface UnfixedItem {
  finding_id: string;
  reason: string;
}

export interface Fix {
  id: string;
  scan_id: string;
  status: JobStatus;
  /** True only when the corrected files passed verification. A fix that is not applicable is never offered for approval. */
  applicable: boolean;
  failure_reason: string | null;
  patches: Patch[];
  unfixed?: UnfixedItem[];
  verification: Verification | null;
  [more: string]: unknown;
}

export interface Capabilities {
  contract_version: string;
  languages: { id: string; roles: string[] }[];
  limits: { max_files: number; max_file_bytes: number; max_total_bytes: number; max_wait_seconds: number };
  retention_hours: number;
  features?: { fixes: boolean; verifications: boolean };
  [more: string]: unknown;
}

export interface InputFile {
  path: string;
  content: string;
}

/** The body of an error response (RFC 9457 style). It never contains submitted code or keys. */
export interface Problem {
  type?: string;
  title: string;
  status: number;
  detail?: string;
  code: string;
  request_id?: string;
}
