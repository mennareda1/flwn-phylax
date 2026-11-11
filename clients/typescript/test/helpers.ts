/**
 * test/helpers.ts: stand-ins and builders shared by the tests (a fake Phylax, an in-memory host, a scripted person).
 */

import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { sha256Text } from '../src/adapters/disk.js';
import type { PhylaxApi } from '../src/api.js';
import { FileUnreadableError, StaleFileError } from '../src/errors.js';
import type { AppliedChange, ApprovalDecision, Approver, ChangeProposal, CorrectionCandidate, FileChange, FileChanger, FileSelection, FileSnapshot, HostCapabilities } from '../src/interfaces.js';
import type { Capabilities, Finding, Fix, InputFile, Patch, Scan, ScanReport, Severity, Verification } from '../src/types.js';

export function finding(id: string, path: string, severity: Severity, type = 'command_injection', line = 3): Finding {
  const eligible = severity === 'medium' || severity === 'high' || severity === 'critical';
  return {
    id, path, vulnerability_type: type, severity, confidence: 'high', evidence_tier: 'static_rule', sources: ['rules'], rule_id: 'R1', cwe: 'CWE-78', line,
    evidence: 'dangerous(call)', description: `A ${severity} ${type} problem.`, recommendation: 'Fix it.', reference: null,
    fix: { eligible, reason: eligible ? 'Medium severity or above: a correction can be offered.' : 'Low and informational findings are reported, not corrected by default.' },
  };
}

export const CAPABILITIES: Capabilities = {
  contract_version: '1.4.0', languages: [{ id: 'javascript', roles: ['analyzer'] }], retention_hours: 24, features: { fixes: true, verifications: true },
  limits: { max_files: 50, max_file_bytes: 200_000, max_total_bytes: 1_000_000, max_wait_seconds: 30 },
};

export function reportFor(files: InputFile[], findings: Finding[], decision: ScanReport['decision'] = 'review_required'): ScanReport {
  return {
    status: 'completed', decision, risk_level: decision === 'pass' ? 'none' : 'high', findings, decision_reasons: [`decision ${decision}`], duration_ms: 5,
    coverage: {
      languages: ['javascript'], files_scanned: files.map((f) => f.path), scanned_files: files.map((f) => ({ path: f.path, sha256: sha256Text(f.content) })),
      skipped_files: [], analyzers_run: ['rules'], analyzers_failed: {}, not_assessable: ['authentication logic'],
    },
  };
}

/** A scripted Phylax. Each method can be replaced; calls are recorded. */
export class FakePhylax implements PhylaxApi {
  calls: { method: string; args: unknown[] }[] = [];
  capabilitiesValue: Capabilities = CAPABILITIES;
  scanCounter = 0;
  onScan: (files: InputFile[], n: number) => Scan = (files, n) => ({ id: `scn_${n}`, status: 'completed', report: reportFor(files, []) });
  onFix: (scanId: string, findingIds: string[] | undefined) => Fix = () => { throw new Error('fix not scripted'); };
  onVerify: (scanId: string, files: InputFile[]) => Verification = (scanId) => ({ id: 'ver_1', scan_id: scanId, status: 'completed', outcome: 'passed', checks: [], new_findings: [], resolved_finding_ids: [] });
  deleted: string[] = [];
  /** The findings each scan returned, so a scripted fix can refer to them. */
  scansSeen = new Map<string, Finding[]>();

  async capabilities(): Promise<Capabilities> { this.calls.push({ method: 'capabilities', args: [] }); return this.capabilitiesValue; }
  async scan(files: InputFile[]): Promise<Scan> { this.scanCounter += 1; this.calls.push({ method: 'scan', args: [files] }); return this.onScan(files, this.scanCounter); }
  async fix(scanId: string, options?: { findingIds?: string[] }): Promise<Fix> { this.calls.push({ method: 'fix', args: [scanId, options?.findingIds] }); return this.onFix(scanId, options?.findingIds); }
  async verify(scanId: string, files: InputFile[]): Promise<Verification> { this.calls.push({ method: 'verify', args: [scanId, files] }); return this.onVerify(scanId, files); }
  async deleteScan(scanId: string): Promise<void> { this.calls.push({ method: 'deleteScan', args: [scanId] }); this.deleted.push(scanId); }
  count(method: string): number { return this.calls.filter((c) => c.method === method).length; }
}

export function patchFor(original: string, corrected: string, path: string, findingIds: string[]): Patch {
  return {
    path, finding_ids: findingIds, unified_diff: `--- a/${path}\n+++ b/${path}\n@@ -1 +1 @@\n-${original.trim()}\n+${corrected.trim()}\n`, explanation: 'Made it safe.',
    base_sha256: sha256Text(original), corrected_content: corrected, corrected_sha256: sha256Text(corrected),
  };
}

export function okFix(scanId: string, patches: Patch[], unfixed: { finding_id: string; reason: string }[] = []): Fix {
  return {
    id: 'fix_1', scan_id: scanId, status: 'completed', applicable: true, failure_reason: null, patches, unfixed,
    verification: { id: 'ver_fix', scan_id: scanId, status: 'completed', outcome: 'passed', new_findings: [], resolved_finding_ids: patches.flatMap((p) => p.finding_ids),
      checks: [{ name: 'rescan', result: 'pass', detail: 'The problem is gone.' }] },
  };
}

/** A host whose files live in memory. Every write goes through apply(), which checks the hash like a real host. */
export class MemoryHost implements FileChanger {
  readonly capabilities: HostCapabilities;
  files = new Map<string, string>();
  applied: FileChange[] = [];
  readCount = 0;
  failWith: Error | null = null;
  writeWrong = false;                 // simulate a host that stores something other than what it was given
  reverted: string[] = [];
  constructor(files: Record<string, string>, capabilities: HostCapabilities = {}) {
    this.capabilities = capabilities;
    for (const [name, content] of Object.entries(files)) this.files.set(name, content);
  }
  async listFiles(selection: FileSelection): Promise<string[]> {
    return selection.kind === 'project' ? [...this.files.keys()].sort() : selection.paths;
  }
  async read(path: string): Promise<FileSnapshot> {
    this.readCount += 1;
    const content = this.files.get(path);
    if (content === undefined) throw new FileUnreadableError(`${path} does not exist.`);
    return { path, content, sha256: sha256Text(content) };
  }
  async apply(change: FileChange): Promise<AppliedChange> {
    if (this.failWith) throw this.failWith;
    const current = this.files.get(change.path);
    if (current === undefined || sha256Text(current) !== change.expectedSha256) throw new StaleFileError();
    this.applied.push(change);
    const stored = this.writeWrong ? change.content + '\n// tampered' : change.content;
    this.files.set(change.path, stored);
    return { path: change.path, sha256: sha256Text(stored), changeId: `chg_${this.applied.length}` };
  }
  async revert(changeId: string): Promise<AppliedChange> { this.reverted.push(changeId); return { path: 'x', sha256: 'x' }; }
}

/** A scripted person. Records what they were shown. */
export class ScriptedPerson implements Approver {
  asked: CorrectionCandidate[][] = [];
  shown: ChangeProposal[] = [];
  constructor(public picks: ((candidates: CorrectionCandidate[]) => string[]) | string[], public approve: boolean | ((p: ChangeProposal) => ApprovalDecision) = true) {}
  async chooseCorrections(candidates: CorrectionCandidate[]): Promise<string[]> {
    this.asked.push(candidates);
    return typeof this.picks === 'function' ? this.picks(candidates) : this.picks;
  }
  async approveChange(proposal: ChangeProposal): Promise<ApprovalDecision> {
    this.shown.push(proposal);
    if (typeof this.approve === 'function') return this.approve(proposal);
    return { approved: this.approve };
  }
}

export async function tempProject(files: Record<string, string | Buffer>): Promise<{ root: string; cleanup: () => Promise<void> }> {
  const root = await mkdtemp(path.join(tmpdir(), 'phylax-ts-'));
  for (const [name, content] of Object.entries(files)) {
    const target = path.join(root, ...name.split('/'));
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, content);
  }
  return { root, cleanup: () => rm(root, { recursive: true, force: true }) };
}
