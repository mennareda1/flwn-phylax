/**
 * src/review.ts
 *
 * THE WORKFLOW. One class, SecurityReview, drives the review a person asks for after their coding agent has finished its task:
 *
 *   scan()                   read the chosen files, send them to Phylax, report what it found (decision, findings, what could not be checked)
 *   proposeCorrections()     for findings the person picked: ask Phylax for corrections (Phylax checks each one before it is offered)
 *   applyProposal()          show one correction to the person; only on an explicit yes, apply it through the host's FileChanger
 *   verify()                 re-read what is now on disk and have Phylax check it against the original scan
 *   runInteractive()         all of the above in order, asking the person through the Approver
 *
 * Rules this class keeps, each covered by a test:
 *   - FIX ELIGIBILITY IS SEPARATE FROM THE VERDICT. Which findings may be corrected comes from each finding's own `fix.eligible` (medium severity and
 *     above; low and informational are report-only; a hardcoded secret is never edited away). A finding can be eligible when the decision is `pass`
 *     or `review_required`, and a `block` does not make a low finding eligible.
 *   - NOTHING IS REQUESTED OR WRITTEN WITHOUT THE PERSON. A correction is requested only for findings they chose, and applied only after an
 *     explicit yes to that file's diff. There is no "approve all" and no way to apply without an Approver.
 *   - NOTHING STALE IS OFFERED. Before asking, the file is read again: if it is no longer what was scanned, or the correction cannot fit the host's
 *     change mechanism, the person is told and not asked. The host's own hash check is the last line of defence.
 *   - THE HASHES MUST AGREE. If the host's hash of a file differs from Phylax's, the review stops: a patch could never be applied safely.
 *   - WHAT IS VERIFIED IS WHAT IS ON DISK, not what was proposed.
 */

import { Buffer } from 'node:buffer';

import type { PhylaxApi } from './api.js';
import { ChangeRefusedError, FileUnreadableError, ReviewError, StaleFileError } from './errors.js';
import type { Approver, ChangeProposal, FileChanger, FileSelection, FileSnapshot } from './interfaces.js';
import type { Capabilities, Decision, Finding, InputFile, Scan, Verification } from './types.js';

// ------------------------------------------------------------------------------------------------------------ results

export interface ReviewFinding {
  /** Identifies the finding in later calls: `<scan id>:<finding id>`. */
  key: string;
  scanId: string;
  finding: Finding;
}

export interface UnscannedFile {
  path: string;
  reason: string;
  /** True if the file's absence from the scan stops the review from saying `pass`. */
  blocksPass: boolean;
}

export interface ScanSummary {
  /** The worst decision across everything scanned: block, then scan_failed, then review_required, then pass. */
  decision: Decision;
  riskLevel: string;
  reasons: string[];
  findings: ReviewFinding[];
  /** Findings a correction can be offered for (each finding's own `fix.eligible`; independent of `decision`). */
  correctable: ReviewFinding[];
  /** Findings that are reported only, each with the reason on `finding.fix.reason`. */
  reportOnly: ReviewFinding[];
  scannedFiles: string[];
  unscanned: UnscannedFile[];
  /** Checks that could not run, so the decision is weaker than it looks. */
  engineProblems: string[];
  notAssessable: string[];
  scanIds: string[];
  /** Whether this Phylax deployment can produce corrections at all. */
  correctionsAvailable: boolean;
}

export interface ProposedCorrection extends ChangeProposal {
  scanId: string;
  baseSha256: string;
  correctedContent: string;
  correctedSha256: string;
}

export interface NotCorrected {
  findings: Finding[];
  reason: string;
}

export interface ProposalResult {
  proposals: ProposedCorrection[];
  notCorrected: NotCorrected[];
}

export type ApplyStatus = 'applied' | 'rejected' | 'stale' | 'too_large' | 'refused' | 'failed';

export interface ApplyOutcome {
  key: string;
  scanId: string;
  path: string;
  status: ApplyStatus;
  message: string;
  findingIds: string[];
  changeId?: string;
}

export interface VerificationResult {
  scanId: string;
  paths: string[];
  outcome: 'passed' | 'failed' | 'inconclusive';
  /** Findings of the original scan that are gone from the files as they are on disk now. */
  resolved: Finding[];
  /** Findings of the original scan, in the changed files, that are still there. */
  remaining: Finding[];
  /** Problems the corrected files have that the original did not. */
  introduced: Finding[];
  checks: { name: string; result: string; detail: string }[];
}

export interface ReviewResult {
  summary: ScanSummary;
  /** The findings the person chose to have corrected. */
  requested: string[];
  proposals: ProposalResult | null;
  outcomes: ApplyOutcome[];
  verification: VerificationResult[];
}

export interface ReviewOptions {
  phylax: PhylaxApi;
  files: FileChanger;
  signal?: AbortSignal;
  clientRef?: string;
  maxPatchLines?: number;
  /** Receives plain progress messages ("Scanning 12 files..."). */
  onProgress?: (message: string) => void;
}

// --------------------------------------------------------------------------------------------------------- internals

interface Batch {
  scanId: string;
  report: NonNullable<Scan['report']>;
  snapshots: Map<string, FileSnapshot>;
}

const DECISION_RANK: Record<Decision, number> = { pass: 0, review_required: 1, scan_failed: 2, block: 3 };
const SEVERITY_RANK: Record<string, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

const utf8Bytes = (text: string): number => Buffer.byteLength(text, 'utf8');

function compareText(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

export class SecurityReview {
  private readonly phylax: PhylaxApi;
  private readonly files: FileChanger;
  private readonly options: ReviewOptions;
  private readonly batches = new Map<string, Batch>();
  private readonly findings = new Map<string, ReviewFinding>();
  private capabilities: Capabilities | null = null;

  constructor(options: ReviewOptions) {
    this.phylax = options.phylax;
    this.files = options.files;
    this.options = options;
  }

  private say(message: string): void {
    this.options.onProgress?.(message);
  }

  private async limits(): Promise<Capabilities> {
    this.capabilities ??= await this.phylax.capabilities(this.callOptions());
    return this.capabilities;
  }

  private callOptions(): { signal?: AbortSignal; clientRef?: string } {
    return { ...(this.options.signal ? { signal: this.options.signal } : {}), ...(this.options.clientRef ? { clientRef: this.options.clientRef } : {}) };
  }

  // ------------------------------------------------------------------------------------------------------ 1. scan

  async scan(selection: FileSelection): Promise<ScanSummary> {
    const capabilities = await this.limits();
    const paths = await this.files.listFiles(selection);
    if (paths.length === 0) throw new ReviewError('nothing_to_scan', 'There are no files to scan in that selection.');

    this.say(`Reading ${paths.length} file(s)...`);
    const unscanned: UnscannedFile[] = [];
    const readable: FileSnapshot[] = [];
    for (const path of paths) {
      try {
        readable.push(await this.files.read(path));
      } catch (error) {
        if (!(error instanceof FileUnreadableError)) throw error;
        unscanned.push({ path, reason: error.message, blocksPass: true });
      }
    }

    const { max_files: maxFiles, max_file_bytes: maxFileBytes, max_total_bytes: maxTotalBytes } = capabilities.limits;
    const sendable: FileSnapshot[] = [];
    for (const snapshot of readable) {
      if (utf8Bytes(snapshot.content) > maxFileBytes) unscanned.push({ path: snapshot.path, reason: `larger than the ${maxFileBytes} bytes Phylax accepts per file`, blocksPass: true });
      else sendable.push(snapshot);
    }

    const groups: FileSnapshot[][] = [];
    let current: FileSnapshot[] = [];
    let currentBytes = 0;
    for (const snapshot of sendable) {
      const size = utf8Bytes(snapshot.content);
      if (current.length > 0 && (current.length >= maxFiles || currentBytes + size > maxTotalBytes)) {
        groups.push(current);
        current = [];
        currentBytes = 0;
      }
      current.push(snapshot);
      currentBytes += size;
    }
    if (current.length > 0) groups.push(current);

    for (const [index, group] of groups.entries()) {
      this.say(groups.length > 1 ? `Scanning batch ${index + 1} of ${groups.length} (${group.length} file(s))...` : `Scanning ${group.length} file(s)...`);
      const scan = await this.phylax.scan(group.map((s): InputFile => ({ path: s.path, content: s.content })), this.callOptions());
      if (!scan.report) throw new ReviewError('no_report', 'Phylax finished the scan without a report.');
      const snapshots = new Map(group.map((s) => [s.path, s] as const));
      for (const scanned of scan.report.coverage.scanned_files) {                     // the host and Phylax must agree on what a file is, byte for byte
        const ours = snapshots.get(scanned.path);
        if (ours && ours.sha256 !== scanned.sha256) {
          throw new ReviewError('hash_mismatch', `The host and Phylax compute different hashes for ${scanned.path}, so a correction could never be applied safely. ` +
            'The host must hash the exact UTF-8 text of the file with SHA-256 (see the FileChanger interface).');
        }
      }
      const batch: Batch = { scanId: scan.id, report: scan.report, snapshots };
      this.batches.set(scan.id, batch);
      for (const finding of scan.report.findings) {
        const key = `${scan.id}:${finding.id}`;
        this.findings.set(key, { key, scanId: scan.id, finding });
      }
    }
    return this.summarize(unscanned, capabilities);
  }

  private summarize(localUnscanned: UnscannedFile[], capabilities: Capabilities): ScanSummary {
    const batches = [...this.batches.values()];
    let decision: Decision = 'pass';
    let riskLevel = 'none';
    const reasons: string[] = [];
    const engineProblems: string[] = [];
    const notAssessable = new Set<string>();
    const unscanned = [...localUnscanned];
    const scannedFiles: string[] = [];
    for (const { report } of batches) {
      if (DECISION_RANK[report.decision] > DECISION_RANK[decision]) decision = report.decision;
      if (compareRisk(report.risk_level, riskLevel) > 0) riskLevel = report.risk_level;
      reasons.push(...report.decision_reasons);
      for (const [engine, problem] of Object.entries(report.coverage.analyzers_failed)) engineProblems.push(`${engine}: ${problem}`);
      report.coverage.not_assessable.forEach((item) => notAssessable.add(item));
      scannedFiles.push(...report.coverage.files_scanned);
      for (const skipped of report.coverage.skipped_files) unscanned.push({ path: skipped.path, reason: skipped.reason, blocksPass: skipped.blocks_pass });
    }
    if (decision === 'pass' && unscanned.some((u) => u.blocksPass)) {
      decision = 'review_required';
      reasons.push(`${unscanned.filter((u) => u.blocksPass).length} file(s) could not be scanned, so a pass cannot be claimed.`);
    }
    const findings = [...this.findings.values()].sort((a, b) =>
      (SEVERITY_RANK[b.finding.severity] ?? 0) - (SEVERITY_RANK[a.finding.severity] ?? 0) || compareText(a.finding.path ?? '', b.finding.path ?? '') || (a.finding.line ?? 0) - (b.finding.line ?? 0));
    return {
      decision,
      riskLevel,
      reasons,
      findings,
      correctable: findings.filter((f) => f.finding.fix.eligible),                           // NOT derived from `decision`
      reportOnly: findings.filter((f) => !f.finding.fix.eligible),
      scannedFiles: scannedFiles.sort(compareText),
      unscanned,
      engineProblems,
      notAssessable: [...notAssessable],
      scanIds: batches.map((b) => b.scanId),
      correctionsAvailable: capabilities.features?.fixes !== false,
    };
  }

  // ------------------------------------------------------------------------------------ 2. ask for corrections

  /**
   * Ask Phylax for corrections for exactly these findings (by key). By default only findings the service marks as correctable are accepted; a
   * report-only finding is refused unless `allowReportOnly` is set (and a hardcoded secret is never corrected either way, Phylax says why).
   */
  async proposeCorrections(keys: string[], options: { allowReportOnly?: boolean } = {}): Promise<ProposalResult> {
    const capabilities = await this.limits();
    if (capabilities.features?.fixes === false) throw new ReviewError('corrections_unavailable', 'This Phylax deployment does not produce corrections.');
    const wanted: ReviewFinding[] = [];
    for (const key of new Set(keys)) {
      const found = this.findings.get(key);
      if (!found) throw new ReviewError('unknown_finding', `There is no finding ${key} in this review. Scan first, and use the keys the scan returned.`);
      if (!found.finding.fix.eligible && !options.allowReportOnly) {
        throw new ReviewError('not_correctable', `Finding ${key} is reported only: ${found.finding.fix.reason}`);
      }
      wanted.push(found);
    }
    const byScan = new Map<string, ReviewFinding[]>();
    for (const item of wanted) byScan.set(item.scanId, [...(byScan.get(item.scanId) ?? []), item]);

    const result: ProposalResult = { proposals: [], notCorrected: [] };
    for (const [scanId, items] of byScan) {
      const batch = this.batches.get(scanId);
      if (!batch) throw new ReviewError('unknown_scan', `Scan ${scanId} is not part of this review.`);
      this.say(`Asking for ${items.length} correction(s)...`);
      const fix = await this.phylax.fix(scanId, { ...this.callOptions(), findingIds: items.map((i) => i.finding.id), ...(this.options.maxPatchLines ? { maxPatchLines: this.options.maxPatchLines } : {}) });
      const explained = new Set<string>();
      for (const unfixed of fix.unfixed ?? []) {
        const finding = items.find((i) => i.finding.id === unfixed.finding_id)?.finding;
        if (finding) {
          result.notCorrected.push({ findings: [finding], reason: unfixed.reason });
          explained.add(finding.id);
        }
      }
      if (!fix.applicable) {                                                              // an unverified correction is never offered for approval
        const rest = items.filter((i) => !explained.has(i.finding.id)).map((i) => i.finding);
        if (rest.length > 0) result.notCorrected.push({ findings: rest, reason: fix.failure_reason ?? 'The proposed correction did not pass Phylax\'s checks, so it is not offered.' });
        continue;
      }
      const covered = new Set<string>();
      for (const patch of fix.patches) {
        const addressed = patch.finding_ids.map((id) => items.find((i) => i.finding.id === id)?.finding).filter((f): f is Finding => f !== undefined);
        patch.finding_ids.forEach((id) => covered.add(id));
        result.proposals.push({
          key: `${scanId}:${patch.path}`,
          scanId,
          path: patch.path,
          diff: patch.unified_diff,
          explanation: patch.explanation,
          findings: addressed,
          verification: fix.verification,
          baseSha256: patch.base_sha256,
          correctedContent: patch.corrected_content,
          correctedSha256: patch.corrected_sha256,
        });
      }
      const missing = items.filter((i) => !covered.has(i.finding.id) && !explained.has(i.finding.id)).map((i) => i.finding);
      if (missing.length > 0) result.notCorrected.push({ findings: missing, reason: 'No correction was proposed for this finding.' });
    }
    return result;
  }

  // ------------------------------------------------------------------------------------ 3. approve and apply

  /** Show one correction to the person and, only on an explicit yes, apply it through the host. Never throws for an expected outcome: see `status`. */
  async applyProposal(proposal: ProposedCorrection, approver: Approver): Promise<ApplyOutcome> {
    const outcome = (status: ApplyStatus, message: string, changeId?: string): ApplyOutcome => ({
      key: proposal.key, scanId: proposal.scanId, path: proposal.path, status, message,
      findingIds: proposal.findings.map((f) => f.id), ...(changeId ? { changeId } : {}),
    });

    const maxChars = this.files.capabilities?.maxContentChars;
    if (maxChars !== undefined && proposal.correctedContent.length > maxChars) {
      return outcome('too_large', `The corrected ${proposal.path} is ${proposal.correctedContent.length} characters, more than the ${maxChars} this host can apply. ` +
        'It was not applied. You can apply the diff yourself.');
    }
    try {                                                    // do not ask a person to approve something that can no longer be applied
      const now = await this.files.read(proposal.path);
      if (now.sha256 !== proposal.baseSha256) return outcome('stale', `${proposal.path} changed after it was scanned, so the correction was not offered. Scan again.`);
    } catch (error) {
      if (error instanceof FileUnreadableError) return outcome('stale', `${proposal.path} can no longer be read as it was when it was scanned (${error.message}). Scan again.`);
      throw error;
    }

    const decision = await approver.approveChange({
      key: proposal.key, path: proposal.path, diff: proposal.diff, explanation: proposal.explanation, findings: proposal.findings, verification: proposal.verification,
    });
    if (decision.approved !== true) return outcome('rejected', decision.reason ? `Not applied: ${decision.reason}` : 'Not applied: you did not approve it.');

    let applied;
    try {
      applied = await this.files.apply({ path: proposal.path, expectedSha256: proposal.baseSha256, content: proposal.correctedContent });
    } catch (error) {
      if (error instanceof StaleFileError) return outcome('stale', error.message);
      if (error instanceof ChangeRefusedError) return outcome('refused', error.message);
      throw error;
    }
    if (applied.sha256 !== proposal.correctedSha256) {                                    // the host wrote something other than what was approved
      let undone = 'It could not be undone automatically; check the file.';
      if (applied.changeId && this.files.revert) {
        try {
          await this.files.revert(applied.changeId);
          undone = 'The change was undone.';
        } catch {
          /* the message above stays */
        }
      }
      return outcome('failed', `${proposal.path} does not contain exactly what was approved (the host changed it while writing). ${undone}`, applied.changeId);
    }
    return outcome('applied', `Applied the correction to ${proposal.path}.`, applied.changeId);
  }

  // --------------------------------------------------------------------------------------- 4. verify what is on disk

  /** For every file that was changed: read it back as it is NOW and have Phylax check it against the scan it came from. */
  async verify(outcomes: ApplyOutcome[]): Promise<VerificationResult[]> {
    const changed = new Map<string, string[]>();
    for (const o of outcomes) if (o.status === 'applied') changed.set(o.scanId, [...(changed.get(o.scanId) ?? []), o.path]);
    const results: VerificationResult[] = [];
    for (const [scanId, paths] of changed) {
      const batch = this.batches.get(scanId);
      if (!batch) throw new ReviewError('unknown_scan', `Scan ${scanId} is not part of this review.`);
      this.say(`Verifying ${paths.length} corrected file(s)...`);
      const onDisk: FileSnapshot[] = [];
      for (const path of paths) onDisk.push(await this.files.read(path));
      const verification: Verification = await this.phylax.verify(scanId, onDisk.map((s) => ({ path: s.path, content: s.content })), this.callOptions());
      const inScan = batch.report.findings;
      const resolvedIds = new Set(verification.resolved_finding_ids);
      results.push({
        scanId,
        paths,
        outcome: verification.outcome ?? 'inconclusive',
        resolved: inScan.filter((f) => resolvedIds.has(f.id)),
        remaining: inScan.filter((f) => f.path !== null && paths.includes(f.path) && !resolvedIds.has(f.id)),
        introduced: verification.new_findings,
        checks: verification.checks.map((c) => ({ name: c.name, result: c.result, detail: c.detail })),
      });
    }
    return results;
  }

  // ----------------------------------------------------------------------------------- the whole review, step by step

  /**
   * The full review with a person in the loop: scan, show what was found, ask which findings to correct, ask Phylax for those corrections only,
   * show each one and apply it only on a yes, then verify what is on disk. Scans are removed from the service afterwards.
   */
  async runInteractive(selection: FileSelection, approver: Approver): Promise<ReviewResult> {
    try {
      const summary = await this.scan(selection);
      const empty: ReviewResult = { summary, requested: [], proposals: null, outcomes: [], verification: [] };
      if (summary.correctable.length === 0 || !summary.correctionsAvailable) return empty;

      const chosen = await approver.chooseCorrections(summary.correctable.map((f) => ({ key: f.key, finding: f.finding })));
      const offered = new Set(summary.correctable.map((f) => f.key));
      const requested = [...new Set(chosen)].filter((key) => offered.has(key));            // only what was offered and what the person picked
      if (requested.length === 0) return empty;

      const proposals = await this.proposeCorrections(requested);
      const outcomes: ApplyOutcome[] = [];
      for (const proposal of proposals.proposals) outcomes.push(await this.applyProposal(proposal, approver));
      const verification = await this.verify(outcomes);
      return { summary, requested, proposals, outcomes, verification };
    } finally {
      await this.close();
    }
  }

  /** Remove this review's scans (and the code Phylax holds for them) from the service. Best effort. */
  async close(): Promise<void> {
    for (const scanId of [...this.batches.keys()]) {
      try {
        await this.phylax.deleteScan(scanId, this.callOptions());
      } catch {
        /* the service removes scans on its own after its retention period */
      }
    }
  }
}

function compareRisk(a: string, b: string): number {
  const order = ['none', 'info', 'low', 'medium', 'high', 'critical'];
  return order.indexOf(a) - order.indexOf(b);
}
