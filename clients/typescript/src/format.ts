/**
 * src/format.ts
 *
 * Plain-text renderings of the review's results, for hosts that just want something readable to show (a terminal, a chat message). ASCII only,
 * no colour codes, no code from the user's files except the single evidence line Phylax itself reports.
 */

import type { ChangeProposal } from './interfaces.js';
import type { ApplyOutcome, ScanSummary, VerificationResult } from './review.js';
import type { Finding } from './types.js';

const clip = (text: string, length: number): string => (text.length > length ? `${text.slice(0, length - 3)}...` : text);

function where(finding: Finding): string {
  return finding.path ? (finding.line ? `${finding.path}:${finding.line}` : finding.path) : '(whole review)';
}

function oneFinding(finding: Finding): string {
  return `${finding.severity.toUpperCase()} ${finding.vulnerability_type} at ${where(finding)}: ${clip(finding.description, 160)}`;
}

export function formatSummary(summary: ScanSummary): string {
  const lines: string[] = [];
  lines.push(`Decision: ${summary.decision}   risk level: ${summary.riskLevel}`);
  for (const reason of summary.reasons) lines.push(`  - ${clip(reason, 200)}`);
  lines.push(`Scanned ${summary.scannedFiles.length} file(s).`);
  if (summary.findings.length === 0) lines.push('Findings: none.');
  if (summary.correctable.length > 0) {
    lines.push('', `A correction can be offered for ${summary.correctable.length} finding(s):`);
    summary.correctable.forEach((f, i) => lines.push(`  ${i + 1}. ${oneFinding(f.finding)}`));
  }
  if (summary.reportOnly.length > 0) {
    lines.push('', `Reported only (${summary.reportOnly.length}), no correction offered:`);
    for (const f of summary.reportOnly) lines.push(`  - ${oneFinding(f.finding)}`, `      ${clip(f.finding.fix.reason, 160)}`);
  }
  if (summary.unscanned.length > 0) {
    lines.push('', 'Not scanned:');
    for (const u of summary.unscanned) lines.push(`  - ${u.path} (${clip(u.reason, 120)})${u.blocksPass ? ', so a pass cannot be claimed' : ''}`);
  }
  if (summary.engineProblems.length > 0) lines.push('', 'Checks that did not run:', ...summary.engineProblems.map((p) => `  - ${clip(p, 200)}`));
  if (summary.notAssessable.length > 0) lines.push('', 'Not assessable by any scan of submitted files:', ...summary.notAssessable.map((n) => `  - ${clip(n, 200)}`));
  if (!summary.correctionsAvailable && summary.correctable.length > 0) lines.push('', 'This Phylax deployment does not produce corrections, so they cannot be offered.');
  return lines.join('\n');
}

export function formatProposal(proposal: ChangeProposal): string {
  const lines = [`Proposed correction for ${proposal.path}`, `  Fixes: ${proposal.findings.map((f) => `${f.vulnerability_type} (${f.severity})`).join(', ') || 'see diff'}`, `  Why: ${clip(proposal.explanation, 300)}`];
  if (proposal.verification) {
    lines.push('  Phylax checked it before showing it:');
    for (const check of proposal.verification.checks) lines.push(`    - ${check.name}: ${check.result}. ${clip(check.detail, 200)}`);
  }
  lines.push('', proposal.diff.trimEnd());
  return lines.join('\n');
}

export function formatOutcomes(outcomes: ApplyOutcome[]): string {
  if (outcomes.length === 0) return 'No corrections were applied.';
  return outcomes.map((o) => `  ${o.status === 'applied' ? '[applied]' : `[${o.status}]`} ${o.message}`).join('\n');
}

export function formatVerification(results: VerificationResult[]): string {
  if (results.length === 0) return 'Nothing to verify.';
  const lines: string[] = [];
  for (const r of results) {
    lines.push(`Verification of ${r.paths.join(', ')}: ${r.outcome}`);
    for (const c of r.checks) lines.push(`    - ${c.name}: ${c.result}. ${clip(c.detail, 200)}`);
    if (r.resolved.length > 0) lines.push(`    Resolved: ${r.resolved.map((f) => `${f.vulnerability_type} at ${where(f)}`).join('; ')}`);
    if (r.remaining.length > 0) lines.push(`    Still present: ${r.remaining.map((f) => `${f.vulnerability_type} at ${where(f)}`).join('; ')}`);
    if (r.introduced.length > 0) lines.push(`    New: ${r.introduced.map((f) => `${f.vulnerability_type} at ${where(f)}`).join('; ')}`);
  }
  return lines.join('\n');
}
