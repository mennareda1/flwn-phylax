const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;
// The verdict belongs to the last scan, and the sentence says so: a correction applied since then is only confirmed by scanning again.
const DECISION = {
  block: 'The last scan blocked this review.',
  review_required: 'The last scan found things that need a person.',
  pass: 'The last scan passed.',
  scan_failed: 'A check could not run on the last scan, so it is not reliable.',
};

/** The one-line summary in the gold banner, worked out from where the review is. Plain, short, sentence case. */
export function sumUp({ phase, error, scan, findings, proposals, scannedSinceApply }) {
  if (phase === 'scanning' || phase === 'proposing') return '';   // the thinking indicator speaks while Phylax works
  if (error) return 'Something stopped the review. Nothing was changed.';
  if (!scan) return 'Ready when you are. Scan the sample project.';
  const open = findings.filter((f) => f.status === 'found');
  const correctable = open.filter((f) => f.fix.eligible).length;
  const reportOnly = open.length - correctable;
  const fixed = proposals.filter((p) => p.state === 'applied').length;
  const waiting = proposals.filter((p) => p.state !== 'applied').length;
  // "Nothing found" is only ever said when the scan PASSED. A scan whose check could not run also finds nothing, and must not sound reassuring.
  if (findings.length === 0 && fixed === 0 && scan.decision === 'pass') return `Nothing found in ${plural(scan.coverage.files_scanned.length, 'file', 'files')}.`;
  const parts = [DECISION[scan.decision] ?? DECISION.review_required];
  if (waiting > 0) parts.push(`${plural(waiting, 'correction is', 'corrections are')} waiting for your decision.`);
  if (correctable > 0) parts.push(`${plural(correctable, 'correction can', 'corrections can')} be requested.`);
  if (fixed > 0) parts.push(scannedSinceApply ? `${plural(fixed, 'correction', 'corrections')} applied and confirmed by that scan.` : `${plural(fixed, 'correction', 'corrections')} applied. Scan again to confirm.`);
  if (reportOnly > 0) parts.push(`${plural(reportOnly, 'finding is', 'findings are')} reported only.`);
  return parts.join(' ');
}
