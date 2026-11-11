import { describe, expect, it } from 'vitest';

import { sumUp } from '../src/lib/sumUp.js';

const finding = (extra = {}) => ({ status: 'found', fix: { eligible: true }, ...extra });
const scan = (decision = 'block', files = 5) => ({ decision, coverage: { files_scanned: new Array(files).fill('f') } });
const base = { phase: 'ready', error: null, scan: scan(), findings: [], proposals: [], scannedSinceApply: false };

describe('the sentence in the gold banner', () => {
  it('is plain before anything happens, and silent while Phylax works (the thinking indicator speaks)', () => {
    expect(sumUp({ ...base, scan: null })).toBe('Ready when you are. Scan the sample project.');
    expect(sumUp({ ...base, phase: 'scanning' })).toBe('');
    expect(sumUp({ ...base, phase: 'proposing' })).toBe('');
  });

  it('says what happened when something failed, and that nothing was changed', () => {
    expect(sumUp({ ...base, error: 'x' })).toBe('Something stopped the review. Nothing was changed.');
  });

  it('gives the verdict as the LAST scan\'s, then what can be done, with correct plurals', () => {
    const findings = [finding(), finding(), finding({ fix: { eligible: false } })];
    expect(sumUp({ ...base, findings })).toBe('The last scan blocked this review. 2 corrections can be requested. 1 finding is reported only.');
    expect(sumUp({ ...base, findings: [finding()], scan: scan('review_required') })).toBe('The last scan found things that need a person. 1 correction can be requested.');
  });

  it('counts the corrections waiting for a decision, and says a correction applied since the scan is not yet confirmed', () => {
    const proposals = [{ state: 'ready' }, { state: 'applied' }];
    expect(sumUp({ ...base, proposals })).toBe('The last scan blocked this review. 1 correction is waiting for your decision. 1 correction applied. Scan again to confirm.');
  });

  it('says a scan after the corrections confirmed them', () => {
    const text = sumUp({ ...base, scan: scan('review_required'), proposals: [{ state: 'applied' }, { state: 'applied' }], scannedSinceApply: true, findings: [finding({ fix: { eligible: false } }), finding({ fix: { eligible: false } })] });
    expect(text).toBe('The last scan found things that need a person. 2 corrections applied and confirmed by that scan. 2 findings are reported only.');
  });

  it('says so when nothing was found, and when a check could not run', () => {
    expect(sumUp({ ...base, scan: scan('pass', 3) })).toBe('Nothing found in 3 files.');
    expect(sumUp({ ...base, scan: scan('scan_failed'), findings: [] })).toMatch(/could not run on the last scan, so it is not reliable/);
  });
});
