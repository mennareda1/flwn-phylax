import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import recorded from '../src/api/demo/recorded.json';
import { SAMPLE_PROJECT } from '../scripts/sample-project.mjs';

const sha = (text) => createHash('sha256').update(text, 'utf8').digest('hex');

// The recording is real data. These tests keep it that way: it must be internally consistent, and it must match the sample project it was recorded from.
describe('the recording behind the demo', () => {
  it('was recorded from exactly the sample project in the repository', () => {
    expect(recorded.project).toEqual(SAMPLE_PROJECT);
    expect(recorded.recorded_with).toMatch(/real scanner and verifier/);
  });

  it('holds a scan for every state the demo can reach, each with a verdict and a reason for each finding', () => {
    expect(Object.keys(recorded.scans).sort()).toEqual(['none', 'src/db.ts', 'src/db.ts+src/run.js', 'src/run.js']);
    for (const scan of Object.values(recorded.scans)) {
      expect(['block', 'review_required', 'pass']).toContain(scan.report.decision);
      for (const finding of scan.report.findings) {
        expect(finding.fix.reason.length).toBeGreaterThan(10);
        expect(typeof finding.fix.eligible).toBe('boolean');
      }
    }
    expect(recorded.scans.none.report.findings).toHaveLength(5);
    expect(recorded.scans['src/db.ts+src/run.js'].report.findings).toHaveLength(3);
  });

  it('has corrections whose hashes are the real hashes of the files', () => {
    for (const [combo, fix] of Object.entries(recorded.fixes)) {
      expect(fix.applicable, combo).toBe(true);
      expect(fix.patches.map((p) => p.path).sort().join('+')).toBe(combo);
      for (const patch of fix.patches) {
        expect(sha(recorded.project.files[patch.path])).toBe(patch.base_sha256);
        expect(sha(patch.corrected_content)).toBe(patch.corrected_sha256);
        expect(patch.unified_diff).toContain(`--- a/${patch.path}`);
      }
      expect(fix.verification.checks.map((c) => c.result)).toEqual(['pass', 'pass', 'pass', 'pass']);
    }
  });

  it('has a verification for each way corrections can be applied, and every one passed with nothing new', () => {
    expect(Object.keys(recorded.verifications).sort()).toEqual(['src/db.ts', 'src/db.ts+src/run.js', 'src/run.js']);
    for (const verification of Object.values(recorded.verifications)) {
      expect(verification.outcome).toBe('passed');
      expect(verification.new_findings).toEqual([]);
    }
  });
});
