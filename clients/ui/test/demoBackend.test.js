import { describe, expect, it } from 'vitest';

import { createDemoBackend } from '../src/api/demoBackend.js';

const fresh = () => createDemoBackend({ latency: 0 });
const keysOf = (scan, ...paths) => scan.findings.filter((f) => paths.includes(f.path)).map((f) => f.key);

describe('the demo backend replays what the real Phylax said', () => {
  it('describes the project, honestly', async () => {
    const info = await fresh().info();
    expect(info).toMatchObject({ mode: 'demo', projectName: 'sample-app', corrections: true });
    expect(info.files).toEqual(['config/mail.yaml', 'src/config.js', 'src/db.ts', 'src/ok.js', 'src/run.js', 'src/token.js']);
    expect(info.recordedWith).toMatch(/real scanner and verifier/);
  });

  it('the first scan blocks, finds five things, and says for each whether a correction is offered and why', async () => {
    const scan = await fresh().scan();
    expect(scan.decision).toBe('block');
    expect(scan.reasons[0]).toMatch(/command_injection/);
    expect(scan.findings).toHaveLength(5);
    const by = Object.fromEntries(scan.findings.map((f) => [f.path, f]));
    expect(by['src/run.js'].fix.eligible).toBe(true);
    expect(by['src/db.ts'].fix.eligible).toBe(true);
    expect(by['src/token.js'].fix).toMatchObject({ eligible: false, reason: expect.stringMatching(/reported, not corrected/) });
    expect(by['src/config.js'].fix).toMatchObject({ eligible: false, reason: expect.stringMatching(/hardcoded secret is not fixed automatically/i) });
    expect(by['src/config.js'].evidence).not.toMatch(/AKIA/);   // the secret itself is never shown
    expect(scan.findings.every((f) => f.key.startsWith(`${scan.scanId}:`))).toBe(true);
    expect(scan.coverage.files_scanned).toHaveLength(6);
    expect(scan.coverage.limited_scope).toEqual([{ path: 'config/mail.yaml', language: 'yaml', checked_for: 'hardcoded secrets only' }]);   // the configuration file says what it was checked for
    expect(by['config/mail.yaml']).toMatchObject({ rule_id: 'SECRET-CONFIG', fix: { eligible: false } });
    expect(by['config/mail.yaml'].evidence).not.toMatch(/Sm7p/);                                                                        // an unquoted secret is masked too
  });

  it('a correction is prepared only for the findings that were chosen, and only for files that are not corrected yet', async () => {
    const backend = fresh();
    const scan = await backend.scan();
    const one = await backend.propose(keysOf(scan, 'src/run.js'));
    expect(one.proposals).toHaveLength(1);
    expect(one.proposals[0]).toMatchObject({ path: 'src/run.js', explanation: expect.stringMatching(/execFile/), checkedTogether: ['src/run.js'] });
    expect(one.proposals[0].diff).toMatch(/\+\s+execFile\("ls", \[dir\]\);/);
    expect(one.proposals[0].checks.map((c) => c.name)).toEqual(['scope', 'syntax', 'patch_size', 'rescan']);
    expect(one.proposals[0].checks.every((c) => c.result === 'pass')).toBe(true);
    expect(one.proposals[0].checks[0].detail).toMatch(/^1 file/);

    const both = await backend.propose(keysOf(scan, 'src/run.js', 'src/db.ts'));
    expect(both.proposals.map((p) => p.path).sort()).toEqual(['src/db.ts', 'src/run.js']);
    expect(both.proposals[0].checkedTogether).toHaveLength(2);
    expect(both.proposals[0].checks[0].detail).toMatch(/^2 file/);
  });

  it('a finding that cannot be corrected is never turned into a correction, and the reason comes back', async () => {
    const backend = fresh();
    const scan = await backend.scan();
    const result = await backend.propose(keysOf(scan, 'src/config.js', 'src/token.js'));
    expect(result.proposals).toEqual([]);
    expect(result.notCorrected).toHaveLength(2);
    expect(result.notCorrected.map((n) => n.reason).join(' ')).toMatch(/hardcoded secret/);
    await expect(backend.propose(['scn_nope:f9'])).rejects.toThrow(/Scan again/);
  });

  it('applying verifies the files applied so far, refuses a second apply, and the next scan shows the difference', async () => {
    const backend = fresh();
    const scan = await backend.scan();
    const { proposals } = await backend.propose(keysOf(scan, 'src/run.js', 'src/db.ts'));
    const run = proposals.find((p) => p.path === 'src/run.js');
    const db = proposals.find((p) => p.path === 'src/db.ts');

    const first = await backend.apply(run.id);
    expect(first.status).toBe('applied');
    expect(first.verification).toMatchObject({ outcome: 'passed', resolved: [{ path: 'src/run.js', type: 'command_injection' }], introduced: [] });
    expect(await backend.apply(run.id)).toMatchObject({ status: 'stale' });

    const afterOne = await backend.scan();
    expect(afterOne.findings.map((f) => f.path)).not.toContain('src/run.js');
    expect(afterOne.decision).toBe('review_required');

    const second = await backend.apply(db.id);
    expect(second.verification.resolved.map((r) => r.path).sort()).toEqual(['src/db.ts', 'src/run.js']);
    const afterBoth = await backend.scan();
    expect(afterBoth.findings.map((f) => f.vulnerability_type).sort()).toEqual(['hardcoded_credentials', 'hardcoded_credentials', 'insecure_random']);
    expect((await backend.propose(afterBoth.findings.map((f) => f.key))).proposals).toEqual([]);
  });

  it('a correction for a file that is already corrected is not offered again', async () => {
    const backend = fresh();
    const scan = await backend.scan();
    const { proposals } = await backend.propose(keysOf(scan, 'src/run.js'));
    await backend.apply(proposals[0].id);
    expect((await backend.propose(keysOf(scan, 'src/run.js'))).proposals).toEqual([]);
  });

  it('starting over restores the sample project', async () => {
    const backend = fresh();
    const scan = await backend.scan();
    const { proposals } = await backend.propose(keysOf(scan, 'src/run.js'));
    await backend.apply(proposals[0].id);
    await backend.reset();
    expect((await backend.scan()).findings).toHaveLength(5);
    expect(await backend.apply(proposals[0].id)).toMatchObject({ status: 'stale' });
  });

  it('the error switch fails exactly one call, the way an unreachable service does', async () => {
    const backend = fresh();
    backend.failNext();
    await expect(backend.scan()).rejects.toMatchObject({ code: 'unreachable', message: expect.stringMatching(/Could not reach Phylax/) });
    expect((await backend.scan()).findings).toHaveLength(5);
  });

  it('keeps the pace of a real service unless told otherwise', async () => {
    const backend = createDemoBackend({ latency: 0.01 });
    const started = Date.now();
    await backend.scan();
    expect(Date.now() - started).toBeGreaterThanOrEqual(10);   // 1500ms scaled by 0.01
  });
});
