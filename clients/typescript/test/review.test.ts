import assert from 'node:assert/strict';
import { test } from 'node:test';

import { sha256Text } from '../src/adapters/disk.js';
import { FileUnreadableError, ReviewError, StaleFileError, ChangeRefusedError } from '../src/errors.js';
import { formatOutcomes, formatProposal, formatSummary, formatVerification } from '../src/format.js';
import type { FileSnapshot } from '../src/interfaces.js';
import { SecurityReview, type ProposedCorrection } from '../src/review.js';
import type { Decision, Finding, Patch, Scan, Severity } from '../src/types.js';
import { CAPABILITIES, FakePhylax, MemoryHost, ScriptedPerson, finding, okFix, patchFor, reportFor } from './helpers.js';

const RUN = 'const { exec } = require("child_process");\nexec(`ls ${dir}`);\n';
const RUN_FIXED = 'const { execFile } = require("child_process");\nexecFile("ls", [dir]);\n';
const DB = 'export const find = (id) => pool.query(`SELECT * FROM t WHERE id = ${id}`);\n';
const DB_FIXED = 'export const find = (id) => pool.query("SELECT * FROM t WHERE id = $1", [id]);\n';
const OK = 'function makeResetToken() {\n  return Math.random().toString(36);\n}\n';
const FIXED_OF: Record<string, [string, string]> = { 'run.js': [RUN, RUN_FIXED], 'db.ts': [DB, DB_FIXED] };
const SEVERITY_OF: Record<string, Severity> = { 'run.js': 'high', 'db.ts': 'medium', 'ok.js': 'low' };
const ID_OF: Record<string, string> = { 'run.js': 'f1', 'db.ts': 'f2', 'ok.js': 'f3' };       // fixed ids, whatever order the files are listed in

function setup(options: { decision?: Decision; files?: Record<string, string> } = {}) {
  const host = new MemoryHost(options.files ?? { 'run.js': RUN, 'db.ts': DB, 'ok.js': OK });
  const phylax = new FakePhylax();
  phylax.onScan = (files, n): Scan => {
    const found: Finding[] = [];
    for (const file of files) {
      const severity = SEVERITY_OF[file.path];
      if (severity) found.push(finding(ID_OF[file.path] as string, file.path, severity));
    }
    return { id: `scn_${n}`, status: 'completed', report: reportFor(files, found, options.decision ?? 'review_required') };
  };
  phylax.onFix = (scanId, ids) => {
    const scan = phylax.scansSeen.get(scanId) as Finding[];
    const wanted = scan.filter((f) => (ids ?? scan.filter((x) => x.fix.eligible).map((x) => x.id)).includes(f.id));
    const patches: Patch[] = wanted.flatMap((f) => { const pair = FIXED_OF[f.path as string]; return pair ? [patchFor(pair[0], pair[1], f.path as string, [f.id])] : []; });
    return okFix(scanId, patches);
  };
  const scanOnce = phylax.onScan;
  phylax.onScan = (files, n) => { const scan = scanOnce(files, n); phylax.scansSeen.set(scan.id, scan.report?.findings ?? []); return scan; };
  return { host, phylax, review: new SecurityReview({ phylax, files: host }) };
}

// ----------------------------------------------------------------------------------- eligibility is not the verdict

test('which findings can be corrected comes from each finding, never from the verdict', async () => {
  for (const decision of ['pass', 'review_required', 'block', 'scan_failed'] as Decision[]) {
    const { review } = setup({ decision });
    const summary = await review.scan({ kind: 'project' });
    assert.equal(summary.decision, decision);
    assert.deepEqual(summary.correctable.map((f) => f.finding.path), ['run.js', 'db.ts'], `decision ${decision}: the high and the medium finding are offered a correction`);
    assert.deepEqual(summary.reportOnly.map((f) => f.finding.path), ['ok.js'], `decision ${decision}: the low finding is reported only`);
    assert.match(summary.reportOnly[0]?.finding.fix.reason ?? '', /not corrected by default/);
  }
});

test('a medium finding is correctable even though the verdict is only review_required, and a block does not make a low finding correctable', async () => {
  const onlyMedium = setup({ files: { 'db.ts': DB } });
  const a = await onlyMedium.review.scan({ kind: 'project' });
  assert.equal(a.decision, 'review_required');
  assert.equal(a.correctable.length, 1);

  const blockWithLow = setup({ decision: 'block', files: { 'ok.js': OK } });
  const b = await blockWithLow.review.scan({ kind: 'project' });
  assert.equal(b.decision, 'block');
  assert.equal(b.correctable.length, 0, 'the verdict is block but the only finding is low: no correction is offered');
  assert.equal(b.reportOnly.length, 1);
});

test('a hardcoded secret is reported with the reason it is not corrected, and is never offered', async () => {
  const phylax = new FakePhylax();
  const secret: Finding = { ...finding('f1', 'cfg.js', 'high', 'hardcoded_credentials'), fix: { eligible: false, reason: 'A hardcoded secret is not fixed automatically: remove it from the code, move it to configuration, and rotate it.' } };
  phylax.onScan = (files) => ({ id: 'scn_1', status: 'completed', report: reportFor(files, [secret], 'review_required') });
  const review = new SecurityReview({ phylax, files: new MemoryHost({ 'cfg.js': 'const k = "AKIAABCDEFGHIJKLMNOP";\n' }) });
  const summary = await review.scan({ kind: 'project' });
  assert.equal(summary.correctable.length, 0);
  assert.match(formatSummary(summary), /rotate it/);
  const person = new ScriptedPerson(() => { throw new Error('the person must not be asked when nothing is correctable'); });
  const result = await review.runInteractive({ kind: 'project' }, person);
  assert.equal(result.proposals, null);
  assert.equal(person.asked.length, 0);
});

// ------------------------------------------------------------------------------------------------ scanning

test('large projects are scanned in batches within the service limits, and the worst decision wins', async () => {
  const files: Record<string, string> = {};
  for (let i = 0; i < 5; i += 1) files[`f${i}.js`] = `const a${i} = ${i};\n`;
  files['run.js'] = RUN;
  const host = new MemoryHost(files);
  const phylax = new FakePhylax();
  phylax.capabilitiesValue = { ...CAPABILITIES, limits: { ...CAPABILITIES.limits, max_files: 2 } };
  phylax.onScan = (sent, n) => ({ id: `scn_${n}`, status: 'completed', report: reportFor(sent, sent.some((f) => f.path === 'run.js') ? [finding('f1', 'run.js', 'high')] : [], sent.some((f) => f.path === 'run.js') ? 'block' : 'pass') });
  const summary = await new SecurityReview({ phylax, files: host }).scan({ kind: 'project' });
  assert.equal(phylax.count('scan'), 3, 'six files at two per request');
  assert.ok(phylax.calls.filter((c) => c.method === 'scan').every((c) => (c.args[0] as unknown[]).length <= 2));
  assert.equal(summary.decision, 'block', 'one block among passes is a block');
  assert.equal(summary.scannedFiles.length, 6);
  assert.equal(summary.scanIds.length, 3);
  assert.equal(new Set(summary.findings.map((f) => f.key)).size, summary.findings.length, 'finding keys are unique across scans');

  const byBytes = new FakePhylax();
  byBytes.capabilitiesValue = { ...CAPABILITIES, limits: { ...CAPABILITIES.limits, max_total_bytes: 60 } };
  await new SecurityReview({ phylax: byBytes, files: new MemoryHost({ 'a.js': 'x'.repeat(40) + '\n', 'b.js': 'y'.repeat(40) + '\n', 'c.js': 'z\n' }) }).scan({ kind: 'project' });
  assert.equal(byBytes.count('scan'), 2, 'batches also respect the total size limit');
});

test('files that cannot be scanned are listed and stop a clean pass', async () => {
  const host = new MemoryHost({ 'ok.js': 'const a = 1;\n', 'huge.js': 'x'.repeat(300), 'binary.js': 'y' });
  const realRead = host.read.bind(host);
  host.read = async (path: string): Promise<FileSnapshot> => { if (path === 'binary.js') throw new FileUnreadableError('binary.js is not valid UTF-8 text.'); return realRead(path); };
  const phylax = new FakePhylax();
  phylax.capabilitiesValue = { ...CAPABILITIES, limits: { ...CAPABILITIES.limits, max_file_bytes: 200 } };
  phylax.onScan = (files, n) => ({ id: `scn_${n}`, status: 'completed', report: reportFor(files, [], 'pass') });
  const summary = await new SecurityReview({ phylax, files: host }).scan({ kind: 'project' });
  assert.deepEqual(summary.unscanned.map((u) => u.path).sort(), ['binary.js', 'huge.js']);
  assert.equal(summary.unscanned.every((u) => u.blocksPass), true);
  assert.equal(summary.decision, 'review_required', 'a pass cannot be claimed while files were not scanned');
  assert.match(summary.reasons.join(' '), /2 file\(s\) could not be scanned/);
  assert.deepEqual((phylax.calls.find((c) => c.method === 'scan')?.args[0] as { path: string }[]).map((f) => f.path), ['ok.js'], 'the oversized file was never sent');
  await assert.rejects(new SecurityReview({ phylax, files: new MemoryHost({}) }).scan({ kind: 'project' }), (e: unknown) => e instanceof ReviewError && e.code === 'nothing_to_scan');
});

test('if the host and Phylax disagree on a file\'s hash the review stops before anything could go wrong', async () => {
  const { host, phylax, review } = setup();
  const wrongHash = host.read.bind(host);
  host.read = async (path) => ({ ...(await wrongHash(path)), sha256: sha256Text('something else') });
  await assert.rejects(review.scan({ kind: 'project' }), (e: unknown) => e instanceof ReviewError && e.code === 'hash_mismatch' && /SHA-256/.test(e.message));
  assert.equal(phylax.count('fix'), 0);
});

// ------------------------------------------------------------------------------------ asking for corrections

test('corrections are requested only for the findings that were chosen, once each', async () => {
  const { phylax, review } = setup();
  const summary = await review.scan({ kind: 'project' });
  const high = summary.correctable.find((f) => f.finding.path === 'run.js')?.key as string;
  const result = await review.proposeCorrections([high, high]);
  assert.equal(phylax.count('fix'), 1);
  assert.deepEqual(phylax.calls.find((c) => c.method === 'fix')?.args, ['scn_1', ['f1']], 'only the chosen finding, once');
  assert.equal(result.proposals.length, 1);
  assert.equal(result.proposals[0]?.path, 'run.js');
  assert.equal(result.proposals[0]?.baseSha256, sha256Text(RUN));
  assert.equal(result.proposals[0]?.correctedContent, RUN_FIXED);
});

test('a report-only or unknown finding cannot be requested by accident', async () => {
  const { phylax, review } = setup();
  const summary = await review.scan({ kind: 'project' });
  const low = summary.reportOnly[0]?.key as string;
  await assert.rejects(review.proposeCorrections([low]), (e: unknown) => e instanceof ReviewError && e.code === 'not_correctable' && /reported only/.test(e.message));
  await assert.rejects(review.proposeCorrections(['scn_1:f99']), (e: unknown) => e instanceof ReviewError && e.code === 'unknown_finding');
  await assert.rejects(review.proposeCorrections(['not a key']), (e: unknown) => e instanceof ReviewError && e.code === 'unknown_finding');
  assert.equal(phylax.count('fix'), 0, 'nothing was requested');
  await review.proposeCorrections([low], { allowReportOnly: true });                  // a deliberate override
  assert.equal(phylax.count('fix'), 1);
});

test('when corrections are not available the review says so instead of trying', async () => {
  const { phylax, review } = setup();
  phylax.capabilitiesValue = { ...CAPABILITIES, features: { fixes: false, verifications: true } };
  const summary = await review.scan({ kind: 'project' });
  assert.equal(summary.correctionsAvailable, false);
  await assert.rejects(review.proposeCorrections([summary.correctable[0]?.key as string]), (e: unknown) => e instanceof ReviewError && e.code === 'corrections_unavailable');
  const person = new ScriptedPerson(() => { throw new Error('not asked'); });
  const result = await review.runInteractive({ kind: 'project' }, person);
  assert.equal(person.asked.length, 0);
  assert.equal(result.proposals, null);
  assert.equal(phylax.count('fix'), 0);
  assert.match(formatSummary(summary), /does not produce corrections/);
});

test('a correction that did not pass Phylax\'s checks is never offered, and unfixed findings come back with their reasons', async () => {
  const { phylax, review } = setup();
  const summary = await review.scan({ kind: 'project' });
  const keys = summary.correctable.map((f) => f.key);
  phylax.onFix = (scanId) => ({ ...okFix(scanId, [patchFor(RUN, RUN_FIXED, 'run.js', ['f1'])]), applicable: false, failure_reason: 'The corrected file still has the problem.' });
  const failed = await review.proposeCorrections(keys);
  assert.deepEqual(failed.proposals, [], 'unverified corrections are not proposals');
  assert.equal(failed.notCorrected.length, 1);
  assert.equal(failed.notCorrected[0]?.reason, 'The corrected file still has the problem.');
  assert.equal(failed.notCorrected[0]?.findings.length, 2);

  phylax.onFix = (scanId) => okFix(scanId, [patchFor(RUN, RUN_FIXED, 'run.js', ['f1'])], [{ finding_id: 'f2', reason: 'Not attempted: too many.' }]);
  const partial = await review.proposeCorrections(keys);
  assert.equal(partial.proposals.length, 1);
  assert.deepEqual(partial.notCorrected.map((n) => [n.findings[0]?.id, n.reason]), [['f2', 'Not attempted: too many.']]);

  phylax.onFix = (scanId) => okFix(scanId, []);
  const nothing = await review.proposeCorrections(keys);
  assert.equal(nothing.notCorrected[0]?.reason, 'No correction was proposed for this finding.');
});

// ------------------------------------------------------------------------------------ approving and applying

async function oneProposal(): Promise<{ host: MemoryHost; phylax: FakePhylax; review: SecurityReview; proposal: ProposedCorrection }> {
  const s = setup();
  const summary = await s.review.scan({ kind: 'project' });
  const proposals = await s.review.proposeCorrections([summary.correctable.find((f) => f.finding.path === 'run.js')?.key as string]);
  return { ...s, proposal: proposals.proposals[0] as ProposedCorrection };
}

test('a correction is applied only after an explicit yes, exactly as Phylax produced it', async () => {
  const { host, review, proposal } = await oneProposal();
  const person = new ScriptedPerson([], true);
  const outcome = await review.applyProposal(proposal, person);
  assert.equal(outcome.status, 'applied');
  assert.deepEqual(host.applied, [{ path: 'run.js', expectedSha256: sha256Text(RUN), content: RUN_FIXED }], 'the hash the file had when scanned is what the host is told to expect');
  assert.equal(host.files.get('run.js'), RUN_FIXED);
  assert.equal(person.shown.length, 1);
  assert.equal(person.shown[0]?.diff, proposal.diff, 'the person is shown the diff that will be applied');
  assert.equal(outcome.changeId, 'chg_1');
});

test('anything other than an explicit yes writes nothing', async () => {
  for (const answer of [false, () => ({ approved: false, reason: 'looks wrong' }), () => ({ approved: 'yes' as unknown as boolean }), () => ({ approved: 1 as unknown as boolean }), () => ({} as unknown as { approved: boolean }), () => ({ approved: undefined as unknown as boolean })]) {
    const { host, review, proposal } = await oneProposal();
    const outcome = await review.applyProposal(proposal, new ScriptedPerson([], answer as boolean));
    assert.equal(outcome.status, 'rejected');
    assert.equal(host.applied.length, 0);
    assert.equal(host.files.get('run.js'), RUN, 'the file is untouched');
  }
  const { host, review, proposal } = await oneProposal();
  const rejected = await review.applyProposal(proposal, new ScriptedPerson([], () => ({ approved: false, reason: 'looks wrong' })));
  assert.match(rejected.message, /looks wrong/);
  await assert.rejects(review.applyProposal(proposal, undefined as never), TypeError);                      // there is no way to apply without a person
  assert.equal(host.applied.length, 0);
});

test('a file edited WHILE the person reads the diff is not overwritten: the host is told which hash to expect', async () => {
  const { host, review, proposal } = await oneProposal();
  const person = new ScriptedPerson([], () => {
    host.files.set('run.js', RUN + '// edited while you were deciding\n');                                 // the file changes after the pre-check, before the write
    return { approved: true };
  });
  const outcome = await review.applyProposal(proposal, person);
  assert.equal(outcome.status, 'stale', 'the host refused because the file is no longer the one that was scanned');
  assert.equal(host.files.get('run.js'), RUN + '// edited while you were deciding\n', 'the edit made during the decision survives');
  assert.equal(host.applied.length, 0);
});

test('a correction for a file that changed since the scan is not even offered', async () => {
  const { host, review, proposal } = await oneProposal();
  host.files.set('run.js', RUN + '// edited by a person after the scan\n');
  const person = new ScriptedPerson([], true);
  const outcome = await review.applyProposal(proposal, person);
  assert.equal(outcome.status, 'stale');
  assert.match(outcome.message, /Scan again/);
  assert.equal(person.shown.length, 0, 'the person is not asked to approve something that can no longer be applied');
  assert.equal(host.applied.length, 0);
  host.files.delete('run.js');                                                                              // a file that disappeared is stale too
  assert.equal((await review.applyProposal(proposal, person)).status, 'stale');
});

test('a correction the host cannot hold is shown as too large and never offered for approval', async () => {
  const s = setup();
  const limited = new MemoryHost({ 'run.js': RUN }, { maxContentChars: 30 });
  const review = new SecurityReview({ phylax: s.phylax, files: limited });
  const summary = await review.scan({ kind: 'project' });
  const proposals = await review.proposeCorrections([summary.correctable[0]?.key as string]);
  const person = new ScriptedPerson([], true);
  const outcome = await review.applyProposal(proposals.proposals[0] as ProposedCorrection, person);
  assert.equal(outcome.status, 'too_large');
  assert.match(outcome.message, /apply the diff yourself/);
  assert.equal(person.shown.length, 0);
  assert.equal(limited.applied.length, 0);
});

test('a race at the last moment, a refusal, or a host that writes something different are all reported, and nothing is claimed that did not happen', async () => {
  const stale = await oneProposal();
  stale.host.failWith = new StaleFileError();
  assert.equal((await stale.review.applyProposal(stale.proposal, new ScriptedPerson([], true))).status, 'stale');

  const refused = await oneProposal();
  refused.host.failWith = new ChangeRefusedError('That path is protected.');
  const refusal = await refused.review.applyProposal(refused.proposal, new ScriptedPerson([], true));
  assert.equal(refusal.status, 'refused');
  assert.match(refusal.message, /protected/);

  const wrong = await oneProposal();
  wrong.host.writeWrong = true;
  const failed = await wrong.review.applyProposal(wrong.proposal, new ScriptedPerson([], true));
  assert.equal(failed.status, 'failed');
  assert.match(failed.message, /does not contain exactly what was approved/);
  assert.match(failed.message, /undone/);
  assert.deepEqual(wrong.host.reverted, ['chg_1'], 'the unexpected write was undone through the host');

  const crash = await oneProposal();
  crash.host.failWith = new Error('disk on fire');
  await assert.rejects(crash.review.applyProposal(crash.proposal, new ScriptedPerson([], true)), /disk on fire/, 'an unexpected error is not swallowed');
});

// ---------------------------------------------------------------------------------------------------- the whole review

test('the full review: only chosen findings are corrected, only approved files change, and what is verified is what is on disk', async () => {
  const { host, phylax, review } = setup();
  const person = new ScriptedPerson((candidates) => candidates.filter((c) => c.finding.path === 'run.js').map((c) => c.key), true);
  const progress: string[] = [];
  const result = await new SecurityReview({ phylax, files: host, onProgress: (m) => progress.push(m) }).runInteractive({ kind: 'project' }, person);

  assert.equal(person.asked.length, 1);
  assert.deepEqual(person.asked[0]?.map((c) => c.finding.path), ['run.js', 'db.ts'], 'the person is offered the correctable findings, and not the low one');
  assert.deepEqual(phylax.calls.find((c) => c.method === 'fix')?.args, ['scn_1', ['f1']], 'only the finding the person chose was sent for correction');
  assert.equal(host.files.get('run.js'), RUN_FIXED);
  assert.equal(host.files.get('db.ts'), DB, 'the finding the person did not choose is untouched');
  assert.equal(host.files.get('ok.js'), OK);
  assert.deepEqual(result.outcomes.map((o) => [o.path, o.status]), [['run.js', 'applied']]);

  const verifyCall = phylax.calls.find((c) => c.method === 'verify');
  assert.deepEqual(verifyCall?.args, ['scn_1', [{ path: 'run.js', content: host.files.get('run.js') }]], 'what is verified is what is on disk now, and only the files that changed');
  assert.deepEqual(phylax.deleted, ['scn_1'], 'the scan is removed from the service afterwards');
  assert.ok(progress.some((m) => /Scanning/.test(m)) && progress.some((m) => /Verifying/.test(m)));
  void review;
});

test('verification reports what is resolved, what remains and what is new, from the files as they are on disk', async () => {
  const { host, phylax } = setup();
  phylax.onVerify = (scanId) => ({ id: 'ver_1', scan_id: scanId, status: 'completed', outcome: 'failed', checks: [{ name: 'rescan', result: 'fail', detail: 'A new problem appeared.' }],
    new_findings: [finding('n1', 'run.js', 'medium', 'xss_or_template_injection')], resolved_finding_ids: [] });
  const person = new ScriptedPerson((c) => c.map((x) => x.key), true);
  const result = await new SecurityReview({ phylax, files: host }).runInteractive({ kind: 'project' }, person);
  const verification = result.verification[0];
  assert.equal(verification?.outcome, 'failed');
  assert.deepEqual(verification?.remaining.map((f) => f.path).sort(), ['db.ts', 'run.js']);
  assert.deepEqual(verification?.resolved, []);
  assert.deepEqual(verification?.introduced.map((f) => f.id), ['n1']);
  assert.match(formatVerification(result.verification), /Still present/);
  assert.match(formatVerification(result.verification), /New: xss_or_template_injection/);
});

test('declining everything, choosing nothing offered, or having nothing to correct changes no file and requests nothing', async () => {
  for (const picks of [[], ['scn_1:f3'], ['scn_1:f99'], ['garbage']]) {
    const { host, phylax } = setup();
    const person = new ScriptedPerson(picks, true);
    const result = await new SecurityReview({ phylax, files: host }).runInteractive({ kind: 'project' }, person);
    assert.equal(phylax.count('fix'), 0, `picks ${JSON.stringify(picks)} request nothing (the low finding and unknown keys were never offered)`);
    assert.equal(host.applied.length, 0);
    assert.deepEqual(result.requested, []);
    assert.equal(phylax.count('verify'), 0);
    assert.equal(phylax.deleted.length, 1, 'the scan is still removed');
  }
  const clean = setup({ files: { 'ok.js': OK } });
  const person = new ScriptedPerson(() => { throw new Error('not asked'); }, true);
  await new SecurityReview({ phylax: clean.phylax, files: clean.host }).runInteractive({ kind: 'project' }, person);
  assert.equal(person.asked.length, 0, 'with nothing correctable the person is not asked to choose');
});

test('rejecting every diff leaves every file alone and verifies nothing', async () => {
  const { host, phylax } = setup();
  const person = new ScriptedPerson((c) => c.map((x) => x.key), false);
  const result = await new SecurityReview({ phylax, files: host }).runInteractive({ kind: 'project' }, person);
  assert.deepEqual(result.outcomes.map((o) => o.status), ['rejected', 'rejected']);
  assert.equal(host.applied.length, 0);
  assert.equal(phylax.count('verify'), 0, 'nothing changed, so there is nothing to verify');
  assert.equal(person.shown.length, 2, 'each file was shown separately');
});

test('findings from several scans are corrected and verified through the scan they came from', async () => {
  const files: Record<string, string> = { 'run.js': RUN, 'db.ts': DB };
  const host = new MemoryHost(files);
  const phylax = new FakePhylax();
  phylax.capabilitiesValue = { ...CAPABILITIES, limits: { ...CAPABILITIES.limits, max_files: 1 } };
  const seen = new Map<string, Finding[]>();
  phylax.onScan = (sent, n) => { const found = [finding('f1', sent[0]?.path as string, SEVERITY_OF[sent[0]?.path as string] ?? 'low')]; seen.set(`scn_${n}`, found); return { id: `scn_${n}`, status: 'completed', report: reportFor(sent, found) }; };
  phylax.onFix = (scanId, ids) => { const f = (seen.get(scanId) as Finding[])[0] as Finding; const [a, b] = FIXED_OF[f.path as string] as [string, string]; return okFix(scanId, ids?.includes('f1') ? [patchFor(a, b, f.path as string, ['f1'])] : []); };
  const person = new ScriptedPerson((c) => c.map((x) => x.key), true);
  const result = await new SecurityReview({ phylax, files: host }).runInteractive({ kind: 'project' }, person);
  const byScan = (calls: { args: unknown[] }[]) => calls.map((c) => c.args).sort((a, b) => String(a[0]).localeCompare(String(b[0])));          // the order across scans is by severity; what matters is who gets what
  assert.deepEqual(byScan(phylax.calls.filter((c) => c.method === 'fix')), [['scn_1', ['f1']], ['scn_2', ['f1']]]);
  assert.deepEqual(byScan(phylax.calls.filter((c) => c.method === 'verify')).map((a) => [a[0], (a[1] as { path: string }[]).map((f) => f.path)]), [['scn_1', ['db.ts']], ['scn_2', ['run.js']]]);
  assert.deepEqual(phylax.calls.filter((c) => c.method === 'fix').map((c) => c.args[0]), ['scn_2', 'scn_1'], 'the more severe finding is handled first');
  assert.deepEqual(result.outcomes.map((o) => o.status), ['applied', 'applied']);
  assert.deepEqual(phylax.deleted.sort(), ['scn_1', 'scn_2']);
});

test('the scans are removed from the service even when something goes wrong half way', async () => {
  const { host, phylax } = setup();
  phylax.onFix = () => { throw new Error('the correction service is down'); };
  const person = new ScriptedPerson((c) => c.map((x) => x.key), true);
  await assert.rejects(new SecurityReview({ phylax, files: host }).runInteractive({ kind: 'project' }, person), /the correction service is down/);
  assert.deepEqual(phylax.deleted, ['scn_1']);
  assert.equal(host.applied.length, 0);
});

test('the plain-text renderings are ASCII, readable, and show why a finding is report-only', async () => {
  const { host, phylax } = setup();
  const person = new ScriptedPerson((c) => c.map((x) => x.key), true);
  const result = await new SecurityReview({ phylax, files: host }).runInteractive({ kind: 'project' }, person);
  const text = [formatSummary(result.summary), formatOutcomes(result.outcomes), formatVerification(result.verification), formatProposal(person.shown[0] as never)].join('\n');
  assert.equal(/^[\x00-\x7f]*$/.test(text), true, 'ASCII only');
  assert.match(formatSummary(result.summary), /A correction can be offered for 2 finding\(s\)/);
  assert.match(formatSummary(result.summary), /Reported only \(1\)/);
  assert.match(formatSummary(result.summary), /not corrected by default/);
  assert.match(formatSummary(result.summary), /Not assessable by any scan/);
  assert.match(formatOutcomes(result.outcomes), /\[applied\]/);
  assert.equal(formatOutcomes([]), 'No corrections were applied.');
});
