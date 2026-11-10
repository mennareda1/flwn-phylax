import assert from 'node:assert/strict';
import { test } from 'node:test';

import { exitCodeFor, parseArguments, terminalApprover, toSelection } from '../src/cli.js';
import { PhylaxError } from '../src/errors.js';
import type { ReviewResult } from '../src/review.js';
import { finding } from './helpers.js';

test('arguments: defaults, the environment, and the options', () => {
  const none = parseArguments([], {});
  assert.deepEqual(none, { files: [], project: '.', server: 'http://127.0.0.1:8080', reportOnly: false, applyWith: 'disk', oqeliraChanges: null, help: false });
  assert.equal(parseArguments([], { PHYLAX_URL: 'https://phylax.example.com' }).server, 'https://phylax.example.com');
  const full = parseArguments(['src/a.js', 'b.ts', '--project', '/work', '--server', 'http://localhost:9', '--report-only', '--apply-with', 'oqelira', '--oqelira-changes', 'c.mjs'], {});
  assert.deepEqual(full, { files: ['src/a.js', 'b.ts'], project: '/work', server: 'http://localhost:9', reportOnly: true, applyWith: 'oqelira', oqeliraChanges: 'c.mjs', help: true && false });
  assert.equal(parseArguments(['-h'], {}).help, true);
  assert.equal(parseArguments(['--help'], {}).help, true);
});

test('there is no way to skip the question, and no way to put the key on the command line', () => {
  for (const [args, pattern] of [[['--yes'], /no --yes/], [['-y'], /no --yes/], [['--yes=true'], /no --yes/], [['--key', 'abc'], /PHYLAX_API_KEY/], [['--key=abc'], /PHYLAX_API_KEY/],
    [['--bogus'], /Unknown option/], [['--project'], /needs a value/], [['--server', '--report-only'], /needs a value/], [['--apply-with', 'ftp'], /disk or oqelira/]] as const) {
    assert.throws(() => parseArguments([...args], {}), (e: unknown) => e instanceof PhylaxError && pattern.test(e.message), JSON.stringify(args));
  }
});

test('named files become project-relative paths with forward slashes', () => {
  const path = '/work/project';
  assert.deepEqual(toSelection(parseArguments([], {})), { kind: 'project' });
  assert.deepEqual(toSelection(parseArguments(['src/a.js', './src/b.ts', '/work/project/c.js', '--project', path], {})), { kind: 'files', paths: ['src/a.js', 'src/b.ts', 'c.js'] });
  const outside = toSelection(parseArguments(['/elsewhere/x.js', '--project', path], {}));
  assert.equal(outside.kind === 'files' && (outside.paths[0] ?? '').startsWith('..'), true, 'a path outside the project stays visibly outside, and the adapter refuses it');
});

test('the terminal asks plainly and treats anything but yes as no', async () => {
  const said: string[] = [];
  const candidates = [1, 2, 3].map((n) => ({ key: `scn_1:f${n}`, finding: finding(`f${n}`, `file${n}.js`, 'high') }));
  const answering = (...answers: string[]) => { const queue = [...answers]; return terminalApprover(async () => queue.shift() ?? '', (t) => said.push(t)); };

  assert.deepEqual(await answering('1,3').chooseCorrections(candidates), ['scn_1:f1', 'scn_1:f3']);
  assert.deepEqual(await answering('2').chooseCorrections(candidates), ['scn_1:f2']);
  assert.deepEqual(await answering('all').chooseCorrections(candidates), candidates.map((c) => c.key));
  assert.deepEqual(await answering('ALL').chooseCorrections(candidates), candidates.map((c) => c.key));
  assert.deepEqual(await answering('').chooseCorrections(candidates), [], 'Enter skips');
  assert.deepEqual(await answering('   ').chooseCorrections(candidates), []);
  assert.deepEqual(await answering('2 2 2').chooseCorrections(candidates), ['scn_1:f2'], 'a number counts once');
  assert.deepEqual(await answering('9, 0, x, -1').chooseCorrections(candidates), [], 'nonsense selects nothing');
  assert.ok(said.some((line) => /ignoring "x"/.test(line)));

  const proposal = { key: 'scn_1:run.js', path: 'run.js', diff: '--- a/run.js\n+++ b/run.js\n', explanation: 'Safer.', findings: [finding('f1', 'run.js', 'high')], verification: null };
  for (const [answer, approved] of [['y', true], ['Y', true], ['yes', true], [' YES ', true], ['', false], ['n', false], ['no', false], ['yep', false], ['ok', false], ['1', false], ['yes please', false], ['ye', false]] as const) {
    assert.equal((await answering(answer).approveChange(proposal)).approved, approved, `answer ${JSON.stringify(answer)}`);
  }
  assert.ok(said.some((line) => line.includes('--- a/run.js')), 'the diff is shown before the question');
});

test('the exit code is 0 only for a clean review', () => {
  const resolved = (keys: string[]) => keys.map((k) => ({ scanId: 'scn_1', paths: ['a.js'], outcome: 'passed' as const, resolved: [finding(k, 'a.js', 'high')], remaining: [], introduced: [], checks: [] }));
  const result = (decision: ReviewResult['summary']['decision'], correctable: string[], verified: string[], extra: Partial<ReviewResult['summary']> = {}): ReviewResult => ({
    summary: { decision, riskLevel: 'x', reasons: [], findings: [], correctable: correctable.map((k) => ({ key: `scn_1:${k}`, scanId: 'scn_1', finding: finding(k, 'a.js', 'high') })), reportOnly: [], scannedFiles: [], unscanned: [],
      engineProblems: [], notAssessable: [], scanIds: ['scn_1'], correctionsAvailable: true, ...extra },
    requested: [], proposals: null, outcomes: [], verification: resolved(verified),
  });
  assert.equal(exitCodeFor(result('pass', [], [])), 0, 'nothing found');
  assert.equal(exitCodeFor(result('block', ['f1'], ['f1'])), 0, 'found, corrected and verified');
  assert.equal(exitCodeFor(result('block', ['f1', 'f2'], ['f1'])), 1, 'one finding is still unresolved');
  assert.equal(exitCodeFor(result('review_required', ['f1'], [])), 1, 'found and not corrected');
  assert.equal(exitCodeFor(result('scan_failed', [], [])), 1);
  assert.equal(exitCodeFor(result('pass', [], [], { unscanned: [{ path: 'x.js', reason: 'binary', blocksPass: true }] })), 1, 'a file that could not be scanned is not clean');
  assert.equal(exitCodeFor(result('pass', [], [], { engineProblems: ['jsrules: failed'] })), 1, 'a check that did not run is not clean');
  assert.equal(exitCodeFor(result('pass', [], [], { unscanned: [{ path: 'x.js', reason: 'empty', blocksPass: false }] })), 0);
});
