/**
 * End to end, against the REAL Phylax service (started by tests/serve_for_clients.py, with a stand-in for GPT-6 Astra behind it): real HTTP, the real
 * contract, the real scanner, the real verifier. Skipped, with the reason, if Python or the service is not available on this machine.
 */

import assert from 'node:assert/strict';
import { spawn, spawnSync, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { readFile, readdir } from 'node:fs/promises';
import path from 'node:path';
import { after, before, test } from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { OqeliraFileChanger, type OqeliraChangesModule } from '../src/adapters/oqelira.js';
import { DiskFileChanger } from '../src/adapters/disk.js';
import { HttpPhylaxApi, type PhylaxApi } from '../src/api.js';
import { PhylaxApiError } from '../src/errors.js';
import { SecurityReview } from '../src/review.js';
import { createSecurityTools, type SecurityTool } from '../src/tools.js';
import { ScriptedPerson, tempProject } from './helpers.js';

const REPO_ROOT = fileURLToPath(new URL('../../../../', import.meta.url));
const FIXTURE = fileURLToPath(new URL('../../test/fixtures/oqelira_changes.mjs', import.meta.url));

const RUN = 'const { exec } = require("child_process");\n\nfunction run(dir) {\n  exec(`ls ${dir}`);\n}\n';
const RUN_FIXED = 'const { execFile } = require("child_process");\n\nfunction run(dir) {\n  execFile("ls", [dir]);\n}\n';
const DB = 'export function find(id: string) {\n  return pool.query(`SELECT * FROM t WHERE id = ${id}`);\n}\n';
const DB_FIXED = 'export function find(id: string) {\n  return pool.query("SELECT * FROM t WHERE id = $1", [id]);\n}\n';
const TOKEN = 'function makeResetToken() {\n  return Math.random().toString(36);\n}\n';
const CLEAN = 'const add = (a, b) => a + b;\n';
const crlf = (text: string): string => text.replace(/\n/g, '\r\n');

let service: { url: string; key: string } | null = null;
let child: ChildProcessWithoutNullStreams | null = null;
let skipReason: string | null = null;

before(async () => {
  const python = process.env['PHYLAX_PYTHON'] ?? (process.platform === 'win32' ? 'python' : 'python3');
  try {
    child = spawn(python, ['-m', 'tests.serve_for_clients'], { cwd: REPO_ROOT, env: { ...process.env, PYTHONUNBUFFERED: '1' } }) as ChildProcessWithoutNullStreams;
  } catch (error) {
    skipReason = `could not start ${python}: ${(error as Error).message}`;
    return;
  }
  child.on('error', (error) => { skipReason = `could not start ${python}: ${error.message}`; });
  const line = await new Promise<string>((resolve) => {
    let buffer = '';
    const timer = setTimeout(() => resolve(''), 60_000);
    child?.stdout.on('data', (chunk: Buffer) => { buffer += chunk.toString('utf8'); if (buffer.includes('\n')) { clearTimeout(timer); resolve(buffer.split('\n')[0] ?? ''); } });
    child?.on('exit', () => { clearTimeout(timer); resolve(buffer.split('\n')[0] ?? ''); });
    child?.on('error', () => { clearTimeout(timer); resolve(''); });
  });
  try {
    const parsed = JSON.parse(line) as { url?: string; key?: string; error?: string };
    if (parsed.url && parsed.key) service = { url: parsed.url, key: parsed.key };
    else skipReason = parsed.error ?? 'the service did not start';
  } catch {
    skipReason = skipReason ?? 'the service did not start (is Python installed with the packages in requirements.txt?)';
  }
}, { timeout: 100_000 });

after(async () => {
  const helper = child;
  if (!helper) return;
  try { helper.stdin.end(); } catch { /* already closed */ }                    // the helper stops the service itself when its input closes
  await new Promise<void>((resolve) => {
    if (helper.exitCode !== null) return resolve();
    const timer = setTimeout(resolve, 15_000);
    helper.once('exit', () => { clearTimeout(timer); resolve(); });
  });
  if (helper.exitCode === null && helper.pid !== undefined) {                    // it did not stop: kill it AND the service it started (on Windows, killing a process leaves its children running)
    if (process.platform === 'win32') spawnSync('taskkill', ['/pid', String(helper.pid), '/T', '/F'], { stdio: 'ignore' });
    else helper.kill('SIGKILL');
  }
}, { timeout: 30_000 });

function api(): HttpPhylaxApi {
  if (!service) throw new Error('no service');
  return new HttpPhylaxApi({ baseUrl: service.url, apiKey: service.key, pollIntervalMs: 50, timeoutMs: 60_000 });
}

/** The real client, with the calls that cost money counted. */
function counting(real: PhylaxApi): { api: PhylaxApi; fixes: () => number } {
  let fixes = 0;
  return { api: { capabilities: (o) => real.capabilities(o), scan: (f, o) => real.scan(f, o), fix: (s, o) => { fixes += 1; return real.fix(s, o); }, verify: (s, f, o) => real.verify(s, f, o), deleteScan: (s, o) => real.deleteScan(s, o) }, fixes: () => fixes };
}

const choosesAll = (): ScriptedPerson => new ScriptedPerson((c) => c.map((x) => x.key), true);

test('the service speaks the contract this client was written against', { timeout: 90_000 }, async (t) => {
  if (!service) return t.skip(skipReason ?? 'no service');
  const capabilities = await api().capabilities();
  assert.equal(capabilities.contract_version, '1.3.0');
  assert.equal(capabilities.features?.fixes, true);
  assert.ok(capabilities.limits.max_files >= 1);
  await assert.rejects(new HttpPhylaxApi({ baseUrl: service.url, apiKey: 'wrong-key-wrong-key-wrong-key' }).capabilities(), (e: unknown) => e instanceof PhylaxApiError && e.code === 'unauthorized' && e.status === 401);
});

test('a full review of a project: scan, choose, approve, apply, verify, with a Windows file and the real eligibility rule', { timeout: 90_000 }, async (t) => {
  if (!service) return t.skip(skipReason ?? 'no service');
  const project = await tempProject({ 'run.js': crlf(RUN), 'db.ts': DB, 'token.js': TOKEN, 'ok.js': CLEAN, 'README.md': '# not code\n' });
  try {
    const counted = counting(api());
    const person = choosesAll();
    const result = await new SecurityReview({ phylax: counted.api, files: new DiskFileChanger(project.root) }).runInteractive({ kind: 'project' }, person);

    const { summary } = result;
    assert.equal(summary.decision, 'block', 'the command injection is a rule-backed high finding');
    assert.deepEqual(summary.correctable.map((f) => f.finding.path), ['run.js', 'db.ts'], 'a high and a medium finding are offered a correction');
    assert.deepEqual(summary.reportOnly.map((f) => f.finding.path), ['token.js'], 'the low finding is reported only');
    assert.match(summary.reportOnly[0]?.finding.fix.reason ?? '', /not corrected by default/);
    assert.deepEqual(person.asked[0]?.map((c) => c.finding.path), ['run.js', 'db.ts'], 'the low finding was never offered to the person');

    assert.equal(counted.fixes(), 1, 'one request for the chosen findings');
    assert.deepEqual(result.outcomes.map((o) => [o.path, o.status]).sort(), [['db.ts', 'applied'], ['run.js', 'applied']]);
    assert.equal(await readFile(path.join(project.root, 'run.js'), 'utf8'), crlf(RUN_FIXED), 'the Windows file is corrected and is still a Windows file');
    assert.equal(await readFile(path.join(project.root, 'db.ts'), 'utf8'), DB_FIXED);
    assert.equal(await readFile(path.join(project.root, 'token.js'), 'utf8'), TOKEN, 'the report-only file was not touched');
    assert.deepEqual((await readdir(project.root)).sort(), ['README.md', 'db.ts', 'ok.js', 'run.js', 'token.js'], 'no stray files');

    assert.equal(result.verification.length, 1);
    assert.equal(result.verification[0]?.outcome, 'passed');
    assert.deepEqual(result.verification[0]?.resolved.map((f) => f.path).sort(), ['db.ts', 'run.js']);
    assert.deepEqual(result.verification[0]?.remaining, []);
    assert.deepEqual(result.proposals?.notCorrected, []);

    for (const scanId of summary.scanIds) {                                                                 // the review removed its scans from the service
      const gone: Response = await fetch(`${service.url}/v1/scans/${scanId}`, { headers: { Authorization: `Bearer ${service.key}` } });
      assert.equal(gone.status, 404);
    }
    const again = await new SecurityReview({ phylax: api(), files: new DiskFileChanger(project.root) }).scan({ kind: 'project' });
    assert.equal(again.decision, 'pass', 'a new scan of the corrected project passes');
    assert.deepEqual(again.correctable, []);
  } finally { await project.cleanup(); }
});

test('the same review through Oqelira\'s real change mechanism', { timeout: 90_000 }, async (t) => {
  if (!service) return t.skip(skipReason ?? 'no service');
  const changes = (await import(pathToFileURL(FIXTURE).href)) as OqeliraChangesModule;
  const project = await tempProject({ 'run.js': crlf(RUN), 'db.ts': DB, 'ok.js': CLEAN });
  try {
    const result = await new SecurityReview({ phylax: api(), files: new OqeliraFileChanger({ cwd: project.root, changes }) }).runInteractive({ kind: 'project' }, choosesAll());
    assert.deepEqual(result.outcomes.map((o) => o.status).sort(), ['applied', 'applied']);
    assert.equal(await readFile(path.join(project.root, 'run.js'), 'utf8'), crlf(RUN_FIXED));
    assert.equal(await readFile(path.join(project.root, 'db.ts'), 'utf8'), DB_FIXED);
    assert.ok((await readdir(project.root)).includes('.oqelira'), 'Oqelira recorded the changes in its own ledger');
    for (const outcome of result.outcomes) assert.match(outcome.changeId ?? '', /^[0-9a-f-]{36}$/);
    assert.equal(result.verification[0]?.outcome, 'passed');
  } finally { await project.cleanup(); }
});

test('a medium finding is offered a correction even though the verdict is only review_required', { timeout: 90_000 }, async (t) => {
  if (!service) return t.skip(skipReason ?? 'no service');
  const project = await tempProject({ 'db.ts': DB });
  try {
    const review = new SecurityReview({ phylax: api(), files: new DiskFileChanger(project.root) });
    const summary = await review.scan({ kind: 'project' });
    assert.equal(summary.decision, 'review_required');
    assert.equal(summary.correctable.length, 1);
    assert.equal(summary.correctable[0]?.finding.fix.eligible, true);
    await review.close();
  } finally { await project.cleanup(); }
});

test('a file edited after the scan is not overwritten, and the person is not asked about it', { timeout: 90_000 }, async (t) => {
  if (!service) return t.skip(skipReason ?? 'no service');
  const project = await tempProject({ 'run.js': RUN, 'db.ts': DB });
  try {
    const host = new DiskFileChanger(project.root);
    const review = new SecurityReview({ phylax: api(), files: host });
    const summary = await review.scan({ kind: 'project' });
    const proposals = await review.proposeCorrections(summary.correctable.map((f) => f.key));
    assert.equal(proposals.proposals.length, 2);
    const { writeFile } = await import('node:fs/promises');
    await writeFile(path.join(project.root, 'db.ts'), DB + '// edited by a person after the scan\n');
    const person = choosesAll();
    const outcomes = [];
    for (const proposal of proposals.proposals) outcomes.push(await review.applyProposal(proposal, person));
    assert.deepEqual(outcomes.map((o) => [o.path, o.status]).sort(), [['db.ts', 'stale'], ['run.js', 'applied']]);
    assert.deepEqual(person.shown.map((p) => p.path), ['run.js'], 'only the file that could still be changed was shown');
    assert.equal(await readFile(path.join(project.root, 'db.ts'), 'utf8'), DB + '// edited by a person after the scan\n');
    await review.close();
  } finally { await project.cleanup(); }
});

test('declining, or choosing nothing, changes nothing and asks for no correction', { timeout: 90_000 }, async (t) => {
  if (!service) return t.skip(skipReason ?? 'no service');
  const project = await tempProject({ 'run.js': RUN, 'db.ts': DB });
  try {
    const declined = counting(api());
    const a = await new SecurityReview({ phylax: declined.api, files: new DiskFileChanger(project.root) }).runInteractive({ kind: 'project' }, new ScriptedPerson((c) => c.map((x) => x.key), false));
    assert.deepEqual(a.outcomes.map((o) => o.status), ['rejected', 'rejected']);
    const nothing = counting(api());
    const b = await new SecurityReview({ phylax: nothing.api, files: new DiskFileChanger(project.root) }).runInteractive({ kind: 'project' }, new ScriptedPerson([], true));
    assert.equal(nothing.fixes(), 0, 'no correction is requested (and none is paid for) unless the person chooses a finding');
    assert.deepEqual(b.outcomes, []);
    assert.equal(await readFile(path.join(project.root, 'run.js'), 'utf8'), RUN);
    assert.equal(await readFile(path.join(project.root, 'db.ts'), 'utf8'), DB);
  } finally { await project.cleanup(); }
});

test('the three tools, driven the way a model would drive them: scan, pick, propose, apply, against the real service', { timeout: 90_000 }, async (t) => {
  if (!service) return t.skip(skipReason ?? 'no service');
  const changes = (await import(pathToFileURL(FIXTURE).href)) as OqeliraChangesModule;
  for (const host of ['a plain folder', "Oqelira's change mechanism"]) {
    const project = await tempProject({ 'run.js': crlf(RUN), 'db.ts': DB, 'token.js': TOKEN, 'ok.js': CLEAN });
    try {
      const shown: string[] = [];
      const pack = createSecurityTools({
        phylax: api(),
        files: (ctx) => (host === 'a plain folder' ? new DiskFileChanger(ctx.cwd) : new OqeliraFileChanger({ cwd: ctx.cwd, changes })),
        consent: { kind: 'callback', confirm: async (proposal) => { shown.push(proposal.diff); return true; } },
      });
      const [scan, propose, apply] = pack.tools as [SecurityTool, SecurityTool, SecurityTool];
      const context = { cwd: project.root };

      const scanned = JSON.parse((await scan.execute({}, context)).content);
      assert.equal(scanned.decision, 'block', host);
      const offered = scanned.findings.filter((f: { correction: { offered: boolean } }) => f.correction.offered);
      assert.deepEqual(offered.map((f: { where: string }) => f.where.split(':')[0]), ['run.js', 'db.ts'], `${host}: high and medium are offered`);
      const reportOnly = scanned.findings.filter((f: { correction: { offered: boolean } }) => !f.correction.offered);
      assert.deepEqual(reportOnly.map((f: { where: string }) => f.where.split(':')[0]), ['token.js'], `${host}: the low finding is reported only`);

      const proposals = JSON.parse((await propose.execute({ finding_keys: offered.map((f: { key: string }) => f.key) }, context)).content);
      assert.equal(proposals.proposals.length, 2, host);
      assert.equal(JSON.stringify(proposals).includes('corrected_content'), false);
      assert.equal(await readFile(path.join(project.root, 'run.js'), 'utf8'), crlf(RUN), 'proposing changes nothing');

      for (const proposal of proposals.proposals) {
        const applied = JSON.parse((await apply.execute({ proposal_id: proposal.proposal_id }, context)).content);
        assert.equal(applied.applied, true, `${host}: ${proposal.path}`);
        assert.equal(applied.verification.outcome, 'passed');
      }
      assert.equal(shown.length, 2, 'the person was shown both diffs');
      assert.equal(await readFile(path.join(project.root, 'run.js'), 'utf8'), crlf(RUN_FIXED), `${host}: the Windows file is corrected and is still a Windows file`);
      assert.equal(await readFile(path.join(project.root, 'db.ts'), 'utf8'), DB_FIXED);
      assert.equal(await readFile(path.join(project.root, 'token.js'), 'utf8'), TOKEN);
      await pack.close();
      const gone: Response = await fetch(`${service.url}/v1/scans/${scanned.findings[0].key.split(':')[0]}`, { headers: { Authorization: `Bearer ${service.key}` } });
      assert.equal(gone.status, 404, 'closing removed the scan from the service');
    } finally { await project.cleanup(); }
  }
});
