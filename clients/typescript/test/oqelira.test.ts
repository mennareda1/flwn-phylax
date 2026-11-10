import assert from 'node:assert/strict';
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { sha256Text } from '../src/adapters/disk.js';
import { OQELIRA_MAX_CONTENT_CHARS, OqeliraFileChanger, type OqeliraChangesModule } from '../src/adapters/oqelira.js';
import { ChangeRefusedError, FileUnreadableError, StaleFileError } from '../src/errors.js';
import { SecurityReview } from '../src/review.js';
import { FakePhylax, ScriptedPerson, finding, okFix, patchFor, reportFor, tempProject } from './helpers.js';

// Oqelira's real, unmodified change mechanism (a copy of its changes.mjs), loaded the way a host would hand it to the adapter.
const FIXTURE = fileURLToPath(new URL('../../test/fixtures/oqelira_changes.mjs', import.meta.url));
const changes = (await import(pathToFileURL(FIXTURE).href)) as OqeliraChangesModule;

const WIN = 'const { exec } = require("child_process");\r\nexec(`ls ${dir}`);\r\n';
const WIN_FIXED = 'const { execFile } = require("child_process");\r\nexecFile("ls", [dir]);\r\n';

test('reading through Oqelira gives exactly the hash Phylax computes, for LF, CRLF and non-ASCII text', async () => {
  const texts = { 'lf.js': 'a = 1\nb = 2\n', 'crlf.js': WIN, 'uni.js': '// caf\u00e9 \u65e5\u672c\u8a9e \u{1F600}\nx = 1\n' };
  const project = await tempProject(texts);
  try {
    const host = new OqeliraFileChanger({ cwd: project.root, changes });
    for (const [name, text] of Object.entries(texts)) {
      const snapshot = await host.read(name);
      assert.equal(snapshot.content, text);
      assert.equal(snapshot.sha256, sha256Text(text), `${name}: Oqelira's snapshot hash and Phylax's SHA-256 of the text agree`);
    }
    await assert.rejects(host.read('missing.js'), FileUnreadableError);
  } finally { await project.cleanup(); }
});

test('a correction goes through Oqelira\'s own mechanism, keeps Windows line endings, and is recorded so Oqelira can revert it', async () => {
  const project = await tempProject({ 'run.js': WIN });
  try {
    const host = new OqeliraFileChanger({ cwd: project.root, changes });
    const before = await host.read('run.js');
    const applied = await host.apply({ path: 'run.js', expectedSha256: before.sha256, content: WIN_FIXED });
    assert.equal(applied.sha256, sha256Text(WIN_FIXED));
    assert.match(applied.changeId ?? '', /^[0-9a-f-]{36}$/);
    const bytes = await readFile(path.join(project.root, 'run.js'));
    assert.equal(bytes.toString('utf8'), WIN_FIXED);
    assert.equal(bytes.toString('utf8').replace(/\r\n/g, '').includes('\n'), false, 'no line ending was translated');
    const record = await changes.readFileChange(project.root, applied.changeId as string);        // Oqelira's own ledger knows about it
    assert.equal(record.content, WIN);

    const restored = await host.revert(applied.changeId as string);                               // and the adapter reverts through Oqelira's mechanism
    assert.equal(restored.sha256, before.sha256);
    assert.equal(await readFile(path.join(project.root, 'run.js'), 'utf8'), WIN);
    await assert.rejects(host.revert(applied.changeId as string), StaleFileError, 'reverting the same change again is refused: the file no longer has the hash it had after the change');
  } finally { await project.cleanup(); }
});

test('Oqelira\'s own stale-write guard protects a file that changed after the scan', async () => {
  const project = await tempProject({ 'run.js': WIN });
  try {
    const host = new OqeliraFileChanger({ cwd: project.root, changes });
    const scanned = await host.read('run.js');
    await writeFile(path.join(project.root, 'run.js'), WIN + '// a person edited this\r\n');
    await assert.rejects(host.apply({ path: 'run.js', expectedSha256: scanned.sha256, content: WIN_FIXED }), StaleFileError);
    assert.equal(await readFile(path.join(project.root, 'run.js'), 'utf8'), WIN + '// a person edited this\r\n', 'nothing was overwritten');
  } finally { await project.cleanup(); }
});

test('what Oqelira refuses is reported as a refusal, and large files can still be scanned but not changed', async () => {
  const big = '// padding\n'.repeat(1500) + 'eval(x);\n';            // more than 10,000 characters
  const project = await tempProject({ 'big.js': big, 'ok.js': 'x = 1\n', '.env': 'SECRET=1\n' });
  try {
    const host = new OqeliraFileChanger({ cwd: project.root, changes });
    assert.equal(host.capabilities.maxContentChars, OQELIRA_MAX_CONTENT_CHARS);
    assert.equal(OQELIRA_MAX_CONTENT_CHARS, 10_000);
    await assert.rejects(host.apply({ path: '.env', expectedSha256: sha256Text('SECRET=1\n'), content: 'SECRET=2\n' }), ChangeRefusedError, 'protected files are refused by Oqelira');
    const snapshot = await host.read('big.js');                                                    // too big for Oqelira's snapshot, still readable for a scan
    assert.equal(snapshot.content, big);
    assert.equal(snapshot.sha256, sha256Text(big));
    const ok = await host.read('ok.js');
    await assert.rejects(host.apply({ path: 'ok.js', expectedSha256: ok.sha256, content: 'y'.repeat(20_000) }), ChangeRefusedError, 'Oqelira will not write more than 10,000 characters');
    assert.equal(await readFile(path.join(project.root, 'ok.js'), 'utf8'), 'x = 1\n');
  } finally { await project.cleanup(); }
});

test('an answer from Oqelira that does not report the hash of the changed file is refused, never trusted', async () => {
  const project = await tempProject({ 'a.js': 'x\n' });
  try {
    for (const answer of ['{"change_id":"abc"}', 'not json at all', '{"sha256":42}', '[]', 'null']) {
      const stub: OqeliraChangesModule = { ...changes, applyFileChange: async () => answer };
      const host = new OqeliraFileChanger({ cwd: project.root, changes: stub });
      await assert.rejects(host.apply({ path: 'a.js', expectedSha256: sha256Text('x\n'), content: 'y\n' }), ChangeRefusedError, `answer ${answer}`);
    }
  } finally { await project.cleanup(); }
});

test('listing a project skips Oqelira\'s own ledger folder and protected files', async () => {
  const project = await tempProject({ 'a.js': 'x\n', '.env': 'S=1\n' });
  try {
    const host = new OqeliraFileChanger({ cwd: project.root, changes });
    const a = await host.read('a.js');
    await host.apply({ path: 'a.js', expectedSha256: a.sha256, content: 'y\n' });                  // this creates .oqelira/changes inside the project
    assert.ok((await readdir(project.root)).includes('.oqelira'));
    assert.deepEqual(await host.listFiles({ kind: 'project' }), ['a.js']);
  } finally { await project.cleanup(); }
});

test('the whole review works through Oqelira\'s mechanism, with a Windows file, and a person\'s yes is still required', async () => {
  const project = await tempProject({ 'run.js': WIN });
  try {
    const host = new OqeliraFileChanger({ cwd: project.root, changes });
    const phylax = new FakePhylax();
    phylax.onScan = (files, n) => ({ id: `scn_${n}`, status: 'completed', report: reportFor(files, [finding('f1', 'run.js', 'high')], 'block') });
    phylax.onFix = (scanId) => okFix(scanId, [patchFor(WIN, WIN_FIXED, 'run.js', ['f1'])]);

    const declined = await new SecurityReview({ phylax, files: host }).runInteractive({ kind: 'project' }, new ScriptedPerson((c) => c.map((x) => x.key), false));
    assert.deepEqual(declined.outcomes.map((o) => o.status), ['rejected']);
    assert.equal(await readFile(path.join(project.root, 'run.js'), 'utf8'), WIN, 'declined: untouched');

    const accepted = await new SecurityReview({ phylax, files: host }).runInteractive({ kind: 'project' }, new ScriptedPerson((c) => c.map((x) => x.key), true));
    assert.deepEqual(accepted.outcomes.map((o) => o.status), ['applied']);
    assert.equal(await readFile(path.join(project.root, 'run.js'), 'utf8'), WIN_FIXED);
    assert.deepEqual(phylax.calls.filter((c) => c.method === 'verify').map((c) => c.args[1]).pop(), [{ path: 'run.js', content: WIN_FIXED }], 'verified as it is on disk, Windows line endings included');
  } finally { await project.cleanup(); }
});

test('Phylax\'s package never imports Oqelira: the host passes its module in', async () => {
  const { readdir: list, readFile: read } = await import('node:fs/promises');
  const sourceDir = fileURLToPath(new URL('../../src/', import.meta.url));
  const files = [...(await list(sourceDir)).map((f) => path.join(sourceDir, f)), ...(await list(path.join(sourceDir, 'adapters'))).map((f) => path.join(sourceDir, 'adapters', f))].filter((f) => f.endsWith('.ts'));
  assert.ok(files.length > 8);
  for (const file of files) {
    const imports = (await read(file, 'utf8')).split('\n').filter((line) => /^\s*(import|export)\b.*\bfrom\b|^\s*(const|let)\b.*\bimport\(|\brequire\(/.test(line));
    for (const line of imports) assert.equal(/oqelira(?!_?fil)|changes\.mjs|\/tools\//i.test(line.replace(/\.\/adapters\/oqelira\.js|\.\/oqelira\.js|OqeliraFileChanger|OqeliraChangesModule|OQELIRA_MAX_CONTENT_CHARS|oqeliraChanges/g, '')), false, `${path.basename(file)} imports a host: ${line.trim()}`);
  }
  void mkdir;
});
