import assert from 'node:assert/strict';
import { chmod, mkdir, readFile, readdir, stat, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { test } from 'node:test';

import { DiskFileChanger, sha256Text } from '../src/adapters/disk.js';
import { ChangeRefusedError, FileUnreadableError, StaleFileError } from '../src/errors.js';
import { sortPaths } from '../src/project-files.js';
import { tempProject } from './helpers.js';

const isWindows = process.platform === 'win32';

test('read returns the exact text and its SHA-256, line endings and byte order mark included', async () => {
  const project = await tempProject({ 'lf.js': 'a = 1\nb = 2\n', 'crlf.js': 'a = 1\r\nb = 2\r\n', 'bom.js': Buffer.from('\uFEFFconst x = 1;\n', 'utf8'), 'uni.js': '// caf\u00e9 \u65e5\u672c\u8a9e \u{1F600}\n' });
  try {
    const host = new DiskFileChanger(project.root);
    for (const name of ['lf.js', 'crlf.js', 'bom.js', 'uni.js']) {
      const snapshot = await host.read(name);
      const bytes = await readFile(path.join(project.root, name));
      assert.equal(Buffer.from(snapshot.content, 'utf8').equals(bytes), true, `${name}: the text is exactly the file's bytes`);
      assert.equal(snapshot.sha256, sha256Text(snapshot.content));
      assert.match(snapshot.sha256, /^[0-9a-f]{64}$/);
    }
    assert.equal((await host.read('crlf.js')).content, 'a = 1\r\nb = 2\r\n');
    assert.notEqual((await host.read('crlf.js')).sha256, (await host.read('lf.js')).sha256, 'CRLF and LF files hash differently');
    assert.equal((await host.read('bom.js')).content.startsWith('\uFEFF'), true, 'a byte order mark is kept');
    // known values, so an implementation that hashes something else cannot pass
    assert.equal(sha256Text(''), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    assert.equal(sha256Text('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    assert.equal(sha256Text('caf\u00e9'), '850f7dc43910ff890f8879c0ed26fe697c93a067ad93a7d50f466a7028a9bf4e');
  } finally { await project.cleanup(); }
});

test('read refuses what is not plain UTF-8 text, and what is not a regular file', async () => {
  const project = await tempProject({ 'ok.js': 'x\n', 'bad.js': Buffer.from([0x66, 0x6f, 0xff, 0xfe, 0x0a]), 'nul.js': Buffer.from('a\0b\n'), 'big.js': 'x'.repeat(5000) });
  try {
    await mkdir(path.join(project.root, 'dir.js'));
    const host = new DiskFileChanger(project.root, { maxReadBytes: 1000 });
    await assert.rejects(host.read('bad.js'), FileUnreadableError);
    await assert.rejects(host.read('nul.js'), FileUnreadableError);
    await assert.rejects(host.read('big.js'), /larger than 1000 bytes/);
    await assert.rejects(host.read('dir.js'), FileUnreadableError);
    await assert.rejects(host.read('missing.js'), FileUnreadableError);
    assert.equal((await host.read('ok.js')).content, 'x\n');
  } finally { await project.cleanup(); }
});

test('paths can never leave the project or reach protected files', async () => {
  const project = await tempProject({ 'a.js': 'x\n', '.env': 'SECRET=1\n', '.git/config': '[core]\n', 'key.pem': 'k\n', 'sub/ok.js': 'y\n', '.env.example': 'SECRET=\n' });
  const outside = await tempProject({ 'outside.js': 'secret\n' });
  try {
    const host = new DiskFileChanger(project.root);
    for (const bad of ['../outside.js', '..\\outside.js', 'sub/../../outside.js', '/etc/passwd', 'C:\\Windows\\win.ini', 'c:/x.js', '', 'a\0.js', '.', '..']) {
      await assert.rejects(host.read(bad), ChangeRefusedError, `read(${JSON.stringify(bad)}) must be refused`);
      await assert.rejects(host.apply({ path: bad, expectedSha256: 'x', content: 'y' }), ChangeRefusedError, `apply(${JSON.stringify(bad)}) must be refused`);
    }
    for (const protectedPath of ['.env', '.git/config', 'key.pem', '.env.local', 'sub/.ssh/id_rsa', '.aws/credentials']) {
      await assert.rejects(host.read(protectedPath), ChangeRefusedError, `${protectedPath} is protected`);
    }
    assert.equal((await host.read('.env.example')).content, 'SECRET=\n', 'an example env file is not a secret');
    assert.equal((await host.read('sub/./ok.js')).path, 'sub/ok.js', 'a path is normalized');
    assert.equal((await host.read('sub\\ok.js')).path, 'sub/ok.js', 'backslashes are treated as separators');
    if (!isWindows) {                                                          // a symlink that points outside must not be followed
      await symlink(path.join(outside.root, 'outside.js'), path.join(project.root, 'link.js'));
      await symlink(outside.root, path.join(project.root, 'linkdir'));
      await assert.rejects(host.read('link.js'), ChangeRefusedError);                    // a symlink that leaves the project is refused outright
      await assert.rejects(host.read('linkdir/outside.js'), ChangeRefusedError);
      await assert.rejects(host.apply({ path: 'linkdir/outside.js', expectedSha256: sha256Text('secret\n'), content: 'pwned\n' }), ChangeRefusedError);
      assert.equal(await readFile(path.join(outside.root, 'outside.js'), 'utf8'), 'secret\n', 'the file outside was never touched');
    }
  } finally { await project.cleanup(); await outside.cleanup(); }
});

test('listFiles walks the project like the Python tool: skips other people\'s code, build output and minified files, in a stable order', async () => {
  const names = ['src/index.ts', 'src/App.tsx', 'src/util.js', 'src/lib.mjs', 'src/legacy.cjs', 'src/Widget.jsx', 'app.py', 'README.md', 'package.json',
    'src/types.d.ts', 'src/app.min.js', 'src/app.bundle.js', 'node_modules/x/index.js', 'vendor/jquery.js', 'dist/main.js', 'build/o.js', '.next/page.js', 'coverage/c.js', '.hidden/h.js', '.env', 'key.pem',
    '.env.js', '.env.local.ts',                                           // protected names are never listed, even when their extension is a source one
    'config/app.yaml', 'config/app.yml', 'settings.toml', 'conf/db.ini', 'db.properties', 'web.config', 'notes.txt', 'config/prod.json',        // configuration and text files: checked for secrets
    'package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'static/bundle.min.json', 'tsconfig.tsbuildinfo', 'app.js.map',                // lock files and generated files: never
    'node_modules/x/config.json', 'dist/c.json', 'vendor/v.yaml', '.hidden/h.json', '.env.json', '.aws/credentials.json', 'secrets.pem.txt.key'];  // other people's folders and protected names: never
  const project = await tempProject(Object.fromEntries(names.map((n) => [n, 'x = 1\n'])));
  try {
    const host = new DiskFileChanger(project.root);
    assert.deepEqual(await host.listFiles({ kind: 'project' }), [
      'app.py', 'conf/db.ini', 'config/app.yaml', 'config/app.yml', 'config/prod.json', 'db.properties', 'notes.txt', 'package.json', 'settings.toml',
      'src/App.tsx', 'src/Widget.jsx', 'src/index.ts', 'src/legacy.cjs', 'src/lib.mjs', 'src/util.js', 'web.config',
    ], 'source code and configuration files, in a stable order; lock files, generated files, other people\'s folders and protected names are not listed');
    assert.deepEqual(await host.listFiles({ kind: 'files', paths: ['src/util.js', 'app.py', 'src/util.js', 'src\\util.js'] }), ['app.py', 'src/util.js'], 'chosen files are de-duplicated and sorted');
    assert.deepEqual(await host.listFiles({ kind: 'files', paths: ['README.md', 'dist/main.js'] }), ['README.md', 'dist/main.js'], 'a file you name yourself is always used');
    await assert.rejects(host.listFiles({ kind: 'files', paths: ['nope.js'] }), /does not exist/);
    await assert.rejects(host.listFiles({ kind: 'files', paths: ['src'] }), /not a file/);
    await assert.rejects(host.listFiles({ kind: 'files', paths: ['.env'] }), ChangeRefusedError);
  } finally { await project.cleanup(); }
});

test('file order is plain string order, whatever order the operating system lists them in', () => {
  assert.deepEqual(sortPaths(['b.js', 'B.js', 'sub/z.js', 'a.js', 'Sub/a.js', 'A.js']), ['A.js', 'B.js', 'Sub/a.js', 'a.js', 'b.js', 'sub/z.js'], 'uppercase before lowercase: not the case-insensitive order Windows lists files in');
  const original = ['b.js', 'a.js'];
  sortPaths(original);
  assert.deepEqual(original, ['b.js', 'a.js'], 'the input is not modified');
});

test('apply replaces the file only if its hash is unchanged, writes the text exactly, and leaves nothing behind', async () => {
  const original = 'const a = 1;\r\nconst b = 2;\r\n';
  const corrected = 'const a = 1;\r\nconst b = 3;\r\n';
  const project = await tempProject({ 'a.js': original, 'b.js': 'untouched\n' });
  try {
    const host = new DiskFileChanger(project.root);
    const before = await host.read('a.js');
    const applied = await host.apply({ path: 'a.js', expectedSha256: before.sha256, content: corrected });
    assert.equal(applied.sha256, sha256Text(corrected));
    assert.ok(applied.changeId);
    const onDisk = await readFile(path.join(project.root, 'a.js'));
    assert.equal(onDisk.toString('utf8'), corrected);
    assert.equal(onDisk.includes(Buffer.from('\r\n')), true, 'Windows line endings are kept: no translation');
    assert.equal(onDisk.toString('utf8').replace(/\r\n/g, '').includes('\n'), false, 'and no bare LF appears');
    assert.deepEqual((await readdir(project.root)).sort(), ['a.js', 'b.js'], 'no temporary file is left behind');

    // stale: the same expected hash no longer matches, so nothing is written
    await assert.rejects(host.apply({ path: 'a.js', expectedSha256: before.sha256, content: 'overwritten\n' }), StaleFileError);
    assert.equal(await readFile(path.join(project.root, 'a.js'), 'utf8'), corrected);
    await assert.rejects(host.apply({ path: 'gone.js', expectedSha256: before.sha256, content: 'x' }), StaleFileError, 'a file that disappeared is stale');
    assert.deepEqual((await readdir(project.root)).sort(), ['a.js', 'b.js']);
    if (!isWindows) {                                                          // the file's permissions survive the replacement
      await chmod(path.join(project.root, 'b.js'), 0o750);
      const b = await host.read('b.js');
      await host.apply({ path: 'b.js', expectedSha256: b.sha256, content: 'changed\n' });
      assert.equal((await stat(path.join(project.root, 'b.js'))).mode & 0o777, 0o750);
    }
  } finally { await project.cleanup(); }
});

test('apply does not overwrite a file that changes while the write is being prepared', async () => {
  const project = await tempProject({ 'a.js': 'original\n' });
  try {
    let reads = 0;
    class Racy extends DiskFileChanger {
      override async read(relative: string) {
        reads += 1;
        if (reads === 2) await writeFile(path.join(project.root, 'a.js'), 'someone else edited this\n');   // a person saves just before our rename
        return super.read(relative);
      }
    }
    const host = new Racy(project.root);
    const sha = sha256Text('original\n');
    await assert.rejects(host.apply({ path: 'a.js', expectedSha256: sha, content: 'corrected\n' }), StaleFileError);
    assert.equal(await readFile(path.join(project.root, 'a.js'), 'utf8'), 'someone else edited this\n', 'the other edit survives');
    assert.deepEqual(await readdir(project.root), ['a.js'], 'and the temporary file is cleaned up');
  } finally { await project.cleanup(); }
});

test('revert restores the previous text, only while the file is as it was left, and only once', async () => {
  const project = await tempProject({ 'a.js': 'one\n', 'b.js': 'two\n' });
  try {
    const host = new DiskFileChanger(project.root);
    const a = await host.read('a.js');
    const change = await host.apply({ path: 'a.js', expectedSha256: a.sha256, content: 'ONE\n' });
    const restored = await host.revert(change.changeId as string);
    assert.equal(restored.sha256, a.sha256);
    assert.equal(await readFile(path.join(project.root, 'a.js'), 'utf8'), 'one\n');
    await assert.rejects(host.revert(change.changeId as string), ChangeRefusedError, 'a change is reverted once');
    await assert.rejects(host.revert('00000000-0000-0000-0000-000000000000'), ChangeRefusedError);

    const b = await host.read('b.js');
    const second = await host.apply({ path: 'b.js', expectedSha256: b.sha256, content: 'TWO\n' });
    await writeFile(path.join(project.root, 'b.js'), 'edited since\n');
    await assert.rejects(host.revert(second.changeId as string), StaleFileError, 'a file edited since is not reverted');
    assert.equal(await readFile(path.join(project.root, 'b.js'), 'utf8'), 'edited since\n');
  } finally { await project.cleanup(); }
});
