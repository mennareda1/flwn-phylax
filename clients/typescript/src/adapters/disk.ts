/**
 * src/adapters/disk.ts
 *
 * A FileChanger for a plain folder: it works with any agent, or with none. What it guarantees:
 *   - a write happens only if the file still has the hash it was scanned with (otherwise StaleFileError, and nothing is written);
 *   - text is written exactly as given: no line-ending translation, byte order marks kept;
 *   - a file is replaced atomically (written beside it, then renamed over it), so a crash never leaves half a file;
 *   - nothing outside the project folder, and nothing protected (.git, .env, keys...), is ever read or written;
 *   - what was written is read back and checked before the call returns.
 * Changes can be reverted within the same session (the previous text is kept in memory; nothing extra is written into the project).
 */

import { createHash, randomUUID } from 'node:crypto';
import { chmod, lstat, open, readFile, rename, rm } from 'node:fs/promises';
import path from 'node:path';

import { ChangeRefusedError, FileUnreadableError, StaleFileError } from '../errors.js';
import type { AppliedChange, FileChange, FileChanger, FileSelection, FileSnapshot, HostCapabilities } from '../interfaces.js';
import { resolveInside, selectFiles } from '../project-files.js';

export const MAX_READ_BYTES = 2_000_000;

export function sha256Text(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });      // ignoreBOM: a byte order mark stays in the text, so the hash matches the bytes

interface Recorded {
  path: string;
  before: string;
  beforeSha: string;
  afterSha: string;
}

export interface DiskFileChangerOptions {
  /** Refuse to read files larger than this many bytes. */
  maxReadBytes?: number;
  capabilities?: HostCapabilities;
}

export class DiskFileChanger implements FileChanger {
  readonly capabilities: HostCapabilities;
  private readonly root: string;
  private readonly maxReadBytes: number;
  private readonly ledger = new Map<string, Recorded>();

  constructor(root: string, options: DiskFileChangerOptions = {}) {
    this.root = path.resolve(root);
    this.maxReadBytes = options.maxReadBytes ?? MAX_READ_BYTES;
    this.capabilities = options.capabilities ?? {};
  }

  listFiles(selection: FileSelection): Promise<string[]> {
    return selectFiles(this.root, selection);
  }

  async read(relativePath: string): Promise<FileSnapshot> {
    const { absolute, relative } = await resolveInside(this.root, relativePath);
    let stat;
    try {
      stat = await lstat(absolute);
    } catch {
      throw new FileUnreadableError(`${relative} does not exist.`);
    }
    if (!stat.isFile()) throw new FileUnreadableError(`${relative} is not a regular file.`);
    if (stat.size > this.maxReadBytes) throw new FileUnreadableError(`${relative} is larger than ${this.maxReadBytes} bytes.`);
    const bytes = await readFile(absolute);
    let content: string;
    try {
      content = decoder.decode(bytes);
    } catch {
      throw new FileUnreadableError(`${relative} is not valid UTF-8 text.`);
    }
    if (content.includes('\0') || !Buffer.from(content, 'utf8').equals(bytes)) throw new FileUnreadableError(`${relative} is not plain UTF-8 text.`);
    return { path: relative, content, sha256: sha256Text(content) };
  }

  async apply(change: FileChange): Promise<AppliedChange> {
    const { absolute, relative } = await resolveInside(this.root, change.path);
    let current: FileSnapshot;
    try {
      current = await this.read(relative);
    } catch (error) {
      if (error instanceof FileUnreadableError) throw new StaleFileError(`${relative} can no longer be read as it was when it was scanned (${error.message}).`);
      throw error;
    }
    if (current.sha256 !== change.expectedSha256) throw new StaleFileError(`${relative} changed after it was scanned, so the correction was not applied.`);
    const written = await this.replace(absolute, relative, change.content, current.sha256);
    const changeId = randomUUID();
    this.ledger.set(changeId, { path: relative, before: current.content, beforeSha: current.sha256, afterSha: written });
    return { path: relative, sha256: written, changeId };
  }

  async revert(changeId: string): Promise<AppliedChange> {
    const record = this.ledger.get(changeId);
    if (!record) throw new ChangeRefusedError('That change is not known to this session, so it cannot be reverted.');
    const { absolute } = await resolveInside(this.root, record.path);
    const current = await this.read(record.path);
    if (current.sha256 !== record.afterSha) throw new StaleFileError(`${record.path} changed after the correction was applied, so it was not reverted.`);
    const restored = await this.replace(absolute, record.path, record.before, current.sha256);
    this.ledger.delete(changeId);
    return { path: record.path, sha256: restored };
  }

  /** Write beside the file, check, rename over it, read back. Returns the hash of what is now on disk. */
  private async replace(absolute: string, relative: string, content: string, expectedBefore: string): Promise<string> {
    const stat = await lstat(absolute);
    const temp = path.join(path.dirname(absolute), `.phylax-${randomUUID()}.tmp`);
    const handle = await open(temp, 'wx', stat.mode & 0o777);
    try {
      await handle.writeFile(Buffer.from(content, 'utf8'));
      await handle.sync();
    } finally {
      await handle.close();
    }
    try {
      await chmod(temp, stat.mode & 0o777);
      const still = await this.read(relative);                           // one last look: if it changed while we prepared the write, do not overwrite it
      if (still.sha256 !== expectedBefore) throw new StaleFileError(`${relative} changed while the correction was being written, so it was not applied.`);
      await rename(temp, absolute);
    } catch (error) {
      await rm(temp, { force: true });
      throw error;
    }
    const after = await this.read(relative);
    if (after.sha256 !== sha256Text(content)) throw new ChangeRefusedError(`${relative} does not contain what was written.`);
    return after.sha256;
  }
}
