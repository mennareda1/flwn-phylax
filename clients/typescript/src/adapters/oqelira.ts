/**
 * src/adapters/oqelira.ts
 *
 * The Oqelira adapter: a FileChanger that makes changes through Oqelira's own reviewed change mechanism (snapshotFile, applyFileChange,
 * readFileChange in changes.mjs), so a correction is recorded in Oqelira's change ledger and can be reverted with Oqelira's own revert.
 *
 * This package never imports Oqelira. The host passes its module in, so Phylax stays independent of it:
 *
 *     import * as changes from './changes.mjs';
 *     const files = new OqeliraFileChanger({ cwd: projectFolder, changes });
 *
 * Oqelira's mechanism takes files of up to 10,000 characters. Larger files can still be SCANNED (they are read from disk), but a correction to
 * them is shown and not applied (capabilities.maxContentChars says so, and the review checks it before asking the person anything).
 */

import { ChangeRefusedError, FileUnreadableError, StaleFileError } from '../errors.js';
import type { AppliedChange, FileChange, FileChanger, FileSelection, FileSnapshot, HostCapabilities } from '../interfaces.js';
import { DiskFileChanger } from './disk.js';

/** The part of Oqelira's changes module this adapter uses. */
export interface OqeliraChangesModule {
  snapshotFile(cwd: string, name: string): Promise<{ path: string; exists: boolean; content: string | null; sha256: string | null }>;
  applyFileChange(cwd: string, input: { path: string; expected_sha256: string | null; content: string | null; change_id?: string }, revert?: boolean, signal?: AbortSignal): Promise<string>;
  readFileChange(cwd: string, id: string): Promise<{ change_id: string; path: string; expected_sha256: string | null; content: string | null }>;
}

export interface OqeliraFileChangerOptions {
  /** The project folder Oqelira works in. */
  cwd: string;
  /** Oqelira's changes module (see above). */
  changes: OqeliraChangesModule;
  signal?: AbortSignal;
}

export const OQELIRA_MAX_CONTENT_CHARS = 10_000;

export class OqeliraFileChanger implements FileChanger {
  readonly capabilities: HostCapabilities = { maxContentChars: OQELIRA_MAX_CONTENT_CHARS };
  private readonly cwd: string;
  private readonly changes: OqeliraChangesModule;
  private readonly signal: AbortSignal | undefined;
  private readonly disk: DiskFileChanger;           // used only to list and to READ files too large for Oqelira's mechanism; it never writes

  constructor(options: OqeliraFileChangerOptions) {
    this.cwd = options.cwd;
    this.changes = options.changes;
    this.signal = options.signal;
    this.disk = new DiskFileChanger(options.cwd);
  }

  listFiles(selection: FileSelection): Promise<string[]> {
    return this.disk.listFiles(selection);
  }

  async read(path: string): Promise<FileSnapshot> {
    try {
      const snapshot = await this.changes.snapshotFile(this.cwd, path);
      if (!snapshot.exists || snapshot.content === null || snapshot.sha256 === null) throw new FileUnreadableError(`${path} does not exist.`);
      return { path: snapshot.path, content: snapshot.content, sha256: snapshot.sha256 };
    } catch (error) {
      if (error instanceof FileUnreadableError) throw error;
      const message = error instanceof Error ? error.message : String(error);
      if (/at most 10000 characters/i.test(message)) return this.disk.read(path);       // too big to CHANGE through Oqelira, still fine to scan
      throw new FileUnreadableError(message);
    }
  }

  async apply(change: FileChange): Promise<AppliedChange> {
    let raw: string;
    try {
      raw = await this.changes.applyFileChange(this.cwd, { path: change.path, expected_sha256: change.expectedSha256, content: change.content }, false, this.signal);
    } catch (error) {
      throw translate(error);
    }
    const result = parseResult(raw);
    return { path: change.path, sha256: result.sha256, ...(result.changeId ? { changeId: result.changeId } : {}) };
  }

  async revert(changeId: string): Promise<AppliedChange> {
    try {
      const record = await this.changes.readFileChange(this.cwd, changeId);
      const raw = await this.changes.applyFileChange(this.cwd, record, true, this.signal);
      const result = parseResult(raw);
      return { path: record.path, sha256: result.sha256 };
    } catch (error) {
      throw translate(error);
    }
  }
}

function translate(error: unknown): Error {
  const message = error instanceof Error ? error.message : String(error);
  if (/changed since preview/i.test(message)) return new StaleFileError('The file changed after it was scanned, so the correction was not applied.');
  return new ChangeRefusedError(message);
}

function parseResult(raw: string): { sha256: string; changeId: string | undefined } {
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    throw new ChangeRefusedError('Oqelira answered with something this adapter does not understand.');
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new ChangeRefusedError('Oqelira answered with something this adapter does not understand.');
  const record = value as { sha256?: unknown; change_id?: unknown; after?: { sha256?: unknown } };
  const sha = typeof record.sha256 === 'string' ? record.sha256 : typeof record.after?.sha256 === 'string' ? record.after.sha256 : null;
  if (sha === null) throw new ChangeRefusedError('Oqelira did not report the hash of the changed file.');
  return { sha256: sha, changeId: typeof record.change_id === 'string' ? record.change_id : undefined };
}
