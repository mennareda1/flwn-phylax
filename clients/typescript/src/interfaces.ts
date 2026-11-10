/**
 * src/interfaces.ts
 *
 * THE TWO THINGS A HOST AGENT PROVIDES. Phylax asks nothing else of the agent it is attached to, and it never imports a host's code: an adapter
 * for Oqelira, one for a plain folder, one for any future coding agent all implement the same two interfaces.
 *
 *   FileChanger  how Phylax reads files and (after a person approves) changes them.
 *   Approver     how a person is shown findings and diffs and says yes or no.
 *
 * Write an adapter in four methods: listFiles, read, apply, and (optionally) revert. See clients/typescript/README.md.
 */

import type { Finding, Verification } from './types.js';

// ------------------------------------------------------------------------------------------------------------------ files

/** What to review: the whole project, or exactly these project-relative paths. */
export type FileSelection = { kind: 'project' } | { kind: 'files'; paths: string[] };

/** A file as it is right now. `sha256` is the SHA-256 (lowercase hex) of `content` as UTF-8, line endings included. */
export interface FileSnapshot {
  path: string;
  content: string;
  sha256: string;
}

/** One file replaced by new content, but only if it still has the hash it had when it was scanned. */
export interface FileChange {
  path: string;
  expectedSha256: string;
  content: string;
}

export interface AppliedChange {
  path: string;
  /** The hash the file has now. Phylax compares it with the hash it expected and treats a difference as a failed write. */
  sha256: string;
  /** Present if the host can undo this change later with revert(). */
  changeId?: string;
}

export interface HostCapabilities {
  /** The largest file content, in characters, the host's change mechanism accepts. A larger correction is shown to the person but not applied. */
  maxContentChars?: number;
  /** Informational: the host already asks the person before each write (Phylax asks too: nothing is ever applied without an explicit yes). */
  hostConfirmsWrites?: boolean;
}

export interface FileChanger {
  readonly capabilities?: HostCapabilities;

  /** Turn a selection into project-relative paths with forward slashes, in a stable order. Never returns a path outside the project. */
  listFiles(selection: FileSelection): Promise<string[]>;

  /** The file as it is on disk right now. Throws FileUnreadableError if it is not UTF-8 text. */
  read(path: string): Promise<FileSnapshot>;

  /**
   * Replace the file with `content` ONLY IF its hash is still `expectedSha256`. Throws StaleFileError if it is not (nothing is written) and
   * ChangeRefusedError if the host will not make the change. Must not translate line endings: the text is written exactly as given.
   */
  apply(change: FileChange): Promise<AppliedChange>;

  /** Undo a change made by apply(), if the host supports it and the file has not changed since. */
  revert?(changeId: string): Promise<AppliedChange>;
}

// ------------------------------------------------------------------------------------------------------------- the person

/** A finding a correction can be offered for, as the person sees it. `key` identifies it in later calls. */
export interface CorrectionCandidate {
  key: string;
  finding: Finding;
}

/** A correction ready for a decision. It has already passed Phylax's own checks; nothing has been written. */
export interface ChangeProposal {
  key: string;
  path: string;
  /** What changes, as a unified diff. */
  diff: string;
  explanation: string;
  /** The findings this correction addresses. */
  findings: Finding[];
  /** What Phylax checked before showing it. */
  verification: Verification | null;
}

export interface ApprovalDecision {
  approved: boolean;
  reason?: string;
}

export interface Approver {
  /**
   * The person's explicit request: which of these findings should get a correction? Return the keys. Asking is not free (each correction is a model
   * call), so nothing is requested the person did not pick. Return [] to decline all.
   */
  chooseCorrections(candidates: CorrectionCandidate[]): Promise<string[]>;

  /** Show one correction and get a yes or no. Called once per file; nothing is written unless it returns approved: true. */
  approveChange(proposal: ChangeProposal): Promise<ApprovalDecision>;
}
