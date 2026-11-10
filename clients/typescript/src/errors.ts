/**
 * src/errors.ts
 *
 * Every error this package throws, each with a code a host can switch on. None of them carries file content or an API key.
 */

import type { Problem } from './types.js';

export class PhylaxError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = new.target.name;
    this.code = code;
  }
}

/** The Phylax service answered with an error (or could not be reached). */
export class PhylaxApiError extends PhylaxError {
  readonly status: number | null;
  readonly requestId: string | null;
  readonly retryAfterSeconds: number | null;
  constructor(code: string, message: string, status: number | null = null, requestId: string | null = null, retryAfterSeconds: number | null = null) {
    super(code, message);
    this.status = status;
    this.requestId = requestId;
    this.retryAfterSeconds = retryAfterSeconds;
  }
  static fromProblem(problem: Problem, retryAfterSeconds: number | null = null): PhylaxApiError {
    const text = problem.detail ? `${problem.title}: ${problem.detail}` : problem.title;
    return new PhylaxApiError(problem.code, text, problem.status, problem.request_id ?? null, retryAfterSeconds);
  }
}

/** The file on disk is no longer the file that was scanned (a person or another agent changed it). Nothing was written. */
export class StaleFileError extends PhylaxError {
  constructor(message = 'The file changed after it was scanned, so the correction was not applied.') {
    super('stale_file', message);
  }
}

/** The host refused the change (blocked path, too large, not a text file...). Nothing was written. */
export class ChangeRefusedError extends PhylaxError {
  constructor(message: string) {
    super('change_refused', message);
  }
}

/** A file could not be read as UTF-8 text by the host. */
export class FileUnreadableError extends PhylaxError {
  constructor(message: string) {
    super('file_unreadable', message);
  }
}

/** A problem with how the review is being used, or with a precondition of the workflow. */
export class ReviewError extends PhylaxError {}
