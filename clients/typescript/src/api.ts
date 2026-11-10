/**
 * src/api.ts
 *
 * The Phylax HTTP API, as a small interface (PhylaxApi) and a client for it (HttpPhylaxApi). The review workflow depends on the interface, so
 * tests and other transports can stand in for the network.
 *
 * What the HTTP client takes care of:
 *   - every POST carries an Idempotency-Key that is REUSED when the request is retried, so a retry never runs (or pays for) a second scan or fix;
 *   - 429 (rate limited) waits for the service's Retry-After; 502/503/504 and network failures back off and retry; other errors are thrown at once;
 *   - a job that is still running is polled until it finishes or the time limit passes;
 *   - the API key is sent only as a bearer header, only over https (or to a loopback address), and never appears in an error, a log line or a URL.
 */

import { randomUUID } from 'node:crypto';

import { PhylaxApiError } from './errors.js';
import type { Capabilities, Fix, InputFile, Problem, Scan, Verification } from './types.js';

export interface CallOptions {
  signal?: AbortSignal;
  /** A label of your own, kept with the job (for example a task id). Never put secrets in it. */
  clientRef?: string;
}

export interface PhylaxApi {
  capabilities(options?: CallOptions): Promise<Capabilities>;
  /** Scan these files. Resolves when the scan has finished (a slow scan is polled). */
  scan(files: InputFile[], options?: CallOptions): Promise<Scan>;
  /** Ask for corrections for findings of a finished scan. Each call may run the correction model, which costs money. */
  fix(scanId: string, options?: CallOptions & { findingIds?: string[]; maxPatchLines?: number }): Promise<Fix>;
  /** Check corrected files against a finished scan: do they still parse, do they stay in scope, and does a new scan find the problem gone? */
  verify(scanId: string, files: InputFile[], options?: CallOptions): Promise<Verification>;
  /** Remove a scan (and the code Phylax holds for it). */
  deleteScan(scanId: string, options?: CallOptions): Promise<void>;
}

export interface HttpPhylaxApiOptions {
  baseUrl: string;
  apiKey: string;
  /** Allow sending the key over plain http to a non-loopback host. Off by default. */
  allowInsecureHttp?: boolean;
  /** How long to ask the service to hold a request open for a result before it answers 202 (the service caps this). Default 25. */
  waitSeconds?: number;
  /** Time limit for one operation including polling, in milliseconds. Default 180000. */
  timeoutMs?: number;
  /** How many times a failed request is retried. Default 3. */
  maxRetries?: number;
  pollIntervalMs?: number;
  /** Injectable for tests. */
  fetch?: typeof fetch;
  sleep?: (milliseconds: number, signal?: AbortSignal) => Promise<void>;
}

const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);
const RETRYABLE = new Set([502, 503, 504]);
const MAX_RETRY_AFTER_SECONDS = 30;

export function defaultSleep(milliseconds: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(signal.reason ?? new Error('aborted'));
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, milliseconds);
    const onAbort = (): void => {
      clearTimeout(timer);
      reject(signal?.reason ?? new Error('aborted'));
    };
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

interface Reply {
  status: number;
  body: unknown;
  headers: Headers;
}

export class HttpPhylaxApi implements PhylaxApi {
  private readonly baseUrl: string;
  private readonly apiKey: string;
  private readonly waitSeconds: number;
  private readonly timeoutMs: number;
  private readonly maxRetries: number;
  private readonly pollIntervalMs: number;
  private readonly fetchImpl: typeof fetch;
  private readonly sleep: (milliseconds: number, signal?: AbortSignal) => Promise<void>;

  constructor(options: HttpPhylaxApiOptions) {
    let url: URL;
    try {
      url = new URL(options.baseUrl);
    } catch {
      throw new PhylaxApiError('invalid_configuration', 'The Phylax address is not a valid URL.');
    }
    if (url.protocol !== 'https:' && url.protocol !== 'http:') throw new PhylaxApiError('invalid_configuration', 'The Phylax address must start with https:// (or http:// for a service on this computer).');
    if (url.protocol !== 'https:' && !(LOOPBACK.has(url.hostname) || options.allowInsecureHttp)) {
      throw new PhylaxApiError('insecure_url', 'The API key would travel over plain http to a remote host. Use https, or pass allowInsecureHttp if you accept that.');
    }
    if (url.username || url.password) throw new PhylaxApiError('invalid_configuration', 'Put no credentials in the Phylax address; the key is sent as a header.');
    if (!options.apiKey || /\s/.test(options.apiKey)) throw new PhylaxApiError('invalid_configuration', 'The API key is missing or contains whitespace.');
    this.baseUrl = url.origin + url.pathname.replace(/\/+$/, '');
    this.apiKey = options.apiKey;
    this.waitSeconds = options.waitSeconds ?? 25;
    this.timeoutMs = options.timeoutMs ?? 180_000;
    this.maxRetries = options.maxRetries ?? 3;
    this.pollIntervalMs = options.pollIntervalMs ?? 1000;
    this.fetchImpl = options.fetch ?? fetch;
    this.sleep = options.sleep ?? defaultSleep;
  }

  capabilities(options: CallOptions = {}): Promise<Capabilities> {
    return this.call<Capabilities>('GET', '/v1/capabilities', undefined, options);
  }

  scan(files: InputFile[], options: CallOptions = {}): Promise<Scan> {
    const body = { files, ...(options.clientRef ? { client_ref: options.clientRef } : {}) };
    return this.job<Scan>('POST', '/v1/scans', body, '/v1/scans/', options);
  }

  fix(scanId: string, options: CallOptions & { findingIds?: string[]; maxPatchLines?: number } = {}): Promise<Fix> {
    const body = {
      ...(options.findingIds ? { finding_ids: options.findingIds } : {}),
      ...(options.maxPatchLines ? { max_patch_lines: options.maxPatchLines } : {}),
    };
    return this.job<Fix>('POST', `/v1/scans/${encodeURIComponent(scanId)}/fixes`, body, '/v1/fixes/', options);
  }

  verify(scanId: string, files: InputFile[], options: CallOptions = {}): Promise<Verification> {
    const body = { scan_id: scanId, files, ...(options.clientRef ? { client_ref: options.clientRef } : {}) };
    return this.job<Verification>('POST', '/v1/verifications', body, '/v1/verifications/', options);
  }

  async deleteScan(scanId: string, options: CallOptions = {}): Promise<void> {
    await this.call('DELETE', `/v1/scans/${encodeURIComponent(scanId)}`, undefined, options);
  }

  // ------------------------------------------------------------------------------------------------------- internals

  /** Start a job, wait for it, and return the finished job. */
  private async job<T extends { id: string; status: string }>(method: 'POST', path: string, body: unknown, pollBase: string, options: CallOptions): Promise<T> {
    const deadline = Date.now() + this.timeoutMs;
    let job = await this.call<T>(method, path, body, options, true);
    while (job.status === 'queued' || job.status === 'running') {
      if (Date.now() >= deadline) throw new PhylaxApiError('timeout', 'Phylax did not finish in time. The job is still running; try again in a moment.');
      await this.sleep(this.pollIntervalMs, options.signal);
      job = await this.call<T>('GET', `${pollBase}${encodeURIComponent(job.id)}`, undefined, options);
    }
    if (job.status === 'failed') throw new PhylaxApiError('job_failed', 'Phylax could not complete the job.');
    return job;
  }

  private async call<T>(method: string, path: string, body: unknown, options: CallOptions, waitForResult = false): Promise<T> {
    const reply = await this.send(method, path, body, options, waitForResult);
    return reply.body as T;
  }

  private async send(method: string, path: string, body: unknown, options: CallOptions, waitForResult: boolean): Promise<Reply> {
    const idempotencyKey = method === 'POST' ? randomUUID() : null;               // one key for the whole operation, reused by every retry
    const payload = body === undefined ? undefined : JSON.stringify(body);
    let delay = 500;
    for (let attempt = 0; ; attempt += 1) {
      const headers: Record<string, string> = { Authorization: `Bearer ${this.apiKey}`, Accept: 'application/json' };
      if (payload !== undefined) headers['Content-Type'] = 'application/json; charset=utf-8';
      if (idempotencyKey) headers['Idempotency-Key'] = idempotencyKey;
      if (waitForResult) headers['Prefer'] = `wait=${this.waitSeconds}`;
      const signals = [AbortSignal.timeout(this.timeoutMs), ...(options.signal ? [options.signal] : [])];
      let response: Response;
      try {
        response = await this.fetchImpl(this.baseUrl + path, { method, headers, ...(payload !== undefined ? { body: payload } : {}), signal: AbortSignal.any(signals) });
      } catch (error) {
        if (options.signal?.aborted) throw error;
        if (attempt >= this.maxRetries) throw new PhylaxApiError('unreachable', 'Could not reach Phylax. Check the address and that the service is running.');
        await this.sleep(delay, options.signal);
        delay = Math.min(delay * 2, 8000);
        continue;
      }
      const reply = await this.read(response);
      if (response.status >= 200 && response.status < 300) return reply;
      const retryAfter = parseRetryAfter(response.headers.get('retry-after'));
      if ((response.status === 429 || RETRYABLE.has(response.status)) && attempt < this.maxRetries) {
        const seconds = response.status === 429 && retryAfter !== null ? Math.min(retryAfter, MAX_RETRY_AFTER_SECONDS) : delay / 1000;
        await this.sleep(seconds * 1000, options.signal);
        delay = Math.min(delay * 2, 8000);
        continue;
      }
      throw this.errorFrom(reply, retryAfter);
    }
  }

  private async read(response: Response): Promise<Reply> {
    const text = await response.text();
    let body: unknown = null;
    if (text.length > 0) {
      try {
        body = JSON.parse(text);
      } catch {
        if (response.ok) throw new PhylaxApiError('bad_response', `Phylax answered ${response.status} with something that is not JSON.`, response.status);
      }
    }
    return { status: response.status, body, headers: response.headers };
  }

  private errorFrom(reply: Reply, retryAfter: number | null): PhylaxApiError {
    const candidate = reply.body as Partial<Problem> | null;
    if (candidate && typeof candidate === 'object' && typeof candidate.code === 'string' && typeof candidate.title === 'string') {
      return PhylaxApiError.fromProblem({ ...candidate, status: reply.status } as Problem, retryAfter);
    }
    return new PhylaxApiError('http_error', `Phylax answered with status ${reply.status}.`, reply.status, null, retryAfter);
  }
}

function parseRetryAfter(value: string | null): number | null {
  if (value === null) return null;
  const seconds = Number(value);
  return Number.isFinite(seconds) && seconds >= 0 ? seconds : null;
}
