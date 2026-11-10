import assert from 'node:assert/strict';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { test } from 'node:test';

import { HttpPhylaxApi } from '../src/api.js';
import { PhylaxApiError } from '../src/errors.js';

const KEY = 'sk_test_0123456789abcdefghij0123456789';

interface Seen { method: string; url: string; headers: IncomingMessage['headers']; body: string }
type Script = (request: Seen, count: number, response: ServerResponse) => void;

async function serve(script: Script): Promise<{ url: string; seen: Seen[]; close: () => Promise<void> }> {
  const seen: Seen[] = [];
  const server: Server = createServer((request, response) => {
    const chunks: Buffer[] = [];
    request.on('data', (c: Buffer) => chunks.push(c));
    request.on('end', () => {
      const entry = { method: request.method ?? '', url: request.url ?? '', headers: request.headers, body: Buffer.concat(chunks).toString('utf8') };
      seen.push(entry);
      script(entry, seen.length, response);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as AddressInfo).port;
  return { url: `http://127.0.0.1:${port}`, seen, close: () => new Promise<void>((resolve) => { server.closeAllConnections(); server.close(() => resolve()); }) };
}

const json = (response: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void => {
  response.writeHead(status, { 'Content-Type': 'application/json', ...headers });
  response.end(JSON.stringify(body));
};
const problem = (response: ServerResponse, status: number, code: string, headers: Record<string, string> = {}): void =>
  json(response, status, { type: 'about:blank', title: code.replace(/_/g, ' '), status, detail: 'Something happened.', code, request_id: 'req_abc123' }, headers);

const noSleep = (log: number[] = []) => async (ms: number): Promise<void> => { log.push(ms); };
const scanDone = { id: 'scn_1', status: 'completed', report: { status: 'completed', decision: 'pass', findings: [], coverage: {} } };

test('a scan is sent the way the contract says, and the key travels only in the Authorization header', async () => {
  const server = await serve((_r, _n, response) => json(response, 200, scanDone));
  try {
    const api = new HttpPhylaxApi({ baseUrl: server.url, apiKey: KEY, waitSeconds: 20 });
    const scan = await api.scan([{ path: 'a.js', content: 'x = 1\n' }], { clientRef: 'task-7' });
    assert.equal(scan.id, 'scn_1');
    const request = server.seen[0] as Seen;
    assert.equal(request.method, 'POST');
    assert.equal(request.url, '/v1/scans');
    assert.equal(request.headers['authorization'], `Bearer ${KEY}`);
    assert.equal(request.headers['content-type'], 'application/json; charset=utf-8');
    assert.equal(request.headers['prefer'], 'wait=20');
    assert.match(String(request.headers['idempotency-key']), /^[0-9a-f-]{36}$/);
    assert.deepEqual(JSON.parse(request.body), { files: [{ path: 'a.js', content: 'x = 1\n' }], client_ref: 'task-7' });
    assert.equal(request.url.includes(KEY) || request.body.includes(KEY), false, 'the key is not in the URL or the body');
  } finally { await server.close(); }
});

test('fix and verification requests carry exactly what the contract defines', async () => {
  const server = await serve((request, _n, response) => json(response, 200, request.url.startsWith('/v1/verifications') ? { id: 'ver_1', status: 'completed', outcome: 'passed' } : { id: 'fix_1', status: 'completed', applicable: true }));
  try {
    const api = new HttpPhylaxApi({ baseUrl: server.url, apiKey: KEY });
    await api.fix('scn_1', { findingIds: ['f1', 'f2'], maxPatchLines: 60 });
    await api.fix('scn_1');
    await api.verify('scn_1', [{ path: 'a.js', content: 'y\n' }]);
    await api.deleteScan('scn_1').catch(() => undefined);
    assert.equal(server.seen[0]?.url, '/v1/scans/scn_1/fixes');
    assert.deepEqual(JSON.parse(server.seen[0]?.body ?? ''), { finding_ids: ['f1', 'f2'], max_patch_lines: 60 });
    assert.deepEqual(JSON.parse(server.seen[1]?.body ?? ''), {}, 'no finding ids means the service chooses its default');
    assert.equal(server.seen[2]?.url, '/v1/verifications');
    assert.deepEqual(JSON.parse(server.seen[2]?.body ?? ''), { scan_id: 'scn_1', files: [{ path: 'a.js', content: 'y\n' }] });
    assert.equal(server.seen[3]?.method, 'DELETE');
    assert.equal(server.seen[3]?.url, '/v1/scans/scn_1');
    const keys = server.seen.slice(0, 3).map((s) => s.headers['idempotency-key']);
    assert.equal(new Set(keys).size, 3, 'separate operations never share an idempotency key');
    assert.equal(server.seen[3]?.headers['idempotency-key'], undefined, 'only POSTs carry one');
  } finally { await server.close(); }
});

test('a job that is still running is polled until it finishes', async () => {
  const server = await serve((request, n, response) => {
    if (request.method === 'POST') return json(response, 202, { id: 'scn_9', status: 'queued', report: null }, { Location: '/v1/scans/scn_9' });
    json(response, 200, n < 4 ? { id: 'scn_9', status: 'running', report: null } : { ...scanDone, id: 'scn_9' });
  });
  try {
    const sleeps: number[] = [];
    const api = new HttpPhylaxApi({ baseUrl: server.url, apiKey: KEY, sleep: noSleep(sleeps), pollIntervalMs: 250 });
    const scan = await api.scan([{ path: 'a.js', content: 'x' }]);
    assert.equal(scan.status, 'completed');
    assert.deepEqual(server.seen.map((s) => `${s.method} ${s.url}`), ['POST /v1/scans', 'GET /v1/scans/scn_9', 'GET /v1/scans/scn_9', 'GET /v1/scans/scn_9']);
    assert.deepEqual(sleeps, [250, 250, 250]);
    assert.equal(server.seen[1]?.headers['idempotency-key'], undefined);
  } finally { await server.close(); }
});

test('a job that never finishes ends with a clear timeout, and a failed job is reported as failed', async () => {
  const forever = await serve((request, _n, response) => json(response, request.method === 'POST' ? 202 : 200, { id: 'scn_1', status: 'running', report: null }));
  const failing = await serve((_r, _n, response) => json(response, 200, { id: 'scn_2', status: 'failed', report: null }));
  try {
    const slow = new HttpPhylaxApi({ baseUrl: forever.url, apiKey: KEY, timeoutMs: 40, pollIntervalMs: 5 });
    await assert.rejects(slow.scan([{ path: 'a.js', content: 'x' }]), (error: unknown) => error instanceof PhylaxApiError && error.code === 'timeout');
    const broken = new HttpPhylaxApi({ baseUrl: failing.url, apiKey: KEY });
    await assert.rejects(broken.scan([{ path: 'a.js', content: 'x' }]), (error: unknown) => error instanceof PhylaxApiError && error.code === 'job_failed');
  } finally { await forever.close(); await failing.close(); }
});

test('rate limiting waits for Retry-After and retries with the SAME idempotency key', async () => {
  const server = await serve((_r, n, response) => (n < 3 ? problem(response, 429, 'rate_limited', { 'Retry-After': '7' }) : json(response, 200, scanDone)));
  try {
    const sleeps: number[] = [];
    const api = new HttpPhylaxApi({ baseUrl: server.url, apiKey: KEY, sleep: noSleep(sleeps) });
    assert.equal((await api.scan([{ path: 'a.js', content: 'x' }])).id, 'scn_1');
    assert.equal(server.seen.length, 3);
    assert.deepEqual(sleeps, [7000, 7000], 'it waited as long as the service asked');
    assert.equal(new Set(server.seen.map((s) => s.headers['idempotency-key'])).size, 1, 'one key for the whole operation, so a retry can never run twice');
  } finally { await server.close(); }
});

test('Retry-After is capped, server errors back off and retry, and giving up reports the service\'s own error', async () => {
  const capped = await serve((_r, n, response) => (n < 2 ? problem(response, 429, 'rate_limited', { 'Retry-After': '9999' }) : json(response, 200, scanDone)));
  const flaky = await serve((_r, n, response) => (n < 3 ? problem(response, 503, 'provider_unavailable') : json(response, 200, scanDone)));
  const hopeless = await serve((_r, _n, response) => problem(response, 429, 'rate_limited', { 'Retry-After': '2' }));
  try {
    const cappedSleeps: number[] = [];
    await new HttpPhylaxApi({ baseUrl: capped.url, apiKey: KEY, sleep: noSleep(cappedSleeps) }).scan([{ path: 'a.js', content: 'x' }]);
    assert.deepEqual(cappedSleeps, [30000], 'a huge Retry-After is capped at 30 seconds');

    const flakySleeps: number[] = [];
    await new HttpPhylaxApi({ baseUrl: flaky.url, apiKey: KEY, sleep: noSleep(flakySleeps) }).scan([{ path: 'a.js', content: 'x' }]);
    assert.deepEqual(flakySleeps, [500, 1000], 'exponential backoff');

    await assert.rejects(new HttpPhylaxApi({ baseUrl: hopeless.url, apiKey: KEY, sleep: noSleep(), maxRetries: 2 }).scan([{ path: 'a.js', content: 'x' }]), (error: unknown) => {
      assert.ok(error instanceof PhylaxApiError);
      assert.equal(error.code, 'rate_limited');
      assert.equal(error.status, 429);
      assert.equal(error.requestId, 'req_abc123');
      assert.equal(error.retryAfterSeconds, 2);
      return true;
    });
    assert.equal(hopeless.seen.length, 3, 'the first try plus two retries');
  } finally { await capped.close(); await flaky.close(); await hopeless.close(); }
});

test('errors that retrying cannot fix are thrown at once, with the service\'s code, and never contain the key or submitted code', async () => {
  for (const [status, code] of [[401, 'unauthorized'], [403, 'forbidden'], [404, 'not_found'], [413, 'payload_too_large'], [409, 'fix_limit_reached'], [409, 'scan_not_completed'], [501, 'not_implemented'], [400, 'invalid_request']] as const) {
    const server = await serve((_r, _n, response) => problem(response, status, code));
    try {
      const api = new HttpPhylaxApi({ baseUrl: server.url, apiKey: KEY, sleep: noSleep() });
      await assert.rejects(api.scan([{ path: 'a.js', content: 'SUPER_SECRET_CODE' }]), (error: unknown) => {
        assert.ok(error instanceof PhylaxApiError);
        assert.equal(error.code, code);
        assert.equal(error.status, status);
        assert.equal(`${error.message}${error.stack ?? ''}`.includes(KEY), false, 'the key is not in the error');
        assert.equal(`${error.message}`.includes('SUPER_SECRET_CODE'), false, 'submitted code is not in the error');
        return true;
      });
      assert.equal(server.seen.length, 1, `${status} ${code} is not retried`);
    } finally { await server.close(); }
  }
  const odd = await serve((_r, _n, response) => { response.writeHead(500, { 'Content-Type': 'text/html' }); response.end('<html>boom ' + KEY + '</html>'); });
  try {
    await assert.rejects(new HttpPhylaxApi({ baseUrl: odd.url, apiKey: KEY }).capabilities(), (error: unknown) => {
      assert.ok(error instanceof PhylaxApiError);
      assert.equal(error.code, 'http_error');
      assert.equal(error.message.includes('boom') || error.message.includes(KEY), false, 'an unexpected body is never echoed');
      return true;
    });
  } finally { await odd.close(); }
  const strange = await serve((_r, _n, response) => json(response, 500, { oops: 'SUPER_SECRET_CODE and ' + KEY }));      // JSON, but not the service's error format
  try {
    await assert.rejects(new HttpPhylaxApi({ baseUrl: strange.url, apiKey: KEY, sleep: noSleep() }).capabilities(), (error: unknown) => {
      assert.ok(error instanceof PhylaxApiError);
      assert.equal(error.code, 'http_error');
      assert.equal(`${error.message}`.includes('SUPER_SECRET_CODE') || `${error.message}`.includes(KEY), false, 'a body that is not the service\'s error format is never echoed');
      return true;
    });
  } finally { await strange.close(); }
});

test('an unreachable service is reported plainly after the retries', async () => {
  const sleeps: number[] = [];
  const api = new HttpPhylaxApi({ baseUrl: 'http://127.0.0.1:9', apiKey: KEY, sleep: noSleep(sleeps), maxRetries: 2 });
  await assert.rejects(api.capabilities(), (error: unknown) => error instanceof PhylaxApiError && error.code === 'unreachable' && !error.message.includes(KEY));
  assert.deepEqual(sleeps, [500, 1000]);
});

test('the key is never sent over plain http to a remote host, and a bad configuration is refused', () => {
  const base = { apiKey: KEY };
  for (const url of ['http://localhost:8080', 'http://127.0.0.1:8080', 'https://phylax.example.com', 'https://phylax.example.com/api/', 'http://[::1]:8080']) {
    assert.doesNotThrow(() => new HttpPhylaxApi({ ...base, baseUrl: url }), url);
  }
  assert.throws(() => new HttpPhylaxApi({ ...base, baseUrl: 'http://phylax.example.com' }), (e: unknown) => e instanceof PhylaxApiError && e.code === 'insecure_url');
  assert.doesNotThrow(() => new HttpPhylaxApi({ ...base, baseUrl: 'http://phylax.example.com', allowInsecureHttp: true }), 'the person can accept the risk explicitly');
  assert.throws(() => new HttpPhylaxApi({ ...base, baseUrl: 'ftp://phylax.example.com' }), (e: unknown) => e instanceof PhylaxApiError && e.code === 'invalid_configuration' && /https/.test(e.message));
  assert.throws(() => new HttpPhylaxApi({ ...base, baseUrl: 'not a url' }), (e: unknown) => e instanceof PhylaxApiError && e.code === 'invalid_configuration');
  assert.throws(() => new HttpPhylaxApi({ ...base, baseUrl: 'https://user:pass@phylax.example.com' }), (e: unknown) => e instanceof PhylaxApiError && e.code === 'invalid_configuration');
  assert.throws(() => new HttpPhylaxApi({ baseUrl: 'https://phylax.example.com', apiKey: '' }), (e: unknown) => e instanceof PhylaxApiError && e.code === 'invalid_configuration');
  assert.throws(() => new HttpPhylaxApi({ baseUrl: 'https://phylax.example.com', apiKey: 'has space' }), (e: unknown) => e instanceof PhylaxApiError && e.code === 'invalid_configuration');
});

test('cancelling an operation stops it at once', async () => {
  const server = await serve(() => { /* never answers */ });
  try {
    const controller = new AbortController();
    const api = new HttpPhylaxApi({ baseUrl: server.url, apiKey: KEY, timeoutMs: 5000 });
    const pending = api.scan([{ path: 'a.js', content: 'x' }], { signal: controller.signal });
    setTimeout(() => controller.abort(new Error('cancelled by the person')), 20);
    await assert.rejects(pending, /cancelled by the person/);
    assert.equal(server.seen.length, 1, 'a cancelled request is not retried');
  } finally { await server.close(); }
});
