"""
benchmark/cases_heldout_js.py

THE JavaScript and TypeScript HELD-OUT cases for Decision-1. Written on 2026-11-07, in the same sitting as the questions and the development
cases (benchmark/cases_javascript.py) and BEFORE any model had seen a single JavaScript case, then fingerprinted. They are for ONE final run:

    python -m benchmark.classifier_eval --language javascript --heldout

Rules of this file, the same as the Python held-out set (benchmark/cases_heldout.py):
  - Nothing here is ever used to tune the question wording. If the final run fails, the answer is "not yet", not "reword and run again".
  - The fingerprint is pinned below. The evaluation refuses to give a final verdict if a single character here has changed since.
  - 14 vulnerable cases (every one of the twelve categories at least once) and 25 safe ones, every safe one safe under ALL twelve questions.
  - Nine of the 14 vulnerable cases are built so that our JavaScript RULES do not alarm on them, so the model has real room to add something.
  - No case is debatable. Where a safe-looking snippet could be argued either way it was left out.
"""

from __future__ import annotations

from functools import partial

from benchmark.cases_heldout import fingerprint as _fingerprint_of


def _case(case_id: str, kind: str, category: str, note: str, code: str, language: str = "javascript") -> dict:
    return {"id": case_id, "kind": kind, "category": category, "note": note,
            "code": code.strip("\n") + "\n", "group": "heldout", "language": language}


# After the cases are written, `python -m benchmark.cases_heldout_js` prints the fingerprint and demo() fails until it is pinned here.
PINNED_FINGERPRINT = "7c174d9dca25"

HELDOUT_CASES: list[dict] = [
    # ================= VULNERABLE (14) =================
    _case("hj-cmd-exec-concat", "vulnerable", "command_injection", "author name concatenated into a git command run through exec", r'''
const { exec } = require('child_process');

app.get('/history', (req, res) => {
  exec('git log --oneline --author=' + req.query.author, { cwd: '/srv/repo' }, (err, out) => {
    res.type('text/plain').send(out);
  });
});
'''),
    _case("hj-cmd-sh-c-ts", "vulnerable", "command_injection", "file name run through /bin/sh -c (rules miss: no shell option)", r'''
import { execFileSync } from 'child_process';

export function compress(name: string): void {
  execFileSync('/bin/sh', ['-c', `gzip -k ${name}`], { cwd: '/srv/exports' });
}

app.post('/compress', (req, res) => {
  compress(req.body.name);
  res.sendStatus(204);
});
''', "typescript"),
    _case("hj-sql-template-ts", "vulnerable", "sql_injection", "amount and account id interpolated into an UPDATE (TypeScript)", r'''
export async function withdraw(client: Client, id: string, amount: string): Promise<void> {
  await client.query(`UPDATE accounts SET balance = balance - ${amount} WHERE id = ${id}`);
}
''', "typescript"),
    _case("hj-sql-parts-join", "vulnerable", "sql_injection", "WHERE clause assembled in an array and joined, then run (rules miss: the built text reaches query through a variable)", r'''
app.get('/items', async (req, res) => {
  const parts = ['SELECT id, title FROM items'];
  parts.push("WHERE owner = '" + req.query.owner + "'");
  parts.push('ORDER BY created_at DESC');
  const sql = parts.join(' ');
  res.json((await db.query(sql)).rows);
});
'''),
    _case("hj-code-eval-json", "vulnerable", "code_injection", "request body wrapped in parentheses and eval'd as if it were JSON", r'''
app.post('/config', (req, res) => {
  const config = eval('(' + req.body.json + ')');
  settings.apply(config);
  res.sendStatus(200);
});
'''),
    _case("hj-deser-yaml-upload", "vulnerable", "insecure_deserialization", "uploaded YAML parsed with the full schema (rules have no rule for it)", r'''
const yaml = require('js-yaml');
const fs = require('fs');

function readUpload(file) {
  const raw = fs.readFileSync(file.path, 'utf8');
  return yaml.load(raw, { schema: yaml.DEFAULT_FULL_SCHEMA });
}

module.exports = { readUpload };
'''),
    _case("hj-crypto-ecb-variable", "vulnerable", "weak_crypto", "ECB mode chosen through a variable to encrypt card data (rules read only literal names)", r'''
const crypto = require('crypto');

const MODE = 'aes-128-ecb';

function encryptCard(number, key) {
  const cipher = crypto.createCipheriv(MODE, key, null);
  return Buffer.concat([cipher.update(number, 'utf8'), cipher.final()]).toString('base64');
}

module.exports = { encryptCard };
'''),
    _case("hj-random-session-id", "vulnerable", "insecure_random", "session identifier from Math.random (rules see it only as LOW, which does not alarm)", r'''
function newSession(user) {
  const sessionId = Math.random().toString(16).slice(2);
  sessions.set(sessionId, { user, createdAt: Date.now() });
  return sessionId;
}

module.exports = { newSession };
'''),
    _case("hj-path-helper-delete-ts", "vulnerable", "path_traversal", "a helper deletes a file named by its parameter; the route passes the request in (rules miss: the link crosses a function)", r'''
import fs from 'fs';
import path from 'path';

const UPLOAD_DIR = '/srv/uploads';

function removeUpload(name: string): void {
  fs.unlinkSync(path.join(UPLOAD_DIR, name));
}

app.delete('/uploads/:name', (req, res) => {
  removeUpload(req.params.name);
  res.sendStatus(204);
});
''', "typescript"),
    _case("hj-ssrf-axios-webhook", "vulnerable", "ssrf", "server posts to a webhook URL taken from the request", r'''
const axios = require('axios');

app.post('/notify', async (req, res) => {
  await axios.post(req.body.webhook, { event: 'signup', user: req.user.id });
  res.sendStatus(202);
});
'''),
    _case("hj-xss-react-dangerous", "vulnerable", "xss_or_template_injection", "comment body rendered as raw HTML in React", r'''
export function Comment({ comment }) {
  return (
    <article className="comment">
      <h4>{comment.author}</h4>
      <div dangerouslySetInnerHTML={{ __html: comment.body }} />
    </article>
  );
}
'''),
    _case("hj-tls-variable-flag", "vulnerable", "tls_verification_disabled", "verification switched off through a variable that is false (rules read only the literal false)", r'''
const https = require('https');

const verifyCertificates = false;

const agent = new https.Agent({ rejectUnauthorized: verifyCertificates });

module.exports = { agent };
'''),
    _case("hj-debug-force-env", "vulnerable", "debug_enabled", "NODE_ENV forced to development with bracket syntax (rules read dot syntax only)", r'''
process.env['NODE_ENV'] = 'development';

const app = require('./app');
app.listen(process.env.PORT || 3000);
'''),
    _case("hj-temp-timestamp-name", "vulnerable", "insecure_temp_file", "predictable name in /tmp built from a timestamp (rules look for a fixed literal)", r'''
const fs = require('fs');

function stageUpload(buffer) {
  const target = `/tmp/upload-${Date.now()}.bin`;
  fs.writeFileSync(target, buffer);
  return target;
}

module.exports = { stageUpload };
'''),

    # ================= SAFE: fixed twins (12) =================
    _case("hj-cmd-execfile-fixed", "fixed", "command_injection", "fixed program, arguments as an array", r'''
const { execFile } = require('child_process');

app.get('/history', (req, res) => {
  execFile('git', ['log', '--oneline', '--author', String(req.query.author)], { cwd: '/srv/repo' }, (err, out) => {
    res.type('text/plain').send(out);
  });
});
'''),
    _case("hj-sql-params-fixed-ts", "fixed", "sql_injection", "the UPDATE with placeholders (TypeScript)", r'''
export async function withdraw(client: Client, id: string, amount: number): Promise<void> {
  await client.query('UPDATE accounts SET balance = balance - $1 WHERE id = $2', [amount, id]);
}
''', "typescript"),
    _case("hj-code-jsonparse-fixed", "fixed", "code_injection", "JSON.parse instead of eval", r'''
app.post('/config', (req, res) => {
  let config;
  try {
    config = JSON.parse(req.body.json);
  } catch (error) {
    return res.status(400).json({ error: 'invalid json' });
  }
  settings.apply(config);
  res.sendStatus(200);
});
'''),
    _case("hj-deser-safeload-fixed", "fixed", "insecure_deserialization", "safe YAML loader", r'''
const yaml = require('js-yaml');
const fs = require('fs');

function readUpload(file) {
  const raw = fs.readFileSync('/srv/uploads/current.yml', 'utf8');
  return yaml.safeLoad(raw);
}

module.exports = { readUpload };
'''),
    _case("hj-crypto-gcm-fixed", "fixed", "weak_crypto", "AES-256-GCM with a random IV", r'''
const crypto = require('crypto');

function encryptCard(number, key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const data = Buffer.concat([cipher.update(number, 'utf8'), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), data]).toString('base64');
}

module.exports = { encryptCard };
'''),
    _case("hj-random-uuid-fixed", "fixed", "insecure_random", "crypto.randomUUID for the session id", r'''
const crypto = require('crypto');

function newSession(user) {
  const sessionId = crypto.randomUUID();
  sessions.set(sessionId, { user, createdAt: Date.now() });
  return sessionId;
}

module.exports = { newSession };
'''),
    _case("hj-path-checked-fixed-ts", "fixed", "path_traversal", "resolved and checked against the base directory before deleting (TypeScript)", r'''
import fs from 'fs';
import path from 'path';

const UPLOAD_DIR = path.resolve('/srv/uploads');

function removeUpload(name: string): void {
  const full = path.resolve(UPLOAD_DIR, name);
  if (!full.startsWith(UPLOAD_DIR + path.sep)) {
    throw new Error('outside the upload directory');
  }
  fs.unlinkSync(full);
}

app.delete('/uploads/:name', (req, res) => {
  removeUpload(req.params.name);
  res.sendStatus(204);
});
''', "typescript"),
    _case("hj-ssrf-allowlist-fixed", "fixed", "ssrf", "webhook host checked against an allow-list first", r'''
const axios = require('axios');
const ALLOWED = new Set(['hooks.partner.example']);

app.post('/notify', async (req, res) => {
  const target = new URL(req.body.webhook);
  if (target.protocol !== 'https:' || !ALLOWED.has(target.hostname)) {
    return res.sendStatus(400);
  }
  await axios.post(target.href, { event: 'signup', user: req.user.id });
  res.sendStatus(202);
});
'''),
    _case("hj-xss-react-child-fixed", "fixed", "xss_or_template_injection", "comment body rendered as a React child, which escapes it", r'''
export function Comment({ comment }) {
  return (
    <article className="comment">
      <h4>{comment.author}</h4>
      <p>{comment.body}</p>
    </article>
  );
}
'''),
    _case("hj-tls-default-fixed", "fixed", "tls_verification_disabled", "an agent that only sets keep-alive, verification untouched", r'''
const https = require('https');

const agent = new https.Agent({ keepAlive: true, maxSockets: 10 });

module.exports = { agent };
'''),
    _case("hj-debug-generic-fixed", "fixed", "debug_enabled", "logs on the server, a generic message to the client", r'''
app.use((err, req, res, next) => {
  logger.error({ err, path: req.path });
  res.status(500).json({ error: 'Internal server error' });
});
'''),
    _case("hj-temp-mkdtemp-fixed", "fixed", "insecure_temp_file", "a unique directory from fs.mkdtemp", r'''
const fs = require('fs');
const os = require('os');
const path = require('path');

function stageUpload(buffer) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'upload-'));
  const target = path.join(dir, 'upload.bin');
  fs.writeFileSync(target, buffer);
  return target;
}

module.exports = { stageUpload };
'''),

    # ================= SAFE: look-alikes (13) =================
    _case("hj-cmd-literal-lookalike", "lookalike", "command_injection", "exec of a fixed literal command", r'''
const { execSync } = require('child_process');

function nodeVersion() {
  return execSync('node --version').toString().trim();
}

module.exports = { nodeVersion };
'''),
    _case("hj-sql-constant-lookalike", "lookalike", "sql_injection", "SQL text in a constant, values as parameters", r'''
const LIST_ITEMS = 'SELECT id, title FROM items WHERE owner = $1 ORDER BY created_at DESC LIMIT $2';

async function listItems(db, owner) {
  return (await db.query(LIST_ITEMS, [owner, 50])).rows;
}

module.exports = { listItems };
'''),
    _case("hj-sql-mongo-eq-lookalike", "lookalike", "sql_injection", "MongoDB filter with the $eq operator", r'''
app.get('/items', async (req, res) => {
  const docs = await items.find({ owner: { $eq: String(req.query.owner) } }).toArray();
  res.json(docs);
});
'''),
    _case("hj-code-timer-function-lookalike", "lookalike", "code_injection", "setTimeout and setInterval given functions", r'''
function startPolling(check) {
  const timer = setInterval(() => check(), 5000);
  setTimeout(() => clearInterval(timer), 60000);
  return timer;
}

module.exports = { startPolling };
'''),
    _case("hj-deser-jsonparse-lookalike", "lookalike", "insecure_deserialization", "JSON.parse of stored preferences", r'''
function loadPreferences(storage) {
  const raw = storage.getItem('preferences');
  return raw ? JSON.parse(raw) : { theme: 'light' };
}

module.exports = { loadPreferences };
'''),
    _case("hj-crypto-cachekey-lookalike", "lookalike", "weak_crypto", "SHA-1 only to name a cache entry", r'''
const crypto = require('crypto');

function cacheKey(url) {
  return crypto.createHash('sha1').update(url).digest('hex');
}

module.exports = { cacheKey };
'''),
    _case("hj-random-greeting-lookalike", "lookalike", "insecure_random", "Math.random only to pick a greeting", r'''
const GREETINGS = ['Hello', 'Welcome back', 'Good to see you'];

function randomGreeting() {
  return GREETINGS[Math.floor(Math.random() * GREETINGS.length)];
}

module.exports = { randomGreeting };
'''),
    _case("hj-path-fixed-lookalike", "lookalike", "path_traversal", "reads one fixed template file", r'''
const fs = require('fs');

function welcomeTemplate() {
  return fs.readFileSync('./templates/welcome.html', 'utf8');
}

module.exports = { welcomeTemplate };
'''),
    _case("hj-ssrf-fixed-lookalike", "lookalike", "ssrf", "request to one fixed URL", r'''
async function loadItems() {
  const response = await fetch('https://api.example.com/v1/items');
  return response.json();
}

module.exports = { loadItems };
'''),
    _case("hj-xss-literal-lookalike", "lookalike", "xss_or_template_injection", "innerHTML given a fixed literal", r'''
function showLoading(container) {
  container.innerHTML = '<span class="spinner">Loading...</span>';
}

module.exports = { showLoading };
'''),
    _case("hj-tls-true-lookalike", "lookalike", "tls_verification_disabled", "verification explicitly on", r'''
const https = require('https');

const agent = new https.Agent({ rejectUnauthorized: true });

module.exports = { agent };
'''),
    _case("hj-debug-read-lookalike", "lookalike", "debug_enabled", "reads NODE_ENV to decide whether to log; never sets it", r'''
const isDevelopment = process.env.NODE_ENV === 'development';

function trace(message) {
  if (isDevelopment) {
    console.log('[trace]', message);
  }
}

module.exports = { trace };
'''),
    _case("hj-temp-print-lookalike", "lookalike", "insecure_temp_file", "only prints where the temp directory is; creates nothing", r'''
const os = require('os');

function describeEnvironment() {
  return `temporary files go to ${os.tmpdir()} on ${os.platform()}`;
}

module.exports = { describeEnvironment };
'''),
]


# The fingerprint is computed by the one shared function in cases_heldout.py, applied to THESE cases.
fingerprint = partial(_fingerprint_of, HELDOUT_CASES)


def demo() -> None:
    from benchmark.cases_javascript import CASES as DEV_CASES
    from security_service.adapters.js_rules import check_syntax
    from security_service.core.questions import CATEGORY_IDS

    ids = [c["id"] for c in HELDOUT_CASES]
    assert len(ids) == len(set(ids)), "duplicate case id"
    assert not set(ids) & {c["id"] for c in DEV_CASES}, "a held-out id is also a development id"
    assert not {c["code"] for c in HELDOUT_CASES} & {c["code"] for c in DEV_CASES}, "a held-out case is a copy of a development case"
    vulnerable = [c for c in HELDOUT_CASES if c["kind"] == "vulnerable"]
    safe = [c for c in HELDOUT_CASES if c["kind"] != "vulnerable"]
    assert (len(vulnerable), len(safe), len(HELDOUT_CASES)) == (14, 25, 39), (len(vulnerable), len(safe))
    assert {c["category"] for c in vulnerable} == set(CATEGORY_IDS), "every category needs a vulnerable case"
    assert {c["category"] for c in safe} == set(CATEGORY_IDS), "every category needs a safe case"
    for case in HELDOUT_CASES:
        assert case["kind"] in ("vulnerable", "fixed", "lookalike") and case["language"] in ("javascript", "typescript") and case["group"] == "heldout", case["id"]
        assert case["id"].startswith("hj-") and case["note"] and case["code"].endswith("\n") and "\t" not in case["code"], case["id"]
        assert check_syntax(case["code"], case["language"]) is None, (case["id"], check_syntax(case["code"], case["language"]))
    assert sum(c["language"] == "typescript" for c in HELDOUT_CASES) >= 5

    # the model must have room to add something: most vulnerable cases are ones the rules do not alarm on
    from benchmark.run_benchmark import run
    from security_service.core.scan_service import ScanService

    rows = run(ScanService(), HELDOUT_CASES)
    missed = [r["case"]["id"] for r in rows if r["case"]["kind"] == "vulnerable" and not r["alarmed"]]
    assert len(missed) == 9, f"expected 9 vulnerable cases the rules do not alarm on, found {len(missed)}: {missed}"
    assert not any(r["decision"].value == "scan_failed" for r in rows)

    actual = fingerprint()
    assert PINNED_FINGERPRINT == actual, (
        f"the held-out cases changed: fingerprint is now {actual}, pinned {PINNED_FINGERPRINT}. If this is the first time, pin it. If a model has already "
        "judged these cases, they are no longer held out.")
    print(f"cases_heldout_js OK: {len(HELDOUT_CASES)} cases (14 vulnerable, 25 safe), every category on both sides, all parse, 9 of 14 vulnerable ones "
          f"are invisible to the rules, none shared with the development set, fingerprint {actual} pinned")


if __name__ == "__main__":
    print("fingerprint", fingerprint())
    demo()
