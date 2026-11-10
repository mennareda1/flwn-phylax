"""
benchmark/cases_javascript.py

Labeled JavaScript and TypeScript DEVELOPMENT cases for Decision-1 (the classifier). Three kinds, as for Python:

  vulnerable - a real weakness; `category` is what a correct scanner should call it
  fixed      - the secure twin of a vulnerable case (same task, safe code)
  lookalike  - looks suspicious to a pattern matcher but is actually safe

These cases are for TUNING the JavaScript question wording (security_service/core/questions.py). They are not the test: the
verdict comes from benchmark/cases_heldout_js.py, which was written at the same time but is never used to tune anything.

Labelling rules, learned from the Python run (where three "safe" cases were mislabelled and corrupted the first result):
  - A safe case must be safe under ALL twelve questions, not only its own category. It never opens a path built from a
    variable, never fetches a variable URL, never uses Math.random for anything secret, and so on.
  - A debatable case is left out, not labelled with a guess.
  - Several vulnerable cases are written so that our JavaScript RULES cannot see them (the flow crosses a function, the command
    is run through `sh -c`, the algorithm name sits in a constant, the setting is written with brackets). The model has to add
    something the rules do not, or it earns no place.

Each case has `language` ("javascript" or "typescript"). There are no cases about hardcoded secrets: the secrets check owns them.
"""

from __future__ import annotations


def _case(case_id: str, kind: str, category: str, note: str, code: str, language: str = "javascript") -> dict:
    return {"id": case_id, "kind": kind, "category": category, "note": note,
            "code": code.strip("\n") + "\n", "group": "base", "language": language}


CASES: list[dict] = [
    # ---------------- command injection ----------------
    _case("js-cmd-exec-template", "vulnerable", "command_injection", "request value interpolated into child_process.exec", r'''
const { exec } = require('child_process');
const express = require('express');
const app = express();

app.get('/ping', (req, res) => {
  exec(`ping -c 1 ${req.query.host}`, (error, stdout) => {
    res.send(stdout);
  });
});
'''),
    _case("js-cmd-sh-c", "vulnerable", "command_injection", "built string run through sh -c (the rules look for shell: true and miss this)", r'''
const { spawn } = require('child_process');

function convert(file) {
  return spawn('sh', ['-c', 'convert ' + file + ' out.png']);
}

module.exports = (req, res) => {
  convert(req.body.file).on('close', () => res.sendStatus(200));
};
''', "javascript"),
    _case("js-cmd-execsync-concat", "vulnerable", "command_injection", "directory name concatenated into execSync (TypeScript)", r'''
import { execSync } from 'child_process';

export function backup(dir: string): Buffer {
  return execSync('tar -czf backup.tgz ' + dir);
}
''', "typescript"),
    _case("js-cmd-execfile-fixed", "fixed", "command_injection", "fixed program, arguments as an array, host validated", r'''
const { execFile } = require('child_process');

function ping(host, done) {
  if (!/^[a-z0-9.-]+$/i.test(host)) {
    return done(new Error('bad host'));
  }
  execFile('ping', ['-c', '1', host], (error, stdout) => done(error, stdout));
}

module.exports = ping;
'''),
    _case("js-cmd-fixed-literal", "lookalike", "command_injection", "exec of a fixed literal command", r'''
const { exec } = require('child_process');

function currentCommit(callback) {
  exec('git rev-parse --short HEAD', (error, stdout) => {
    callback(error ? 'unknown' : stdout.trim());
  });
}

module.exports = { currentCommit };
'''),

    # ---------------- sql injection ----------------
    _case("js-sql-template", "vulnerable", "sql_injection", "request value interpolated into SQL with a template literal", r'''
app.get('/users', async (req, res) => {
  const rows = await db.query(`SELECT id, name FROM users WHERE name = '${req.query.name}'`);
  res.json(rows);
});
'''),
    _case("js-sql-builder-helper", "vulnerable", "sql_injection", "SQL assembled by a helper, then run (the rules never see the concatenation reach query)", r'''
import { Pool } from 'pg';

const pool = new Pool();

function buildSearch(term: string): string {
  return "SELECT * FROM products WHERE title LIKE '%" + term + "%'";
}

export async function search(term: string) {
  const sql = buildSearch(term);
  return (await pool.query(sql)).rows;
}
''', "typescript"),
    _case("js-sql-mongo-where", "vulnerable", "sql_injection", "MongoDB $where built from a request value", r'''
app.get('/orders/:id', (req, res) => {
  orders.find({ $where: 'this.orderId == "' + req.params.id + '"' }).toArray((err, docs) => {
    res.json(docs);
  });
});
'''),
    _case("js-sql-placeholder-fixed", "fixed", "sql_injection", "the same query with a placeholder", r'''
app.get('/users', async (req, res) => {
  const rows = await db.query('SELECT id, name FROM users WHERE name = $1', [req.query.name]);
  res.json(rows);
});
'''),
    _case("js-sql-mongo-operator-fixed", "fixed", "sql_injection", "MongoDB filter with a query operator, no $where", r'''
app.get('/orders/:id', (req, res) => {
  orders.find({ orderId: { $eq: String(req.params.id) } }).toArray((err, docs) => {
    res.json(docs);
  });
});
'''),
    _case("js-sql-constant-lookalike", "lookalike", "sql_injection", "SQL text kept in a constant, values passed as parameters", r'''
const FIND_USER = 'SELECT id, email FROM users WHERE id = $1 AND active = $2';

async function findUser(db, id) {
  const result = await db.query(FIND_USER, [id, true]);
  return result.rows[0] || null;
}

module.exports = { findUser };
'''),

    # ---------------- code injection ----------------
    _case("js-code-eval", "vulnerable", "code_injection", "request value passed to eval", r'''
app.post('/calc', (req, res) => {
  const result = eval(req.body.expression);
  res.json({ result });
});
'''),
    _case("js-code-timeout-string", "vulnerable", "code_injection", "string from a variable given to setTimeout (the rules look only at literal strings)", r'''
app.post('/later', (req, res) => {
  const action = req.body.action;
  setTimeout(action, 1000);
  res.sendStatus(202);
});
'''),
    _case("js-code-newfunction", "vulnerable", "code_injection", "new Function built from a variable (TypeScript)", r'''
export function compile(body: string): (x: number) => number {
  return new Function('x', 'return ' + body) as (x: number) => number;
}
''', "typescript"),
    _case("js-code-jsonparse-fixed", "fixed", "code_injection", "JSON.parse instead of eval", r'''
app.post('/calc', (req, res) => {
  let operands;
  try {
    operands = JSON.parse(req.body.operands);
  } catch (error) {
    return res.status(400).json({ error: 'invalid json' });
  }
  res.json({ sum: operands.reduce((a, b) => a + b, 0) });
});
'''),
    _case("js-code-words-lookalike", "lookalike", "code_injection", "the word eval only in a string and a comment", r'''
// Never call eval on input that came from a user.
const WARNING = 'do not use eval() or new Function() here';

function describe(error) {
  return `${WARNING}: ${error.message}`;
}

module.exports = { describe };
'''),

    # ---------------- insecure deserialization ----------------
    _case("js-deser-yaml-full", "vulnerable", "insecure_deserialization", "js-yaml load with the full schema on request data (the rules have no rule for it)", r'''
const yaml = require('js-yaml');

app.post('/import', (req, res) => {
  const settings = yaml.load(req.body.text, { schema: yaml.DEFAULT_FULL_SCHEMA });
  res.json(settings);
});
'''),
    _case("js-deser-node-serialize", "vulnerable", "insecure_deserialization", "node-serialize unserialize on a cookie", r'''
const serialize = require('node-serialize');

app.get('/profile', (req, res) => {
  const profile = serialize.unserialize(Buffer.from(req.cookies.profile, 'base64').toString());
  res.send(`Hello ${profile.name}`);
});
'''),
    _case("js-deser-safeload-fixed", "fixed", "insecure_deserialization", "safe loader and JSON", r'''
const yaml = require('js-yaml');

app.post('/import', (req, res) => {
  const settings = yaml.safeLoad(req.body.text);
  res.json(settings);
});

app.get('/profile', (req, res) => {
  const profile = JSON.parse(Buffer.from(req.cookies.profile, 'base64').toString());
  res.json({ name: String(profile.name) });
});
'''),

    # ---------------- weak crypto ----------------
    _case("js-crypto-md5-password", "vulnerable", "weak_crypto", "MD5 used to hash a password", r'''
const crypto = require('crypto');

function hashPassword(password) {
  return crypto.createHash('md5').update(password).digest('hex');
}

module.exports = { hashPassword };
'''),
    _case("js-crypto-algo-constant", "vulnerable", "weak_crypto", "SHA-1 chosen through a constant to hash a password (TypeScript; the rules read only literal names)", r'''
import { createHash } from 'crypto';

const ALGORITHM = 'sha1';

export function storePassword(password: string): string {
  return createHash(ALGORITHM).update(password).digest('hex');
}
''', "typescript"),
    _case("js-crypto-sha256-fixed", "fixed", "weak_crypto", "bcrypt for passwords", r'''
const bcrypt = require('bcrypt');

async function hashPassword(password) {
  return bcrypt.hash(password, 12);
}

module.exports = { hashPassword };
'''),
    _case("js-crypto-etag-lookalike", "lookalike", "weak_crypto", "MD5 only as a cache validator (ETag), not a security control", r'''
const crypto = require('crypto');

function etagFor(buffer) {
  return '"' + crypto.createHash('md5').update(buffer).digest('hex') + '"';
}

module.exports = { etagFor };
'''),

    # ---------------- insecure random ----------------
    _case("js-random-reset-token", "vulnerable", "insecure_random", "password-reset token from Math.random", r'''
function makeResetToken() {
  return Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);
}

module.exports = { makeResetToken };
'''),
    _case("js-random-otp", "vulnerable", "insecure_random", "one-time login code from Math.random (the variable is just called code, so the rules do not notice)", r'''
async function sendLoginCode(phone) {
  const code = Math.floor(100000 + Math.random() * 900000);
  await sms.send(phone, `Your login code is ${code}`);
  await store.set(`otp:${phone}`, String(code), { ttl: 300 });
}
'''),
    _case("js-random-bytes-fixed", "fixed", "insecure_random", "crypto.randomBytes for the token", r'''
const crypto = require('crypto');

function makeResetToken() {
  return crypto.randomBytes(32).toString('hex');
}

module.exports = { makeResetToken };
'''),
    _case("js-random-jitter-lookalike", "lookalike", "insecure_random", "Math.random only for display jitter and a shuffle", r'''
function jitter(baseMs) {
  return baseMs + Math.random() * 100;
}

function shuffleForDisplay(items) {
  return [...items].sort(() => Math.random() - 0.5);
}

module.exports = { jitter, shuffleForDisplay };
'''),

    # ---------------- path traversal ----------------
    _case("js-path-readfile", "vulnerable", "path_traversal", "request parameter joined into a path and read", r'''
const fs = require('fs');
const path = require('path');
const UPLOADS = '/srv/app/uploads';

app.get('/files/:name', (req, res) => {
  fs.readFile(path.join(UPLOADS, req.params.name), (err, data) => {
    if (err) return res.sendStatus(404);
    res.send(data);
  });
});
'''),
    _case("js-path-helper-param", "vulnerable", "path_traversal", "a helper joins its parameter into a path; the route passes the request in (the rules never see the link)", r'''
import fs from 'fs';
import path from 'path';

const ROOT = '/srv/docs';

function readDoc(name: string): string {
  return fs.readFileSync(path.join(ROOT, name), 'utf8');
}

app.get('/docs/:name', (req, res) => {
  res.send(readDoc(req.params.name));
});
''', "typescript"),
    _case("js-path-checked-fixed", "fixed", "path_traversal", "resolved and checked against the base directory", r'''
const fs = require('fs');
const path = require('path');
const UPLOADS = path.resolve('/srv/app/uploads');

app.get('/files/:name', (req, res) => {
  const full = path.resolve(UPLOADS, req.params.name);
  if (!full.startsWith(UPLOADS + path.sep)) {
    return res.sendStatus(400);
  }
  fs.readFile(full, (err, data) => (err ? res.sendStatus(404) : res.send(data)));
});
'''),
    _case("js-path-fixed-lookalike", "lookalike", "path_traversal", "reads one fixed configuration file", r'''
const fs = require('fs');

function loadConfig() {
  const text = fs.readFileSync('/etc/myapp/config.json', 'utf8');
  return JSON.parse(text);
}

module.exports = { loadConfig };
'''),

    # ---------------- ssrf ----------------
    _case("js-ssrf-fetch", "vulnerable", "ssrf", "server fetches a URL from the query string", r'''
app.get('/preview', async (req, res) => {
  const response = await fetch(req.query.url);
  res.send(await response.text());
});
'''),
    _case("js-ssrf-helper-param", "vulnerable", "ssrf", "a helper fetches its parameter; the route passes the request body in (the rules never see the link)", r'''
async function fetchPreview(target) {
  const response = await fetch(target);
  return response.text();
}

app.post('/preview', async (req, res) => {
  res.send(await fetchPreview(req.body.url));
});
'''),
    _case("js-ssrf-allowlist-fixed", "fixed", "ssrf", "host checked against an allow-list before the request", r'''
const ALLOWED_HOSTS = new Set(['api.example.com', 'cdn.example.com']);

app.get('/preview', async (req, res) => {
  const target = new URL(req.query.url);
  if (target.protocol !== 'https:' || !ALLOWED_HOSTS.has(target.hostname)) {
    return res.sendStatus(400);
  }
  const response = await fetch(target);
  res.send(await response.text());
});
'''),
    _case("js-ssrf-fixed-lookalike", "lookalike", "ssrf", "request to one fixed URL", r'''
async function serviceStatus() {
  const response = await fetch('https://status.example.com/api/v2/status.json');
  return response.json();
}

module.exports = { serviceStatus };
'''),

    # ---------------- xss / template injection ----------------
    _case("js-xss-innerhtml", "vulnerable", "xss_or_template_injection", "task text concatenated into innerHTML", r'''
const list = document.querySelector('#tasks');

function addTask(name) {
  list.innerHTML += '<li>' + name + '</li>';
}

document.querySelector('#add').addEventListener('click', () => {
  addTask(document.querySelector('#name').value);
});
'''),
    _case("js-xss-ejs-render", "vulnerable", "xss_or_template_injection", "template source taken from the request", r'''
const ejs = require('ejs');

app.post('/preview-email', (req, res) => {
  const html = ejs.render(req.body.template, { user: req.user });
  res.send(html);
});
'''),
    _case("js-xss-textcontent-fixed", "fixed", "xss_or_template_injection", "textContent instead of innerHTML", r'''
const list = document.querySelector('#tasks');

function addTask(name) {
  const item = document.createElement('li');
  item.textContent = name;
  list.append(item);
}

document.querySelector('#add').addEventListener('click', () => {
  addTask(document.querySelector('#name').value);
});
'''),
    _case("js-xss-dompurify-lookalike", "lookalike", "xss_or_template_injection", "markup sanitized with DOMPurify before insertion", r'''
import DOMPurify from 'dompurify';

export function showComment(container: HTMLElement, html: string): void {
  container.innerHTML = DOMPurify.sanitize(html);
}
''', "typescript"),
    _case("js-xss-react-lookalike", "lookalike", "xss_or_template_injection", "React renders the text as a child, which escapes it", r'''
export function Greeting({ name }) {
  return <p className="greeting">Hello, {name}</p>;
}
'''),

    # ---------------- tls verification disabled ----------------
    _case("js-tls-reject-false", "vulnerable", "tls_verification_disabled", "https agent that accepts any certificate", r'''
const https = require('https');
const agent = new https.Agent({ rejectUnauthorized: false });

function getJson(url) {
  return fetch(url, { agent }).then((r) => r.json());
}
'''),
    _case("js-tls-env-brackets", "vulnerable", "tls_verification_disabled", "NODE_TLS_REJECT_UNAUTHORIZED set to 0 with bracket syntax (the rules read dot syntax only)", r'''
if (process.env.INTEGRATION_HOST) {
  process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = '0';
}

module.exports = require('./client');
'''),
    _case("js-tls-default-fixed", "fixed", "tls_verification_disabled", "default verification, nothing switched off", r'''
const https = require('https');

function getJson(url, done) {
  https.get(url, (res) => {
    let body = '';
    res.on('data', (chunk) => (body += chunk));
    res.on('end', () => done(JSON.parse(body)));
  });
}
'''),
    _case("js-tls-explicit-true-lookalike", "lookalike", "tls_verification_disabled", "verification explicitly switched ON", r'''
const https = require('https');
const agent = new https.Agent({ rejectUnauthorized: true, keepAlive: true });

module.exports = { agent };
'''),

    # ---------------- debug enabled ----------------
    _case("js-debug-stack-to-client", "vulnerable", "debug_enabled", "the stack trace is sent to the client", r'''
app.use((err, req, res, next) => {
  res.status(500).send(err.stack);
});
'''),
    _case("js-debug-showstack", "vulnerable", "debug_enabled", "error handler configured to show stacks (the rules read only NODE_ENV)", r'''
const errorhandler = require('errorhandler');

app.use(errorhandler({ dumpExceptions: true, showStack: true }));
'''),
    _case("js-debug-generic-fixed", "fixed", "debug_enabled", "logs the error, tells the client nothing", r'''
app.use((err, req, res, next) => {
  logger.error(err);
  res.status(500).json({ error: 'Something went wrong' });
});
'''),
    _case("js-debug-env-check-lookalike", "lookalike", "debug_enabled", "debug logging that only runs outside production (reads NODE_ENV, never sets it)", r'''
function debugLog(message) {
  if (process.env.NODE_ENV !== 'production') {
    console.log(`[debug] ${message}`);
  }
}

module.exports = { debugLog };
'''),

    # ---------------- insecure temp file ----------------
    _case("js-temp-fixed-path", "vulnerable", "insecure_temp_file", "report written to a fixed path in /tmp", r'''
const fs = require('fs');

function saveReport(csv) {
  fs.writeFileSync('/tmp/report.csv', csv);
  return '/tmp/report.csv';
}
'''),
    _case("js-temp-concat-name", "vulnerable", "insecure_temp_file", "guessable file name under /tmp built from the user name (the rules look for a fixed literal)", r'''
const fs = require('fs');

function saveExport(username, data) {
  const target = '/tmp/export-' + username + '.json';
  fs.writeFileSync(target, JSON.stringify(data));
  return target;
}
'''),
    _case("js-temp-mkdtemp-fixed", "fixed", "insecure_temp_file", "unique directory from fs.mkdtemp", r'''
const fs = require('fs');
const os = require('os');
const path = require('path');

function saveReport(csv) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'report-'));
  fs.writeFileSync(path.join(dir, 'report.csv'), csv);
  return dir;
}
'''),
]


def demo() -> None:
    from security_service.core.questions import CATEGORY_IDS

    ids = [c["id"] for c in CASES]
    assert len(ids) == len(set(ids)), "duplicate case id"
    assert len({c["code"] for c in CASES}) == len(CASES), "two cases share the same code"
    for case in CASES:
        assert case["kind"] in ("vulnerable", "fixed", "lookalike") and case["language"] in ("javascript", "typescript"), case["id"]
        assert case["category"] in CATEGORY_IDS, case["id"]
        assert case["id"].startswith("js-") and case["note"] and case["code"].endswith("\n") and "\t" not in case["code"], case["id"]
    vulnerable = [c for c in CASES if c["kind"] == "vulnerable"]
    safe = [c for c in CASES if c["kind"] != "vulnerable"]
    assert {c["category"] for c in vulnerable} == set(CATEGORY_IDS), "every category needs a vulnerable case"
    for category in CATEGORY_IDS:                                                       # every category also has a safe twin
        assert any(c["category"] == category and c["kind"] != "vulnerable" for c in CASES), category
    assert len(vulnerable) >= 20 and len(safe) >= 20 and any(c["language"] == "typescript" for c in CASES)

    # every case must parse in its own language: a case that does not would be a scan failure, not a test of anything
    from security_service.adapters.js_rules import check_syntax

    for case in CASES:
        assert check_syntax(case["code"], case["language"]) is None, (case["id"], check_syntax(case["code"], case["language"]))
    print(f"cases_javascript OK: {len(CASES)} cases ({len(vulnerable)} vulnerable, {len(safe)} safe), every category has a vulnerable case and a safe twin, all parse")


if __name__ == "__main__":
    demo()
