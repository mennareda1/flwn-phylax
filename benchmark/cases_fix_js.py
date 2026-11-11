"""
benchmark/cases_fix_js.py

The cases for measuring how good GPT-6 Astra's FIXES are on JavaScript and TypeScript (benchmark/fix_eval.py). Each case is a small, believable file with one finding the real rules flag at
medium or above, plus what is needed to judge a fix by BEHAVIOR and not only by the service's four checks (scope, syntax, size, re-scan):

  probe       what to do with the module in Node, with the dangerous functions replaced by recorders (child_process, https, SQL, node-serialize). The probe runs on the ORIGINAL and on the
              fixed code with a benign input, and the recorded events are compared.
  compare     the recorded event names that must be identical before and after.
  expect_after  events that must have this value after the fix (for example: TLS verification is on).
  good / bad  a hand-written correct fix and a hand-written wrong fix. They exist to prove the probes can tell the two apart: the self-test in fix_eval.py fails if they cannot.
  decline_ok  True where no small edit can keep the behavior (dynamic code): "I cannot fix this safely" is a correct answer there, not a failure.

These are DEVELOPMENT cases: the prompt Astra is given is ours and may be tuned after seeing results. Nothing here is a held-out set, and the report says so.
"""

from __future__ import annotations

CASES: list[dict] = [
    {"id": "fx-js-exec-concat", "path": "run.js", "rule": "JS-EXEC", "decline_ok": False, "compare": ["cmd"], "expect_after": {},
     "note": "a folder name concatenated into a shell command",
     "code": 'const { exec } = require("child_process");\n\nfunction run(dir) {\n  exec("ls " + dir);\n}\n\nmodule.exports = { run };\n',
     "probe": 'mod.run("docs");',
     "good": 'const { execFile } = require("child_process");\n\nfunction run(dir) {\n  execFile("ls", [dir]);\n}\n\nmodule.exports = { run };\n',
     "bad": 'const { execFile } = require("child_process");\n\nfunction run(dir) {\n  execFile("ls", []);\n}\n\nmodule.exports = { run };\n'},
    {"id": "fx-ts-exec-template", "path": "folders.ts", "rule": "JS-EXEC", "decline_ok": False, "compare": ["cmd"], "expect_after": {},
     "note": "TypeScript: a folder name inside a template literal passed to exec",
     "code": 'import { exec } from "child_process";\n\nexport function listFolder(dir: string): void {\n  exec(`ls ${dir}`);\n}\n',
     "probe": 'mod.listFolder("docs");',
     "good": 'import { execFile } from "child_process";\n\nexport function listFolder(dir: string): void {\n  execFile("ls", [dir]);\n}\n',
     "bad": 'import { execFile } from "child_process";\n\nexport function listFolder(dir: string): void {\n  execFile("ls", ["-la"]);\n}\n'},
    {"id": "fx-js-spawn-shell", "path": "convert.js", "rule": "JS-SHELL-OPTION", "decline_ok": False, "compare": ["cmd"], "expect_after": {},
     "note": "a file name concatenated into a command that spawn runs through a shell",
     "code": 'const { spawn } = require("child_process");\n\nfunction convert(file) {\n  return spawn("convert " + file + " out.png", { shell: true });\n}\n\nmodule.exports = { convert };\n',
     "probe": 'mod.convert("in.png");',
     "good": 'const { spawn } = require("child_process");\n\nfunction convert(file) {\n  return spawn("convert", [file, "out.png"]);\n}\n\nmodule.exports = { convert };\n',
     "bad": 'const { spawn } = require("child_process");\n\nfunction convert(file) {\n  return spawn("convert", ["out.png"]);\n}\n\nmodule.exports = { convert };\n'},
    {"id": "fx-ts-sql-template", "path": "users.ts", "rule": "JS-SQL", "decline_ok": False, "compare": ["sql"], "expect_after": {},
     "note": "TypeScript: an id inside a template literal passed to query",
     "code": 'type Db = { query: (sql: string, params?: unknown[]) => unknown };\n\nexport function findUser(db: Db, id: string) {\n  return db.query(`SELECT * FROM users WHERE id = ${id}`);\n}\n',
     "probe": 'mod.findUser(db, "42");',
     "good": 'type Db = { query: (sql: string, params?: unknown[]) => unknown };\n\nexport function findUser(db: Db, id: string) {\n  return db.query("SELECT * FROM users WHERE id = $1", [id]);\n}\n',
     "bad": 'type Db = { query: (sql: string, params?: unknown[]) => unknown };\n\nexport function findUser(db: Db, id: string) {\n  return db.query("SELECT * FROM users WHERE id = $1", []);\n}\n'},
    {"id": "fx-js-sql-concat", "path": "accounts.js", "rule": "JS-SQL", "decline_ok": False, "compare": ["sql"], "expect_after": {},
     "note": "an e-mail address concatenated into a quoted SQL string",
     "code": 'function findByEmail(db, email) {\n  return db.query("SELECT * FROM users WHERE email = \'" + email + "\'");\n}\n\nmodule.exports = { findByEmail };\n',
     "probe": 'mod.findByEmail(db, "ana@example.com");',
     "good": 'function findByEmail(db, email) {\n  return db.query("SELECT * FROM users WHERE email = $1", [email]);\n}\n\nmodule.exports = { findByEmail };\n',
     "bad": 'function findByEmail(db, email) {\n  return db.query("SELECT * FROM users WHERE email = $1", []);\n}\n\nmodule.exports = { findByEmail };\n'},
    {"id": "fx-js-tls-off", "path": "status.js", "rule": "JS-TLS-OFF", "decline_ok": False, "compare": ["https"], "expect_after": {"tls_verified": True},
     "note": "certificate verification switched off on an HTTPS request",
     "code": 'const https = require("https");\n\nfunction fetchStatus(host) {\n  return https.request({ hostname: host, path: "/status", method: "GET", rejectUnauthorized: false });\n}\n\nmodule.exports = { fetchStatus };\n',
     "probe": 'mod.fetchStatus("api.example.com");',
     "good": 'const https = require("https");\n\nfunction fetchStatus(host) {\n  return https.request({ hostname: host, path: "/status", method: "GET" });\n}\n\nmodule.exports = { fetchStatus };\n',
     "bad": 'const https = require("https");\n\nfunction fetchStatus(host) {\n  return https.request({ hostname: "localhost", path: "/status", method: "GET" });\n}\n\nmodule.exports = { fetchStatus };\n'},
    {"id": "fx-js-eval", "path": "calc.js", "rule": "JS-EVAL", "decline_ok": True, "compare": ["result"], "expect_after": {},
     "note": "eval of a user-supplied expression; a restricted evaluator or a decline are both acceptable",
     "code": 'function calculate(expression) {\n  return eval(expression);\n}\n\nmodule.exports = { calculate };\n',
     "probe": 'events.push(["result", mod.calculate("2 + 3")]);',
     "good": 'function calculate(expression) {\n  const tokens = expression.match(/\\d+(\\.\\d+)?|[+\\-]/g);\n  if (!tokens || tokens.join("") !== expression.replace(/\\s+/g, "")) throw new Error("unsupported expression");\n  let total = 0;\n  let sign = 1;\n  for (const token of tokens) {\n    if (token === "+") sign = 1;\n    else if (token === "-") sign = -1;\n    else {\n      total += sign * Number(token);\n      sign = 1;\n    }\n  }\n  return total;\n}\n\nmodule.exports = { calculate };\n',
     "bad": 'function calculate(expression) {\n  return 0;\n}\n\nmodule.exports = { calculate };\n'},
    {"id": "fx-js-unserialize", "path": "profile.js", "rule": "JS-DESERIALIZE", "decline_ok": False, "compare": ["result"], "expect_after": {},
     "note": "a cookie deserialized with node-serialize, which can run code",
     "code": 'const serialize = require("node-serialize");\n\nfunction loadProfile(cookie) {\n  return serialize.unserialize(Buffer.from(cookie, "base64").toString());\n}\n\nmodule.exports = { loadProfile };\n',
     "probe": 'events.push(["result", JSON.stringify(mod.loadProfile(Buffer.from(\'{"name":"ana"}\').toString("base64")))]);',
     "good": 'function loadProfile(cookie) {\n  return JSON.parse(Buffer.from(cookie, "base64").toString());\n}\n\nmodule.exports = { loadProfile };\n',
     "bad": 'function loadProfile(cookie) {\n  return {};\n}\n\nmodule.exports = { loadProfile };\n'},
    {"id": "fx-ts-execsync-template", "path": "commits.ts", "rule": "JS-EXEC", "decline_ok": False, "compare": ["cmd"], "expect_after": {},
     "note": "TypeScript: an author name inside a template literal passed to execSync",
     "code": 'import { execSync } from "child_process";\n\nexport function commitsBy(author: string): string {\n  return execSync(`git log --author=${author} --oneline`).toString();\n}\n',
     "probe": 'mod.commitsBy("ana");',
     "good": 'import { execFileSync } from "child_process";\n\nexport function commitsBy(author: string): string {\n  return execFileSync("git", ["log", `--author=${author}`, "--oneline"]).toString();\n}\n',
     "bad": 'import { execFileSync } from "child_process";\n\nexport function commitsBy(author: string): string {\n  return execFileSync("git", ["log", "--oneline"]).toString();\n}\n'},
    {"id": "fx-js-weak-hash", "path": "fingerprint.js", "rule": "JS-WEAK-HASH", "decline_ok": False, "compare": ["hash_shape", "deterministic"], "expect_after": {},
     "note": "MD5 used to fingerprint a password; any strong hex digest keeps the shape",
     "code": 'const crypto = require("crypto");\n\nfunction fingerprint(password) {\n  return crypto.createHash("md5").update(password).digest("hex");\n}\n\nmodule.exports = { fingerprint };\n',
     "probe": 'const h = mod.fingerprint("s3cret"); events.push(["hash_shape", /^[0-9a-f]{32,}$/.test(h)]); events.push(["deterministic", h === mod.fingerprint("s3cret")]);',
     "good": 'const crypto = require("crypto");\n\nfunction fingerprint(password) {\n  return crypto.createHash("sha256").update(password).digest("hex");\n}\n\nmodule.exports = { fingerprint };\n',
     "bad": 'const crypto = require("crypto");\n\nfunction fingerprint(password) {\n  return crypto.createHash("sha256").update(password).digest("hex").slice(0, 8);\n}\n\nmodule.exports = { fingerprint };\n'},
    {"id": "fx-js-new-function", "path": "adder.js", "rule": "JS-FUNCTION", "decline_ok": True, "compare": ["result"], "expect_after": {},
     "note": "new Function built from a caller-supplied body; no small edit keeps that, so declining is correct",
     "code": 'function makeAdder(body) {\n  return new Function("a", "b", body);\n}\n\nmodule.exports = { makeAdder };\n',
     "probe": 'events.push(["result", mod.makeAdder("return a + b")(2, 3)]);',
     "good": None,
     "bad": 'function makeAdder(body) {\n  return (a, b) => 0;\n}\n\nmodule.exports = { makeAdder };\n'},
]


def demo() -> None:
    ids = [c["id"] for c in CASES]
    assert len(ids) == len(set(ids)) and len({c["path"] for c in CASES}) == len(CASES)
    assert sum(c["path"].endswith(".ts") for c in CASES) == 3 and sum(c["path"].endswith(".js") for c in CASES) == 8
    for case in CASES:
        assert case["code"].endswith("\n") and case["probe"] and case["compare"] and case["rule"].startswith("JS-"), case["id"]
        assert case["bad"] and case["bad"] != case["code"], case["id"]
        assert (case["good"] is None) == (case["id"] == "fx-js-new-function"), case["id"]      # the one case with no correct small edit
    assert sum(c["decline_ok"] for c in CASES) == 2
    print(f"cases_fix_js OK: {len(CASES)} cases (8 JavaScript, 3 TypeScript), each with a behavior probe, a known-good and a known-bad fix; two where declining is correct")


if __name__ == "__main__":
    demo()
