"""
benchmark/cases_heldout.py

The HELD-OUT set: 39 cases written on 2026-10-23, after the first real model run and before any model saw them.
It exists to judge version 2 of the questions honestly. The 50 cases in cases_python.py are now a DEVELOPMENT set:
their results were seen, three of their labels were corrected because of what the model flagged, and the questions
were reworded because of what it missed, so they can no longer give an unbiased verdict.

Rules for this file (they are what makes the verdict mean something):
  1. It is run through the model ONCE for the final verdict:  python -m benchmark.classifier_eval --heldout
  2. Nothing here, and no question, is edited after that run. If it must be, the set becomes a development set and
     a new held-out set must be written first. The fingerprint below is pinned so an edit cannot go unnoticed.
  3. Every SAFE case is clean for EVERY category the classifier is asked about, not only the one it twins.
     Every vulnerable case contains its own problem only.
  4. No case is about hardcoded secrets: the classifier is not asked about them (the secrets check owns that).

Per category: one vulnerable case (V), its clean fix (F), and a look-alike (L) that resembles the vulnerable
pattern but is safe. Three extra cases probe weaknesses the first run showed: the unsafe YAML loaders, a template
built from text, and a ping to a variable host (not an HTTP request).
"""

from __future__ import annotations

import hashlib

# The lock. If this does not match the cases below, someone edited a held-out case: see rule 2.
PINNED_FINGERPRINT = "7871031988b1"
GROUP = "heldout_v1"


def _case(case_id: str, kind: str, category: str, note: str, code: str) -> dict:
    return {"id": case_id, "kind": kind, "category": category, "note": note,
            "code": code.strip("\n") + "\n", "group": GROUP}


HELDOUT_CASES: list[dict] = [
    # ---------------- command injection ----------------
    _case("h-cmd-vuln", "vulnerable", "command_injection", "shell command joined from a parameter", '''
import os

def archive(folder):
    os.system("tar czf backup.tgz " + folder)
'''),
    _case("h-cmd-fixed", "fixed", "command_injection", "fixed program and fixed arguments, no shell", '''
import subprocess

def archive():
    subprocess.run(["tar", "czf", "backup.tgz", "data"], check=True)
'''),
    _case("h-cmd-look", "lookalike", "command_injection", "os.system with a constant string", '''
import os

def clean_cache():
    os.system("rm -rf build/cache")
'''),

    # ---------------- SQL injection ----------------
    _case("h-sql-vuln", "vulnerable", "sql_injection", "quote-joined value in the query text", '''
import sqlite3

def find_user(conn, name):
    return conn.execute("SELECT * FROM users WHERE name = '" + name + "'").fetchall()
'''),
    _case("h-sql-fixed", "fixed", "sql_injection", "parameterized query", '''
import sqlite3

def find_user(conn, name):
    return conn.execute("SELECT * FROM users WHERE name = ?", (name,)).fetchall()
'''),
    _case("h-sql-look", "lookalike", "sql_injection", "query text joined from constants only", '''
COLUMNS = ["id", "name"]
QUERY = "SELECT " + ", ".join(COLUMNS) + " FROM users"

def all_users(conn):
    return conn.execute(QUERY).fetchall()
'''),

    # ---------------- code injection ----------------
    _case("h-code-vuln", "vulnerable", "code_injection", "eval of a caller-supplied rule, with empty globals (which is not a sandbox)", '''
def apply_filter(rows, rule):
    return [row for row in rows if eval(rule, {}, {"row": row})]
'''),
    _case("h-code-fixed", "fixed", "code_injection", "literal parsing only", '''
import ast

def parse_value(text):
    return ast.literal_eval(text)
'''),
    _case("h-code-look", "lookalike", "code_injection", "eval of a fixed literal", '''
def default_limits():
    return eval("{'rate': 10, 'burst': 20}")
'''),

    # ---------------- insecure deserialization ----------------
    _case("h-deser-vuln", "vulnerable", "insecure_deserialization", "pickle.loads on bytes from a caller", '''
import pickle

def load_session(blob):
    return pickle.loads(blob)
'''),
    _case("h-deser-vuln-yaml", "vulnerable", "insecure_deserialization", "yaml.load with an explicit full (unsafe) loader", '''
import yaml

def read_settings(text):
    return yaml.load(text, Loader=yaml.FullLoader)
'''),
    _case("h-deser-fixed", "fixed", "insecure_deserialization", "json", '''
import json

def load_session(blob):
    return json.loads(blob)
'''),
    _case("h-deser-look", "lookalike", "insecure_deserialization", "pickle used only to write, never to read", '''
import pickle

def save_session(session):
    return pickle.dumps(session)
'''),

    # ---------------- weak cryptography ----------------
    _case("h-crypto-vuln", "vulnerable", "weak_crypto", "SHA-1 to store a password", '''
import hashlib

def store_password(password):
    return hashlib.sha1(password.encode()).hexdigest()
'''),
    _case("h-crypto-fixed", "fixed", "weak_crypto", "salted PBKDF2", '''
import hashlib
import os

def store_password(password):
    salt = os.urandom(16)
    return salt + hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)
'''),
    _case("h-crypto-look", "lookalike", "weak_crypto", "MD5 declared as not for security, used for an ETag", '''
import hashlib

def etag(content):
    return hashlib.md5(content, usedforsecurity=False).hexdigest()
'''),

    # ---------------- insecure randomness ----------------
    _case("h-rand-vuln", "vulnerable", "insecure_random", "reset token from the random module", '''
import random
import string

def reset_token():
    return "".join(random.choices(string.ascii_letters + string.digits, k=32))
'''),
    _case("h-rand-fixed", "fixed", "insecure_random", "secrets module", '''
import secrets

def reset_token():
    return secrets.token_urlsafe(32)
'''),
    _case("h-rand-look", "lookalike", "insecure_random", "random used to shuffle a playlist", '''
import random

def shuffle_playlist(tracks):
    random.shuffle(tracks)
    return tracks
'''),

    # ---------------- path traversal ----------------
    _case("h-path-vuln", "vulnerable", "path_traversal", "caller-supplied name joined onto a folder, unchecked", '''
import os

def read_upload(name):
    with open(os.path.join("/srv/uploads", name)) as handle:
        return handle.read()
'''),
    _case("h-path-fixed", "fixed", "path_traversal", "resolved path checked against the base folder", '''
import os

BASE = os.path.realpath("/srv/uploads")

def read_upload(name):
    path = os.path.realpath(os.path.join(BASE, name))
    if not path.startswith(BASE + os.sep):
        raise ValueError("outside the upload folder")
    with open(path) as handle:
        return handle.read()
'''),
    _case("h-path-look", "lookalike", "path_traversal", "opens a fixed path", '''
def read_banner():
    with open("/srv/app/banner.txt") as handle:
        return handle.read()
'''),

    # ---------------- SSRF ----------------
    _case("h-ssrf-vuln", "vulnerable", "ssrf", "server fetches a caller-supplied URL", '''
import urllib.request

def proxy(url):
    return urllib.request.urlopen(url, timeout=5).read()
'''),
    _case("h-ssrf-fixed", "fixed", "ssrf", "host checked against an allow-list", '''
import urllib.parse
import urllib.request

ALLOWED_HOSTS = {"api.example.com", "cdn.example.com"}

def proxy(url):
    if urllib.parse.urlparse(url).hostname not in ALLOWED_HOSTS:
        raise ValueError("host not allowed")
    return urllib.request.urlopen(url, timeout=5).read()
'''),
    _case("h-ssrf-look", "lookalike", "ssrf", "request to a fixed URL", '''
import requests

def get_status():
    return requests.get("https://api.example.com/status", timeout=5).json()
'''),
    _case("h-ssrf-ping", "lookalike", "ssrf", "ping with a variable host: a command, not an HTTP request", '''
import subprocess

def reachable(host):
    return subprocess.run(["ping", "-c", "1", host]).returncode == 0
'''),

    # ---------------- XSS / template injection ----------------
    _case("h-xss-vuln", "vulnerable", "xss_or_template_injection", "template built from an f-string with a parameter", '''
from jinja2 import Template

def greeting(name):
    return Template(f"<h1>Hello {name}</h1>").render()
'''),
    _case("h-xss-vuln-autoescape", "vulnerable", "xss_or_template_injection", "auto-escaping switched off", '''
from jinja2 import Environment

env = Environment(autoescape=False)
PAGE = env.from_string("<p>{{ comment }}</p>")

def show(comment):
    return PAGE.render(comment=comment)
'''),
    _case("h-xss-fixed", "fixed", "xss_or_template_injection", "fixed template, values passed as variables", '''
from flask import render_template_string

def greeting(name):
    return render_template_string("<h1>Hello {{ name }}</h1>", name=name)
'''),
    _case("h-xss-look", "lookalike", "xss_or_template_injection", "template text joined from a constant", '''
from jinja2 import Template

TITLE = "Dashboard"

def page():
    return Template("<h1>" + TITLE + "</h1>").render()
'''),

    # ---------------- TLS verification ----------------
    _case("h-tls-vuln", "vulnerable", "tls_verification_disabled", "unverified SSL context", '''
import ssl
import urllib.request

def fetch_status():
    context = ssl._create_unverified_context()
    return urllib.request.urlopen("https://api.example.com/status", context=context, timeout=5).read()
'''),
    _case("h-tls-fixed", "fixed", "tls_verification_disabled", "default verification", '''
import urllib.request

def fetch_status():
    return urllib.request.urlopen("https://api.example.com/status", timeout=5).read()
'''),
    _case("h-tls-look", "lookalike", "tls_verification_disabled", "verification against a custom CA file", '''
import requests

def fetch_status():
    return requests.get("https://internal.example.com/status", verify="/etc/ssl/internal-ca.pem", timeout=5).text
'''),

    # ---------------- debug mode ----------------
    _case("h-debug-vuln", "vulnerable", "debug_enabled", "Flask started in debug mode", '''
from flask import Flask

app = Flask(__name__)

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
'''),
    _case("h-debug-fixed", "fixed", "debug_enabled", "debug off", '''
from flask import Flask

app = Flask(__name__)

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=False)
'''),
    _case("h-debug-look", "lookalike", "debug_enabled", "debug-level logging, not framework debug mode", '''
import logging

logging.basicConfig(level=logging.DEBUG)
'''),

    # ---------------- temporary files ----------------
    _case("h-temp-vuln", "vulnerable", "insecure_temp_file", "tempfile.mktemp", '''
import tempfile

def scratch_path():
    path = tempfile.mktemp()
    open(path, "w").close()
    return path
'''),
    _case("h-temp-fixed", "fixed", "insecure_temp_file", "NamedTemporaryFile", '''
import tempfile

def scratch_file():
    handle = tempfile.NamedTemporaryFile(delete=False)
    handle.close()
    return handle.name
'''),
    _case("h-temp-look", "lookalike", "insecure_temp_file", "a fixed path that is not a temporary file", '''
def save_state(text):
    with open("/var/lib/app/state.json", "w") as handle:
        handle.write(text)
'''),
]


def fingerprint(cases: list[dict] = HELDOUT_CASES) -> str:
    """12 hex characters identifying exactly these cases (ids, labels and code)."""
    text = "\n".join(f"{c['id']}|{c['kind']}|{c['category']}|{c['code']}" for c in cases)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


def demo() -> None:
    from benchmark.cases_python import CASES as DEV_CASES
    from security_service.core.questions import CATEGORY_IDS

    ids = [c["id"] for c in HELDOUT_CASES]
    assert len(ids) == len(set(ids)), "duplicate ids"
    assert not set(ids) & {c["id"] for c in DEV_CASES}, "a held-out id collides with a development id"
    dev_code = {c["code"] for c in DEV_CASES}
    assert not [c["id"] for c in HELDOUT_CASES if c["code"] in dev_code], "a held-out case repeats a development case"

    for case in HELDOUT_CASES:
        assert case["kind"] in {"vulnerable", "fixed", "lookalike"} and case["group"] == GROUP, case["id"]
        assert case["category"] in CATEGORY_IDS, f"{case['id']}: the classifier is not asked about {case['category']}"
        compile(case["code"], case["id"], "exec")                       # every case is valid Python

    # coverage: every question category has at least one vulnerable case and at least two safe ones
    for category in CATEGORY_IDS:
        mine = [c for c in HELDOUT_CASES if c["category"] == category]
        assert any(c["kind"] == "vulnerable" for c in mine), f"no vulnerable case for {category}"
        assert sum(c["kind"] != "vulnerable" for c in mine) >= 2, f"fewer than two safe cases for {category}"
    vulnerable = [c for c in HELDOUT_CASES if c["kind"] == "vulnerable"]
    safe = [c for c in HELDOUT_CASES if c["kind"] != "vulnerable"]
    assert (len(HELDOUT_CASES), len(vulnerable), len(safe)) == (39, 14, 25), (len(HELDOUT_CASES), len(vulnerable), len(safe))

    # rule 3's mechanical half: a safe case never contains a pattern that is the vulnerable pattern of another category
    import re
    forbidden = {r"(?<![\w.])eval\(": "code_injection", r"pickle\.loads": "insecure_deserialization", r"mktemp\(": "insecure_temp_file",
                 r"verify=False": "tls_verification_disabled", r"debug=True": "debug_enabled", r"_create_unverified_context": "tls_verification_disabled"}
    for case in safe:
        for pattern, owner in forbidden.items():
            if re.search(pattern, case["code"]) and not (case["id"] == "h-code-look" and "eval" in pattern):   # h-code-look is the deliberate eval look-alike
                raise AssertionError(f"{case['id']} (safe) contains {pattern!r}, the vulnerable pattern of {owner}")
    # ...and the check itself works: it flags a bare eval but not ast.literal_eval
    assert re.search(r"(?<![\w.])eval\(", "x = eval(y)") and not re.search(r"(?<![\w.])eval\(", "ast.literal_eval(text)")

    # the fingerprint is sensitive to everything that matters: a changed line of code, a changed label, a changed id, a removed case
    base = fingerprint()
    edited_code = [dict(c) for c in HELDOUT_CASES]
    edited_code[0]["code"] += "# edited\n"
    relabeled = [dict(c) for c in HELDOUT_CASES]
    relabeled[0]["kind"] = "fixed"
    renamed = [dict(c) for c in HELDOUT_CASES]
    renamed[0]["id"] = "h-renamed"
    for label, changed in (("code", edited_code), ("label", relabeled), ("id", renamed), ("removal", HELDOUT_CASES[1:])):
        assert fingerprint(changed) != base, f"the fingerprint ignores a change of {label}"

    # the lock: the cases are exactly the ones written before any model run
    assert PINNED_FINGERPRINT == fingerprint(), (
        f"the held-out cases changed: fingerprint is now {fingerprint()}, pinned {PINNED_FINGERPRINT}. "
        "If this was deliberate, the set is no longer held out: write a new one (see the rules at the top).")

    print(f"cases_heldout OK: {len(HELDOUT_CASES)} cases ({len(vulnerable)} vulnerable, {len(safe)} safe), none seen by a model, "
          f"every category covered, fingerprint {fingerprint()} matches the pin")


if __name__ == "__main__":
    demo()
