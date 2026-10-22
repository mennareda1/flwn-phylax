"""
benchmark/cases_python.py

Labeled Python test cases for the scanner. Three kinds:

  vulnerable - real weakness; `category` is what a correct scanner should call it
  fixed      - the secure twin of a vulnerable case (same task, safe code)
  lookalike  - looks suspicious to a pattern matcher but is actually safe

This is the part to REVIEW BY HAND: a mislabeled case silently corrupts every
number the benchmark produces. Add real Executor outputs here too (hand-label
them) -- that is the closest thing to Flwn's real distribution.

Never train a model on these cases; they are the held-out test.
"""

from __future__ import annotations


def _case(case_id: str, kind: str, category: str, note: str, code: str, group: str = "base") -> dict:
    return {"id": case_id, "kind": kind, "category": category, "note": note,
            "code": code.strip("\n") + "\n", "group": group}


CASES: list[dict] = [
    # ---------------- command injection ----------------
    _case("cmd-os-system", "vulnerable", "command_injection", "user value concatenated into a shell command", '''
import os

def ping_host(host):
    os.system("ping -c 1 " + host)
'''),
    _case("cmd-shell-fstring", "vulnerable", "command_injection", "f-string into shell=True", '''
import subprocess

def archive(filename):
    subprocess.run(f"tar -czf backup.tgz {filename}", shell=True)
'''),
    _case("cmd-nosec", "vulnerable", "command_injection", "same bug with a '# nosec' comment trying to silence the linter", '''
import subprocess

def run_user_command(cmd):
    subprocess.run(cmd, shell=True)  # nosec
'''),
    _case("cmd-list-args", "fixed", "command_injection", "argument list, no shell", '''
import subprocess

def ping_host(host):
    subprocess.run(["ping", "-c", "1", host], check=True)
'''),
    _case("cmd-shell-literal", "lookalike", "command_injection", "shell=True but the command is a constant, no input", '''
import subprocess

def list_files():
    subprocess.run("ls -l", shell=True)
'''),
    _case("cmd-git-status", "lookalike", "command_injection", "fixed argument list, no user input", '''
import subprocess

def git_status():
    return subprocess.run(["git", "status", "--short"], capture_output=True, text=True).stdout
'''),

    # ---------------- SQL injection ----------------
    _case("sqli-fstring", "vulnerable", "sql_injection", "f-string SQL", '''
def get_user(cursor, username):
    cursor.execute(f"SELECT * FROM users WHERE name = '{username}'")
    return cursor.fetchone()
'''),
    _case("sqli-concat", "vulnerable", "sql_injection", "string concatenation SQL", '''
def find_orders(cursor, customer_id):
    query = "SELECT * FROM orders WHERE customer_id = " + customer_id
    cursor.execute(query)
    return cursor.fetchall()
'''),
    _case("sqli-param", "fixed", "sql_injection", "parameterized query", '''
def get_user(cursor, username):
    cursor.execute("SELECT * FROM users WHERE name = %s", (username,))
    return cursor.fetchone()
'''),
    _case("sqli-constant-table", "lookalike", "sql_injection", "SQL built only from a module constant", '''
TABLE = "users"

def count_users(cursor):
    cursor.execute("SELECT COUNT(*) FROM " + TABLE)
    return cursor.fetchone()[0]
'''),

    # ---------------- hardcoded credentials ----------------
    _case("cred-password", "vulnerable", "hardcoded_credentials", "password literal in source", '''
import psycopg2

DB_PASSWORD = "SuperSecret123!"

def connect():
    return psycopg2.connect(host="db", user="admin", password=DB_PASSWORD)
'''),
    _case("cred-api-key", "vulnerable", "hardcoded_credentials", "API key literal under a name that pattern rules often miss", '''
import requests

API_KEY = "sk-live-EXAMPLE0000000000000000"

def fetch_orders():
    return requests.get("https://api.example.com/orders", headers={"Authorization": "Bearer " + API_KEY}, timeout=10)
'''),
    _case("cred-env", "fixed", "hardcoded_credentials", "secret read from the environment", '''
import os
import psycopg2

DB_PASSWORD = os.environ["DB_PASSWORD"]

def connect():
    return psycopg2.connect(host="db", user="admin", password=DB_PASSWORD)
'''),
    _case("cred-token-url", "lookalike", "hardcoded_credentials", "variable name contains 'token' but it is just a URL", '''
TOKEN_URL = "https://auth.example.com/oauth/token"

def token_endpoint():
    return TOKEN_URL
'''),

    # ---------------- insecure deserialization ----------------
    _case("deser-pickle", "vulnerable", "insecure_deserialization", "pickle.loads on request data", '''
import pickle

def load_session(data):
    return pickle.loads(data)
'''),
    _case("deser-yaml", "vulnerable", "insecure_deserialization", "yaml.load with the unsafe loader", '''
import yaml

def read_config(text):
    return yaml.load(text, Loader=yaml.Loader)
'''),
    _case("deser-json", "fixed", "insecure_deserialization", "JSON instead of pickle", '''
import json

def load_session(data):
    return json.loads(data)
'''),
    _case("deser-yaml-safe", "fixed", "insecure_deserialization", "yaml.safe_load", '''
import yaml

def read_config(text):
    return yaml.safe_load(text)
'''),

    # ---------------- code injection ----------------
    _case("code-eval", "vulnerable", "code_injection", "eval on user text", '''
def calculate(expression):
    return eval(expression)
'''),
    _case("code-literal-eval", "fixed", "code_injection", "ast.literal_eval", '''
import ast

def calculate(expression):
    return ast.literal_eval(expression)
'''),

    # ---------------- weak crypto ----------------
    _case("crypto-md5-password", "vulnerable", "weak_crypto", "MD5 used for password hashing", '''
import hashlib

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
'''),
    _case("crypto-pbkdf2", "fixed", "weak_crypto", "salted PBKDF2", '''
import hashlib
import os

def hash_password(password):
    salt = os.urandom(16)
    return salt + hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)
'''),
    _case("crypto-md5-cache-key", "lookalike", "weak_crypto", "MD5 for a cache key, explicitly not for security", '''
import hashlib

def cache_key(text):
    return hashlib.md5(text.encode(), usedforsecurity=False).hexdigest()
'''),

    # ---------------- insecure randomness ----------------
    _case("random-token", "vulnerable", "insecure_random", "password-reset token from the random module", '''
import random
import string

def make_reset_token():
    return "".join(random.choices(string.ascii_letters + string.digits, k=32))
'''),
    _case("random-secrets", "fixed", "insecure_random", "secrets module", '''
import secrets

def make_reset_token():
    return secrets.token_urlsafe(32)
'''),
    _case("random-greeting", "lookalike", "insecure_random", "random used for non-security text", '''
import random

def pick_greeting():
    return random.choice(["Hi", "Hello", "Hey"])
'''),

    # ---------------- path traversal ----------------
    _case("path-open-join", "vulnerable", "path_traversal", "user filename joined onto a base dir with no check", '''
import os

BASE_DIR = "/srv/uploads"

def read_upload(filename):
    with open(os.path.join(BASE_DIR, filename)) as handle:
        return handle.read()
'''),
    _case("path-realpath", "fixed", "path_traversal", "resolved path must stay inside the base dir", '''
import os

BASE_DIR = os.path.realpath("/srv/uploads")

def read_upload(filename):
    path = os.path.realpath(os.path.join(BASE_DIR, filename))
    if not path.startswith(BASE_DIR + os.sep):
        raise ValueError("invalid path")
    with open(path) as handle:
        return handle.read()
'''),

    # ---------------- SSRF ----------------
    _case("ssrf-request-arg", "vulnerable", "ssrf", "server fetches a URL taken straight from the request", '''
import requests
from flask import request

def preview():
    url = request.args["url"]
    return requests.get(url, timeout=5).text
'''),
    _case("ssrf-allowlist", "fixed", "ssrf", "host allow-list before fetching", '''
import requests
from urllib.parse import urlparse
from flask import request

ALLOWED_HOSTS = {"images.example.com"}

def preview():
    url = request.args["url"]
    if urlparse(url).hostname not in ALLOWED_HOSTS:
        raise ValueError("host not allowed")
    return requests.get(url, timeout=5).text
'''),

    # ---------------- XSS / template injection ----------------
    _case("ssti-concat", "vulnerable", "xss_or_template_injection", "user input concatenated into a template string", '''
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    return render_template_string("<h1>Hello " + name + "</h1>")
'''),
    _case("ssti-variable", "fixed", "xss_or_template_injection", "value passed as a template variable (auto-escaped)", '''
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    return render_template_string("<h1>Hello {{ name }}</h1>", name=name)
'''),
    _case("jinja-autoescape-off", "vulnerable", "xss_or_template_injection", "Jinja2 environment with autoescape disabled", '''
import jinja2

env = jinja2.Environment(autoescape=False)

def render(template_text, **values):
    return env.from_string(template_text).render(**values)
'''),
    _case("jinja-autoescape-on", "fixed", "xss_or_template_injection", "autoescape enabled", '''
import jinja2

env = jinja2.Environment(autoescape=True)

def render(template_text, **values):
    return env.from_string(template_text).render(**values)
'''),

    # ---------------- TLS verification ----------------
    _case("tls-verify-off", "vulnerable", "tls_verification_disabled", "verify=False", '''
import requests

def fetch(url):
    return requests.get(url, verify=False, timeout=10).text
'''),
    _case("tls-verify-default", "fixed", "tls_verification_disabled", "default certificate verification", '''
import requests

def fetch(url):
    return requests.get(url, timeout=10).text
'''),

    # ---------------- debug mode ----------------
    _case("flask-debug-on", "vulnerable", "debug_enabled", "Flask app started with debug=True", '''
from flask import Flask

app = Flask(__name__)

if __name__ == "__main__":
    app.run(debug=True)
'''),
    _case("flask-debug-off", "fixed", "debug_enabled", "no debug flag", '''
from flask import Flask

app = Flask(__name__)

if __name__ == "__main__":
    app.run()
'''),

    # ---------------- temp files ----------------
    _case("temp-mktemp", "vulnerable", "insecure_temp_file", "tempfile.mktemp is race-prone", '''
import tempfile

def scratch_path():
    return tempfile.mktemp()
'''),
    _case("temp-mkstemp", "fixed", "insecure_temp_file", "tempfile.mkstemp", '''
import tempfile

def scratch_file():
    handle, path = tempfile.mkstemp()
    return handle, path
'''),

    # ---------------- other harmless code ----------------
    _case("lookalike-assert-test", "lookalike", "other", "assert inside a test function", '''
def test_addition():
    assert 1 + 1 == 2
'''),
]


BASE_CASES = list(CASES)   # the original 41 cases, kept as a fixed reference set for before/after comparisons

# Added in session 1 for the secrets check. They were written AFTER the check's heuristics were
# designed, so they are regression guards and false-alarm probes, not independent evidence.
_SV1 = "secrets_v1"
SECRET_CASES: list[dict] = [
    _case("cred-aws-key", "vulnerable", "hardcoded_credentials", "cloud access key in its documented format", '''
import boto3

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"

def s3():
    return boto3.client("s3", aws_access_key_id=AWS_ACCESS_KEY_ID)
''', _SV1),
    _case("cred-github-token", "vulnerable", "hardcoded_credentials", "GitHub token in its documented format", '''
import requests

GITHUB_TOKEN = "ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"

def repos():
    return requests.get("https://api.github.com/user/repos", headers={"Authorization": "token " + GITHUB_TOKEN}, timeout=10)
''', _SV1),
    _case("cred-dict-password", "vulnerable", "hardcoded_credentials", "password literal inside a config dict", '''
DB_CONFIG = {"host": "db", "user": "admin", "password": "hunter22"}
''', _SV1),
    _case("cred-private-key", "vulnerable", "hardcoded_credentials", "private key pasted into the source", '''
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu
-----END RSA PRIVATE KEY-----"""
''', _SV1),
    _case("cred-header-name", "lookalike", "hardcoded_credentials", "credential-looking NAME that holds a header name", '''
API_KEY_HEADER = "X-Api-Key"

def headers(key):
    return {API_KEY_HEADER: key}
''', _SV1),
    _case("cred-env-var-name", "lookalike", "hardcoded_credentials", "holds the NAME of an environment variable, not a secret", '''
import os

PASSWORD_ENV_VAR = "DB_PASSWORD"

def password():
    return os.environ[PASSWORD_ENV_VAR]
''', _SV1),
    _case("cred-secret-path", "lookalike", "hardcoded_credentials", "path to a secret in a vault, not the secret", '''
SECRET_PATH = "prod/db/credentials"
''', _SV1),
    _case("cred-version-string", "lookalike", "hardcoded_credentials", "a date under a credential-looking name", '''
API_KEY_VERSION = "2024-01-01"
''', _SV1),
    _case("cred-getenv-empty", "fixed", "hardcoded_credentials", "secret read from the environment with an empty default", '''
import os

API_TOKEN = os.getenv("API_TOKEN", "")
''', _SV1),
]

CASES = BASE_CASES + SECRET_CASES


def summary() -> str:
    from collections import Counter
    kinds = Counter(c["kind"] for c in CASES)
    return f"{len(CASES)} cases: " + ", ".join(f"{n} {k}" for k, n in sorted(kinds.items()))


if __name__ == "__main__":
    ids = [c["id"] for c in CASES]
    assert len(ids) == len(set(ids)), "duplicate case ids"
    for c in CASES:
        compile(c["code"], c["id"], "exec")  # every case must be valid Python
    print(summary())
