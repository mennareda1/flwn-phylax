"""
security_service/core/redaction.py

Secret handling shared by two jobs that must agree on what a secret looks like:

  1. MASKING (redact_secrets, mask_for_report): before code is sent to ANY external model, and
     before an evidence line is shown to a user, secrets are replaced with <REDACTED_SECRET>.
     Line count is preserved, so line numbers in a model's answer still match the original.
     Masking is deliberately LIBERAL: a missed secret leaks, a wrongly masked value costs nothing.
  2. DETECTING (scan_secrets, used by adapters/secrets.py): finding secrets to report to a user.
     Detection is deliberately CAREFUL: every report becomes an alarm someone must look at, so a
     match is only "strict" (reportable) when the value could plausibly be a real secret. Names,
     header names, environment-variable names, paths, URLs and version strings are not.

So: mask liberally, accuse carefully. Both are best-effort. A secret in an unusual format or an
oddly named variable can slip through either one; neither replaces choosing providers whose data
terms are acceptable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

PLACEHOLDER = "<REDACTED_SECRET>"

_KNOWN_TOKENS = re.compile(
    r"sk-[A-Za-z0-9_\-]{12,}"
    r"|AKIA[0-9A-Z]{16}"
    r"|gh[pousr]_[A-Za-z0-9]{20,}"
    r"|xox[baprs]-[A-Za-z0-9\-]{10,}"
    r"|eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"
)
_BEARER = re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._\-]{16,}")

_CRED_NAME = (
    r"(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[_\-]?key|apikey|"
    r"access[_\-]?key|private[_\-]?key|credential|auth[_\-]?key)"
)
_CRED_ASSIGN = re.compile(
    r"(?i)(\b[\w.]*" + _CRED_NAME + r"[\w.]*['\"]?\s*[:=]\s*)(['\"])([^'\"\n]{6,})\2"
)
_URL_OR_PATH = re.compile(r"^(?:[a-zA-Z][a-zA-Z0-9+.\-]*://|/|\./|\.\./|~/|[A-Za-z]:\\)")
_STRING_LITERAL = re.compile(r"""(['"])(?:\\.|(?!\1).)*\1""")

_PRIVATE_KEY_BEGIN = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_PRIVATE_KEY_END = re.compile(r"-----END [A-Z ]*PRIVATE KEY-----")

_NAME_LIKE = re.compile(r"[A-Za-z][A-Za-z_.\-/]*")
_VERSION_LIKE = re.compile(r"[vV]?[0-9][0-9._\-:/]*")
_SYMBOLS = re.compile(r"[!@#$%^&*()+={}\[\]|;:<>?~]")


def _looks_like_secret_value(value: str) -> bool:
    """LIBERAL test used for masking."""
    if re.search(r"\s", value) or _URL_OR_PATH.match(value):
        return False
    has_digit_or_symbol = bool(re.search(r"[^A-Za-z]", value))
    return has_digit_or_symbol or len(value) >= 16


def is_probable_secret(value: str) -> bool:
    """CAREFUL test used for reporting. False for names, headers, env-var names, paths, URLs,
    dates and versions; true for values with digits or symbols mixed in, or a long mixed-case run."""
    if len(value) < 6 or re.search(r"\s", value) or _URL_OR_PATH.match(value):
        return False
    if _VERSION_LIKE.fullmatch(value):
        return False
    if _NAME_LIKE.fullmatch(value):
        return len(value) >= 20 and value.isalpha() and value != value.lower() and value != value.upper()
    return bool(re.search(r"\d", value) or _SYMBOLS.search(value))


@dataclass(frozen=True)
class SecretHit:
    kind: str       # known_token | bearer_token | credential_assignment | private_key
    strict: bool    # True when careful enough to report to a user; False means "mask it, do not accuse"


def scan_line(line: str) -> list[SecretHit]:
    hits: list[SecretHit] = []
    hits += [SecretHit("known_token", True) for _ in _KNOWN_TOKENS.finditer(line)]
    hits += [SecretHit("bearer_token", True) for _ in _BEARER.finditer(line)]
    for match in _CRED_ASSIGN.finditer(line):
        value = match.group(3)
        if PLACEHOLDER in value or not _looks_like_secret_value(value):
            continue
        hits.append(SecretHit("credential_assignment", is_probable_secret(value)))
    return hits


def scan_secrets(code: str) -> list[tuple[int, SecretHit]]:
    """(1-based line number, hit) for every secret in the code. A private key block is reported once,
    at its BEGIN line."""
    results: list[tuple[int, SecretHit]] = []
    in_block = False
    for number, line in enumerate(code.split("\n"), start=1):
        if in_block:
            if _PRIVATE_KEY_END.search(line):
                in_block = False
            continue
        begin = _PRIVATE_KEY_BEGIN.search(line)
        if begin:
            results.append((number, SecretHit("private_key", True)))
            in_block = not _PRIVATE_KEY_END.search(line, begin.end())
            continue
        results.extend((number, hit) for hit in scan_line(line))
    return results


def redact_line(line: str) -> tuple[str, int]:
    count = 0

    def known(_match: re.Match) -> str:
        nonlocal count
        count += 1
        return PLACEHOLDER

    def bearer(match: re.Match) -> str:
        nonlocal count
        count += 1
        return match.group(1) + PLACEHOLDER

    def assign(match: re.Match) -> str:
        nonlocal count
        if PLACEHOLDER in match.group(3) or not _looks_like_secret_value(match.group(3)):
            return match.group(0)   # already masked, or not secret-like (URL, plain word)
        count += 1
        return f"{match.group(1)}{match.group(2)}{PLACEHOLDER}{match.group(2)}"

    line = _KNOWN_TOKENS.sub(known, line)
    line = _BEARER.sub(bearer, line)
    line = _CRED_ASSIGN.sub(assign, line)
    return line, count


def redact_secrets(code: str) -> tuple[str, int]:
    """Mask secrets line by line, and whole private key blocks. Returns (redacted_code, replacements).
    Line count is unchanged."""
    total = 0
    out: list[str] = []
    in_block = False
    for line in code.split("\n"):
        if in_block:
            end = _PRIVATE_KEY_END.search(line)
            out.append(PLACEHOLDER + (line[end.end():] if end else ""))
            in_block = end is None
            continue
        begin = _PRIVATE_KEY_BEGIN.search(line)
        if begin:
            total += 1
            end = _PRIVATE_KEY_END.search(line, begin.end())
            out.append(line[:begin.start()] + PLACEHOLDER + (line[end.end():] if end else ""))
            in_block = end is None
            continue
        redacted, n = redact_line(line)
        total += n
        out.append(redacted)
    return "\n".join(out), total


def mask_for_report(line: str, vuln_type: str) -> str:
    """Evidence line safe to show to users: tokens redacted; string values hidden for credential findings."""
    line, _ = redact_line(line)
    if vuln_type == "hardcoded_credentials":
        line = _STRING_LITERAL.sub('"***"', line)
    return line


def demo() -> None:
    code = (
        'DB_PASSWORD = "SuperSecret123!"\n'
        'API_KEY = "sk-live-EXAMPLE0000000000000000"\n'
        'TOKEN_URL = "https://auth.example.com/oauth/token"\n'
        'password_label = "Password"\n'
        'headers = {"Authorization": "Bearer abcdefghijklmnop12345"}\n'
        'cfg = {"password": "hunter22"}\n'
        'x = 1\n'
    )
    redacted, n = redact_secrets(code)
    lines = redacted.split("\n")
    assert len(lines) == len(code.split("\n")), "line count must be preserved"
    assert lines[0] == f'DB_PASSWORD = "{PLACEHOLDER}"'
    assert PLACEHOLDER in lines[1] and "sk-live" not in lines[1]
    assert lines[2] == 'TOKEN_URL = "https://auth.example.com/oauth/token"'   # URL left alone
    assert lines[3] == 'password_label = "Password"'                           # plain word left alone
    assert "abcdefghijklmnop12345" not in lines[4] and "Bearer" in lines[4]
    assert "hunter22" not in lines[5]
    assert lines[6] == "x = 1"
    assert n == 4, n

    assert mask_for_report('DB_PASSWORD = "SuperSecret123!"', "hardcoded_credentials") == 'DB_PASSWORD = "***"'
    assert "sk-live" not in mask_for_report('k = "sk-live-EXAMPLE0000000000000000"', "other")

    # careful test: what counts as a probable secret
    for secret in ("SuperSecret123!", "hunter22", "abc123", "x9Zk2mQ8vL1pR4tY7wN0", "P@ssw0rd", "AbCdEfGhIjKlMnOpQrStUv"):
        assert is_probable_secret(secret), secret
    for not_secret in ("Password", "changeme", "X-Api-Key", "DB_PASSWORD", "prod/db/credentials", "my-service-token-name",
                       "2024-01-01", "v2.1.0", "https://auth.example.com/token", "/etc/secrets/key", "short",
                       "correcthorsebatterystaple"):
        assert not is_probable_secret(not_secret), not_secret
    # ... but masking stays liberal: a long lowercase passphrase is still masked
    assert PLACEHOLDER in redact_line('passphrase = "correcthorsebatterystaple"')[0]

    # detection: only careful matches are strict
    assert [h.strict for h in scan_line('password = "hunter22"')] == [True]
    assert [h.strict for h in scan_line('passphrase = "correcthorsebatterystaple"')] == [False]
    strict = lambda line: [h for h in scan_line(line) if h.strict]
    assert strict('API_KEY_HEADER = "X-Api-Key"') == []          # masked liberally, never accused
    assert strict('SECRET_PATH = "prod/db/credentials"') == []
    assert strict('API_KEY_VERSION = "2024-01-01"') == []
    assert strict('PASSWORD_ENV_VAR = "DB_PASSWORD"') == []
    assert {h.kind for h in scan_line('API_KEY = "sk-live-EXAMPLE0000000000000000"')} == {"known_token", "credential_assignment"}

    # masking and detection agree on whether a line holds a secret (so nothing is detected but unmasked)
    samples = [l for l in code.split("\n")] + [
        'x = os.environ["TOKEN"]', 'secret_name = "prod/db/credentials"', 'api_key = "AKIAIOSFODNN7EXAMPLE"',
        'ghp = "ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"', 'jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop"',
    ]
    for line in samples:
        assert bool(scan_line(line)) == bool(redact_line(line)[1]), line

    # private key blocks: detected once at the BEGIN line, and masked in full, with line count and surrounding code kept
    key = 'KEY = """-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n-----END RSA PRIVATE KEY-----"""\nx = 1'
    assert scan_secrets(key) == [(1, SecretHit("private_key", True))]
    masked, count = redact_secrets(key)
    mlines = masked.split("\n")
    assert len(mlines) == 4 and count == 1
    assert mlines[0] == f'KEY = """{PLACEHOLDER}' and mlines[1] == PLACEHOLDER and mlines[2] == f'{PLACEHOLDER}"""' and mlines[3] == "x = 1"
    assert "MIIBOg" not in masked
    unterminated, _ = redact_secrets("a = 1\n-----BEGIN PRIVATE KEY-----\nAAAA\nBBBB")
    assert "AAAA" not in unterminated and len(unterminated.split("\n")) == 4   # fails safe: masks to the end

    print("core.redaction OK: mask liberally, accuse carefully; names, URLs and versions are not accused; private key blocks masked")


if __name__ == "__main__":
    demo()
