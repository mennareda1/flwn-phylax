"""
security_service/core/redaction.py

Best-effort secret masking, used in two places:

  1. Before code is sent to ANY external model: known token formats and
     credential-looking assignments are replaced with <REDACTED_SECRET>, so
     customer secrets do not leave the system. Line count is preserved, so
     line numbers in the model's answer still match the original code. The
     placeholder still shows a string literal sits in a credential-named
     variable, so hardcoded-credential detection keeps working.
  2. Before evidence lines are put into a report or chat message.

This is a safety net, not a guarantee: a secret in an unusual format or an
oddly named variable can slip through. It reduces exposure; it does not
replace choosing vendors whose data terms are acceptable.
"""

from __future__ import annotations

import re

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


def _looks_like_secret_value(value: str) -> bool:
    if re.search(r"\s", value) or _URL_OR_PATH.match(value):
        return False
    has_digit_or_symbol = bool(re.search(r"[^A-Za-z]", value))
    return has_digit_or_symbol or len(value) >= 16


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
    """Mask secrets line by line. Returns (redacted_code, number_of_replacements). Line count is unchanged."""
    total = 0
    out = []
    for line in code.split("\n"):
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
    print("redaction OK: secrets masked, URLs and plain words kept, line count preserved")


if __name__ == "__main__":
    demo()
