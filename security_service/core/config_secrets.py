"""
security_service/core/config_secrets.py

Finds hardcoded secrets in CONFIGURATION and TEXT files (.json .yaml .yml .toml .ini .properties .config .txt). Secrets only: nothing else about such a file is judged, and
the report says so (coverage.limited_scope).

Why this is not just the code scanner. In code a secret sits inside quotes (`password = "x"`). In a configuration file it often does not: YAML `password: hunter2secret`, properties
`db.password=P@ssw0rd`, INI `api_key = 1a2b3c`. And configuration has its own places for credentials: a password inside a connection URL
(`postgres://admin:S3cr3t@db/app`), inside a connection string (`Server=db;Password=...;`), in a query string (`jdbc:mysql://db/app?password=...`), or in an XML setting
(`<add key="ApiKey" value="..."/>`).

Same policy as the rest of the project: MASK LIBERALLY, ACCUSE CAREFULLY. A value is reported only if it could plausibly be a real secret:
  - a reference is never a secret: ${DB_PASSWORD}, $DB_PASSWORD, %DB_PASSWORD%, {{ vault_password }}, <your-password>, ENC(...), vault:..., !secret name, an ARN;
  - a placeholder is never a secret: changeme, password, your-password-here, ******, xxxxxxxx, null, true, TODO;
  - a key that merely mentions a credential is not a credential: token_url, secret_name, password_min_length, api_key_header, use_password, token_type, password_hash;
  - the value must pass the same careful test as in code (core.redaction.is_probable_secret): digits or symbols mixed in, or a long mixed-case run. A dictionary passphrase such as
    `correcthorsebatterystaple` is NOT reported. That is a known false negative, recorded in the tests, not a surprise.

Every finding's evidence line has the secret value replaced by ***, not only quoted strings: an unquoted value would otherwise leak into the report.
"""

from __future__ import annotations

import re
from typing import NamedTuple
from urllib.parse import unquote

from security_service.core.redaction import PLACEHOLDER, is_probable_secret, redact_secrets, scan_secrets


class ConfigFinding(NamedTuple):
    line: int
    kind: str        # private_key | known_token | bearer_token | url_credential | connection_string | config_credential
    evidence: str    # the line with every detected secret masked


_ORDER = ("private_key", "known_token", "bearer_token", "url_credential", "connection_string", "config_credential")

_CRED = r"(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[_\-.]?key|apikey|access[_\-.]?key|private[_\-.]?key|credential|auth[_\-.]?key)"
_KEY = rf"[A-Za-z0-9_.\-/\[\]]*{_CRED}[A-Za-z0-9_.\-/\[\]]*"
_QUOTED_PAIR = re.compile(rf"""(?P<key>{_KEY})["']?\s*[:=]\s*(?P<q>["'])(?P<value>[^"'\n]*)(?P=q)""", re.I)
_BARE_PAIR = re.compile(rf"""^\s*(?:(?:[#;!]+|//)\s*)?(?:-\s+)?["']?(?P<key>{_KEY})["']?\s*[:=]\s*(?P<value>[^\s"'#;][^\n]*?)\s*$""", re.I)   # a leading comment marker is allowed: a commented-out credential is still leaked
# A comment line may put words before the key: "# old password: Hunter2!Prod". Found by the first held-out run.
_COMMENT_PAIR = re.compile(rf"""^\s*(?:[#;!]+|//)\s*(?:[^\n]*?[\s"'(])?(?P<key>{_KEY})["']?\s*[:=]\s*(?P<value>[^\s"'#;][^\n]*?)\s*$""", re.I)
_URL_CRED = re.compile(r"""[A-Za-z][A-Za-z0-9+.\-]*://(?P<user>[^/\s:@"'<>]*):(?P<value>[^/\s@"'<>]+)@""")
_QUERY_PW = re.compile(r"""(?i)[?&;](?:password|passwd|pwd|pass)=(?P<value>[^&;\s"'<>]+)""")
_CONN_PW = re.compile(r"""(?i)(?<![A-Za-z_])(?:password|pwd)\s*=\s*(?P<value>[^;"'\n]+)""")
_XML_ADD = re.compile(rf"""(?i)<add\s+key=["'](?P<key>[^"']*{_CRED}[^"']*)["']\s+value=["'](?P<value>[^"']*)["']""")
_XML_ELEMENT = re.compile(rf"""(?i)<(?P<key>[A-Za-z_.\-]*{_CRED}[A-Za-z_.\-]*)>(?P<value>[^<]+)</(?P=key)>""")

# A key that mentions a credential but is not one: a URL, a name, a length, a flag, a hash...
_BENIGN_KEY_END = re.compile(
    r"(?i)(?:url|uri|name|label|field|header|path|file|length|len|min|max|expiry|expires|expiration|ttl|policy|required|enabled|type|endpoint|prefix|suffix|format|pattern|"
    r"regex|hint|placeholder|text|message|msg|rotation|age|count|attempts|provider|mode|algorithm|alg|hash|id|ref|env|var|variable|location|dir|directory|timeout|key_name)$"
)
_REFERENCE = re.compile(
    r"(?i)^(?:\$\{|\$[A-Za-z_(]|%[A-Za-z_][A-Za-z0-9_]*%|\{\{|\{%|<[^>]*>$|ENC\(|vault:|secret:|secrets\.|env:|ref\+|!secret|!vault|!Ref|!Sub|!GetAtt|file:|arn:|kms:|ssm:|op://)"
)
_PLACEHOLDER_WORDS = {
    "password", "passwd", "passphrase", "secret", "token", "apikey", "api_key", "api-key", "key", "changeme", "change-me", "change_me", "changeit", "null", "none", "nil", "true",
    "false", "yes", "no", "on", "off", "required", "todo", "tbd", "fixme", "redacted", "example", "dummy", "test", "sample", "placeholder", "secret123", "password123", "admin",
}
# A dependency version or range: "^9.0.2", "~0.7.0", ">=5.1.0 <6", "1.2.3 - 2.0.0", "latest", "*", "workspace:*", "npm:pkg@1", "git+https://...". Found by the first held-out run:
# package.json has keys such as "jsonwebtoken" and "passport" whose values are version ranges.
_VERSION_RANGE = re.compile(
    r"(?i)^(?:\*|latest|next|workspace:.*|link:.*|npm:.*|git\+.*|github:.*|file:.*|"
    r"(?:[\^~<>=]+\s*)?[vV]?\d+(?:\.[\dxX*]+){0,3}(?:[-+][0-9A-Za-z.\-]+)?(?:\s*(?:\|\||-|,|\s)\s*(?:[\^~<>=]+\s*)?[vV]?\d+(?:\.[\dxX*]+){0,3})*)$"
)
_PLACEHOLDER_SHAPE = re.compile(
    r"(?i)^(?:(?:your|my|the|a)[-_ ]?)?(?:password|passwd|secret|token|api[-_ ]?key|passphrase|key)[-_ ]?(?:here|value|goes[-_ ]?here)?$|^(.)\1{3,}$|^[x*#.\-_\u2022]+$|"
    r"^(?:your|my-|example|sample|dummy|placeholder|replace|insert|enter|todo|tbd|fixme)"
)


def _clean(value: str) -> str:
    v = value.strip()
    if v and v[0] not in "\"'":
        v = re.split(r"\s+[#;]", v, maxsplit=1)[0]        # an inline comment, only when separated by space
    v = v.rstrip(",").strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        v = v[1:-1]
    return v.strip()


def is_secret_value(value: str) -> bool:
    """True when the value could plausibly be a real secret: not a reference, not a placeholder, and probable by the project's careful test."""
    v = _clean(value)
    if not v or PLACEHOLDER in v or _REFERENCE.match(v) or v.lower() in _PLACEHOLDER_WORDS or _PLACEHOLDER_SHAPE.match(v) or _VERSION_RANGE.match(v):
        return False
    return is_probable_secret(v)


def _credential_key(key: str) -> bool:
    return not _BENIGN_KEY_END.search(key.rstrip("]\"'"))


def _mask(line: str, spans: list[tuple[int, int]]) -> str:
    for start, end in sorted(set(spans), reverse=True):
        line = line[:start] + "***" + line[end:]
    masked, _ = redact_secrets(line)                   # known tokens, bearer tokens, quoted credential assignments, private-key blocks on the same line
    return masked


def scan_config(text: str, language: str = "config") -> list[ConfigFinding]:
    """One finding per line that holds a secret, with the strongest kind on that line, in line order."""
    del language                                          # one grammar for every configuration format: the patterns above cover all of them
    kinds: dict[int, set[str]] = {}
    spans: dict[int, list[tuple[int, int]]] = {}

    def add(number: int, kind: str, span: tuple[int, int] | None = None) -> None:
        kinds.setdefault(number, set()).add(kind)
        if span is not None:
            spans.setdefault(number, []).append(span)

    for number, hit in scan_secrets(text):                # known token formats, bearer tokens, private-key blocks
        if hit.kind in ("known_token", "bearer_token", "private_key"):
            add(number, hit.kind)

    for number, line in enumerate(text.split("\n"), start=1):
        if len(line) > 4000:                               # a minified blob, not a setting; the known formats above still apply to it
            continue
        quoted_value_spans: set[tuple[int, int]] = set()
        for m in _QUOTED_PAIR.finditer(line):
            quoted_value_spans.add(m.span("value"))
            if _credential_key(m.group("key")) and is_secret_value(m.group("value")):
                add(number, "config_credential", m.span("value"))
        bare = _BARE_PAIR.match(line) or _COMMENT_PAIR.match(line)
        if bare and _credential_key(bare.group("key")) and is_secret_value(bare.group("value")):
            start, _ = bare.span("value")
            cleaned = _clean(bare.group("value"))
            where = line.find(cleaned, start) if cleaned else -1
            if where != -1 and (where, where + len(cleaned)) not in quoted_value_spans:
                add(number, "config_credential", (where, where + len(cleaned)))
        for m in _URL_CRED.finditer(line):
            if is_secret_value(unquote(m.group("value"))):
                add(number, "url_credential", m.span("value"))
        for m in _QUERY_PW.finditer(line):
            if is_secret_value(unquote(m.group("value"))):
                add(number, "connection_string", m.span("value"))
        if ";" in line and line.count("=") >= 2:
            for m in _CONN_PW.finditer(line):
                if is_secret_value(m.group("value")):
                    add(number, "connection_string", m.span("value"))
        for pattern in (_XML_ADD, _XML_ELEMENT):
            for m in pattern.finditer(line):
                if _credential_key(m.group("key")) and is_secret_value(m.group("value")):
                    add(number, "config_credential", m.span("value"))

    lines = text.split("\n")
    return [ConfigFinding(n, next(k for k in _ORDER if k in kinds[n]), _mask(lines[n - 1].strip(), [(s - (len(lines[n - 1]) - len(lines[n - 1].lstrip())), e - (len(lines[n - 1]) - len(lines[n - 1].lstrip()))) for s, e in spans.get(n, [])])[:200]) for n in sorted(kinds)]


def demo() -> None:
    def found(text: str) -> list[tuple[int, str]]:
        return [(f.line, f.kind) for f in scan_config(text)]

    real = {
        "json nested": '{"db": {"password": "Sup3rS3cret!"}}',
        "json key": '  "api_key": "9f8e7d6c5b4a3210",',
        "json client secret": '    "client_secret": "x7Hk2mQ9vLpR4tYw",',
        "yaml bare": "password: hunter2secret",
        "yaml quoted": "  secret_key: 'x9Zk2mQ8vL1pR4tY7wN0'",
        "yaml list item": "  - token: abcd1234efgh5678",
        "yaml inline comment": "db_password: Sup3rS3cret   # prod",
        "properties": "db.password=P@ssw0rd123",
        "spring": "spring.datasource.password=Sup3rS3cret",
        "ini": "password = Sup3rS3cret",
        "ini key": "api_key=1a2b3c4d5e6f7a8b",
        "toml": 'password = "hunter22secret"',
        "url credential": "DATABASE_URL=postgres://admin:S3cr3tPass@db.internal:5432/app",
        "url no user": "REDIS=redis://:S3cr3tPass@cache:6379",
        "connection string": "Server=db;Database=app;User Id=sa;Password=Sup3rS3cret;",
        "jdbc query": "url=jdbc:mysql://db/app?user=root&password=Sup3rS3cret",
        "xml add": '<add key="AdminPassword" value="Sup3rS3cret"/>',
        "xml element": "<password>Sup3rS3cret</password>",
        "aws key": "aws = AKIAIOSFODNN7EXAMPLE",
        "github token": "token: ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8",
        "private key": "-----BEGIN RSA PRIVATE KEY-----",
        "comment with words": "# old password: Hunter2!Prod2023",
        "comment with words, semicolon": "; legacy api_key = 1a2b3c4d5e6f7a8b",
        "json private key": '{"private_key": "-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0B\\n-----END PRIVATE KEY-----\\n"}',
    }
    for name, text in real.items():
        assert found(text), f"a real secret was missed: {name}"

    lookalikes = {
        "env reference": "password: ${DB_PASSWORD}",
        "shell reference": "password: $DB_PASSWORD",
        "windows reference": "password=%DB_PASSWORD%",
        "jinja reference": 'password: "{{ vault_db_password }}"',
        "angle placeholder": "password: <your-password>",
        "changeme": "password: changeme",
        "empty quoted": 'password: ""',
        "empty": "password:",
        "mask characters": "password: ********",
        "repeated": "password: xxxxxxxx",
        "min length setting": "password_min_length: 12",
        "policy": "password_policy: strong8chars",
        "token url": "token_url: https://auth.example.com/oauth/token",
        "secret name": "secret_name: prod/db/credentials",
        "key header": "api_key_header: X-Api-Key",
        "flag": "use_password: true",
        "token type": "token_type: Bearer",
        "hash": "password_hash: $2b$12$abcdefghijklmnopqrstuv",
        "jasypt": "password: ENC(AbCdEf1234567890)",
        "ansible secret": "password: !secret db_password",
        "trusted connection": "connectionString: Server=db;Database=app;Trusted_Connection=True;",
        "url without password": "postgres://admin@db/app",
        "url with reference": "postgres://admin:${DB_PASSWORD}@db/app",
        "url empty reference": "redis://:${REDIS_PASSWORD}@cache",
        "xml reference": '<add key="ApiKey" value="${API_KEY}"/>',
        "prose": "Reset your password: follow the link in the email",
        "version": "token_version: 2.4.1",
        "example word": "password: example",
        "your password here": "password: your-password-here",
        "known false negative (dictionary passphrase)": "password: correcthorsebatterystaple",
        # found by the first held-out run: dependency version ranges in package.json and friends
        "caret range": '  "dependencies": { "jsonwebtoken": "^9.0.2", "express": "^4.19.2" }',
        "tilde range": '"passport": "~0.7.0"',
        "comparator range": '"bcrypt": ">=5.1.0 <6"',
        "workspace range": '"secret-store": "workspace:*"',
        "star range": '"token-lib": "*"',
        "npm alias": '"jwt": "npm:jsonwebtoken@9.0.2"',
        "word comment": "# the token: see the vault",
    }
    for name, text in lookalikes.items():
        assert not found(text), f"a look-alike was reported: {name}: {found(text)}"

    # the evidence never contains the secret, and an UNQUOTED value is masked (the quoted-string masking of the code scanner would leave it in plain sight)
    secrets_in_lines = {
        "password: hunter2secret": "hunter2secret", "db.password=P@ssw0rd123": "P@ssw0rd123", "password = Sup3rS3cret": "Sup3rS3cret",
        "DATABASE_URL=postgres://admin:S3cr3tPass@db.internal:5432/app": "S3cr3tPass", "Server=db;User Id=sa;Password=Sup3rS3cret;": "Sup3rS3cret",
        '<add key="AdminPassword" value="Sup3rS3cret"/>': "Sup3rS3cret", "url=jdbc:mysql://db/app?user=root&password=Sup3rS3cret": "Sup3rS3cret",
        '"api_key": "9f8e7d6c5b4a3210",': "9f8e7d6c5b4a3210", "token: ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8": "ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8",
    }
    for line, secret in secrets_in_lines.items():
        result = scan_config(line)
        assert result, line
        assert secret not in result[0].evidence, f"the evidence leaks the secret: {result[0].evidence!r}"
    assert scan_config("password: hunter2secret")[0].evidence == "password: ***"
    assert scan_config('  "api_key": "9f8e7d6c5b4a3210",')[0].evidence == '"api_key": "***",'
    assert "MIIEvQIBADANBgkqhkiG9w0B" not in scan_config(real["json private key"])[0].evidence

    # kinds, line numbers, one finding per line, strongest kind first
    text = "name: app\npassword: hunter2secret\n# comment\nurl: postgres://admin:S3cr3tPass@db/app\nkey: AKIAIOSFODNN7EXAMPLE password=hunter2secret\n"
    assert [(f.line, f.kind) for f in scan_config(text)] == [(2, "config_credential"), (4, "url_credential"), (5, "known_token")], scan_config(text)
    # a commented-out secret is still a secret; a secret inside a long minified line is left to the known formats only
    assert found("# password: hunter2secret") == [(1, "config_credential")]
    assert found("x" * 5000 + " password: hunter2secret") == []
    print("config_secrets OK: 24 real secrets found in 8 formats, 37 look-alikes and references left alone, evidence masks unquoted values, one finding per line")


if __name__ == "__main__":
    demo()
