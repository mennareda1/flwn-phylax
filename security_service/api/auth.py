"""
security_service/api/auth.py

Who may call the service, and with what permission. Framework-free, so it is tested without a web server.

Keys are service-to-service secrets sent as  Authorization: Bearer <key>. They are configured in SERVICE_API_KEYS as

    name:scope+scope:key , name:scope:key , ...

for example   flwn-ai:scan+fix+read:<a long random key>,dashboard:read:<another>

Scopes (from the contract): scan = create scans and verifications and delete scans; fix = request fixes; read = fetch results.

Rules this module keeps:
  - The key text is never kept: only its SHA-256 digest is stored, and compared in constant time against every entry, so
    neither the answer nor its timing reveals which part of a key was right.
  - No message, repr or problem list ever contains key text. Problems name the entry by its position and name only.
  - A key must be at least 24 characters, and no two entries may share a name or a key.
  - Generate keys with:  python -m security_service.api --new-key
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass

SCOPES = ("scan", "fix", "read")
MIN_KEY_LENGTH = 24
_NAME = re.compile(r"[A-Za-z0-9_.\-]{1,40}")


@dataclass(frozen=True)
class Principal:
    name: str
    scopes: frozenset[str]

    def allows(self, scope: str) -> bool:
        return scope in self.scopes


class KeyRing:
    def __init__(self, entries: list[tuple[str, frozenset[str], str]]):
        self._entries = [(Principal(name, scopes), hashlib.sha256(key.encode("utf-8")).digest()) for name, scopes, key in entries]

    def authenticate(self, presented: str | None) -> Principal | None:
        if not presented:
            return None
        digest = hashlib.sha256(presented.encode("utf-8")).digest()
        found = None
        for principal, stored in self._entries:           # every entry is compared, so timing does not reveal which matched
            if hmac.compare_digest(stored, digest):
                found = principal
        return found

    def names(self) -> list[str]:
        return [principal.name for principal, _ in self._entries]

    def describe(self) -> str:
        return ", ".join(f"{p.name} ({'+'.join(s for s in SCOPES if s in p.scopes)})" for p, _ in self._entries) or "none"

    def __len__(self) -> int:
        return len(self._entries)

    def __repr__(self) -> str:
        return f"KeyRing({self.describe()})"


def new_key() -> str:
    """A fresh random key of 43 URL-safe characters (256 bits)."""
    return secrets.token_urlsafe(32)


def parse_api_keys(text: str | None) -> tuple[KeyRing, list[str]]:
    """Returns (the key ring, problems). Problems never contain key text. An empty ring plus a problem means: do not start."""
    entries: list[tuple[str, frozenset[str], str]] = []
    problems: list[str] = []
    names: set[str] = set()
    digests: set[str] = set()
    raw = [piece.strip() for piece in (text or "").split(",") if piece.strip()]
    if not raw:
        return KeyRing([]), ["SERVICE_API_KEYS is empty: the service refuses to run without keys (create one with: python -m security_service.api --new-key)"]
    for position, piece in enumerate(raw, start=1):
        parts = piece.split(":", 2)                       # the key may contain ':' itself
        if len(parts) != 3:
            problems.append(f"entry {position} is not in the form name:scopes:key")
            continue
        name, scope_text, key = (part.strip() for part in parts)
        label = f"entry {position} ({name or 'no name'})"
        scopes = frozenset(s for s in scope_text.split("+") if s)
        if not _NAME.fullmatch(name):
            problems.append(f"entry {position} has an invalid name (use letters, digits, '_', '.', '-', up to 40 characters)")
            continue
        if not scopes or not scopes <= set(SCOPES):
            problems.append(f"{label} has invalid scopes; use any of {'+'.join(SCOPES)} joined with '+'")
            continue
        if len(key) < MIN_KEY_LENGTH or re.search(r"\s", key):
            problems.append(f"{label} has a key shorter than {MIN_KEY_LENGTH} characters or containing spaces")
            continue
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        if name in names:
            problems.append(f"{label} repeats a name that is already used")
            continue
        if digest in digests:
            problems.append(f"{label} uses a key that another entry already uses")
            continue
        names.add(name)
        digests.add(digest)
        entries.append((name, scopes, key))
    return KeyRing(entries), problems


def bearer_token(header: str | None) -> str | None:
    """The key from an Authorization header, or None if it is missing or is not a Bearer credential."""
    if not header:
        return None
    scheme, _, rest = header.strip().partition(" ")
    token = rest.strip()
    return token if scheme.lower() == "bearer" and token and " " not in token else None


def demo() -> None:
    k1, k2, k3 = "Kq3vZ8nR2mXw5tYb7LcD9fGh1JpS4aUe", "A" * 24, "key:with:colons-and-more-characters-1234"
    ring, problems = parse_api_keys(f"flwn-ai:scan+fix+read:{k1}, dashboard:read:{k2} ,ci.bot:scan:{k3}")
    assert problems == [] and len(ring) == 3 and ring.names() == ["flwn-ai", "dashboard", "ci.bot"]
    assert ring.describe() == "flwn-ai (scan+fix+read), dashboard (read), ci.bot (scan)"

    # authentication: the right key, with exactly its scopes; everything else is None
    flwn = ring.authenticate(k1)
    assert flwn and flwn.name == "flwn-ai" and flwn.allows("scan") and flwn.allows("fix") and flwn.allows("read")
    dashboard = ring.authenticate(k2)
    assert dashboard and dashboard.allows("read") and not dashboard.allows("scan") and not dashboard.allows("fix")
    assert ring.authenticate(k3).name == "ci.bot"                                   # a key containing ':' works
    for wrong in (None, "", "wrong-key-wrong-key-wrong-key", k1[:-1], k1 + "x", k1.lower(), " " + k1):
        assert ring.authenticate(wrong) is None, wrong

    # every way of writing the configuration wrong is a problem, and no problem ever contains key text
    secret = "SuperSecretKeyValue-0123456789-abcdef"
    bad_inputs = {
        "empty": "", "none": None, "spaces only": "  ,  ",
        "no key part": "a:scan", "no scopes": f"a::{secret}", "unknown scope": f"a:admin:{secret}", "mixed scopes": f"a:scan+admin:{secret}",
        "short key": "a:scan:short", "key with space": f"a:scan:{secret[:20]} {secret[20:]}",
        "bad name": f"bad name:scan:{secret}", "empty name": f":scan:{secret}", "long name": f"{'n' * 41}:scan:{secret}",
        "repeated name": f"a:scan:{secret},a:read:{secret}-different-key-value",
        "repeated key": f"a:scan:{secret},b:read:{secret}",
    }
    for label, text in bad_inputs.items():
        bad_ring, found = parse_api_keys(text)
        assert found, f"{label} must be a problem"
        assert secret not in " ".join(found) and secret[:12] not in " ".join(found), f"{label}: a problem message contains key text"
        if label in {"empty", "none", "spaces only"}:
            assert len(bad_ring) == 0                                              # nothing to start with
    mixed, found = parse_api_keys(f"good:scan:{k1},bad:oops:{k2}")
    assert len(mixed) == 1 and mixed.names() == ["good"] and len(found) == 1       # a bad entry never silently becomes a working one

    # nothing printable contains a key
    for text in (repr(ring), ring.describe(), str(flwn), repr(flwn)):
        assert k1 not in text and k2 not in text and k3 not in text

    # the Authorization header
    assert bearer_token(f"Bearer {k1}") == k1 and bearer_token(f"bearer {k1}") == k1 and bearer_token(f"  BEARER   {k1}  ") == k1
    for odd in (None, "", "Bearer", "Bearer ", f"Basic {k1}", k1, f"Bearer {k1} extra", "Bearer a b"):
        assert bearer_token(odd) is None, odd

    generated = {new_key() for _ in range(50)}
    assert len(generated) == 50 and all(len(k) >= MIN_KEY_LENGTH and re.fullmatch(r"[A-Za-z0-9_\-]+", k) for k in generated)
    assert parse_api_keys(f"x:scan+fix+read:{new_key()}")[1] == []                 # a generated key is always accepted

    print("api.auth OK: keys parsed and checked in constant time, scopes enforced, every bad configuration is a problem, no key text in any message")


if __name__ == "__main__":
    demo()
