"""
security_service/config.py

All configuration comes from environment variables, so nothing sensitive or deployment-specific is
ever written into the code. For convenience, a `.env` file can hold the same variables.

Rules:
  - Real environment variables ALWAYS win over the .env file (the file only fills in what is missing).
  - A .env file is read only when an entry point asks for it (load_env_file()): the live test, the
    config check below, and later the HTTP service. Library code and the automated checks never read
    it, so your real .env cannot change what a test does.
  - Settings.from_env() only reads variables; it does no file or network work.
  - .env is never committed (see .gitignore). .env.example is committed, with placeholders only.

Create your .env, once (it refuses to overwrite one that already exists):

    python -m security_service.config --init

Check your setup without any network call:

    python -m security_service.config
    python -m security_service.config --env-file path\\to\\.env

The variables (all optional unless marked) are listed in .env.example and in the README.
"""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, MutableMapping

from security_service.core.files import Limits

ENV_FILE_VAR = "SECURITY_ENV_FILE"
REPO_ROOT = Path(__file__).resolve().parent.parent
SYSTEMONE_PATH = "/providers/microsoft/v1/systemone"

# Every variable this project reads. Tests clear exactly these, so they never depend on a developer's terminal.
VARIABLES = (
    ENV_FILE_VAR,
    "FOUNDRY_ENDPOINT", "FOUNDRY_API_KEY",
    "DECISION1_ENDPOINT", "DECISION1_API_KEY", "DECISION1_DEPLOYMENT", "DECISION1_MODEL_VERSION",
    "DECISION1_AUTH", "DECISION1_TIMEOUT", "DECISION1_MAX_ATTEMPTS",
    "CLASSIFIER_ENABLED", "CLASSIFIER_REQUIRED", "CLASSIFIER_THRESHOLD",
    "SERVICE_HOST", "SERVICE_PORT", "SERVICE_API_KEYS", "SERVICE_RETENTION_HOURS", "SERVICE_WORKERS",
    "SERVICE_RATE_LIMIT_PER_MINUTE", "SERVICE_MAX_WAIT_SECONDS",
    "SCAN_MAX_FILES", "SCAN_MAX_FILE_BYTES", "SCAN_MAX_TOTAL_BYTES",
)

_ENDPOINT_SUFFIXES = (SYSTEMONE_PATH, "/providers/microsoft/v1", "/openai/v1", "/openai", "/models")


def normalize_endpoint(endpoint: str) -> str:
    """The resource host, without a trailing slash or an API path someone pasted along with it."""
    cleaned = (endpoint or "").strip().rstrip("/")
    for _ in range(5):                       # repeat until stable, so a path pasted twice is still fully removed
        before = cleaned
        for suffix in _ENDPOINT_SUFFIXES:
            if cleaned.endswith(suffix):
                cleaned = cleaned[: -len(suffix)].rstrip("/")
        if cleaned == before:
            break
    return cleaned


# ---------------------------------------------------------------------- .env files

def parse_env_text(text: str) -> dict[str, str]:
    """KEY=VALUE lines. Supports comments, blank lines, an optional `export `, single or double quotes,
    and a trailing ` # comment` on unquoted values. Lines that are not valid assignments are ignored."""
    values: dict[str, str] = {}
    for raw in text.splitlines():            # splitlines also handles Windows (CRLF) endings
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        key, separator, rest = line.partition("=")
        key = key.strip()
        if not separator or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            continue
        value = rest.strip()
        if value[:1] in ("'", '"'):
            end = value.find(value[0], 1)
            value = value[1:end] if end != -1 else value[1:]
        else:
            value = re.split(r"\s+#", value, maxsplit=1)[0].strip()
        values[key] = value
    return values


def find_env_file(environ: Mapping[str, str] | None = None, cwd: Path | None = None) -> Path | None:
    """SECURITY_ENV_FILE if set, else .env in the current folder, else .env in the repo root."""
    environ = os.environ if environ is None else environ
    explicit = environ.get(ENV_FILE_VAR, "").strip()
    if explicit:
        path = Path(explicit)
        return path if path.is_file() else None
    for base in (cwd or Path.cwd(), REPO_ROOT):
        candidate = Path(base) / ".env"
        if candidate.is_file():
            return candidate
    return None


def load_env_file(
    path: str | Path | None = None,
    override: bool = False,
    environ: MutableMapping[str, str] | None = None,
) -> Path | None:
    """Copy variables from a .env file into the environment. Variables that are already set win,
    unless override=True. Returns the file used, or None if there was none. Reads the file as UTF-8
    and tolerates the byte-order mark that Windows Notepad adds."""
    environ = os.environ if environ is None else environ
    file = Path(path) if path else find_env_file(environ)
    if file is None or not file.is_file():
        return None
    for key, value in parse_env_text(file.read_text(encoding="utf-8-sig")).items():
        if override or key not in environ:
            environ[key] = value
    return file


# ---------------------------------------------------------------------- creating .env (once, never overwriting)

def init_env_file(root: Path | None = None) -> tuple[Path, bool]:
    """Create .env from .env.example in the repo root, but NEVER overwrite an existing .env.
    Returns (path, created). Copying the template over .env by hand overwrites silently, which is how
    a filled-in .env gets wiped; this is the safe way."""
    root = Path(root) if root else REPO_ROOT
    target, template = root / ".env", root / ".env.example"
    if target.exists():
        return target, False
    if not template.is_file():
        raise FileNotFoundError(f"{template} is missing, so there is nothing to copy")
    target.write_bytes(template.read_bytes())
    return target, True


# ---------------------------------------------------------------------- the committed template

SECRET_NAME_PARTS = ("KEY", "SECRET", "TOKEN", "PASSWORD")
EXAMPLE_FIX = "Move your values into .env, then restore the template with: git checkout -- .env.example"


def example_file_problems(text: str) -> list[str]:
    """.env.example is committed to a public repository, so it may hold placeholders only. Returns what
    in it looks like a real value. Variable NAMES are reported, never the values."""
    found = []
    for name, value in parse_env_text(text).items():
        if any(part in name for part in SECRET_NAME_PARTS) and value:
            found.append(f"{name} has a value in .env.example (secrets belong in .env only)")
        if name.endswith("ENDPOINT") and value and "YOUR-RESOURCE" not in value.upper():
            found.append(f"{name} in .env.example is not the YOUR-RESOURCE placeholder (real endpoints belong in .env)")
    return found


# ---------------------------------------------------------------------- settings

def _text(environ: Mapping[str, str], name: str, default: str = "") -> str:
    return (environ.get(name) or "").strip() or default


def _number(environ: Mapping[str, str], name: str, default, cast, minimum, notes: list[str]):
    raw = (environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        value = cast(raw)
        if value < minimum:
            raise ValueError
        return value
    except ValueError:
        notes.append(f"{name}={raw!r} is not a valid number (minimum {minimum}); using the default {default}")
        return default


_PLACEHOLDER_KEYS = {"key", "api-key", "apikey", "api_key", "your-key", "your_key", "xxx", "changeme", "<key>", "..."}


def _looks_like_placeholder(value: str) -> bool:
    lowered = value.strip().lower()
    return lowered in _PLACEHOLDER_KEYS or lowered.startswith(("your-", "your_", "paste"))


_TRUE, _FALSE = {"1", "true", "yes", "on"}, {"0", "false", "no", "off"}
VALIDATED_THRESHOLD = 0.70      # the value the held-out test (2026-10-23) validated; changing it needs a new measurement


def _flag(environ: Mapping[str, str], name: str, default: bool, notes: list[str]) -> bool:
    raw = (environ.get(name) or "").strip().lower()
    if not raw:
        return default
    if raw in _TRUE:
        return True
    if raw in _FALSE:
        return False
    notes.append(f"{name}={raw!r} is not true or false; using {str(default).lower()}")
    return default


@dataclass(frozen=True)
class Settings:
    foundry_endpoint: str = ""
    foundry_api_key: str = ""
    decision1_endpoint: str = ""
    decision1_api_key: str = ""
    decision1_endpoint_source: str = "FOUNDRY_ENDPOINT"
    decision1_key_source: str = "FOUNDRY_API_KEY"
    decision1_deployment: str = "decision-1"
    decision1_model_version: str = "1"
    decision1_auth: str = "key"
    decision1_timeout: float = 20.0
    decision1_max_attempts: int = 3
    classifier_enabled: bool = False
    classifier_required: bool = False
    classifier_threshold: float = VALIDATED_THRESHOLD
    service_host: str = "127.0.0.1"
    service_port: int = 8080
    service_api_keys: str = ""          # secret: never printed, only counted and named
    service_retention_hours: int = 24
    service_workers: int = 4
    service_rate_limit_per_minute: int = 120
    service_max_wait_seconds: int = 30
    scan_max_files: int = 50
    scan_max_file_bytes: int = 200_000
    scan_max_total_bytes: int = 1_000_000
    warnings: tuple[str, ...] = ()

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> "Settings":
        environ = os.environ if environ is None else environ
        notes: list[str] = []

        auth = _text(environ, "DECISION1_AUTH", "key").lower()
        if auth not in ("key", "entra"):
            notes.append(f"DECISION1_AUTH={auth!r} is not 'key' or 'entra'; using 'key'")
            auth = "key"

        foundry_endpoint = normalize_endpoint(_text(environ, "FOUNDRY_ENDPOINT"))
        own_endpoint = normalize_endpoint(_text(environ, "DECISION1_ENDPOINT"))
        foundry_key = _text(environ, "FOUNDRY_API_KEY")
        own_key = _text(environ, "DECISION1_API_KEY")

        threshold = _number(environ, "CLASSIFIER_THRESHOLD", VALIDATED_THRESHOLD, float, 0.01, notes)
        if threshold > 1.0:
            notes.append(f"CLASSIFIER_THRESHOLD={threshold} is above 1; using {VALIDATED_THRESHOLD}")
            threshold = VALIDATED_THRESHOLD
        if threshold != VALIDATED_THRESHOLD:
            notes.append(f"CLASSIFIER_THRESHOLD={threshold:g} is not the {VALIDATED_THRESHOLD:.2f} that the held-out test validated; "
                         "results at another threshold have not been measured")

        service_port = _number(environ, "SERVICE_PORT", 8080, int, 1, notes)
        if service_port > 65535:
            notes.append(f"SERVICE_PORT={service_port} is not a valid port; using 8080")
            service_port = 8080

        return cls(
            foundry_endpoint=foundry_endpoint,
            foundry_api_key=foundry_key,
            decision1_endpoint=own_endpoint or foundry_endpoint,
            decision1_api_key=own_key or foundry_key,
            decision1_endpoint_source="DECISION1_ENDPOINT" if own_endpoint else "FOUNDRY_ENDPOINT",
            decision1_key_source="DECISION1_API_KEY" if own_key else "FOUNDRY_API_KEY",
            decision1_deployment=_text(environ, "DECISION1_DEPLOYMENT", "decision-1"),
            decision1_model_version=_text(environ, "DECISION1_MODEL_VERSION", "1"),
            decision1_auth=auth,
            decision1_timeout=_number(environ, "DECISION1_TIMEOUT", 20.0, float, 1.0, notes),
            decision1_max_attempts=_number(environ, "DECISION1_MAX_ATTEMPTS", 3, int, 1, notes),
            classifier_enabled=_flag(environ, "CLASSIFIER_ENABLED", False, notes),
            classifier_required=_flag(environ, "CLASSIFIER_REQUIRED", False, notes),
            classifier_threshold=threshold,
            service_host=_text(environ, "SERVICE_HOST", "127.0.0.1"),
            service_port=service_port,
            service_api_keys=_text(environ, "SERVICE_API_KEYS"),
            service_retention_hours=_number(environ, "SERVICE_RETENTION_HOURS", 24, int, 1, notes),
            service_workers=_number(environ, "SERVICE_WORKERS", 4, int, 1, notes),
            service_rate_limit_per_minute=_number(environ, "SERVICE_RATE_LIMIT_PER_MINUTE", 120, int, 1, notes),
            service_max_wait_seconds=min(_number(environ, "SERVICE_MAX_WAIT_SECONDS", 30, int, 1, notes), 120),
            scan_max_files=_number(environ, "SCAN_MAX_FILES", 50, int, 1, notes),
            scan_max_file_bytes=_number(environ, "SCAN_MAX_FILE_BYTES", 200_000, int, 1, notes),
            scan_max_total_bytes=_number(environ, "SCAN_MAX_TOTAL_BYTES", 1_000_000, int, 1, notes),
            warnings=tuple(notes),
        )

    def service_problems(self) -> list[str]:
        """What stops the HTTP service from starting. Problems never contain key text."""
        from security_service.api.auth import parse_api_keys      # imported here: config must not depend on the service

        _, problems = parse_api_keys(self.service_api_keys)
        if self.classifier_enabled:
            problems += [f"CLASSIFIER_ENABLED is on but {p[0].lower() + p[1:]}" for p in self.problems()]
        return problems

    def describe_service(self) -> str:
        """A summary of the service settings. Keys are never printed: only the callers' names and scopes."""
        from security_service.api.auth import parse_api_keys

        ring, problems = parse_api_keys(self.service_api_keys)
        lines = [
            f"service address ... http://{self.service_host}:{self.service_port}"
            + ("   (this computer only)" if self.service_host in ("127.0.0.1", "localhost", "::1")
               else "   (reachable from the network: put HTTPS in front of it)"),
            f"callers ........... {ring.describe()}" if len(ring) else "callers ........... NONE (the service will not start)",
            f"submitted code kept {self.service_retention_hours} hours, in memory only; {self.service_workers} scans at a time; "
            f"{self.service_rate_limit_per_minute} requests per minute per caller; waits up to {self.service_max_wait_seconds} s",
            "Decision-1 in scans: " + (f"ON at {self.classifier_threshold:.2f}" if self.classifier_enabled else "OFF (rules only)"),
        ]
        lines += [f"WARNING: {w}" for w in self.warnings]
        found = self.service_problems()
        lines.append("Problems: none" if not found else "Problems:")
        lines += [f"  - {p}" for p in found]
        return "\n".join(lines)

    def limits(self) -> Limits:
        return Limits(self.scan_max_files, self.scan_max_file_bytes, self.scan_max_total_bytes)

    @property
    def decision1_url(self) -> str:
        return self.decision1_endpoint + SYSTEMONE_PATH if self.decision1_endpoint else ""

    def problems(self) -> list[str]:
        """What stops Decision-1 from being used. Empty means ready (not that the key is valid)."""
        found = []
        if not self.decision1_endpoint:
            found.append("No endpoint: set FOUNDRY_ENDPOINT (or DECISION1_ENDPOINT) to your resource endpoint")
        elif "YOUR-RESOURCE" in self.decision1_endpoint.upper():
            found.append("The endpoint still has the placeholder YOUR-RESOURCE from .env.example: put your real resource endpoint there")
        elif not self.decision1_endpoint.lower().startswith(("https://", "http://127.0.0.1", "http://localhost")):
            found.append(f"The endpoint should start with https:// (got {self.decision1_endpoint[:40]!r})")
        if self.decision1_auth == "key":
            if not self.decision1_api_key:
                found.append("No API key: set FOUNDRY_API_KEY (or DECISION1_API_KEY), or set DECISION1_AUTH=entra to sign in with Microsoft Entra ID")
            elif _looks_like_placeholder(self.decision1_api_key):
                found.append("The API key looks like a placeholder, not a real key: copy the key from your deployment's details page")
        return found

    def describe(self, env_file: Path | None = None) -> str:
        """A readable summary. Secrets are never printed, only whether they are set and how long they are."""
        if self.decision1_auth == "entra":
            auth = "Microsoft Entra ID (azure-identity; run `az login` first)"
        elif self.decision1_api_key:
            auth = f"API key from {self.decision1_key_source}: set, {len(self.decision1_api_key)} characters"
        else:
            auth = "API key: NOT SET"
        lines = [
            f".env file ........ {env_file if env_file else 'none found (using the terminal environment only)'}",
            "Decision-1",
            f"  endpoint ....... {self.decision1_endpoint or 'NOT SET'}" + (f"   (from {self.decision1_endpoint_source})" if self.decision1_endpoint else ""),
            f"  URL it calls ... {self.decision1_url or 'NOT SET'}",
            f"  deployment ..... {self.decision1_deployment}   (the name you chose in Foundry)",
            f"  model version .. {self.decision1_model_version}   (reported in results as Microsoft-Decision-1@{self.decision1_model_version})",
            f"  sign-in ........ {auth}",
            f"  timeout ........ {self.decision1_timeout:g} s per attempt, {self.decision1_max_attempts} attempts",
            ("Decision-1 in scans: ON, at probability " + f"{self.classifier_threshold:.2f} or higher; "
             + ("REQUIRED (if it is down, a scan that would pass becomes scan_failed)" if self.classifier_required
                else "optional (if it is down, scans still finish on the rules and the report says so)"))
            if self.classifier_enabled else "Decision-1 in scans: OFF (scans use the rules only)",
            "Scan limits",
            f"  files .......... {self.scan_max_files} per request, {self.scan_max_file_bytes} bytes per file, {self.scan_max_total_bytes} bytes in total",
        ]
        lines += [f"WARNING: {w}" for w in self.warnings]
        problems = self.problems()
        lines.append("Problems: " + ("none (this does not prove the key or deployment name is right; run python -m tests.live_decision1)" if not problems else ""))
        lines += [f"  - {p}" for p in problems]
        return "\n".join(lines)


def main(argv: list[str]) -> int:
    if "--init" in argv:
        try:
            target, created = init_env_file()
        except FileNotFoundError as problem:
            print(problem)
            return 2
        if created:
            print(f"Created {target}\nNow open it with `notepad .env`, fill in FOUNDRY_ENDPOINT, FOUNDRY_API_KEY and DECISION1_DEPLOYMENT, and save.\n"
                  "You do this once. After that, `python -m security_service.config` checks it, as often as you like.")
        else:
            print(f"{target} already exists, so it was NOT touched (your values are safe).\nEdit it with: notepad .env")
        return 0
    path = None
    if "--env-file" in argv:
        index = argv.index("--env-file")
        if index + 1 >= len(argv):
            print("--env-file needs a path")
            return 2
        path = argv[index + 1]
        if not Path(path).is_file():
            print(f"No such file: {path}")
            return 2
    loaded = load_env_file(path)
    settings = Settings.from_env()
    print(settings.describe(loaded))
    example = REPO_ROOT / ".env.example"
    exposed = example_file_problems(example.read_text(encoding="utf-8-sig", errors="replace")) if example.is_file() else []
    for problem in exposed:
        print(f"WARNING: {problem}. That file is committed to a public repository, so do NOT commit it. {EXAMPLE_FIX}")
    return 2 if settings.problems() or exposed else 0


# ---------------------------------------------------------------------- self-test

def demo() -> None:
    import tempfile

    # --- parsing: every shape a real .env file takes, including Windows line endings
    text = (
        "# a comment\r\n"
        "\r\n"
        "FOUNDRY_ENDPOINT=https://res.services.ai.azure.com\r\n"
        'FOUNDRY_API_KEY = "abc=123 # not a comment"\n'
        "DECISION1_DEPLOYMENT='my deployment'\n"
        "export DECISION1_AUTH=entra   # trailing comment\n"
        "DECISION1_TIMEOUT=30\n"
        "BROKEN LINE WITHOUT EQUALS\n"
        "1BAD=x\n"
        "EMPTY=\n"
        "DUP=first\n"
        "DUP=second\n"
        "URL=https://a.example/path?x=1#frag\n"
    )
    parsed = parse_env_text(text)
    assert parsed["FOUNDRY_ENDPOINT"] == "https://res.services.ai.azure.com"
    assert parsed["FOUNDRY_API_KEY"] == "abc=123 # not a comment"        # quotes protect '=' and '#'
    assert parsed["DECISION1_DEPLOYMENT"] == "my deployment"
    assert parsed["DECISION1_AUTH"] == "entra"                             # `export` and trailing comment handled
    assert parsed["EMPTY"] == "" and parsed["DUP"] == "second" and parsed["DECISION1_TIMEOUT"] == "30"
    assert parsed["URL"] == "https://a.example/path?x=1#frag"              # '#' without a preceding space is kept
    assert "BROKEN LINE WITHOUT EQUALS" not in parsed and "1BAD" not in parsed

    # --- loading: files are read as UTF-8 (BOM tolerated), real variables win, nothing outside the dict is touched
    import tempfile
    with tempfile.TemporaryDirectory() as folder:
        env_path = Path(folder) / ".env"
        env_path.write_bytes(b"\xef\xbb\xbfFOUNDRY_ENDPOINT=https://from-file.example\r\nFOUNDRY_API_KEY=file-key\r\n")
        env: dict[str, str] = {"FOUNDRY_API_KEY": "real-terminal-key"}
        assert load_env_file(env_path, environ=env) == env_path
        assert env["FOUNDRY_ENDPOINT"] == "https://from-file.example"          # BOM did not corrupt the first key
        assert env["FOUNDRY_API_KEY"] == "real-terminal-key"                    # the terminal wins over the file
        load_env_file(env_path, override=True, environ=env)
        assert env["FOUNDRY_API_KEY"] == "file-key"                             # unless asked to override
        assert load_env_file(Path(folder) / "missing.env", environ={}) is None
        assert find_env_file({ENV_FILE_VAR: str(env_path)}) == env_path
        assert find_env_file({ENV_FILE_VAR: str(Path(folder) / "nope")}) is None   # an explicit path that does not exist is not silently replaced
        assert find_env_file({}, cwd=Path(folder)) == env_path                  # .env in the current folder is found

    # --- endpoints: whatever was pasted, the host comes out
    host = "https://res.services.ai.azure.com"
    for pasted in (host, host + "/", host + SYSTEMONE_PATH, host + SYSTEMONE_PATH + "/", host + "/openai/v1", host + "/models/", "  " + host + " "):
        assert normalize_endpoint(pasted) == host, pasted
    assert normalize_endpoint("") == ""
    assert normalize_endpoint(host + SYSTEMONE_PATH + SYSTEMONE_PATH) == host           # pasted twice
    assert normalize_endpoint(host + "/openai/v1/models/") == host

    # --- defaults and fallbacks
    empty = Settings.from_env({})
    assert (empty.decision1_deployment, empty.decision1_model_version, empty.decision1_auth) == ("decision-1", "1", "key")
    assert empty.scan_max_files == 50 and empty.limits() == Limits()
    assert len(empty.problems()) == 2                                           # no endpoint, no key

    base = {"FOUNDRY_ENDPOINT": host + SYSTEMONE_PATH, "FOUNDRY_API_KEY": "k" * 32, "DECISION1_DEPLOYMENT": "pi-decision-1"}
    s = Settings.from_env(base)
    assert s.decision1_endpoint == host and s.foundry_endpoint == host           # a pasted full URL is reduced to the host
    assert s.decision1_url == host + SYSTEMONE_PATH and s.problems() == []
    assert s.decision1_endpoint_source == "FOUNDRY_ENDPOINT" and s.decision1_key_source == "FOUNDRY_API_KEY"

    # --- Decision-1 can have its own endpoint and key, separate from the shared Foundry ones
    own = Settings.from_env({**base, "DECISION1_ENDPOINT": "https://other.services.ai.azure.com/", "DECISION1_API_KEY": "own-key"})
    assert own.decision1_endpoint == "https://other.services.ai.azure.com" and own.decision1_api_key == "own-key"
    assert own.foundry_endpoint == host and own.decision1_endpoint_source == "DECISION1_ENDPOINT"

    # --- validation
    assert any("API key" in p for p in Settings.from_env({"FOUNDRY_ENDPOINT": host}).problems())
    assert Settings.from_env({"FOUNDRY_ENDPOINT": host, "DECISION1_AUTH": "ENTRA"}).problems() == []   # Entra needs no key
    assert any("https" in p for p in Settings.from_env({"FOUNDRY_ENDPOINT": "http://example.com", "FOUNDRY_API_KEY": "k"}).problems())
    assert Settings.from_env({"FOUNDRY_ENDPOINT": "http://127.0.0.1:8080", "FOUNDRY_API_KEY": "k"}).problems() == []   # local test servers are fine

    # --- the classifier switches: off by default, parsed forgivingly, the validated threshold flagged when changed
    off = Settings.from_env(base)
    assert (off.classifier_enabled, off.classifier_required, off.classifier_threshold) == (False, False, 0.70) and off.warnings == ()
    assert "Decision-1 in scans: OFF" in off.describe()
    for raw, expected in (("true", True), ("TRUE", True), ("1", True), ("yes", True), ("on", True), ("false", False), ("0", False), ("off", False)):
        assert Settings.from_env({**base, "CLASSIFIER_ENABLED": raw}).classifier_enabled is expected, raw
    on = Settings.from_env({**base, "CLASSIFIER_ENABLED": "true", "CLASSIFIER_REQUIRED": "true"})
    assert on.classifier_enabled and on.classifier_required and "ON, at probability 0.70" in on.describe() and "REQUIRED" in on.describe()
    assert "optional" in Settings.from_env({**base, "CLASSIFIER_ENABLED": "true"}).describe()
    odd = Settings.from_env({**base, "CLASSIFIER_ENABLED": "maybe", "CLASSIFIER_THRESHOLD": "0.85"})
    assert odd.classifier_enabled is False and odd.classifier_threshold == 0.85 and len(odd.warnings) == 2
    assert any("not the 0.70" in w for w in odd.warnings)
    assert Settings.from_env({**base, "CLASSIFIER_THRESHOLD": "1.5"}).classifier_threshold == 0.70
    assert Settings.from_env({**base, "CLASSIFIER_THRESHOLD": "soon"}).classifier_threshold == 0.70

    # --- the service settings: safe defaults, validated, and the keys never printed
    service_key = "Kq3vZ8nR2mXw5tYb7LcD9fGh1JpS4aUe"
    svc = Settings.from_env({**base, "SERVICE_API_KEYS": f"flwn-ai:scan+fix+read:{service_key}"})
    assert (svc.service_host, svc.service_port, svc.service_retention_hours, svc.service_workers) == ("127.0.0.1", 8080, 24, 4)
    assert svc.service_problems() == [] and service_key not in svc.describe_service() and "flwn-ai (scan+fix+read)" in svc.describe_service()
    assert "this computer only" in svc.describe_service() and "Problems: none" in svc.describe_service()
    assert "reachable from the network" in Settings.from_env({**base, "SERVICE_HOST": "0.0.0.0", "SERVICE_API_KEYS": f"a:read:{service_key}"}).describe_service()
    no_keys = Settings.from_env(base)
    assert no_keys.service_problems() and "NONE" in no_keys.describe_service()                       # no keys: it refuses to run
    bad_key = Settings.from_env({**base, "SERVICE_API_KEYS": "a:scan:tooshort"})
    assert bad_key.service_problems() and "tooshort" not in bad_key.describe_service() and "tooshort" not in " ".join(bad_key.service_problems())
    tuned_svc = Settings.from_env({**base, "SERVICE_PORT": "9000", "SERVICE_WORKERS": "8", "SERVICE_RETENTION_HOURS": "48",
                                   "SERVICE_RATE_LIMIT_PER_MINUTE": "30", "SERVICE_MAX_WAIT_SECONDS": "500", "SERVICE_API_KEYS": f"a:read:{service_key}"})
    assert (tuned_svc.service_port, tuned_svc.service_workers, tuned_svc.service_retention_hours, tuned_svc.service_rate_limit_per_minute) == (9000, 8, 48, 30)
    assert tuned_svc.service_max_wait_seconds == 120                                                  # capped
    assert Settings.from_env({**base, "SERVICE_PORT": "70000"}).service_port == 8080 and Settings.from_env({**base, "SERVICE_PORT": "x"}).service_port == 8080
    on_without_model = Settings.from_env({"CLASSIFIER_ENABLED": "true", "SERVICE_API_KEYS": f"a:read:{service_key}"})
    assert any("CLASSIFIER_ENABLED is on but" in p for p in on_without_model.service_problems())

    # --- placeholders are caught before any call is made (the most common mistake after copying .env.example)
    assert any("placeholder YOUR-RESOURCE" in p for p in Settings.from_env({"FOUNDRY_ENDPOINT": "https://YOUR-RESOURCE.services.ai.azure.com", "FOUNDRY_API_KEY": "k" * 32}).problems())
    for fake_key in ("key", "YOUR-KEY", "your_key_here", "paste-it-here", "changeme"):
        assert any("placeholder" in p for p in Settings.from_env({"FOUNDRY_ENDPOINT": host, "FOUNDRY_API_KEY": fake_key}).problems()), fake_key
    assert Settings.from_env({"FOUNDRY_ENDPOINT": host, "FOUNDRY_API_KEY": "9f1c2e77a0b84d5e8a3b6c1d2e4f5a60"}).problems() == []

    # --- bad numbers and bad auth never crash: the default is used and a warning is kept
    bad = Settings.from_env({**base, "DECISION1_TIMEOUT": "soon", "DECISION1_MAX_ATTEMPTS": "0", "SCAN_MAX_FILES": "-3", "DECISION1_AUTH": "password"})
    assert (bad.decision1_timeout, bad.decision1_max_attempts, bad.scan_max_files, bad.decision1_auth) == (20.0, 3, 50, "key")
    assert len(bad.warnings) == 4
    tuned = Settings.from_env({**base, "SCAN_MAX_FILES": "7", "SCAN_MAX_FILE_BYTES": "1000", "SCAN_MAX_TOTAL_BYTES": "5000", "DECISION1_TIMEOUT": "2.5"})
    assert tuned.limits() == Limits(7, 1000, 5000) and tuned.decision1_timeout == 2.5 and tuned.warnings == ()

    # --- the summary never prints a secret
    secret = "SuperSecretKeyValue1234567890XYZ"
    summary = Settings.from_env({**base, "FOUNDRY_API_KEY": secret}).describe(Path("C:/x/.env"))
    assert secret not in summary and "32 characters" in summary and ".env" in summary
    assert "NOT SET" in Settings.from_env({}).describe() and "Entra" in Settings.from_env({"DECISION1_AUTH": "entra"}).describe()

    # --- --init creates .env once and never overwrites it
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        (root / ".env.example").write_text("FOUNDRY_ENDPOINT=https://YOUR-RESOURCE.services.ai.azure.com\n", encoding="ascii")
        made, created = init_env_file(root)
        assert created and made == root / ".env" and made.read_text(encoding="ascii").startswith("FOUNDRY_ENDPOINT=")
        made.write_text("FOUNDRY_ENDPOINT=https://my-real.services.ai.azure.com\nFOUNDRY_API_KEY=my-real-key\n", encoding="ascii")   # the user fills it in
        again, created_again = init_env_file(root)
        assert not created_again and again == made
        assert "my-real-key" in made.read_text(encoding="ascii"), "init must never overwrite a filled-in .env"
        (root / ".env").unlink()
        (root / ".env.example").unlink()
        try:
            init_env_file(root)
            raise AssertionError("expected FileNotFoundError when the template is missing")
        except FileNotFoundError:
            pass

    # --- every variable the project reads is listed (tests clear exactly these names)
    for name in ("FOUNDRY_ENDPOINT", "FOUNDRY_API_KEY", "DECISION1_AUTH", "SCAN_MAX_FILES", ENV_FILE_VAR):
        assert name in VARIABLES

    # --- .env.example and the code never drift apart, and the unedited example is not mistaken for a working setup
    example = REPO_ROOT / ".env.example"
    assert example.is_file(), ".env.example is missing"
    example_text = example.read_text(encoding="ascii")
    mentioned = set(re.findall(r"^#?\s*([A-Z][A-Z0-9_]+)=", example_text, re.M))
    assert mentioned == set(VARIABLES), f"variables missing from or unknown to .env.example: {sorted(mentioned ^ set(VARIABLES))}"
    assert example_file_problems(example_text) == [], (
        "the committed .env.example holds real values: " + "; ".join(example_file_problems(example_text)) + ". " + EXAMPLE_FIX)
    clean_text = "FOUNDRY_ENDPOINT=https://YOUR-RESOURCE.services.ai.azure.com\nFOUNDRY_API_KEY=\n# DECISION1_API_KEY=\nDECISION1_DEPLOYMENT=decision-1\n"
    assert example_file_problems(clean_text) == []
    secret_value = "9f1c2e77a0b84d5e8a3b6c1d2e4f5a60"
    leaked = example_file_problems("FOUNDRY_API_KEY=" + secret_value + "\nDECISION1_API_KEY=abc\nFOUNDRY_ENDPOINT=https://aif-real.services.ai.azure.com\n")
    assert len(leaked) == 3 and all(secret_value not in line for line in leaked)        # names are reported, never values
    assert example_file_problems("FOUNDRY_API_KEY=\n# FOUNDRY_API_KEY=real-looking-value-123\n") == []     # comments are fine
    unedited = Settings.from_env(parse_env_text(example_text))
    assert unedited.problems(), "the unedited example must not look ready"
    assert any("placeholder" in p for p in unedited.problems()) and any("API key" in p for p in unedited.problems())

    print("config OK: .env parsing (CRLF, BOM, quotes), terminal beats file, endpoint cleanup, placeholders caught, .env.example in sync and free of real values, secrets never printed")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--selftest":
        demo()
    else:
        sys.exit(main(sys.argv[1:]))
