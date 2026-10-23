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
            scan_max_files=_number(environ, "SCAN_MAX_FILES", 50, int, 1, notes),
            scan_max_file_bytes=_number(environ, "SCAN_MAX_FILE_BYTES", 200_000, int, 1, notes),
            scan_max_total_bytes=_number(environ, "SCAN_MAX_TOTAL_BYTES", 1_000_000, int, 1, notes),
            warnings=tuple(notes),
        )

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
            "Scan limits",
            f"  files .......... {self.scan_max_files} per request, {self.scan_max_file_bytes} bytes per file, {self.scan_max_total_bytes} bytes in total",
        ]
        lines += [f"WARNING: {w}" for w in self.warnings]
        problems = self.problems()
        lines.append("Problems: " + ("none (this does not prove the key or deployment name is right; run python -m tests.live_decision1)" if not problems else ""))
        lines += [f"  - {p}" for p in problems]
        return "\n".join(lines)


def main(argv: list[str]) -> int:
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
    return 2 if settings.problems() else 0


# ---------------------------------------------------------------------- self-test

def demo() -> None:
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

    # --- every variable the project reads is listed (tests clear exactly these names)
    for name in ("FOUNDRY_ENDPOINT", "FOUNDRY_API_KEY", "DECISION1_AUTH", "SCAN_MAX_FILES", ENV_FILE_VAR):
        assert name in VARIABLES

    # --- .env.example and the code never drift apart, and the unedited example is not mistaken for a working setup
    example = REPO_ROOT / ".env.example"
    assert example.is_file(), ".env.example is missing"
    example_text = example.read_text(encoding="ascii")
    mentioned = set(re.findall(r"^#?\s*([A-Z][A-Z0-9_]+)=", example_text, re.M))
    assert mentioned == set(VARIABLES), f"variables missing from or unknown to .env.example: {sorted(mentioned ^ set(VARIABLES))}"
    unedited = Settings.from_env(parse_env_text(example_text))
    assert unedited.problems(), "the unedited example must not look ready"
    assert any("placeholder" in p for p in unedited.problems()) and any("API key" in p for p in unedited.problems())

    print("config OK: .env parsing (CRLF, BOM, quotes), terminal beats file, endpoint cleanup, placeholders caught, .env.example in sync, secrets never printed")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--selftest":
        demo()
    else:
        sys.exit(main(sys.argv[1:]))
