"""
tests/check_layout.py

Catches the mistakes that tests of behavior cannot: a file copied to the wrong place, a copy left
behind, or a function that ended up in two files.

  1. Every Python file in security_service/, benchmark/ and tests/ starts with a docstring whose first
     line is its own path. A file copied to the wrong folder (for example an adapter pasted over the
     decision policy) is caught here, by name.
  2. The key classes and functions each exist in exactly one file, the expected one.
  3. No copy leftovers (`name (1).py`, `name - Copy.py`, `.orig`, `.bak`), and no `.env` that git would commit.

It looks only at what git would COMMIT (tracked files plus new files that are not ignored), so your own
local files never fail it: your real `.env`, a downloaded zip, a scratch script, caches. If git is not
available it falls back to scanning the folder and skipping those same kinds of files.

    python -m tests.check_layout              the normal check
    python -m tests.check_layout --package    stricter: also fails if a .env, a zip or a cache is in the
                                              folder, for use right before a folder is zipped and shared

Run from the repo root:  python -m tests.check_layout
"""

from __future__ import annotations

import ast
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKIP_DIRS = {"__pycache__", ".git", ".venv", "venv", ".idea", ".vscode", ".pytest_cache"}
PROJECT_DIRS = ("security_service", "benchmark", "tests")
SOURCE_LIKE = {".py", ".md", ".yaml", ".yml", ".txt", ".json", ".toml", ".cfg", ".example"}

# Where each key definition must live. If one moves, update this table on purpose.
EXPECTED_HOME = {
    "decide": "security_service/core/policy.py",
    "decide_nothing_scanned": "security_service/core/policy.py",
    "ScanService": "security_service/core/scan_service.py",
    "Settings": "security_service/config.py",
    "Decision1Classifier": "security_service/adapters/decision1.py",
    "FoundryLLM": "security_service/adapters/foundry_llm.py",
    "BanditAnalyzer": "security_service/adapters/bandit.py",
    "SecretsAnalyzer": "security_service/adapters/secrets_check.py",
    "LLMDetector": "security_service/adapters/llm_detector.py",
    "redact_secrets": "security_service/core/redaction.py",
    "prepare_files": "security_service/core/files.py",
    "problem_for": "security_service/core/errors.py",
}
NUMBERED_OR_COPY = re.compile(r"\(\d+\)|[ _-]copy\b", re.IGNORECASE)
BACKUP_SUFFIX = re.compile(r"(\.orig|\.bak|~)$", re.IGNORECASE)


def git_would_commit(root: Path) -> list[Path] | None:
    """Tracked files plus new files that are not ignored, as git sees them; None when git cannot say."""
    if shutil.which("git") is None or not (root / ".git").exists():
        return None
    try:
        done = subprocess.run(["git", "-C", str(root), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
                              capture_output=True, check=False, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    if done.returncode != 0:
        return None
    names = [n for n in done.stdout.decode("utf-8", errors="replace").split("\0") if n]
    return sorted(root / n for n in names if (root / n).is_file())


def candidate_files(root: Path, package: bool = False) -> list[Path]:
    """Files to judge. Normally what git would commit; in package mode (or without git), the whole folder
    minus caches, where package mode keeps .env, zips and caches so they can be reported."""
    if not package:
        tracked = git_would_commit(root)
        if tracked is not None:
            return tracked
    found = []
    for path in sorted(root.rglob("*")):
        parts = set(path.relative_to(root).parts)
        if not path.is_file() or (parts & SKIP_DIRS and not package):
            continue
        if not package and (path.name == ".env" or path.suffix.lower() == ".zip"):
            continue                      # a developer's own local files, ignored by git
        found.append(path)
    return found


def python_files(root: Path = ROOT) -> list[Path]:
    return [p for p in candidate_files(root) if p.suffix == ".py" and p.relative_to(root).parts[0] in PROJECT_DIRS]


def first_docstring_line(source: str) -> str | None:
    doc = ast.get_docstring(ast.parse(source))
    if not doc:
        return None
    return next((line.strip() for line in doc.splitlines() if line.strip()), None)


def problems(root: Path = ROOT, package: bool = False) -> list[str]:
    found: list[str] = []
    definitions: dict[str, list[str]] = {}
    files = candidate_files(root, package)
    for path in files:
        relative = path.relative_to(root).as_posix()
        name = path.name
        if name == ".env":
            found.append(f"{relative}: a real .env would be committed or packaged; it must stay private (check .gitignore)")
        if package and (path.suffix.lower() == ".zip" or "__pycache__" in path.parts or path.suffix == ".pyc"):
            found.append(f"{relative}: must not be inside a folder that is zipped and shared")
        if BACKUP_SUFFIX.search(name) or (NUMBERED_OR_COPY.search(name) and path.suffix.lower() in SOURCE_LIKE):
            found.append(f"{relative}: looks like a copy leftover; delete it")
        if path.suffix != ".py" or path.relative_to(root).parts[0] not in PROJECT_DIRS:
            continue
        source = path.read_text(encoding="utf-8-sig")
        try:
            tree = ast.parse(source)
        except SyntaxError as error:
            found.append(f"{relative}: does not parse ({error.msg}, line {error.lineno})")
            continue
        header = first_docstring_line(source)
        if header != relative:
            found.append(f"{relative}: its header says {header!r}, so a file was probably copied to the wrong place or renamed")
        for node in tree.body:
            if isinstance(node, (ast.ClassDef, ast.FunctionDef)):
                definitions.setdefault(node.name, []).append(relative)
    for name, home in EXPECTED_HOME.items():
        where = definitions.get(name, [])
        if where != [home]:
            found.append(f"{name} should be defined only in {home}, but is in: {where or 'no file at all'}")
    return found


def run(package: bool = False) -> None:
    issues = problems(ROOT, package)
    assert not issues, "layout problems:\n  - " + "\n  - ".join(issues)
    if package:
        print("check_layout --package OK: no .env, zip or cache in the folder; layout is clean")
        return

    # the checker itself must notice each mistake it exists for, and must NOT complain about a developer's
    # own local files (tested on a throwaway copy that never contains a real .env)
    import tempfile
    with tempfile.TemporaryDirectory() as folder:
        copy = Path(folder) / "repo"
        shutil.copytree(ROOT, copy, ignore=shutil.ignore_patterns("__pycache__", ".git", ".env", "*.zip"))
        assert problems(copy) == [], "the copy should start clean"
        policy = copy / "security_service/core/policy.py"
        original = policy.read_text(encoding="utf-8")

        policy.write_text((copy / "security_service/adapters/decision1.py").read_text(encoding="utf-8"), encoding="utf-8")   # THE accident
        found = problems(copy)
        assert any("core/policy.py" in p and "wrong place" in p for p in found), found
        assert any(p.startswith("decide should be defined only in") for p in found), found
        policy.write_text(original, encoding="utf-8")

        (copy / "security_service/core/policy (1).py").write_text("x = 1\n", encoding="utf-8")                  # a browser's duplicate download
        assert any("copy leftover" in p for p in problems(copy))
        (copy / "security_service/core/policy (1).py").unlink()

        (copy / "security_service/core/extra.py").write_text('"""security_service/core/extra.py"""\n\ndef decide():\n    return 1\n', encoding="utf-8")
        assert any(p.startswith("decide should be defined only in") for p in problems(copy))                      # a second `decide`
        (copy / "security_service/core/extra.py").unlink()

        # a developer's own local files are NOT a problem: real .env, a downloaded zip, a scratch script, caches
        (copy / ".env").write_text("FOUNDRY_API_KEY=real\n", encoding="utf-8")
        (copy / "flwn-security (1).zip").write_bytes(b"PK")
        (copy / "scratch.py").write_text("print(1)\n", encoding="utf-8")
        (copy / "security_service/__pycache__").mkdir()
        (copy / "security_service/__pycache__/x.cpython-314.pyc").write_bytes(b"\0")
        assert problems(copy) == [], problems(copy)
        # ...but package mode, used just before zipping, does report them
        packaged = problems(copy, package=True)
        assert any(".env" in p for p in packaged) and any(".zip" in p for p in packaged) and any("__pycache__" in p for p in packaged), packaged

        if shutil.which("git"):                                                    # with git, "what would be committed" is exact
            subprocess.run(["git", "init", "-q"], cwd=copy, check=True)
            assert problems(copy) == [], problems(copy)                           # .env and the zip are ignored by .gitignore
            (copy / ".gitignore").unlink()                                        # a broken .gitignore would commit the real .env
            assert any(p.startswith(".env:") for p in problems(copy)), problems(copy)
            git_mode = "git mode checked"
        else:
            git_mode = "git not installed: fallback mode only"

    print(f"check_layout OK: {len(python_files())} files each carry their own path; {len(EXPECTED_HOME)} key definitions live in exactly one place; "
          f"the pasted-over-policy accident and copy leftovers are detected; your local .env, zips and scratch files are left alone ({git_mode})")


if __name__ == "__main__":
    try:
        run(package="--package" in sys.argv)
    except AssertionError as error:
        print(f"LAYOUT CHECK FAILED: {error}")
        sys.exit(1)
