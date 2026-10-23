"""
tests/check_layout.py

Catches the mistakes that tests of behavior cannot: a file copied to the wrong place, a copy left
behind, or a function that ended up in two files.

  1. Every Python file starts with a docstring whose first line is its own path. A file copied to the
     wrong folder (for example an adapter pasted over the decision policy) is caught here, by name.
  2. The key classes and functions each exist in exactly one file, the expected one.
  3. No copy leftovers (`name (1).py`, `name - Copy.py`, `.orig`, `.bak`) and no real `.env` is packaged.

Run from the repo root:  python -m tests.check_layout
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKIP_DIRS = {"__pycache__", ".git", ".venv", "venv"}

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
COPY_LEFTOVERS = re.compile(r"\(\d+\)|[ _-]copy\b|\.orig$|\.bak$|~$", re.IGNORECASE)


def python_files() -> list[Path]:
    return sorted(p for p in ROOT.rglob("*.py") if not SKIP_DIRS & set(p.relative_to(ROOT).parts))


def first_docstring_line(source: str) -> str | None:
    doc = ast.get_docstring(ast.parse(source))
    if not doc:
        return None
    return next((line.strip() for line in doc.splitlines() if line.strip()), None)


def problems(root: Path = ROOT) -> list[str]:
    found: list[str] = []
    definitions: dict[str, list[str]] = {}
    for path in python_files() if root == ROOT else sorted(root.rglob("*.py")):
        relative = path.relative_to(root).as_posix()
        source = path.read_text(encoding="utf-8")
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
    for path in root.rglob("*"):
        parts = set(path.relative_to(root).parts)
        if parts & SKIP_DIRS or not path.is_file():
            continue
        if COPY_LEFTOVERS.search(path.name):
            found.append(f"{path.relative_to(root).as_posix()}: looks like a copy leftover; delete it")
        if path.name == ".env":
            found.append(".env is present in the project folder; it must never be committed or packaged")
    return found


def run() -> None:
    issues = problems()
    assert not issues, "layout problems:\n  - " + "\n  - ".join(issues)

    # the checker itself must notice each mistake it exists for (tested on a throwaway copy)
    import shutil
    import tempfile
    with tempfile.TemporaryDirectory() as folder:
        copy = Path(folder) / "repo"
        shutil.copytree(ROOT, copy, ignore=shutil.ignore_patterns("__pycache__", ".git"))
        assert problems(copy) == [], "the copy should start clean"

        adapter = (copy / "security_service/adapters/decision1.py").read_text(encoding="utf-8")
        (copy / "security_service/core/policy.py").write_text(adapter, encoding="utf-8")        # THE accident: adapter pasted over the policy
        found = problems(copy)
        assert any("core/policy.py" in p and "wrong place" in p for p in found), found
        assert any(p.startswith("decide should be defined only in") for p in found), found
        shutil.copy(ROOT / "security_service/core/policy.py", copy / "security_service/core/policy.py")

        (copy / "security_service/core/policy (1).py").write_text("x = 1\n", encoding="utf-8")   # a browser's duplicate download
        assert any("copy leftover" in p for p in problems(copy))
        (copy / "security_service/core/policy (1).py").unlink()

        (copy / ".env").write_text("FOUNDRY_API_KEY=real\n", encoding="utf-8")
        assert any(".env is present" in p for p in problems(copy))
        (copy / ".env").unlink()

        (copy / "security_service/core/extra.py").write_text('"""security_service/core/extra.py"""\n\ndef decide():\n    return 1\n', encoding="utf-8")
        assert any(p.startswith("decide should be defined only in") for p in problems(copy))   # a second `decide` anywhere is flagged
        (copy / "security_service/core/extra.py").unlink()
        assert problems(copy) == []

    print(f"check_layout OK: {len(python_files())} files each carry their own path; {len(EXPECTED_HOME)} key definitions live in exactly one place; "
          "the pasted-over-policy accident, copy leftovers and a stray .env are all detected")


if __name__ == "__main__":
    try:
        run()
    except AssertionError as error:
        print(f"LAYOUT CHECK FAILED: {error}")
        sys.exit(1)
