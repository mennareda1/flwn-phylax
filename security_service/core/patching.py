"""
security_service/core/patching.py

Unified-diff helpers. A Patch in the API is a unified diff, so adapters that return corrected
text (most models do) are converted with make_unified_diff. Applying a diff (needed to verify a
fix by re-scanning the corrected code) comes with the verification service, not here.
"""

from __future__ import annotations

import difflib


def make_unified_diff(path: str, old: str, new: str, context: int = 3) -> str:
    diff = difflib.unified_diff(
        old.splitlines(keepends=True),
        new.splitlines(keepends=True),
        fromfile=f"a/{path}",
        tofile=f"b/{path}",
        n=context,
    )
    return "".join(diff)


def changed_line_count(unified_diff: str) -> int:
    """Number of added or removed lines (the size of a patch), ignoring the file headers."""
    return sum(
        1
        for line in unified_diff.splitlines()
        if (line.startswith("+") or line.startswith("-")) and not line.startswith(("+++", "---"))
    )


def demo() -> None:
    old = "import os\n\ndef ping(host):\n    os.system('ping ' + host)\n"
    new = "import subprocess\n\ndef ping(host):\n    subprocess.run(['ping', host], check=True)\n"
    diff = make_unified_diff("app/net.py", old, new)
    assert diff.startswith("--- a/app/net.py\n+++ b/app/net.py\n")
    assert "-    os.system('ping ' + host)" in diff and "+    subprocess.run(['ping', host], check=True)" in diff
    assert changed_line_count(diff) == 4          # two lines removed, two added
    assert make_unified_diff("a.py", old, old) == ""
    assert changed_line_count("") == 0
    print("core.patching OK: diffs and patch size")


if __name__ == "__main__":
    demo()
