"""
security_service/core/patching.py

Unified-diff helpers. A Patch in the API is a unified diff, so adapters that return corrected
text (most models do) are converted with make_unified_diff. Applying a diff (needed to verify a
fix by re-scanning the corrected code) comes with the verification service, not here.
"""

from __future__ import annotations

import difflib
from dataclasses import dataclass


class EditError(ValueError):
    """An edit that cannot be applied exactly as written. The message names the problem, never the code."""


@dataclass(frozen=True)
class Edit:
    """Replace the text `old`, which must occur exactly once in the file, with `new`."""
    old: str
    new: str
    finding_ids: tuple[str, ...] = ()
    explanation: str = ""


def apply_edits(code: str, edits: list[Edit]) -> str:
    """Apply every edit to `code`, or none. Strict on purpose, because the edits come from a model:
      - `old` must be non-empty, differ from `new`, and occur EXACTLY ONCE in the original (a loose match could change the wrong line);
      - `old` must be WHOLE LINES: it starts at the beginning of a line and ends at the end of one, so indentation (which Python
        reads as structure) can never be half-matched; and `new` must end the way `old` does, so lines never merge or split;
      - edits must not overlap, so the result does not depend on the order they are listed in;
      - at least one edit is required.
    Anything else raises EditError and the file is left untouched (this function never mutates anything)."""
    if not edits:
        raise EditError("there are no edits to apply")
    located: list[tuple[int, int, Edit]] = []
    for number, edit in enumerate(edits, start=1):
        if not edit.old:
            raise EditError(f"edit {number} has an empty 'old' text")
        if edit.old == edit.new:
            raise EditError(f"edit {number} changes nothing ('old' and 'new' are the same)")
        found = code.count(edit.old)
        if found == 0:
            raise EditError(f"edit {number}: its 'old' text is not in the file (it must be copied exactly, including indentation)")
        if found > 1:
            raise EditError(f"edit {number}: its 'old' text occurs {found} times; it must occur exactly once, so include more surrounding lines")
        start = code.index(edit.old)
        end = start + len(edit.old)
        if start > 0 and code[start - 1] != "\n":
            raise EditError(f"edit {number}: its 'old' text starts in the middle of a line; it must be whole lines, copied from the start of the line")
        if not (edit.old.endswith("\n") or end == len(code) or code[end] == "\n"):
            raise EditError(f"edit {number}: its 'old' text stops in the middle of a line; it must be whole lines")
        if edit.new and edit.new.endswith("\n") != edit.old.endswith("\n"):
            raise EditError(f"edit {number}: 'new' must end with a newline exactly when 'old' does, or lines would merge or split")
        located.append((start, end, edit))
    located.sort(key=lambda item: item[0])
    for (_, end, _), (start, _, _) in zip(located, located[1:]):
        if start < end:
            raise EditError("two edits overlap, so the result would depend on their order")
    result, cursor = [], 0
    for start, end, edit in located:
        result.append(code[cursor:start])
        result.append(edit.new)
        cursor = end
    result.append(code[cursor:])
    return "".join(result)


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
    code = "import os\n\ndef ping(host):\n    os.system('ping ' + host)\n\ndef other():\n    return 1\n"
    fix = Edit("    os.system('ping ' + host)\n", "    subprocess.run(['ping', host], check=True)\n", ("f1",), "no shell")
    add_import = Edit("import os\n", "import os\nimport subprocess\n")
    done = apply_edits(code, [fix, add_import])
    assert done == "import os\nimport subprocess\n\ndef ping(host):\n    subprocess.run(['ping', host], check=True)\n\ndef other():\n    return 1\n"
    assert apply_edits(code, [add_import, fix]) == done                                  # the order the edits are listed in does not matter
    assert code.count("os.system") == 1                                                   # the original string is untouched
    assert apply_edits(code, [Edit("def other():\n    return 1\n", "")]) == "import os\n\ndef ping(host):\n    os.system('ping ' + host)\n\n"     # deleting whole lines is fine
    assert apply_edits("a = 1\nb = 2", [Edit("b = 2", "b = 3")]) == "a = 1\nb = 3"      # the last line may have no newline at all
    twice = "def a():\n    return 1\n\ndef b():\n    return 1\n"                    # a whole line that occurs twice: the edit must say which, by including more lines
    try:
        apply_edits(twice, [Edit("    return 1\n", "    return 2\n")])
        raise AssertionError("an edit that matches twice must be refused")
    except EditError as problem:
        assert "occurs 2 times" in str(problem)
    assert apply_edits(twice, [Edit("def b():\n    return 1\n", "def b():\n    return 2\n")]) == "def a():\n    return 1\n\ndef b():\n    return 2\n"
    assert apply_edits("a\nb\nc\n", [Edit("a\n", "A\n"), Edit("b\n", "B\n")]) == "A\nB\nc\n"      # edits that merely touch (one ends where the next starts) are fine
    try:                                                                                    # ...overlapping ones are not
        apply_edits("a\nb\nc\n", [Edit("a\nb\n", "X\n"), Edit("b\nc\n", "Y\n")])
        raise AssertionError("overlapping edits must be refused")
    except EditError as problem:
        assert "overlap" in str(problem)
    for label, bad in {
        "no edits": [],
        "empty old": [Edit("", "x")],
        "no change": [Edit("import os\n", "import os\n")],
        "not found": [Edit("    os.system('ping ' + HOST)\n", "x")],
        "wrong indentation (starts mid-line)": [Edit("  os.system('ping ' + host)\n", "  x\n")],
        "stops mid-line": [Edit("    os.system('ping ' + host", "    x")],
        "newline mismatch": [Edit("    os.system('ping ' + host)\n", "    x")],
        "newline mismatch the other way": [Edit("import os\n", "import os")],
        "overlap (both are whole lines)": [Edit("import os\n\ndef ping(host):\n", "X\n"), Edit("def ping(host):\n    os.system('ping ' + host)\n", "Y\n")],
    }.items():
        try:
            apply_edits(code, bad)
            raise AssertionError(f"{label} must be refused")
        except EditError as problem:
            assert "SECRET" not in str(problem), label
    try:                                                                                  # an error message never quotes the code
        apply_edits("token = 'SECRET-VALUE'\n", [Edit("token = 'OTHER'\n", "x")])
    except EditError as problem:
        assert "SECRET-VALUE" not in str(problem) and "OTHER" not in str(problem)
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
