"""
security_service/core/patching.py

Unified-diff helpers. A Patch in the API is a unified diff, so adapters that return corrected
text (most models do) are converted with make_unified_diff. Applying a diff (needed to verify a
fix by re-scanning the corrected code) comes with the verification service, not here.
"""

from __future__ import annotations

import difflib
import re
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


_NO_NEWLINE = "\\ No newline at end of file\n"


def split_lines(text: str) -> list[str]:
    """Lines with their newline kept, split on \\n ONLY (like git): str.splitlines would also split on form feeds and Unicode
    separators, which Python source may contain, and a diff must agree with the tool that applies it about where lines end."""
    return re.findall(r"[^\n]*\n|[^\n]+", text)


def make_unified_diff(path: str, old: str, new: str, context: int = 3) -> str:
    """A diff that `git apply` and apply_unified_diff both accept, including when a file does not end with a newline."""
    out = []
    for line in difflib.unified_diff(split_lines(old), split_lines(new), fromfile=f"a/{path}", tofile=f"b/{path}", n=context):
        if line[:1] in " +-" and not line.startswith(("+++ ", "--- ")) and not line.endswith("\n"):
            line += "\n" + _NO_NEWLINE
        out.append(line)
    return "".join(out)


class PatchError(ValueError):
    """A diff that does not apply EXACTLY to the file it is meant for. The message says what is wrong, never quotes the code."""


_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def apply_unified_diff(original: str, diff: str, path: str | None = None) -> str:
    """Apply a unified diff for ONE file, or raise PatchError. Strict like `git apply`: every context and removed line must match the
    original exactly (no fuzz, no offset search), hunks must be in order and not overlap, and the line counts in each hunk header
    must be true. `path`, when given, must be the file the diff names. The input is never changed."""
    lines = split_lines(diff)
    if len(lines) < 2 or not lines[0].startswith("--- ") or not lines[1].startswith("+++ "):
        raise PatchError("the diff has no '---' and '+++' file header")
    named = {lines[0][4:].strip().removeprefix("a/"), lines[1][4:].strip().removeprefix("b/")}
    if len(named) != 1 or (path is not None and named != {path}):
        raise PatchError("the diff is for a different file than the one it is applied to")
    position = 2
    original_lines = split_lines(original)
    result: list[str] = []
    cursor = 0                                   # index into original_lines: everything before it has been copied or removed
    hunks = 0
    while position < len(lines):
        header = _HUNK.match(lines[position])
        if not header:
            raise PatchError("the diff has text that is not a hunk (a second file, or garbage)" if lines[position].startswith(("--- ", "diff ", "+++ ")) else "the diff has a line outside any hunk")
        old_start, old_count = int(header[1]), int(header[2]) if header[2] is not None else 1
        new_count = int(header[4]) if header[4] is not None else 1
        position += 1
        hunks += 1
        start = old_start if old_count == 0 else old_start - 1           # a hunk that removes nothing is placed AFTER the line it names
        if start < cursor or start > len(original_lines):
            raise PatchError(f"hunk {hunks} is out of order or beyond the end of the file")
        result.extend(original_lines[cursor:start])
        cursor = start
        consumed = produced = 0
        body: list[tuple[str, str]] = []
        while position < len(lines) and not _HUNK.match(lines[position]) and not lines[position].startswith(("--- ", "diff ")):
            line = lines[position]
            if line == _NO_NEWLINE:
                if not body:
                    raise PatchError(f"hunk {hunks} has a 'no newline' marker with no line before it")
                operation, text = body[-1]
                if not text.endswith("\n"):
                    raise PatchError(f"hunk {hunks} has a repeated 'no newline' marker")
                body[-1] = (operation, text[:-1])
            elif line[:1] in (" ", "+", "-"):
                body.append((line[0], line[1:]))
            elif line == "\n":                                             # some tools write an empty context line as a bare newline
                body.append((" ", "\n"))
            else:
                raise PatchError(f"hunk {hunks} has a line that does not start with a space, + or -")
            position += 1
        for operation, text in body:
            if operation in (" ", "-"):
                if cursor >= len(original_lines) or original_lines[cursor] != text:
                    raise PatchError(f"hunk {hunks} does not match the file (the file is not the one this diff was made from)")
                cursor += 1
                consumed += 1
                if operation == " ":
                    result.append(text)
                    produced += 1
            else:
                result.append(text)
                produced += 1
        if consumed != old_count or produced != new_count:
            raise PatchError(f"hunk {hunks} says {old_count} old and {new_count} new lines but has {consumed} and {produced}")
    if hunks == 0:
        raise PatchError("the diff has no hunks")
    result.extend(original_lines[cursor:])
    return "".join(result)


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
    # ---- the diff round trip: apply(a, diff(a, b)) == b, for any a and b, and the diff means the same to git
    import random
    import shutil
    import subprocess
    import tempfile

    random.seed(20261031)
    vocabulary = ["x = 1", "def f():", "    return 1", "", "import os", "    pass", "# note", "if a:", "    b = 2", "\x0cpage break", "s = 'a\u2028b'"]
    for trial in range(400):
        before = [random.choice(vocabulary) for _ in range(random.randint(0, 14))]
        after = list(before)
        for _ in range(random.randint(0, 4)):
            kind = random.choice(("change", "insert", "delete"))
            where = random.randint(0, max(0, len(after) - 1))
            if kind == "insert" or not after:
                after.insert(where, random.choice(vocabulary))
            elif kind == "delete":
                after.pop(where)
            else:
                after[where] = random.choice(vocabulary)
        a = "\n".join(before) + random.choice(("\n", "")) if before else ""             # with and without a final newline
        b = "\n".join(after) + random.choice(("\n", "")) if after else ""
        for context in (0, 1, 3):
            diff = make_unified_diff("pkg/mod.py", a, b, context)
            if a == b:
                assert diff == "", (a, b)
                continue
            assert apply_unified_diff(a, diff, "pkg/mod.py") == b, (trial, context, repr(a), repr(b), diff)
            assert apply_unified_diff(a, diff) == b
    assert make_unified_diff("a.py", "x\n", "x") != "" and "No newline at end of file" in make_unified_diff("a.py", "x\n", "x")
    assert split_lines("a\x0cb\nc\u2028d") == ["a\x0cb\n", "c\u2028d"] and split_lines("") == [] and split_lines("\n\n") == ["\n", "\n"]

    git = shutil.which("git")
    if git:                                                                            # git must read our diffs the way we do, and agree on the result
        for a, b in (("import os\n\ndef ping(host):\n    os.system(host)\n", "import subprocess\n\ndef ping(host):\n    subprocess.run([host])\n    return 1\n"),
                     ("a\nb", "a\nc"), ("a\nb\n", "a\nb"), ("", "new\n"), ("gone\n", ""), ("l1\nl2\nl3\nl4\nl5\nl6\nl7\nl8\nl9\n", "l1\nL2\nl3\nl4\nl5\nl6\nl7\nl8\nL9\n")):
            with tempfile.TemporaryDirectory() as folder:
                (__import__("pathlib").Path(folder) / "f.py").write_bytes(a.encode())
                (__import__("pathlib").Path(folder) / "d.diff").write_bytes(make_unified_diff("f.py", a, b).encode())
                done = subprocess.run([git, "apply", "--unsafe-paths", "d.diff"], cwd=folder, capture_output=True, text=True)
                assert done.returncode == 0, done.stderr
                assert (__import__("pathlib").Path(folder) / "f.py").read_bytes().decode() == b == apply_unified_diff(a, make_unified_diff("f.py", a, b), "f.py")

    # ---- a diff that does not fit is refused, with a message that never quotes the code
    base = "import os\n\ndef ping(host):\n    os.system('ping ' + host)\n    return True\n"
    good = make_unified_diff("net.py", base, base.replace("os.system('ping ' + host)", "subprocess.run(['ping', host])"))
    assert "SECRET" not in good
    for label, diff, source, target, needle in (
        ("another file", good, base, "other.py", "different file"),
        ("the file changed since", good, base.replace("def ping", "def pong"), "net.py", "does not match the file"),
        ("a different file with the same names", good, "x = 1\n", "net.py", "does not match the file"),
        ("no header", "@@ -1,1 +1,1 @@\n-a\n+b\n", "a\n", None, "no '---' and '+++' file header"),
        ("no hunks", "--- a/net.py\n+++ b/net.py\n", base, "net.py", "no hunks"),
        ("garbage line", good + "oops\n", base, "net.py", "does not start with a space"),
        ("counts that lie", good.replace("@@ -1,5 +1,5 @@", "@@ -1,5 +1,9 @@"), base, "net.py", "new lines but has"),
        ("beyond the end", "--- a/net.py\n+++ b/net.py\n@@ -40,1 +40,1 @@\n-x\n+y\n", base, "net.py", "beyond the end"),
        ("hunks out of order", "--- a/net.py\n+++ b/net.py\n@@ -4,1 +4,1 @@\n-    os.system('ping ' + host)\n+    z\n@@ -1,1 +1,1 @@\n-import os\n+import sys\n", base, "net.py", "out of order"),
        ("a second file", good + "--- a/b.py\n+++ b/b.py\n@@ -1,1 +1,1 @@\n-a\n+b\n", base, "net.py", "second file"),
        ("a bare marker", "--- a/net.py\n+++ b/net.py\n@@ -1,1 +1,1 @@\n\\ No newline at end of file\n-x\n+y\n", "x\n", "net.py", "no line before it"),
    ):
        try:
            apply_unified_diff(source, diff, target)
            raise AssertionError(f"{label}: must be refused")
        except PatchError as problem:
            assert needle in str(problem), (label, str(problem))
            assert "os.system" not in str(problem) and "ping" not in str(problem), f"{label}: the message quoted the code"
    assert base.count("os.system") == 1                                                # the input is never changed

    print("core.patching OK: diffs and patch size")


if __name__ == "__main__":
    demo()
