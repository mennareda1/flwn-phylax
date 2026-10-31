"""
security_service/paths.py

What a person types on the command line, turned into the files to scan and the names to call them.

  - A FILE is used as given, whatever its extension (an unsupported one is then reported as skipped, not hidden).
  - A FOLDER is searched recursively for *.py files, skipping the folders that hold other people's code or build output
    (.git, venv, .venv, env, __pycache__, node_modules, site-packages, build, dist, and the like). Hidden folders are skipped.
  - Every file gets a LABEL, the path shown in reports and written into patches, chosen so that `git apply` works:
        1. relative to the folder you are standing in, when the file is inside it (the normal case);
        2. otherwise relative to the root of the git repository the file belongs to, when it has one;
        3. otherwise relative to the folder you named, when the file came from one;
        4. otherwise relative to the common parent of the files given (or just the file name, for one file).
    A label never contains a drive letter, a leading slash or "..", and no two files share one.

Why this matters: a patch whose header says a/C:/Users/me/app.py cannot be applied by git, and a name like that tells a reviewer
nothing. Labels are always forward-slashed, on Windows too.
"""

from __future__ import annotations

import os
from pathlib import Path

SKIP_FOLDERS = {".git", ".hg", ".svn", "venv", ".venv", "env", "__pycache__", "node_modules", "site-packages", ".tox", ".nox",
                ".mypy_cache", ".pytest_cache", ".ruff_cache", "build", "dist", ".eggs", ".idea", ".vscode"}


class PathProblem(Exception):
    """A path that cannot be used, with a message a person can act on."""


def _git_root(path: Path) -> Path | None:
    for parent in path.parents:
        if (parent / ".git").exists():
            return parent
    return None


def _inside(path: Path, base: Path) -> Path | None:
    try:
        return path.relative_to(base)
    except ValueError:
        return None


def expand(arguments: list[str], cwd: Path | None = None) -> list[tuple[Path, str]]:
    """The (file, label) pairs for the paths given. Raises PathProblem for one that cannot be read or holds nothing to scan."""
    here = (cwd or Path.cwd()).resolve()
    found: list[Path] = []
    origin: dict[Path, Path] = {}                  # file -> the folder it was found in, when it came from a folder argument
    for argument in arguments:
        path = Path(argument)
        path = path if path.is_absolute() else here / path                    # a relative path is relative to the folder you stand in
        try:
            resolved = path.resolve(strict=True)
        except (FileNotFoundError, NotADirectoryError):
            raise PathProblem(f"Cannot read {argument}: No such file or folder") from None
        except OSError as problem:
            raise PathProblem(f"Cannot read {argument}: {problem.strerror or problem}") from None
        if resolved.is_dir():
            inside = sorted(p for p in resolved.rglob("*.py")
                            if p.is_file() and not any(part in SKIP_FOLDERS or (part.startswith(".") and part not in (".", "..")) for part in p.relative_to(resolved).parts[:-1]))
            if not inside:
                raise PathProblem(f"No Python files found in {argument} (folders such as .git, venv, node_modules and build are skipped)")
            found.extend(inside)
            origin.update({p: resolved for p in inside})
        elif resolved.is_file():
            found.append(resolved)
        else:
            raise PathProblem(f"Cannot read {argument}: it is not a file or a folder")

    unique = list(dict.fromkeys(found))
    labels: dict[Path, str] = {}
    outside: list[Path] = []
    for file in unique:
        rel = _inside(file, here)
        if rel is not None:
            labels[file] = rel.as_posix()
        else:
            outside.append(file)
    if outside:
        roots = {file: _git_root(file) for file in outside}
        for file in outside:
            if roots[file] is not None:
                labels[file] = file.relative_to(roots[file]).as_posix()
            elif file in origin:
                labels[file] = file.relative_to(origin[file]).as_posix()
        loose = [f for f in outside if f not in labels]
        if loose:
            common = Path(os.path.commonpath([str(f.parent) for f in loose])) if len(loose) > 1 else loose[0].parent
            for file in loose:
                labels[file] = file.relative_to(common).as_posix()
    seen: dict[str, Path] = {}
    for file in unique:                                                        # two files must never share a label
        label = labels[file]
        if label in seen:
            label = f"{file.parent.name}/{label}" if file.parent.name else label
            counter = 2
            while label in seen:
                label, counter = f"{labels[file]}~{counter}", counter + 1
            labels[file] = label
        seen[labels[file]] = file
    return [(file, labels[file]) for file in unique]


def demo() -> None:
    import tempfile

    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder).resolve()
        (root / "app").mkdir()
        (root / "app" / "sub").mkdir()
        (root / "app" / "venv").mkdir()
        (root / "app" / "__pycache__").mkdir()
        (root / "app" / ".hidden").mkdir()
        (root / "app" / "node_modules").mkdir()
        (root / "other").mkdir()
        (root / "other" / ".git").mkdir()
        (root / "other" / "pkg").mkdir()
        (root / "empty").mkdir()
        for name in ("app/main.py", "app/sub/util.py", "app/venv/skip.py", "app/__pycache__/skip.py", "app/.hidden/skip.py", "app/node_modules/skip.py",
                     "app/readme.md", "other/pkg/lib.py", "other/pkg/lib2.py", "lonely.py"):
            (root / name).write_text("x = 1\n", encoding="utf-8")

        # standing in the folder: labels are relative to it, with forward slashes, in sorted order
        pairs = expand(["app"], cwd=root)
        assert [label for _, label in pairs] == ["app/main.py", "app/sub/util.py"], pairs                  # venv, __pycache__, hidden and node_modules skipped; .md ignored in a folder
        assert [label for _, label in expand([str(root / "app" / "main.py")], cwd=root)] == ["app/main.py"]    # an absolute path is shown relative to where you stand
        assert [label for _, label in expand(["."], cwd=root / "app")] == ["main.py", "sub/util.py"]
        assert [label for _, label in expand(["app/readme.md"], cwd=root)] == ["app/readme.md"]               # a file is used as given, whatever its extension

        # outside the current folder: relative to the git repository root, else to the common parent
        elsewhere = root / "empty"
        assert [label for _, label in expand([str(root / "other" / "pkg" / "lib.py")], cwd=elsewhere)] == ["pkg/lib.py"]     # other/ has a .git folder: its root
        assert [label for _, label in expand([str(root / "lonely.py")], cwd=elsewhere)] == ["lonely.py"]                      # no repo: just the name
        mixed = expand([str(root / "app" / "main.py"), str(root / "app" / "sub" / "util.py")], cwd=elsewhere)
        assert [label for _, label in mixed] == ["main.py", "sub/util.py"]                                                      # no repo: relative to the common parent
        assert [label for _, label in expand([str(root / "app")], cwd=elsewhere)] == ["main.py", "sub/util.py"]                # a folder you named, from outside it: relative to that folder
        assert [label for _, label in expand([str(root / "app" / "sub")], cwd=elsewhere)] == ["util.py"]
        assert len({label for _, label in expand([str(root / "app"), str(root / "other")], cwd=elsewhere)}) == 4              # every label distinct

        # a folder whose files all sit in a subfolder keeps that subfolder in the label (relative to the folder NAMED, not to the files' common parent)
        (root / "nest" / "deep").mkdir(parents=True)
        (root / "nest" / "deep" / "one.py").write_text("a = 1\n", encoding="utf-8")
        (root / "nest" / "deep" / "two.py").write_text("b = 2\n", encoding="utf-8")
        assert [label for _, label in expand([str(root / "nest")], cwd=elsewhere)] == ["deep/one.py", "deep/two.py"]

        # two different folders holding a file of the same relative name: the labels are made distinct, so a report never confuses them
        for name in ("p1", "p2"):
            (root / name).mkdir()
            (root / name / "lib.py").write_text(f"v = '{name}'\n", encoding="utf-8")
        clash = expand([str(root / "p1"), str(root / "p2")], cwd=elsewhere)
        assert len({label for _, label in clash}) == 2 and {file.parent.name for file, _ in clash} == {"p1", "p2"} and clash[0][1] == "lib.py" and clash[1][1] != "lib.py", clash

        # the same file given twice is one file; two files with the same name outside any repo are told apart
        assert len(expand(["app/main.py", "app/main.py", "app"], cwd=root)) == 2
        (root / "x").mkdir()
        (root / "y").mkdir()
        (root / "x" / "same.py").write_text("a = 1\n", encoding="utf-8")
        (root / "y" / "same.py").write_text("b = 2\n", encoding="utf-8")
        twins = [label for _, label in expand([str(root / "x" / "same.py"), str(root / "y" / "same.py")], cwd=elsewhere)]
        assert len(set(twins)) == 2 and sorted(twins) == ["x/same.py", "y/same.py"], twins

        # no label ever contains a drive letter, a leading slash, a backslash or ..
        for path in (root / "app", root / "other", root / "lonely.py", root / "x"):
            for _, label in expand([str(path)], cwd=elsewhere):
                assert not label.startswith(("/", "..")) and "\\\\" not in label and ":" not in label and ".." not in label.split("/"), label

        # problems are said in words, not with an operating system's cryptic message
        for argument, needle in (("nope.py", "No such file or folder"), ("empty", "No Python files found in empty")):
            try:
                expand([argument], cwd=root)
                raise AssertionError(f"{argument} must be refused")
            except PathProblem as problem:
                assert needle in str(problem), str(problem)

    print("paths OK: files and folders, junk folders skipped, labels relative to where you stand (else the git root, else the common parent), unique, never absolute")


if __name__ == "__main__":
    demo()
