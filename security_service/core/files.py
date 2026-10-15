"""
security_service/core/files.py

Turns a raw request (a list of files plus an optional default language) into what the
scan service actually analyzes, and records everything it chose not to analyze.

Rules:
  - Request-level problems raise: no files, too many files, total size over the limit,
    duplicate or malformed paths, non-string content, an unsupported top-level language.
  - File-level problems never raise: the file is skipped with a reason. A skipped SOURCE file
    (language known, or content unusable) sets blocks_pass=True, so a report containing one
    can never be a pass. Non-source files (docs, config) are listed but do not block a pass.
  - Paths are labels only. Nothing is ever read from or written to a submitted path.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from security_service.core.schema import SkippedFile

LANGUAGE_ALIASES = {
    "py": "python", "python3": "python",
    "js": "javascript", "node": "javascript",
    "ts": "typescript",
    "c++": "cpp", "cxx": "cpp",
    "c#": "csharp", "cs": "csharp",
}

KNOWN_CODE_LANGUAGES = frozenset(
    {"python", "javascript", "typescript", "cpp", "c", "csharp", "java", "go", "rust", "ruby", "php", "shell"}
)

EXTENSION_LANGUAGES = {
    ".py": "python", ".pyi": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".hpp": "cpp", ".hh": "cpp", ".h": "cpp",
    ".c": "c",
    ".cs": "csharp",
    ".java": "java", ".go": "go", ".rs": "rust", ".rb": "ruby", ".php": "php", ".sh": "shell",
}

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


class InvalidScanInput(ValueError):
    """The request itself is bad. Maps to HTTP 400."""


class PayloadTooLarge(InvalidScanInput):
    """Too many files or too many bytes. Maps to HTTP 413."""


class UnsupportedLanguage(InvalidScanInput):
    """The request asks for a language no engine covers. Maps to HTTP 422."""


@dataclass(frozen=True)
class SourceFile:
    path: str
    content: str
    language: str | None = None


@dataclass(frozen=True)
class Limits:
    # Starting limits; tune after measuring real engine time and model context.
    max_files: int = 50
    max_file_bytes: int = 200_000
    max_total_bytes: int = 1_000_000


@dataclass(frozen=True)
class PreparedFile:
    path: str
    content: str     # line endings normalized to \n so reported line numbers match the caller's
    language: str


def normalize_language(value: str | None) -> str | None:
    if value is None or not str(value).strip():
        return None
    lang = str(value).strip().lower()
    return LANGUAGE_ALIASES.get(lang, lang)


def _clean_path(raw: object) -> str:
    if not isinstance(raw, str) or not raw.strip():
        raise InvalidScanInput("every file needs a non-empty path")
    path = raw.strip().replace("\\", "/")
    if len(path) > 500 or _CONTROL_CHARS.search(path):
        raise InvalidScanInput(f"invalid file path {raw[:60]!r}")
    return path


def _extension_language(path: str) -> str | None:
    dot = path.rfind(".")
    return EXTENSION_LANGUAGES.get(path[dot:].lower()) if dot != -1 else None


def prepare_files(
    files: list[SourceFile],
    default_language: str | None,
    supported_languages: frozenset[str],
    limits: Limits,
) -> tuple[list[PreparedFile], list[SkippedFile]]:
    default = normalize_language(default_language)
    if default is not None and default not in supported_languages:
        raise UnsupportedLanguage(
            f"language {default_language!r} is not supported (supported: {', '.join(sorted(supported_languages)) or 'none'})"
        )
    if not isinstance(files, list) or not files:
        raise InvalidScanInput("at least one file is required")
    if len(files) > limits.max_files:
        raise PayloadTooLarge(f"too many files ({len(files)}, limit {limits.max_files})")

    seen: set[str] = set()
    total_bytes = 0
    entries: list[tuple[str, str, str | None]] = []
    for item in files:
        path = _clean_path(item.path)
        if path in seen:
            raise InvalidScanInput(f"duplicate file path {path!r}")
        seen.add(path)
        if not isinstance(item.content, str):
            raise InvalidScanInput(f"content of {path!r} must be a string")
        total_bytes += len(item.content.encode("utf-8", errors="replace"))
        language = normalize_language(item.language) or default or _extension_language(path)
        entries.append((path, item.content, language))
    if total_bytes > limits.max_total_bytes:
        raise PayloadTooLarge(f"request too large ({total_bytes} bytes, limit {limits.max_total_bytes})")

    prepared: list[PreparedFile] = []
    skipped: list[SkippedFile] = []
    for path, content, language in entries:
        is_source = language in KNOWN_CODE_LANGUAGES
        if not content.strip():
            skipped.append(SkippedFile(path, "empty", False))
        elif "\x00" in content:
            skipped.append(SkippedFile(path, "binary_or_invalid", is_source))
        elif len(content.encode("utf-8", errors="replace")) > limits.max_file_bytes:
            skipped.append(SkippedFile(path, "file_too_large", is_source))
        elif language is None or language not in supported_languages:
            skipped.append(SkippedFile(path, "unsupported_language", is_source))
        else:
            prepared.append(PreparedFile(path, content.replace("\r\n", "\n").replace("\r", "\n"), language))
    return prepared, skipped


def demo() -> None:
    python_only = frozenset({"python"})
    limits = Limits(max_files=3, max_file_bytes=100, max_total_bytes=250)

    def raises(exc, fn, *args):
        try:
            fn(*args)
        except exc:
            return True
        return False

    prep = lambda files, lang=None, lim=limits: prepare_files(files, lang, python_only, lim)

    # request-level errors raise, with the right error class
    assert raises(InvalidScanInput, prep, [])
    assert raises(PayloadTooLarge, prep, [SourceFile(f"{i}.py", "x = 1") for i in range(4)])
    assert raises(PayloadTooLarge, prep, [SourceFile("a.py", "x" * 90), SourceFile("b.py", "y" * 90), SourceFile("c.py", "z" * 90)])
    assert raises(InvalidScanInput, prep, [SourceFile("a.py", "x = 1"), SourceFile("a.py", "y = 2")])
    assert raises(InvalidScanInput, prep, [SourceFile("", "x = 1")])
    assert raises(InvalidScanInput, prep, [SourceFile("bad\x00name.py", "x = 1")])
    assert raises(InvalidScanInput, prep, [SourceFile("a.py", None)])
    assert raises(UnsupportedLanguage, prep, [SourceFile("a.cob", "x")], "cobol")
    assert raises(UnsupportedLanguage, prep, [SourceFile("a.js", "x")], "javascript")   # known but unsupported

    # language resolution: explicit file language > request language > extension; aliases normalized
    prepared, skipped = prep([SourceFile("a.py", "x = 1"), SourceFile("b", "y = 2", "PY")])
    assert [(p.path, p.language) for p in prepared] == [("a.py", "python"), ("b", "python")] and not skipped

    # skips: source files block a pass, non-source files do not
    prepared, skipped = prep([
        SourceFile("ok.py", "x = 1"),
        SourceFile("app.js", "let a = 1"),            # known code, no engine  -> blocks
        SourceFile("README.md", "# docs"),            # not source             -> listed, does not block
        SourceFile("empty.py", "   \n"),              # empty                  -> does not block
        SourceFile("blob.py", "a\x00b"),              # corrupt source         -> blocks
        SourceFile("big.py", "z" * 101),              # too large source       -> blocks
    ], lim=Limits(max_files=10, max_file_bytes=100, max_total_bytes=10_000))
    assert [p.path for p in prepared] == ["ok.py"]
    reasons = {s.path: (s.reason, s.blocks_pass) for s in skipped}
    assert reasons == {
        "app.js": ("unsupported_language", True),
        "README.md": ("unsupported_language", False),
        "empty.py": ("empty", False),
        "blob.py": ("binary_or_invalid", True),
        "big.py": ("file_too_large", True),
    }, reasons

    # paths are normalized, and CRLF is normalized so line numbers match what the caller sees
    prepared, _ = prep([SourceFile("src\\a.py", "a\r\nb\r\nc")])
    assert prepared[0].path == "src/a.py" and prepared[0].content == "a\nb\nc"
    print("core.files OK: request errors raise, file problems skip, source skips block a pass")


if __name__ == "__main__":
    demo()
