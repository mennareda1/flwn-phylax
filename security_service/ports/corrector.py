"""
security_service/ports/corrector.py

Port: propose a fix for findings in one file, the role a model such as GPT-6 Astra plays.

An adapter receives the file and the findings to fix and returns patches as unified diffs. It
never applies anything. The fix service verifies every patch (it parses, a re-scan shows the
finding gone and nothing new at medium or above, the patch stays small) before the API will
call it applicable. Adapters must stay tool-free: JSON in, patch out.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from security_service.core.files import SourceFile
from security_service.core.schema import Finding


@dataclass(frozen=True)
class FixConstraints:
    max_patch_lines: int = 40          # added plus removed lines, per patch
    preserve_behavior: bool = True     # tell the model to change only what the finding requires


@dataclass(frozen=True)
class Patch:
    path: str
    finding_ids: tuple[str, ...]
    unified_diff: str
    explanation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "finding_ids": list(self.finding_ids),
            "unified_diff": self.unified_diff,
            "explanation": self.explanation,
        }


class Corrector(Protocol):
    role: str                          # "corrector"
    name: str

    def propose_fix(self, file: SourceFile, findings: list[Finding], constraints: FixConstraints) -> list[Patch]:
        """Return zero or more patches for `file`. Raise on any failure; never return a half-answer."""
        ...


def demo() -> None:
    patch = Patch("a.py", ("f1",), "--- a/a.py\n+++ b/a.py\n", "why")
    assert patch.to_dict() == {"path": "a.py", "finding_ids": ["f1"], "unified_diff": "--- a/a.py\n+++ b/a.py\n", "explanation": "why"}
    assert FixConstraints().max_patch_lines == 40
    print("ports.corrector OK: patch shape")


if __name__ == "__main__":
    demo()
