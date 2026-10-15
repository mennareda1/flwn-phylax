"""
security_service/ports/analyzer.py

The contract every analyzer follows. Bandit, Semgrep, Cppcheck and the LLM
reviewer all plug in behind this same interface, which is what makes tools
and models replaceable without touching the scanner or the decision engine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from security_service.core.schema import Finding


@dataclass
class AnalyzerResult:
    analyzer: str
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None   # set when the analyzer could not complete
    duration_ms: int = 0
    stats: dict[str, int] = field(default_factory=dict)   # diagnostics, e.g. dropped model findings

    @property
    def ok(self) -> bool:
        return self.error is None


class Analyzer(Protocol):
    role: str          # "analyzer" (rules) or "detector" (model); reported in provenance
    name: str
    languages: tuple[str, ...]

    def analyze(self, code: str, language: str) -> AnalyzerResult:
        """Analyze source text WITHOUT executing it. Never raise: report failure via AnalyzerResult.error."""
        ...
