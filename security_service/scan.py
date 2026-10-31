"""
security_service/scan.py

Scan files from the command line, with the engines your settings switch on, and print the result in plain words:

    python -m security_service.scan app.py
    python -m security_service.scan src\\a.py src\\b.py
    python -m security_service.scan src                  a whole folder: every .py file in it, except venv, .git, build and the like
    python -m security_service.scan app.py --json        the full machine-readable report instead

Settings come from your terminal and .env, as everywhere else (python -m security_service.config shows them). With
CLASSIFIER_ENABLED=false (the default) a scan is Bandit plus the secrets check and makes no network call. With
CLASSIFIER_ENABLED=true each Python file is also sent, masked, to Decision-1, and its answers appear as findings of
tier model_suspicion.

The exit code says what happened, so scripts can act on it:
    0 pass   1 review_required   2 block   3 scan_failed   4 could not start (bad arguments, unreadable file, settings)
A pass means only that nothing was found by the checks that ran, on the files scanned: read the coverage line.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from security_service.config import Settings, load_env_file
from security_service.core.files import InvalidScanInput, SourceFile
from security_service.core.scan_service import ScanService
from security_service.paths import PathProblem, expand

EXIT_CODES = {"pass": 0, "review_required": 1, "block": 2, "scan_failed": 3}
COULD_NOT_START = 4


def format_report(report) -> str:
    data = report.to_dict()
    lines = [f"decision: {data['decision']}   risk level: {data['risk_level']}"]
    lines += ["reasons:"] + [f"  - {reason}" for reason in data["decision_reasons"]]
    if data["findings"]:
        lines.append("findings:")
        for f in data["findings"]:
            where = f"{f['path']}:{f['line']}" if f["line"] else f"{f['path']} (whole file)"
            lines.append(f"  {f['id']}  {where}  {f['vulnerability_type']}  {f['severity']}/{f['confidence']}  {f['evidence_tier']}  by {', '.join(f['sources'])}")
            lines.append(f"      {f['description']}")
            if f["line"]:
                lines.append(f"      evidence: {f['evidence']}")
    else:
        lines.append("findings: none")
    c = data["coverage"]
    scanned = c["files_scanned"]
    lines.append("coverage: scanned " + ((", ".join(scanned) if len(scanned) <= 8 else f"{len(scanned)} files") or "nothing")
                 + "; engines that ran: " + (", ".join(c["analyzers_run"]) or "none")
                 + ("; engines that failed: " + "; ".join(f"{k} ({v[:80]})" for k, v in c["analyzers_failed"].items()) if c["analyzers_failed"] else "")
                 + ("; skipped: " + ", ".join(f"{s['path']} ({s['reason']})" for s in c["skipped_files"]) if c["skipped_files"] else ""))
    lines.append("not checked by any scan of submitted files: " + "; ".join(c["not_assessable"]))
    return "\n".join(lines)


def main(argv: list[str], environ=None, classifier=None, out=print) -> int:
    paths = [a for a in argv if not a.startswith("--")]
    if not paths:
        out("Usage: python -m security_service.scan FILE [FILE ...] [--json]")
        return COULD_NOT_START
    if environ is None:
        load_env_file()
        environ = os.environ
    settings = Settings.from_env(environ)
    for warning in settings.warnings:
        out(f"warning: {warning}")
    try:
        located = expand(paths)
    except PathProblem as problem:
        out(str(problem))
        return COULD_NOT_START
    if len(located) > settings.scan_max_files:
        out(f"Found {len(located)} Python files, and one scan takes at most {settings.scan_max_files} (SCAN_MAX_FILES in .env). Give a smaller folder, or raise the limit.")
        return COULD_NOT_START
    files = []
    for file, label in located:
        try:
            files.append(SourceFile(label, file.read_text(encoding="utf-8", errors="replace")))
        except OSError as problem:
            out(f"Cannot read {label}: {problem.strerror or problem}")
            return COULD_NOT_START
    try:
        service = ScanService.from_settings(settings, classifier=classifier)
        report = service.scan(files)
    except (ValueError, InvalidScanInput) as problem:
        out(f"Cannot scan: {problem}")
        return COULD_NOT_START
    out(json.dumps(report.to_dict(), indent=2) if "--json" in argv else format_report(report))
    return EXIT_CODES[report.decision.value]


def demo() -> None:
    import tempfile

    from security_service.adapters.fakes import FakeClassifier
    from security_service.ports.classifier import Answer

    shown: list[str] = []
    say = shown.append
    with tempfile.TemporaryDirectory() as folder:
        bad, good, odd = Path(folder) / "bad.py", Path(folder) / "good.py", Path(folder) / "notes.md"
        bad.write_text('import os\n\ndef ping(host):\n    os.system("ping " + host)\n', encoding="utf-8")
        good.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
        odd.write_text("# notes\n", encoding="utf-8")
        off = {}                                                     # no variables at all: rules only, no network

        # rules only: a vulnerable file blocks, a clean one passes, and both say what they covered
        assert main([str(bad)], environ=off, out=say) == 2
        text = "\n".join(shown)
        assert "decision: block" in text and "command_injection" in text and "bandit" in text and "microsoft-decision-1" not in text
        assert "not checked by any scan of submitted files" in text and "authentication and authorization" in text
        shown.clear()
        assert main([str(good)], environ=off, out=say) == 0 and "decision: pass" in "\n".join(shown) and "findings: none" in "\n".join(shown)
        shown.clear()
        assert main([str(good), str(odd)], environ=off, out=say) == 0 and "notes.md (unsupported_language)" in "\n".join(shown)   # skipped files are listed
        shown.clear()

        # a FOLDER: every .py file in it, junk folders skipped, files named relative to the folder, a long list of files summarized
        tree = Path(folder) / "project"
        (tree / "pkg").mkdir(parents=True)
        (tree / "venv").mkdir()
        (tree / "pkg" / "net.py").write_text(bad.read_text(encoding="utf-8"), encoding="utf-8")
        (tree / "pkg" / "ok.py").write_text(good.read_text(encoding="utf-8"), encoding="utf-8")
        (tree / "venv" / "skip.py").write_text(bad.read_text(encoding="utf-8"), encoding="utf-8")
        assert main([str(tree)], environ=off, out=say) == 2
        text = "\n".join(shown)
        assert "pkg/net.py:4" in text and "scanned pkg/net.py, pkg/ok.py" in text and "skip.py" not in text
        shown.clear()
        for number in range(10):
            (tree / "pkg" / f"m{number}.py").write_text("x = 1\n", encoding="utf-8")
        assert main([str(tree)], environ=off, out=say) == 2 and "coverage: scanned 12 files;" in "\n".join(shown)                 # many files: counted, not listed
        shown.clear()
        assert main([str(tree)], environ={"SCAN_MAX_FILES": "5"}, out=say) == COULD_NOT_START and "Found 12 Python files" in shown[-1] and "SCAN_MAX_FILES" in shown[-1]
        shown.clear()
        (Path(folder) / "empty").mkdir()
        assert main([str(Path(folder) / "empty")], environ=off, out=say) == COULD_NOT_START and "No Python files found" in shown[-1]
        shown.clear()

        # --json is the full report
        assert main([str(bad), "--json"], environ=off, out=say) == 2
        assert json.loads("\n".join(shown))["decision"] == "block"
        shown.clear()

        # Decision-1 switched on (a stand-in model that suspects path traversal): a model-only finding asks for review, never blocks
        on = {"CLASSIFIER_ENABLED": "true", "FOUNDRY_ENDPOINT": "https://r.services.ai.azure.com", "FOUNDRY_API_KEY": "k" * 32}
        stand_in = FakeClassifier(lambda state, q: Answer("yes_no", probability=0.95 if q.id == "path_traversal" else 0.01), name="stand-in-model")
        assert main([str(good)], environ=on, classifier=stand_in, out=say) == 1
        text = "\n".join(shown)
        assert "decision: review_required" in text and "path_traversal" in text and "model_suspicion" in text and "(whole file)" in text
        assert "stand-in-model" in text and "rest on model suspicion alone" in text
        shown.clear()

        # problems are said plainly and give exit code 4, never a stack trace
        assert main([], environ=off, out=say) == 4 and "Usage" in shown[-1]
        assert main([str(Path(folder) / "missing.py")], environ=off, out=say) == 4 and "Cannot read" in shown[-1]
        assert main([str(good)], environ={"CLASSIFIER_ENABLED": "true"}, out=say) == 4 and "not ready" in shown[-1]
        assert "Traceback" not in "\n".join(shown)

    print("scan OK: rules-only scans, whole-file model findings that never block, coverage always printed, exit codes, plain errors")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--selftest":
        demo()
    else:
        sys.exit(main(sys.argv[1:]))
