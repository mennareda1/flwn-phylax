"""
security_service/fix.py

Ask for verified fixes for your own files, from the command line, and read them before anything changes:

    python -m security_service.fix app.py
    python -m security_service.fix src\\a.py src\\b.py --save-patch fix.diff
    python -m security_service.fix src --save-patch fix.diff     a whole folder (at most 10 files are fixed per run, most severe first)
    python -m security_service.fix app.py --finding f1,f3        only these findings, by the ids a scan printed
    python -m security_service.fix app.py --save-unverified fix.diff   also keep a patch that was NOT confirmed, marked UNVERIFIED inside the file
    python -m security_service.fix app.py --json                 the full machine-readable result

It scans the files with the engines your settings switch on, asks the corrector (GPT-6 Astra) for a patch per file, then VERIFIES
each patch: it must apply exactly, the code must still parse and use no new undefined name, the patch must be small, and a new scan
must show the fixed findings gone and nothing new backed by a rule. It prints the patch, every check, and anything it could not fix.

IT NEVER CHANGES YOUR FILES. With --save-patch it writes the verified patch to a file, and you apply it yourself after reading it:
    git apply fix.diff          (from the folder the paths are relative to)
A patch that failed verification is shown, and is saved only if you ask with --save-unverified, in which case the file begins with a
plain-text UNVERIFIED notice (git ignores it). "Not confirmed" is not "wrong": a rule-based re-scan cannot confirm every correct fix (Bandit
flags SQL built with an f-string even when the only trusted value is a table name), so read the patch and test the code. Hardcoded secrets
are not fixed automatically (rotate them).
Needs the corrector settings (CORRECTOR_DEPLOYMENT in .env); a request costs a few cents. Run `python -m tests.live_corrector` first.

Exit code: 0 a verified fix was produced, 1 nothing at medium severity or above to fix, 3 no verified fix (see why),
4 could not start (settings, an unreadable file, bad arguments).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from security_service.config import Settings, load_env_file
from security_service.core.files import InvalidScanInput, SourceFile
from security_service.core.fix_service import FixService
from security_service.core.scan_service import ScanService
from security_service.paths import PathProblem, expand
from security_service.core.schema import Severity
from security_service.ports.corrector import CorrectorError

COULD_NOT_START = 4


def _value(argv: list[str], flag: str) -> str | None:
    return argv[argv.index(flag) + 1] if flag in argv and argv.index(flag) + 1 < len(argv) else None


def main(argv: list[str], environ=None, out=print, corrector=None, scan_service=None) -> int:
    flags_with_values = {"--finding", "--max-lines", "--save-patch", "--save-unverified"}
    paths = [a for i, a in enumerate(argv) if not a.startswith("--") and not (i > 0 and argv[i - 1] in flags_with_values)]
    if not paths:
        out("Usage: python -m security_service.fix FILE [FILE ...] [--finding f1,f2] [--max-lines N] [--save-patch FILE] [--json]")
        return COULD_NOT_START
    if environ is None:
        load_env_file()
        environ = os.environ
    settings = Settings.from_env(environ)
    for warning in settings.warnings:
        out(f"warning: {warning}")
    if corrector is None:
        problems = settings.corrector_problems()
        if problems:
            out("The corrector is not ready:\n" + "\n".join(f"  - {p}" for p in problems) + "\nAdd the missing setting to .env, then run  python -m tests.live_corrector  to check it.")
            return COULD_NOT_START
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
        limit = int(_value(argv, "--max-lines") or 40)
        if not 1 <= limit <= 200:
            raise ValueError
    except ValueError:
        out("--max-lines must be a whole number from 1 to 200")
        return COULD_NOT_START

    try:
        scanner = scan_service or ScanService.from_settings(settings)
        if corrector is None:
            from security_service.adapters.foundry_corrector import FoundryCorrector

            corrector = FoundryCorrector.from_settings(settings)
        report = scanner.scan(files)
    except (ValueError, InvalidScanInput) as problem:
        out(f"Cannot continue: {problem}")
        return COULD_NOT_START

    wanted = _value(argv, "--finding")
    ids = [i.strip() for i in wanted.split(",") if i.strip()] if wanted else None
    fixable = [f for f in report.findings if f.severity.rank >= Severity.MEDIUM.rank]
    as_json = "--json" in argv
    if not as_json:
        out(f"scan: {report.decision.value}; {len(report.findings)} finding(s), {len(fixable)} at medium severity or above")
        for f in report.findings:
            out(f"  {f.id}  {f.path}:{f.line or 'whole file'}  {f.vulnerability_type}  {f.severity.value}  {f.evidence_tier.value}")
    if not fixable and not ids:
        out(json.dumps({"scan": report.to_dict(), "fix": None}, indent=2) if as_json else "Nothing at medium severity or above to fix.")
        return 1

    try:
        result = FixService(scanner, corrector).fix(files, report.findings, ids, limit)
    except ValueError as problem:
        out(f"Cannot fix: {problem}")
        return COULD_NOT_START
    except CorrectorError as problem:                          # the fix service reports these itself; this is the last line of defense
        out(f"The corrector failed: {type(problem).__name__}: {problem}")
        return 3

    if as_json:
        out(json.dumps({"scan": report.to_dict(), "fix": result.to_dict()}, indent=2))
    else:
        for patch in result.patches:
            out(f"\nPATCH for {patch.path}, fixing {', '.join(patch.finding_ids)}\nthe model says: {patch.explanation}\n")
            out(patch.unified_diff.rstrip())
        if result.verification:
            out(f"\nVERIFICATION: {result.verification.outcome}")
            for check in result.verification.checks:
                out(f"  {check.name:<11}{check.result:<8}{check.detail}")
            for new in result.verification.new_findings:
                out(f"  new finding {new.id}: {new.vulnerability_type} at {new.severity.value} in {new.path} ({new.evidence_tier.value})")
        for item in result.unfixed:
            out(f"NOT FIXED {item['finding_id']}: {item['reason']}")
        usage = getattr(corrector, "usage", None)
        if usage and usage.get("calls"):
            out(f"model use: {usage['calls']} request(s), {usage['prompt_tokens']} tokens in, {usage['completion_tokens']} out ({usage['reasoning_tokens']} thinking)")

    saved, unverified = _value(argv, "--save-patch"), _value(argv, "--save-unverified")
    diff_text = "".join(p.unified_diff for p in result.patches)
    if result.applicable and saved:
        Path(saved).write_text(diff_text, encoding="utf-8", newline="\n")
        if not as_json:
            out(f"\nSaved the verified patch to {saved}. Read it, then apply it yourself, from the folder you ran this in:  git apply --check {saved}  (a dry run), then  git apply {saved}")
            out("If git says \"patch does not apply\" on files with Windows line endings, add --ignore-whitespace.")
    elif saved and not as_json:
        out("\nNot saved: a patch is saved only when it passed verification. To keep it for review anyway, use --save-unverified FILE (it is marked UNVERIFIED inside the file).")
    if unverified:
        if not result.patches:
            if not as_json:
                out("\nNothing to save: no patch was produced.")
        else:
            notice = "" if result.applicable else (
                f"# UNVERIFIED PATCH: Phylax could not confirm this fix. {result.failure_reason}\n"
                "# That means NOT CONFIRMED, not necessarily wrong. Read the patch and test the code before applying it.\n"
                "# This is a plain unified diff: git ignores these comment lines.\n\n")
            Path(unverified).write_text(notice + diff_text, encoding="utf-8", newline="\n")
            if not as_json:
                out(f"\nSaved the patch to {unverified}" + ("." if result.applicable else f", marked UNVERIFIED. It was NOT confirmed: read it carefully and test the code before:  git apply {unverified}"))
    if as_json:
        return 0 if result.applicable else 3
    if result.applicable:
        out("\nRESULT: a verified fix was produced. Nothing was changed: you apply it after reading it." if not result.unfixed else
            "\nRESULT: a verified fix was produced for the findings it covers (see NOT FIXED above for the rest). Nothing was changed: you apply it after reading it.")
        out("Verification shows the problem is gone and nothing new appeared. It does NOT prove the code behaves the same: run your tests, and look for anything that reads data an older version wrote.")
        return 0
    out(f"\nRESULT: no verified fix. {result.failure_reason}")
    if result.patches:
        out("A failed verification means the patch is NOT CONFIRMED, not that it is wrong: a rule-based re-scan cannot confirm every correct fix. Read the patch above.")
    return 3


def demo() -> None:
    import tempfile

    from security_service.adapters.fakes import FakeCorrector
    from security_service.core.files import Limits
    from security_service.core.patching import apply_unified_diff

    bad = 'import os\n\n\ndef ping(host):\n    os.system("ping " + host)\n    return True\n'
    fixed_call = '    subprocess.run(["ping", host], check=True)\n'

    class Corrector(FakeCorrector):
        """Turns the shell call into a safe one, and adds the import: what a good model would do."""

        def __init__(self):
            super().__init__("", "")
            self.usage = {"calls": 0, "prompt_tokens": 0, "completion_tokens": 0, "reasoning_tokens": 0}

        def propose_fix(self, file, findings, constraints):
            from security_service.core.patching import make_unified_diff
            from security_service.ports.corrector import Patch

            self.usage["calls"] += 1
            new = file.content.replace('    os.system("ping " + host)\n', fixed_call).replace("import os\n", "import os\nimport subprocess\n")
            return [Patch(file.path, tuple(f.id for f in findings), make_unified_diff(file.path, file.content, new), "Run ping without a shell.")]

    ready = {"CORRECTOR_DEPLOYMENT": "gpt-6-astra", "FOUNDRY_ENDPOINT": "https://r.services.ai.azure.com", "FOUNDRY_API_KEY": "k" * 30}
    shown: list[str] = []
    say = shown.append
    with tempfile.TemporaryDirectory() as folder:
        net, clean, notes = Path(folder) / "net.py", Path(folder) / "clean.py", Path(folder) / "notes.md"
        net.write_text(bad, encoding="utf-8")
        clean.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
        before = net.read_bytes()
        patch_file = Path(folder) / "fix.diff"

        # a verified fix, printed with every check; the file is never touched; the saved patch applies to the original exactly
        assert main([str(net), "--save-patch", str(patch_file)], environ=ready, out=say, corrector=Corrector()) == 0
        text = "\n".join(shown)
        assert "scan: block" in text and "command_injection" in text and "PATCH for" in text and "+    subprocess.run" in text
        assert "VERIFICATION: passed" in text and "scope" in text and "rescan" in text and "RESULT: a verified fix was produced" in text and "model use: 1 request" in text
        assert net.read_bytes() == before, "the tool changed the user's file"
        assert apply_unified_diff(bad, patch_file.read_text(encoding="utf-8"), "net.py") == bad.replace('    os.system("ping " + host)\n', fixed_call).replace("import os\n", "import os\nimport subprocess\n")
        assert f"git apply {patch_file}" in text and "--ignore-whitespace" in text and "does NOT prove the code behaves the same" in text
        shown.clear()

        # a patch that does not verify is shown, NOT saved, and the result says why
        class Careless(Corrector):
            def propose_fix(self, file, findings, constraints):
                from security_service.core.patching import make_unified_diff
                from security_service.ports.corrector import Patch

                new = file.content.replace('    os.system("ping " + host)\n', '    eval("ping " + host)\n')
                return [Patch(file.path, tuple(f.id for f in findings), make_unified_diff(file.path, file.content, new), "Hopefully safer.")]

        unsaved = Path(folder) / "unsaved.diff"
        assert main([str(net), "--save-patch", str(unsaved)], environ=ready, out=say, corrector=Careless()) == 3
        text = "\n".join(shown)
        assert "VERIFICATION: failed" in text and "new finding n1: code_injection" in text and "RESULT: no verified fix" in text and "Not saved" in text and not unsaved.exists()
        assert "--save-unverified" in text and "NOT CONFIRMED, not that it is wrong" in text
        shown.clear()

        # --save-unverified keeps the patch for review, marked inside the file; it is still not a pass, and the user's file is untouched
        kept = Path(folder) / "kept.diff"
        assert main([str(net), "--save-unverified", str(kept)], environ=ready, out=say, corrector=Careless()) == 3
        body = kept.read_text(encoding="utf-8")
        assert body.startswith("# UNVERIFIED PATCH: Phylax could not confirm this fix.") and "NOT CONFIRMED, not necessarily wrong" in body and "git ignores" in body
        assert "marked UNVERIFIED" in "\n".join(shown) and net.read_bytes() == before
        raw_diff = body[body.index("--- a/"):]
        assert 'eval("ping " + host)' in raw_diff and apply_unified_diff(bad, raw_diff, "net.py").count("eval(") == 1       # the diff after the notice is a normal, strict diff
        shown.clear()
        verified_copy = Path(folder) / "verified_copy.diff"                                         # a verified patch saved this way has NO unverified notice
        assert main([str(net), "--save-unverified", str(verified_copy)], environ=ready, out=say, corrector=Corrector()) == 0
        assert verified_copy.read_text(encoding="utf-8").startswith("--- a/")
        shown.clear()
        nothing_to_keep = Path(folder) / "nothing.diff"
        assert main([str(net), "--save-unverified", str(nothing_to_keep)], environ=ready, out=say, corrector=FakeCorrector("zzz", "yyy")) == 3
        assert "Nothing to save: no patch was produced." in "\n".join(shown) and not nothing_to_keep.exists()
        shown.clear()

        # a clean file, a missing corrector setting, an unreadable file, bad arguments: each said plainly, none a stack trace
        assert main([str(clean)], environ=ready, out=say, corrector=Corrector()) == 1 and "Nothing at medium severity or above to fix." in "\n".join(shown)
        shown.clear()
        assert main([str(net)], environ={}, out=say) == COULD_NOT_START and "No deployment" in "\n".join(shown) and "live_corrector" in "\n".join(shown)
        shown.clear()
        assert main([str(Path(folder) / "missing.py")], environ=ready, out=say, corrector=Corrector()) == COULD_NOT_START and "Cannot read" in shown[-1] and "No such file or folder" in shown[-1]
        assert main([], environ=ready, out=say) == COULD_NOT_START and "Usage" in shown[-1]
        for bad_limit in ("0", "500", "many"):
            assert main([str(net), "--max-lines", bad_limit], environ=ready, out=say, corrector=Corrector()) == COULD_NOT_START and "--max-lines" in shown[-1]
        assert main([str(net), "--finding", "f9"], environ=ready, out=say, corrector=Corrector()) == COULD_NOT_START and "not in the scan" in shown[-1]
        assert "Traceback" not in "\n".join(shown)
        shown.clear()

        # a FOLDER works: every .py file in it (not venv, not __pycache__), labelled relative paths, and the patch header carries no absolute path
        tree = Path(folder) / "project"
        (tree / "pkg").mkdir(parents=True)
        (tree / "venv").mkdir()
        (tree / "pkg" / "net.py").write_text(bad, encoding="utf-8")
        (tree / "pkg" / "ok.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
        (tree / "venv" / "skip.py").write_text(bad, encoding="utf-8")
        folder_patch = Path(folder) / "folder.diff"
        folder_run = Corrector()
        assert main([str(tree), "--save-patch", str(folder_patch)], environ=ready, out=say, corrector=folder_run) == 0 and folder_run.usage["calls"] == 1
        text = "\n".join(shown)
        assert "pkg/net.py:5" in text and "venv" not in text and "skip.py" not in text                  # the venv folder was not searched; the file is named relative to the folder given
        saved_text = folder_patch.read_text(encoding="utf-8")
        assert saved_text.startswith("--- a/pkg/net.py\n+++ b/pkg/net.py\n") and str(folder) not in saved_text and ":" not in saved_text.splitlines()[0]
        shown.clear()
        (Path(folder) / "emptydir").mkdir()
        assert main([str(Path(folder) / "emptydir")], environ=ready, out=say, corrector=Corrector()) == COULD_NOT_START and "No Python files found" in shown[-1]
        shown.clear()

        # --finding picks by id, --max-lines is passed on, and --json is the whole result
        picked = Corrector()
        assert main([str(net), "--finding", "f1", "--max-lines", "9"], environ=ready, out=say, corrector=picked) == 0 and picked.usage["calls"] == 1
        shown.clear()
        assert main([str(net), "--json"], environ=ready, out=say, corrector=Corrector()) == 0
        data = json.loads("\n".join(shown))
        assert data["scan"]["decision"] == "block" and data["fix"]["applicable"] is True and data["fix"]["verification"]["outcome"] == "passed" and data["fix"]["patches"][0]["path"].endswith("net.py")
        shown.clear()
        assert main([str(clean), "--json"], environ=ready, out=say, corrector=Corrector()) == 1 and json.loads("\n".join(shown))["fix"] is None

    print("fix OK: verified patches printed with every check, saved only when verified, files never changed, plain errors and exit codes")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--selftest":
        demo()
    else:
        sys.exit(main(sys.argv[1:]))
