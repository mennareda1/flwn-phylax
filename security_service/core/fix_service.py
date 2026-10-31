"""
security_service/core/fix_service.py

From findings to a verified, never-applied fix. For the findings the caller wants fixed (by default every one at medium severity or
above) it asks the corrector for a patch per file, then checks the patch the way a careful reviewer would:

  1. The diff the corrector returned is APPLIED, strictly, to the exact file that was scanned (core/patching.apply_unified_diff).
     What is verified is therefore exactly the text a client will get and apply, not an internal copy of it.
  2. The corrected files go to the verification service (core/verification.py): scope, syntax and undefined names, patch size, and a
     re-scan that must show the fixed findings gone and nothing new backed by a rule.

`applicable` is True only when verification PASSED. Nothing is ever applied here: a person approves, then applies. Patches that failed
verification are still returned, so a reviewer can see them, with applicable False.

Honest about what it did not do: every finding it did not fix is listed in `unfixed` with the reason (no patch, the model said it is
not safely fixable, the corrector was unavailable, the diff did not fit the file, or the finding is a hardcoded secret, which is
never fixed automatically: it must be removed and the secret rotated). A fix that covers only some of the requested findings can
still be applicable for the findings it does cover; `unfixed` says which remain.

Bounds: at most 10 files and 10 findings per file go to the model in one request, most severe first, so one request cannot become an
unbounded bill. The rest are listed in `unfixed`.
"""

from __future__ import annotations

from dataclasses import dataclass

from security_service.core.files import SourceFile
from security_service.core.patching import PatchError, apply_unified_diff
from security_service.core.schema import Finding, Severity
from security_service.core.verification import VerificationResult, VerificationService
from security_service.ports.corrector import Corrector, CorrectorError, FixConstraints, Patch

MAX_FILES = 10
MAX_FINDINGS_PER_FILE = 10
SECRET_TYPE = "hardcoded_credentials"
SECRET_REASON = "A hardcoded secret is not fixed automatically: remove it from the code, move it to configuration, and rotate it, because it has been exposed."


@dataclass(frozen=True)
class FixResult:
    patches: tuple[Patch, ...]
    verification: VerificationResult | None
    applicable: bool
    failure_reason: str | None
    unfixed: tuple[dict, ...] = ()

    def to_dict(self) -> dict:
        """The contract's Fix without the fields only the API layer knows (id, scan_id, status, timestamps)."""
        return {"patches": [p.to_dict() for p in self.patches], "verification": self.verification.to_dict() if self.verification else None,
                "applicable": self.applicable, "failure_reason": self.failure_reason, "unfixed": [dict(u) for u in self.unfixed]}


def _norm(path: str | None) -> str:
    return (path or "").replace("\\", "/").removeprefix("./")


class FixService:
    def __init__(self, scan_service, corrector: Corrector, verifier: VerificationService | None = None):
        self._corrector = corrector
        self._verifier = verifier or VerificationService(scan_service)

    def fix(self, files: list[SourceFile], baseline: list[Finding], finding_ids: list[str] | None = None, max_patch_lines: int = 40) -> FixResult:
        by_id = {f.id: f for f in baseline}
        if finding_ids is not None:
            unknown = [i for i in finding_ids if i not in by_id]
            if unknown:
                raise ValueError(f"{len(unknown)} requested finding id(s) are not in the scan")
            wanted = [by_id[i] for i in dict.fromkeys(finding_ids)]
        else:
            wanted = [f for f in baseline if f.severity.rank >= Severity.MEDIUM.rank]

        unfixed: list[dict] = []
        askable: list[Finding] = []
        for f in wanted:
            if f.vulnerability_type == SECRET_TYPE:
                unfixed.append({"finding_id": f.id, "reason": SECRET_REASON})
            else:
                askable.append(f)
        if not askable:
            return FixResult((), None, False, "There is nothing the corrector can fix: " + ("every requested finding is a hardcoded secret." if unfixed else "no finding at medium severity or above."), tuple(unfixed))

        sources = {_norm(f.path): f for f in files}
        grouped: dict[str, list[Finding]] = {}
        for f in sorted(askable, key=lambda f: (-f.severity.rank, f.line or 0, f.id)):
            grouped.setdefault(_norm(f.path), []).append(f)
        paths = list(grouped)
        for path in paths[MAX_FILES:]:
            unfixed += [{"finding_id": f.id, "reason": f"Not attempted: one request fixes at most {MAX_FILES} files."} for f in grouped.pop(path)]

        constraints = FixConstraints(max_patch_lines=max_patch_lines)
        patches: list[Patch] = []
        corrected: list[SourceFile] = []
        for path, findings in grouped.items():
            for f in findings[MAX_FINDINGS_PER_FILE:]:
                unfixed.append({"finding_id": f.id, "reason": f"Not attempted: one request fixes at most {MAX_FINDINGS_PER_FILE} findings per file."})
            findings = findings[:MAX_FINDINGS_PER_FILE]
            ids = {f.id for f in findings}

            def give_up(reason: str, covered=findings):
                unfixed.extend({"finding_id": f.id, "reason": reason} for f in covered)

            source = sources.get(path)
            if source is None:
                give_up("The file is not among the submitted files.")
                continue
            try:
                proposed = self._corrector.propose_fix(SourceFile(path, source.content), findings, constraints)
            except CorrectorError as problem:
                give_up(f"The corrector could not produce a fix ({type(problem).__name__}: {problem}).")
                continue
            if not proposed:
                give_up("The corrector proposed no change: it judged the finding not safely fixable by a small change.")
                continue
            if len(proposed) > 1:
                give_up("The corrector returned several patches for one file; only one is supported.")
                continue
            patch = proposed[0]
            if _norm(patch.path) != path:
                give_up("The corrector returned a patch for a different file.")
                continue
            claimed = tuple(i for i in patch.finding_ids if i in ids)
            if not claimed:
                give_up("The corrector's patch does not say which of the requested findings it fixes.")
                continue
            try:
                text = apply_unified_diff(source.content, patch.unified_diff, path)
            except PatchError as problem:
                give_up(f"The corrector's patch does not apply to the file ({problem}).")
                continue
            patches.append(Patch(path, claimed, patch.unified_diff, patch.explanation))
            corrected.append(SourceFile(path, text))
            unfixed.extend({"finding_id": f.id, "reason": "The corrector's patch does not claim to fix this finding."} for f in findings if f.id not in claimed)

        if not patches:
            return FixResult((), None, False, "No patch could be produced: " + "; ".join(f"{u['finding_id']}: {u['reason']}" for u in unfixed[:4]) + ".", tuple(unfixed))

        covered = sorted({i for p in patches for i in p.finding_ids}, key=lambda i: (len(i), i))
        verification = self._verifier.verify(files, corrected, baseline, requested_ids=covered, max_patch_lines=max_patch_lines)
        if verification.outcome == "passed":
            return FixResult(tuple(patches), verification, True, None, tuple(unfixed))
        reason = {"failed": "Verification failed", "inconclusive": "Verification was inconclusive, so the fix is not confirmed"}[verification.outcome]
        why = next((c.detail for c in verification.checks if c.result == "fail"), None) or next((c.detail for c in verification.checks if c.result == "skipped"), "")
        return FixResult(tuple(patches), verification, False, f"{reason}: {why}", tuple(unfixed))


def demo() -> None:
    import re

    from security_service.core.files import Limits
    from security_service.core.patching import make_unified_diff
    from security_service.core.scan_service import ScanService
    from security_service.core.schema import Confidence, EvidenceTier
    from security_service.ports.analyzer import AnalyzerResult
    from security_service.ports.corrector import BadProposal, CorrectorUnavailable

    class Rules:
        role, name, languages = "analyzer", "rules", ("python",)
        table = [(r"os\.system\(", "command_injection", Severity.HIGH), (r"\beval\(", "code_injection", Severity.MEDIUM),
                 (r"password\s*=", SECRET_TYPE, Severity.HIGH), (r"hashlib\.md5", "weak_crypto", Severity.LOW)]

        def analyze(self, code, language):
            return AnalyzerResult(analyzer="rules", findings=[
                Finding(kind, severity, Confidence.HIGH, EvidenceTier.STATIC_RULE, ["rules"], "R", None, number, line.strip(), f"{kind} here", "fix it")
                for number, line in enumerate(code.split("\n"), start=1) for regex, kind, severity in self.table if re.search(regex, line)])

    service = ScanService([Rules()], limits=Limits())
    SAFE = 'subprocess.run(["x", h], check=True)'

    class Scripted:
        """A corrector that turns each os.system(...) line into a safe call, with switches for every way a corrector can go wrong."""
        role, name = "corrector", "scripted"

        def __init__(self, mode="good"):
            self.mode, self.seen = mode, []

        def propose_fix(self, file, findings, constraints):
            self.seen.append((file.path, [f.id for f in findings], constraints.max_patch_lines))
            if self.mode == "unavailable":
                raise CorrectorUnavailable("gpt-6-astra unavailable after 3 attempts (last: HTTP 503)")
            if self.mode == "bad":
                raise BadProposal("the model's edits do not fit the file: edit 1: its 'old' text is not in the file")
            if self.mode == "nothing":
                return []
            if self.mode == "many":
                return [Patch(file.path, tuple(f.id for f in findings), "", ""), Patch(file.path, tuple(f.id for f in findings), "", "")]
            new = file.content.replace("os.system(h)", SAFE).replace("import os\n", "import os\nimport subprocess\n")
            if self.mode == "swapped":
                new = file.content.replace("os.system(h)", "eval(h)")
            if self.mode == "undefined":
                new = file.content.replace("os.system(h)", SAFE)                     # uses subprocess without importing it
            if self.mode == "partial":
                new = file.content.replace("os.system(h)", SAFE, 1).replace("import os\n", "import os\nimport subprocess\n")
            path = "other.py" if self.mode == "wrongfile" else file.path
            diff = make_unified_diff(file.path, "different\n", new) if self.mode == "misfit" else make_unified_diff(file.path, file.content, new)
            ids = () if self.mode == "noclaim" else (("f99",) if self.mode == "foreign" else tuple(f.id for f in findings))
            return [Patch(path, ids, diff, "Replaced the shell call.")]

    one = [SourceFile("a.py", "import os\n\ndef run(h):\n    os.system(h)\n")]
    base = service.scan(one).findings
    assert [(f.id, f.severity.value) for f in base] == [("f1", "high")]

    def fix(corrector, files=None, baseline=None, **kw):
        files = files or one
        return FixService(service, corrector).fix(files, baseline if baseline is not None else service.scan(files).findings, **kw)

    # the good path: a verified, applicable patch whose diff really is what was verified
    scripted = Scripted()
    ok = fix(scripted)
    assert ok.applicable and ok.failure_reason is None and ok.unfixed == () and ok.verification.outcome == "passed"
    assert len(ok.patches) == 1 and ok.patches[0].path == "a.py" and ok.patches[0].finding_ids == ("f1",)
    assert apply_unified_diff(one[0].content, ok.patches[0].unified_diff, "a.py") == "import os\nimport subprocess\n\ndef run(h):\n    " + SAFE + "\n"
    assert scripted.seen == [("a.py", ["f1"], 40)] and ok.verification.resolved_finding_ids == ("f1",)
    too_small = fix(Scripted(), max_patch_lines=2)                                                                # the patch has 3 changed lines; the limit is inclusive
    assert too_small.applicable is False and too_small.failure_reason == "Verification failed: 3 changed line(s), limit 2." and len(too_small.patches) == 1
    assert fix(Scripted(), max_patch_lines=3).applicable is True
    limited = Scripted()
    fix(limited, max_patch_lines=7)
    assert limited.seen[-1][2] == 7                                                                                 # the limit also reaches the corrector, so the model is told
    assert set(ok.to_dict()) == {"patches", "verification", "applicable", "failure_reason", "unfixed"} and ok.to_dict()["verification"]["outcome"] == "passed"

    # a patch that fails verification is shown, but is not applicable, and the reason is the failed check
    for mode, needle in (("swapped", "new finding(s)"), ("undefined", "names nothing defines after the change: subprocess")):
        bad = fix(Scripted(mode))
        assert not bad.applicable and bad.verification.outcome == "failed" and len(bad.patches) == 1 and needle in bad.failure_reason, (mode, bad.failure_reason)

    # everything that can go wrong with the corrector or its patch ends in `unfixed` with a reason, never a crash
    for mode, needle in (("unavailable", "CorrectorUnavailable: gpt-6-astra unavailable"), ("bad", "BadProposal"), ("nothing", "proposed no change"), ("many", "several patches"),
                         ("wrongfile", "different file"), ("noclaim", "does not say which"), ("foreign", "does not say which of the requested"), ("misfit", "does not apply to the file")):
        result = fix(Scripted(mode))
        assert not result.applicable and result.patches == () and result.verification is None, mode
        assert result.unfixed[0]["finding_id"] == "f1" and needle in result.unfixed[0]["reason"] and result.failure_reason.startswith("No patch could be produced"), (mode, result.unfixed)

    # two files: one fixed and verified, one the corrector could not handle: applicable for what it covers, and honest about the rest
    two_files = [SourceFile("a.py", "import os\n\ndef run(h):\n    os.system(h)\n"), SourceFile("b.py", "import os\n\ndef go(h):\n    os.system(h)\n")]
    base2 = service.scan(two_files).findings

    class OnlyA(Scripted):
        def propose_fix(self, file, findings, constraints):
            if file.path == "b.py":
                raise CorrectorUnavailable("unavailable")
            return super().propose_fix(file, findings, constraints)

    mixed = FixService(service, OnlyA()).fix(two_files, base2)
    assert mixed.applicable and [p.path for p in mixed.patches] == ["a.py"] and mixed.verification.outcome == "passed"
    assert [(u["finding_id"], "CorrectorUnavailable" in u["reason"]) for u in mixed.unfixed] == [("f2", True)]

    # a fix that covers only part of what a file needs: verified for the finding it covers, the rest listed
    twice = [SourceFile("t.py", "import os\n\ndef a(h):\n    os.system(h)\n\ndef b(h):\n    os.system(h)\n")]
    base3 = service.scan(twice).findings
    part = FixService(service, Scripted("partial")).fix(twice, base3)
    assert part.applicable is False and "f2" in part.failure_reason                                                   # asked for f1 and f2; only one fixed: not confirmed for f2
    only_first = FixService(service, Scripted("partial")).fix(twice, base3, finding_ids=["f1"])
    assert only_first.applicable and only_first.verification.resolved_finding_ids == ("f1",)

    # a hardcoded secret is never sent to the corrector; asking only for it says why
    secret_code = [SourceFile("s.py", 'import os\npassword = "x"\n\ndef run(h):\n    os.system(h)\n')]
    base4 = service.scan(secret_code).findings
    assert [f.vulnerability_type for f in base4] == [SECRET_TYPE, "command_injection"]    # in file order: the secret is on line 2, the call on line 5
    with_secret = Scripted()
    mixed_secret = FixService(service, with_secret).fix(secret_code, base4)
    assert mixed_secret.applicable and [i for i in with_secret.seen[0][1]] == ["f2"] and mixed_secret.unfixed[0]["finding_id"] == "f1" and "rotate it" in mixed_secret.unfixed[0]["reason"]
    only_secret = FixService(service, Scripted()).fix(secret_code, base4, finding_ids=["f1"])
    assert not only_secret.applicable and only_secret.verification is None and "hardcoded secret" in only_secret.failure_reason and only_secret.unfixed[0]["finding_id"] == "f1"

    # selection: nothing at medium or above, unknown ids, and the defaults
    quiet = [SourceFile("q.py", "import hashlib\nhashlib.md5(b'x')\n")]
    base5 = service.scan(quiet).findings
    assert [f.severity.value for f in base5] == ["low"]
    nothing = FixService(service, Scripted()).fix(quiet, base5)
    assert not nothing.applicable and "no finding at medium severity or above" in nothing.failure_reason and nothing.patches == ()
    try:
        fix(Scripted(), finding_ids=["f9"])
        raise AssertionError("an unknown id must be refused")
    except ValueError as problem:
        assert "not in the scan" in str(problem)
    explicit_low = FixService(service, Scripted()).fix(quiet, base5, finding_ids=["f1"])                          # a low finding can be fixed when asked for by id
    assert explicit_low.patches == () and explicit_low.unfixed[0]["finding_id"] == "f1" and "does not apply to the file" in explicit_low.unfixed[0]["reason"]   # this corrector changes nothing there: an empty diff is refused

    # bounds: no more than 10 files and 10 findings per file go to the model
    many_files = [SourceFile(f"f{i}.py", "import os\n\ndef run(h):\n    os.system(h)\n") for i in range(12)]
    base6 = service.scan(many_files).findings
    seen_many = Scripted()
    result6 = FixService(service, seen_many).fix(many_files, base6)
    assert len(seen_many.seen) == MAX_FILES and sum("at most 10 files" in u["reason"] for u in result6.unfixed) == 2
    crowded = [SourceFile("c.py", "import os\n\n" + "".join(f"def r{i}(h):\n    os.system(h)\n\n" for i in range(13)))]
    base7 = service.scan(crowded).findings
    seen_crowded = Scripted("nothing")
    result7 = FixService(service, seen_crowded).fix(crowded, base7)
    assert len(seen_crowded.seen[0][1]) == MAX_FINDINGS_PER_FILE and sum("at most 10 findings per file" in u["reason"] for u in result7.unfixed) == 3

    # a re-scan that cannot run: inconclusive, and not applicable
    class Down:
        role, name, languages = "analyzer", "down", ("python",)

        def analyze(self, code, language):
            return AnalyzerResult(analyzer="down", error="engine unavailable")

    shaky = FixService(ScanService([Rules(), Down()], limits=Limits()), Scripted()).fix(one, base)
    assert not shaky.applicable and shaky.verification.outcome == "inconclusive" and "inconclusive" in shaky.failure_reason and len(shaky.patches) == 1

    print("core.fix_service OK: the returned diff is what is verified, applicable only when verification passes, every miss is listed with a reason, secrets are never sent, bounded")


if __name__ == "__main__":
    demo()
