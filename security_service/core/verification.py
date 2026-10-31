"""
security_service/core/verification.py

Is a corrected version of the code safe to offer? This is the check that stands between a model's proposal and a person's
approval. It judges a corrected file set against the original scan and never trusts who wrote the correction (Astra, a person, a
script): the same checks apply to all.

The four checks of the contract (openapi.yaml, VerificationCheck):
  scope       only files that were in the scan changed, and something did change.
  syntax      every changed Python file parses, and the change introduced no UNDEFINED NAME. The second half matters: deleting an
              import that other code still uses parses fine and passes a re-scan, then crashes when it runs. Names that were already
              undefined before the change are not blamed on it. A file with `from x import *` cannot be judged this way and says so.
  patch_size  added plus removed lines, over all files, within the limit.
  rescan      the changed files are scanned again with the same engines. Every requested finding must be gone (counted per file and
              problem type, because lines shift), and nothing NEW may appear that a rule backs at medium severity or above. A new
              finding that only a model suspects is listed in `new_findings` for review but does not fail the check: a model alone
              never blocks, and a noisy model must not make good fixes look bad.

Outcome: failed if any check failed; inconclusive if the re-scan could not run (an engine was down: never treat as passed);
otherwise passed. Only `passed` can make a fix applicable.
"""

from __future__ import annotations

import ast
import builtins
import symtable
from dataclasses import dataclass, replace
from typing import Iterable

from security_service.core.files import SourceFile
from security_service.core.patching import changed_line_count, make_unified_diff
from security_service.core.schema import EvidenceTier, Finding, Severity

_MODULE_NAMES = {"__file__", "__name__", "__doc__", "__package__", "__spec__", "__loader__", "__builtins__", "__path__",
                 "__class__", "__annotations__", "__module__", "__qualname__", "__debug__"}
_KNOWN = set(dir(builtins)) | _MODULE_NAMES
MEDIUM = Severity.MEDIUM.rank


def undefined_names(code: str) -> set[str] | None:
    """Names the code uses that nothing in it defines (and that are not builtins), or None when that cannot be judged (the code does
    not parse, or has `from x import *`). Conservative on purpose: it is used to compare a file with its corrected self."""
    try:
        tree = ast.parse(code)
        top = symtable.symtable(code, "<code>", "exec")
    except (SyntaxError, ValueError, RecursionError):
        return None
    if any(isinstance(node, ast.ImportFrom) and any(alias.name == "*" for alias in node.names) for node in ast.walk(tree)):
        return None

    defined = {s.get_name() for s in top.get_symbols() if s.is_assigned() or s.is_imported() or s.is_namespace() or s.is_parameter()}

    def tables(table):
        yield table
        for child in table.get_children():
            yield from tables(child)

    for table in tables(top):                              # `global x` followed by an assignment defines x for the whole module
        for symbol in table.get_symbols():
            if symbol.is_declared_global():
                defined.add(symbol.get_name())

    missing: set[str] = set()
    for table in tables(top):
        for symbol in table.get_symbols():
            name = symbol.get_name()
            if not symbol.is_referenced() or name in _KNOWN or name in defined:
                continue
            if table is top:
                if not (symbol.is_assigned() or symbol.is_imported() or symbol.is_namespace()):
                    missing.add(name)
            elif symbol.is_global():
                missing.add(name)
    return missing


@dataclass(frozen=True)
class Check:
    name: str                  # scope | syntax | patch_size | rescan
    result: str                # pass | fail | skipped
    detail: str

    def to_dict(self) -> dict[str, str]:
        return {"name": self.name, "result": self.result, "detail": self.detail}


@dataclass(frozen=True)
class VerificationResult:
    outcome: str                                   # passed | failed | inconclusive
    checks: tuple[Check, ...]
    new_findings: tuple[Finding, ...] = ()
    resolved_finding_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {"outcome": self.outcome, "checks": [c.to_dict() for c in self.checks],
                "new_findings": [f.to_dict() for f in self.new_findings], "resolved_finding_ids": list(self.resolved_finding_ids)}


def _norm(path: str) -> str:
    return path.replace("\\", "/").removeprefix("./")


def _key(finding: Finding) -> tuple[str, str]:
    return (_norm(finding.path or ""), finding.vulnerability_type)


def _is_python(path: str) -> bool:
    return path.lower().endswith((".py", ".pyi", ".pyw"))


class VerificationService:
    def __init__(self, scan_service, default_max_patch_lines: int = 40):
        self._scan = scan_service
        self._default_limit = default_max_patch_lines

    def verify(self, originals: list[SourceFile], corrected: list[SourceFile], baseline: Iterable[Finding],
               requested_ids: list[str] | None = None, max_patch_lines: int | None = None) -> VerificationResult:
        limit = max_patch_lines or self._default_limit
        before_files = {_norm(f.path): f for f in originals}
        baseline = [f for f in baseline]
        known_ids = {f.id for f in baseline}
        if requested_ids is not None:
            unknown = [i for i in requested_ids if i not in known_ids]
            if unknown:
                raise ValueError(f"{len(unknown)} requested finding id(s) are not in the original scan")

        # ---- scope: only files of the scan, and something really changed
        strangers = sorted({_norm(c.path) for c in corrected if _norm(c.path) not in before_files})
        changed = [SourceFile(_norm(c.path), c.content) for c in corrected
                   if _norm(c.path) in before_files and c.content != before_files[_norm(c.path)].content]
        if strangers:
            scope = Check("scope", "fail", f"{len(strangers)} corrected file(s) were not in the original scan: {', '.join(strangers[:5])}.")
        elif not changed:
            scope = Check("scope", "fail", "No corrected file differs from the original, so nothing was fixed.")
        else:
            scope = Check("scope", "pass", f"{len(changed)} file(s) changed, all of them part of the original scan.")
        checks = [scope]

        # ---- syntax: parses, and no new undefined names
        python = [c for c in changed if _is_python(c.path)]
        if not python:
            checks.append(Check("syntax", "skipped", "No changed file is Python, so there is nothing to parse."))
        else:
            problems, notes = [], []
            for c in python:
                try:
                    ast.parse(c.content)
                except SyntaxError as error:
                    problems.append(f"{c.path} does not parse ({error.msg} at line {error.lineno})")
                    continue
                before, after = undefined_names(before_files[c.path].content), undefined_names(c.content)
                if before is None or after is None:
                    notes.append(f"{c.path}: undefined names could not be checked (a star import)")
                elif after - before:
                    problems.append(f"{c.path} uses names nothing defines after the change: {', '.join(sorted(after - before)[:6])}")
            if problems:
                checks.append(Check("syntax", "fail", "; ".join(problems) + "."))
            else:
                checks.append(Check("syntax", "pass", f"{len(python)} changed Python file(s) parse and use no new undefined name" + (f" ({'; '.join(notes)})." if notes else ".")))

        # ---- patch size
        lines = sum(changed_line_count(make_unified_diff(c.path, before_files[c.path].content, c.content)) for c in changed)
        checks.append(Check("patch_size", "pass" if lines <= limit else "fail", f"{lines} changed line(s), limit {limit}."))

        # ---- rescan: requested findings gone, nothing new that a rule backs
        changed_paths = {c.path for c in changed}
        in_changed = [f for f in baseline if _norm(f.path or "") in changed_paths and f.severity.rank >= MEDIUM]
        wanted = [f for f in baseline if f.id in requested_ids] if requested_ids is not None else in_changed
        resolved: list[str] = []
        new_findings: list[Finding] = []
        if not changed:
            checks.append(Check("rescan", "skipped", "There is nothing to scan again because no file changed."))
        else:
            report = self._scan.scan(changed)
            failed_engines = dict(report.coverage.analyzers_failed)
            if failed_engines or report.status != "completed":
                names = ", ".join(sorted({k.split("@", 1)[0] for k in failed_engines})) or "the scanner"
                checks.append(Check("rescan", "skipped", f"The corrected code could not be scanned again ({names} failed), so the fix is not confirmed."))
            else:
                count_before: dict[tuple[str, str], list[Finding]] = {}
                for f in in_changed:
                    count_before.setdefault(_key(f), []).append(f)
                count_after: dict[tuple[str, str], list[Finding]] = {}
                for f in report.findings:
                    if f.severity.rank >= MEDIUM:
                        count_after.setdefault(_key(f), []).append(f)
                resolved_set: set[str] = set()
                for key, olds in count_before.items():
                    fewer = len(olds) - len(count_after.get(key, []))
                    for f in sorted(olds, key=lambda f: (f.line or 0, f.id))[:max(0, fewer)]:
                        resolved_set.add(f.id)
                resolved = sorted((i for i in resolved_set), key=lambda i: (len(i), i))
                unresolved = [f for f in wanted if f.id not in resolved_set]
                rule_backed_new = 0
                for key, news in count_after.items():
                    extra = len(news) - len(count_before.get(key, []))
                    if extra > 0:
                        for f in sorted(news, key=lambda f: (f.line or 0))[-extra:]:
                            new_findings.append(f)
                            rule_backed_new += f.evidence_tier != EvidenceTier.MODEL_SUSPICION
                new_findings = [replace(f, id=f"n{i}") for i, f in enumerate(new_findings, start=1)]
                model_only = len(new_findings) - rule_backed_new
                if unresolved:
                    listed = "; ".join(f"{f.id} ({f.vulnerability_type} in {f.path})" for f in unresolved[:4])
                    checks.append(Check("rescan", "fail", f"Still present after the change: {listed}."))
                elif rule_backed_new:
                    checks.append(Check("rescan", "fail", f"{rule_backed_new} new finding(s) at medium severity or above appeared, backed by a rule."))
                else:
                    note = f" {model_only} new model-only suspicion(s) are listed for review; a model alone does not fail this check." if model_only else ""
                    checks.append(Check("rescan", "pass", f"{len(wanted)} requested finding(s) are gone and nothing new backed by a rule appeared.{note}"))
        failed = any(c.result == "fail" for c in checks)
        rescan_skipped_for_engines = any(c.name == "rescan" and c.result == "skipped" and "could not be scanned again" in c.detail for c in checks)
        outcome = "failed" if failed else ("inconclusive" if rescan_skipped_for_engines else "passed")
        return VerificationResult(outcome, tuple(checks), tuple(new_findings), tuple(resolved))


def demo() -> None:
    import re

    from security_service.core.files import Limits
    from security_service.core.scan_service import ScanService
    from security_service.core.schema import Confidence
    from security_service.ports.analyzer import AnalyzerResult

    # ---------------------------------------------------------------- undefined names
    assert undefined_names("x = 1\nprint(x)\n") == set() and undefined_names("print(y)\n") == {"y"}
    assert undefined_names("import os\nos.getcwd()\n") == set() and undefined_names("os.getcwd()\n") == {"os"}
    assert undefined_names("def f():\n    return os.name\n") == {"os"} and undefined_names("import os\ndef f():\n    return os.name\n") == set()
    assert undefined_names("def f(a, *b, **c):\n    return a, b, c, len(b)\n") == set()
    assert undefined_names("class A:\n    x = 1\n    y = x\n    def m(self):\n        return A, self.x, __class__\n") == set()
    assert undefined_names("try:\n    import json\nexcept ImportError:\n    json = None\nprint(json)\n") == set()
    assert undefined_names("def f():\n    global G\n    G = 1\ndef g():\n    return G\n") == set()
    assert undefined_names("print([i for i in range(3)], (lambda q: q + 1)(2), __name__, __file__)\n") == set()
    assert undefined_names("def f():\n    return [z for z in zs]\n") == {"zs"}
    assert undefined_names("@deco\ndef f(): pass\n") == {"deco"} and undefined_names("with open('f') as fh:\n    fh.read()\n") == set()
    assert undefined_names("from os import *\nprint(path)\n") is None and undefined_names("def (:\n") is None

    # ---------------------------------------------------------------- the verifier, with scripted engines
    patterns = [(r"os\.system\(", "command_injection", Severity.HIGH, "B605"), (r"\beval\(", "code_injection", Severity.MEDIUM, "B307"),
                (r"shell=True", "command_injection", Severity.HIGH, "B602"), (r"hashlib\.md5", "weak_crypto", Severity.LOW, "B324")]

    class Rules:
        role, name, languages = "analyzer", "rules", ("python",)

        def analyze(self, code, language):
            found = []
            for number, line in enumerate(code.split("\n"), start=1):
                for regex, kind, severity, rule in patterns:
                    if re.search(regex, line):
                        found.append(Finding(kind, severity, Confidence.HIGH, EvidenceTier.STATIC_RULE, ["rules"], rule, None, number, line.strip(), f"{kind} here", "fix it"))
            return AnalyzerResult(analyzer="rules", findings=found)

    class Model:
        """A scripted decision model: suspects path traversal in any file that calls open()."""
        role, name, languages = "classifier", "model", ("python",)

        def analyze(self, code, language):
            hit = "open(" in code
            return AnalyzerResult(analyzer="model", findings=[Finding("path_traversal", Severity.MEDIUM, Confidence.MEDIUM, EvidenceTier.MODEL_SUSPICION, ["model"],
                                                                      "MODEL-path_traversal", None, None, "whole file", "model suspects it", "check it")] if hit else [])

    class Down:
        role, name, languages = "analyzer", "broken-engine", ("python",)

        def analyze(self, code, language):
            return AnalyzerResult(analyzer="broken-engine", error="engine unavailable")

    original = 'import os\n\ndef ping(host):\n    os.system("ping " + host)\n    return True\n\ndef cwd():\n    return os.getcwd()\n'
    good = 'import os\nimport subprocess\n\ndef ping(host):\n    subprocess.run(["ping", host], check=True)\n    return True\n\ndef cwd():\n    return os.getcwd()\n'
    service = ScanService([Rules()], limits=Limits())
    baseline = service.scan([SourceFile("net.py", original)]).findings
    assert [(f.id, f.path, f.vulnerability_type, f.line) for f in baseline] == [("f1", "net.py", "command_injection", 4)]
    verifier = VerificationService(service)

    def verify(corrected, files=None, **kw):
        return verifier.verify(files or [SourceFile("net.py", original)], corrected, baseline, **kw)

    def status(result):
        return {c.name: c.result for c in result.checks}

    # a good fix passes every check, resolves the finding, and reports nothing new
    ok = verify([SourceFile("net.py", good)])
    assert ok.outcome == "passed" and status(ok) == {"scope": "pass", "syntax": "pass", "patch_size": "pass", "rescan": "pass"}
    assert ok.resolved_finding_ids == ("f1",) and ok.new_findings == () and "3 changed line(s), limit 40." in ok.checks[2].detail
    assert ok.to_dict()["checks"][0] == {"name": "scope", "result": "pass", "detail": "1 file(s) changed, all of them part of the original scan."}

    def failed(result, name, needle):
        assert result.outcome == "failed" and status(result)[name] == "fail", (result.outcome, result.checks)
        detail = next(c.detail for c in result.checks if c.name == name)
        assert needle in detail, (needle, detail)
        assert "ping" not in detail or name == "rescan", detail
        return result

    failed(verify([SourceFile("net.py", original)]), "scope", "nothing was fixed")                                # unchanged
    failed(verify([SourceFile("other.py", good)]), "scope", "not in the original scan")                            # a file the scan never had
    failed(verify([SourceFile("net.py", good.replace("check=True)", "check=True"))]), "syntax", "does not parse")  # broken syntax
    failed(verify([SourceFile("net.py", good.replace("import os\n", ""))]), "syntax", "names nothing defines after the change: os")  # removed an import still in use
    failed(verify([SourceFile("net.py", original.replace("return True", "return True  # still unsafe"))]), "rescan", "f1 (command_injection in net.py)")   # the problem is still there
    swapped = verify([SourceFile("net.py", good.replace('subprocess.run(["ping", host], check=True)', 'eval("ping " + host)'))])
    failed(swapped, "rescan", "1 new finding(s)")
    assert swapped.resolved_finding_ids == ("f1",) and [(f.id, f.vulnerability_type) for f in swapped.new_findings] == [("n1", "code_injection")]      # f1 gone, but a new problem came in
    failed(verify([SourceFile("net.py", good)], max_patch_lines=2), "patch_size", "3 changed line(s), limit 2")
    assert status(verify([SourceFile("net.py", good)], max_patch_lines=3))["patch_size"] == "pass"                # the limit is inclusive

    # a name that was ALREADY undefined is not blamed on the change; a star import cannot be judged and says so
    broken_before = original.replace("return os.getcwd()", "return missing_name()")
    base2 = ScanService([Rules()]).scan([SourceFile("net.py", broken_before)]).findings
    fixed2 = broken_before.replace('os.system("ping " + host)', 'print(host)')
    result2 = verifier.verify([SourceFile("net.py", broken_before)], [SourceFile("net.py", fixed2)], base2)
    assert result2.outcome == "passed" and status(result2)["syntax"] == "pass"
    star = original.replace("import os", "import os\nfrom math import *")
    base3 = ScanService([Rules()]).scan([SourceFile("net.py", star)]).findings
    result3 = verifier.verify([SourceFile("net.py", star)], [SourceFile("net.py", star.replace('os.system("ping " + host)', "print(host)"))], base3)
    assert result3.outcome == "passed" and "star import" in next(c.detail for c in result3.checks if c.name == "syntax")

    # an engine that is down makes the outcome INCONCLUSIVE, never passed
    unwell = VerificationService(ScanService([Rules(), Down()], limits=Limits()))
    inconclusive = unwell.verify([SourceFile("net.py", original)], [SourceFile("net.py", good)], baseline)
    assert inconclusive.outcome == "inconclusive" and status(inconclusive)["rescan"] == "skipped" and "broken-engine failed" in inconclusive.checks[-1].detail
    assert unwell.verify([SourceFile("net.py", original)], [SourceFile("net.py", good.replace("check=True)", "check=True"))], baseline).outcome == "failed"   # a failure still beats inconclusive

    # a model's new suspicion is listed for review but does not fail the check; a model's old suspicion must be gone for the fix to count
    with_model = ScanService([Rules(), Model()], limits=Limits())
    plain = 'import os\n\ndef ping(host):\n    os.system("ping " + host)\n    return True\n'
    base4 = with_model.scan([SourceFile("net.py", plain)]).findings
    assert [(f.vulnerability_type, f.evidence_tier.value) for f in base4] == [("command_injection", "static_rule")]
    opens = good.replace("def cwd():\n    return os.getcwd()\n", "def cwd():\n    return open('x').read()\n").replace("import os\n", "")
    noisy = VerificationService(with_model).verify([SourceFile("net.py", plain)], [SourceFile("net.py", opens)], base4)
    assert noisy.outcome == "passed" and [f.vulnerability_type for f in noisy.new_findings] == ["path_traversal"] and "listed for review" in noisy.checks[-1].detail
    path_flag = ScanService([Model()]).scan([SourceFile("up.py", "def r(n):\n    return open(n).read()\n")]).findings
    still = VerificationService(ScanService([Model()])).verify([SourceFile("up.py", "def r(n):\n    return open(n).read()\n")], [SourceFile("up.py", "def r(n):\n    return open(n).read()  # checked\n")], path_flag)
    failed(still, "rescan", "path_traversal in up.py")                                                           # the model still suspects it: not confirmed
    cured = VerificationService(ScanService([Model()])).verify([SourceFile("up.py", "def r(n):\n    return open(n).read()\n")], [SourceFile("up.py", "def r(n):\n    return n\n")], path_flag)
    assert cured.outcome == "passed" and cured.resolved_finding_ids == ("f1",)

    # requested findings: only those must be gone; unknown ids are an error; a finding in an unchanged file cannot be resolved
    two = "import os\n\ndef a(h):\n    os.system(h)\n\ndef b(h):\n    os.system(h)\n"
    base5 = ScanService([Rules()]).scan([SourceFile("m.py", two)]).findings
    assert [f.id for f in base5] == ["f1", "f2"]
    one_fixed = two.replace("def a(h):\n    os.system(h)\n", "def a(h):\n    print(h)\n")
    only_first = verifier.verify([SourceFile("m.py", two)], [SourceFile("m.py", one_fixed)], base5, requested_ids=["f1"])
    assert only_first.outcome == "passed" and only_first.resolved_finding_ids == ("f1",)                          # f2 was not asked about, and is still there
    both = verifier.verify([SourceFile("m.py", two)], [SourceFile("m.py", one_fixed)], base5)                      # by default every medium-or-above finding in changed files
    failed(both, "rescan", "f2 (command_injection in m.py)")
    try:
        verifier.verify([SourceFile("m.py", two)], [SourceFile("m.py", one_fixed)], base5, requested_ids=["f9"])
        raise AssertionError("an unknown id must be refused")
    except ValueError as problem:
        assert "not in the original scan" in str(problem)
    far = verifier.verify([SourceFile("m.py", two), SourceFile("z.py", "x = 1\n")], [SourceFile("z.py", "x = 2\n")], base5, requested_ids=["f1"])
    failed(far, "rescan", "f1 (command_injection in m.py)")                                                       # asked to fix f1, but only z.py changed

    # two files, both fixed
    multi_before = [SourceFile("m.py", two), SourceFile("n.py", original)]
    base6 = ScanService([Rules()]).scan(multi_before).findings
    multi = verifier.verify(multi_before, [SourceFile("m.py", two.replace("os.system(h)", "print(h)")), SourceFile("n.py", good)], base6)
    assert multi.outcome == "passed" and len(multi.resolved_finding_ids) == 3 and multi.new_findings == ()

    # backslashes and ./ in paths are the same file
    same = verifier.verify([SourceFile("net.py", original)], [SourceFile(".\\net.py", good)], baseline)
    assert same.outcome == "passed"

    print("core.verification OK: scope, syntax with undefined names, patch size, rescan; failed vs inconclusive vs passed; model-only noise listed but not failing")


if __name__ == "__main__":
    demo()
