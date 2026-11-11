"""
benchmark/fix_eval.py

Measures how good Astra's FIXES are on JavaScript and TypeScript: not only "did the service's four checks pass" (scope, syntax, size, re-scan), but also "does the fixed code still DO the same
thing". The service cannot see that second question today; this answers it on a set of known cases.

    python -m benchmark.fix_eval                       self-test with a scripted stand-in: no model, no key, no cost. Proves the checks and the behavior probes work.
    python -m benchmark.fix_eval --real                the real Astra on every case (about 11 requests, a few cents each) and a report in benchmark/results/
    python -m benchmark.fix_eval --real --only fx-js-sql-concat     one case
    python -m benchmark.fix_eval --real --repeat 3     each case three times (the model is not deterministic); rates are over all attempts

For each case: scan with the rules, ask the corrector, apply the edit, then check (1) the file still parses, (2) a re-scan no longer shows the finding, (3) no new medium-or-above finding, (4) the
change is within the size limit, and (5) BEHAVIOR: the original and the fixed code run in Node with the dangerous functions replaced by recorders (child_process, https, SQL, node-serialize),
fed a benign input, and the recorded events are compared. Needs Node on PATH (TypeScript runs with Node's own type stripping, Node 22.6 or newer).

Every answer ends in exactly one status:
  usable            all five checks passed
  behavior_changed  the service's four checks passed, but the fixed code behaves differently on a benign input   <- the number the service cannot see
  failed_checks     the file does not parse, the finding is still there, something new appeared, or the change is too large
  declined_ok       the model said it cannot fix this safely, on a case where that is the right answer (dynamic code)
  declined          the model gave no edit on a case that has a correct small fix
  unusable_answer   the answer could not be read as an edit at all
"""

from __future__ import annotations

import difflib
import json
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import date
from pathlib import Path
from types import SimpleNamespace

from benchmark.cases_fix_js import CASES
from benchmark.config_eval import wilson
from security_service.adapters.foundry_corrector import language_of
from security_service.adapters.js_rules import check_syntax as js_syntax
from security_service.core.files import SourceFile
from security_service.core.scan_service import ScanService
from security_service.core.schema import Severity
from security_service.ports.corrector import BadProposal, CorrectorError, FixConstraints
from tests.live_corrector import cost

MAX_CHANGED_LINES = 40            # the service's own limit (core/verification.py, default_max_patch_lines)
RESULTS = Path(__file__).parent / "results"

PRELUDE = r"""
const Module = require('module');
const events = [];
const flat = (f, a) => [f, ...(Array.isArray(a) ? a : [])].join(' ');
const cp = require('child_process');
cp.exec = (c) => { events.push(['cmd', String(c)]); return { on() {} }; };
cp.execSync = (c) => { events.push(['cmd', String(c)]); return Buffer.from(''); };
cp.execFile = (f, a) => { events.push(['cmd', flat(f, a)]); return { on() {} }; };
cp.execFileSync = (f, a) => { events.push(['cmd', flat(f, a)]); return Buffer.from(''); };
cp.spawn = (f, a) => { events.push(['cmd', flat(f, a)]); return { on() {}, stdout: { on() {} }, stderr: { on() {} } }; };
cp.spawnSync = (f, a) => { events.push(['cmd', flat(f, a)]); return { stdout: Buffer.from(''), status: 0 }; };
const https = require('https');
https.request = (o) => { events.push(['https', [o.hostname, o.path, o.method].join(' ')]); events.push(['tls_verified', o.rejectUnauthorized !== false]); return { on() {}, end() {}, write() {} }; };
const originalLoad = Module._load;
Module._load = function (request) { if (request === 'node-serialize') return { unserialize: (s) => JSON.parse(s) }; return originalLoad.apply(this, arguments); };
Module.syncBuiltinESMExports();
const norm = (sql, params = []) => { let i = 0; return String(sql).replace(/\$(\d+)|\?/g, (m, n) => String(params[n ? Number(n) - 1 : i++])).replace(/'/g, '').replace(/\s+/g, ' ').trim(); };
const db = { query: (sql, params) => { events.push(['sql', norm(sql, params)]); return []; } };
(async () => {
  const { pathToFileURL } = require('url');
  const imported = await import(pathToFileURL(process.argv[2]).href);
  const mod = imported.default && typeof imported.default === 'object' ? { ...imported.default, ...imported } : imported;
  await (async () => { PROBE_BODY })();
  console.log('@@EVENTS@@' + JSON.stringify(events));
})().catch((e) => { console.log('@@ERROR@@' + String((e && e.message) || e)); process.exit(3); });
"""


def node_path() -> str | None:
    return shutil.which("node")


def run_probe(case: dict, code: str) -> tuple[str, list | str]:
    """('ok', events) or ('error', message) or ('skipped', reason). The code runs in a temporary folder with the dangerous functions replaced by recorders."""
    node = node_path()
    if node is None:
        return "skipped", "Node is not on PATH"
    suffix = Path(case["path"]).suffix
    with tempfile.TemporaryDirectory(prefix="phylax-fix-") as folder:
        module, probe = Path(folder) / f"mod{suffix}", Path(folder) / "probe.cjs"
        module.write_text(code, encoding="utf-8")
        probe.write_text(PRELUDE.replace("PROBE_BODY", case["probe"]), encoding="utf-8")
        command = [node] + (["--experimental-strip-types", "--no-warnings"] if suffix == ".ts" else ["--no-warnings"]) + [str(probe), str(module)]
        try:
            done = subprocess.run(command, cwd=folder, capture_output=True, text=True, timeout=30)
        except subprocess.TimeoutExpired:
            return "error", "the code did not finish within 30 seconds"
    out = done.stdout
    if "bad option" in done.stderr and suffix == ".ts":
        return "skipped", "this Node cannot run TypeScript (needs 22.6 or newer)"
    for line in out.splitlines():
        if line.startswith("@@EVENTS@@"):
            return "ok", json.loads(line[len("@@EVENTS@@"):])
        if line.startswith("@@ERROR@@"):
            return "error", line[len("@@ERROR@@"):][:300]
    return "error", (done.stderr.strip().splitlines() or ["no output"])[-1][:300]


def same_behavior(case: dict, before: list, after: list) -> tuple[bool, str]:
    pick = lambda events, name: [e[1] for e in events if e[0] == name]
    for name in case["compare"]:
        if pick(before, name) != pick(after, name):
            return False, f"{name}: before {pick(before, name)!r}, after {pick(after, name)!r}"
    for name, wanted in case["expect_after"].items():
        got = pick(after, name)
        if not got or any(value != wanted for value in got):
            return False, f"{name}: expected {wanted!r}, got {got!r}"
    return True, ""


def changed_lines(before: str, after: str) -> int:
    ops = difflib.SequenceMatcher(None, before.splitlines(), after.splitlines()).get_opcodes()
    return sum(max(i2 - i1, j2 - j1) for tag, i1, i2, j1, j2 in ops if tag != "equal")


def run_case(case: dict, corrector, service: ScanService) -> dict:
    result = {"id": case["id"], "note": case["note"], "decline_ok": case["decline_ok"], "status": "", "failed": [], "behavior": "", "behavior_detail": "", "changed": 0,
              "seconds": 0.0, "prompt_tokens": 0, "completion_tokens": 0, "cost": 0.0, "diff": "", "model_said": ""}
    source = SourceFile(case["path"], case["code"])
    base = service.scan([source])
    findings = [f for f in base.findings if f.severity.rank >= Severity.MEDIUM.rank]
    assert any(f.rule_id == case["rule"] for f in findings), f"{case['id']}: the rules no longer flag {case['rule']}; the case is out of date"
    status, baseline = run_probe(case, case["code"])
    assert status in ("ok", "skipped"), f"{case['id']}: the ORIGINAL code does not run under the probe ({baseline}); the case is broken"

    started = time.monotonic()
    try:
        proposal = corrector.propose_detailed(source, findings, FixConstraints())
    except (BadProposal, CorrectorError) as problem:
        result.update(status="unusable_answer", model_said=f"{type(problem).__name__}: {problem}"[:300], seconds=round(time.monotonic() - started, 1))
        return result
    result["seconds"] = round(time.monotonic() - started, 1)
    reply = getattr(proposal, "reply", None)
    if reply is not None:
        result.update(prompt_tokens=reply.prompt_tokens, completion_tokens=reply.completion_tokens, cost=cost(reply.prompt_tokens, reply.completion_tokens))
    if not getattr(proposal, "fixed_code", None) or not proposal.patches:
        result.update(status="declined_ok" if case["decline_ok"] else "declined", model_said="; ".join(u.get("reason", "") for u in proposal.unfixed)[:300] or "no edit")
        return result

    fixed = proposal.fixed_code
    result["changed"] = changed_lines(case["code"], fixed)
    result["diff"] = "\n".join(list(difflib.unified_diff(case["code"].splitlines(), fixed.splitlines(), "before", "after", lineterm="", n=1))[:40])
    parse_problem = js_syntax(fixed, language_of(case["path"]))
    if parse_problem:
        result["failed"].append(f"does not parse ({parse_problem})")
    rescan = service.scan([SourceFile(case["path"], fixed)])
    after = {f.rule_id for f in rescan.findings if f.severity.rank >= Severity.MEDIUM.rank}
    before = {f.rule_id for f in findings}
    if before & after:
        result["failed"].append(f"the finding is still there ({', '.join(sorted(before & after))})")
    if after - before:
        result["failed"].append(f"something new at medium or above ({', '.join(sorted(after - before))})")
    if result["changed"] > MAX_CHANGED_LINES:
        result["failed"].append(f"the change is too large ({result['changed']} lines, limit {MAX_CHANGED_LINES})")
    if result["failed"]:
        result["status"] = "failed_checks"
        return result

    kind, after_events = run_probe(case, fixed)
    if kind == "skipped" or status == "skipped":
        result.update(behavior="skipped", behavior_detail=str(after_events if kind == "skipped" else baseline), status="usable")
    elif kind == "error":
        result.update(behavior="error", behavior_detail=f"the fixed code crashes under the probe: {after_events}", status="behavior_changed")
    else:
        same, why = same_behavior(case, baseline, after_events)
        result.update(behavior="same" if same else "different", behavior_detail=why, status="usable" if same else "behavior_changed")
    return result


def summarize(results: list[dict]) -> dict:
    count = lambda status, only=None: sum(r["status"] == status and (only is None or r["decline_ok"] == only) for r in results)
    fixable = [r for r in results if not r["decline_ok"]]
    usable_fixable = sum(r["status"] == "usable" for r in fixable)
    return {
        "attempts": len(results), "fixable_attempts": len(fixable), "usable_fixable": usable_fixable, "usable_interval": wilson(usable_fixable, len(fixable)),
        "behavior_changed": count("behavior_changed"), "failed_checks": count("failed_checks"), "declined": count("declined"), "unusable_answer": count("unusable_answer"),
        "dynamic_attempts": sum(r["decline_ok"] for r in results), "dynamic_declined_ok": count("declined_ok", True), "dynamic_usable": count("usable", True),
        "behavior_skipped": sum(r["behavior"] == "skipped" for r in results), "cost": round(sum(r["cost"] for r in results), 4), "seconds": round(sum(r["seconds"] for r in results), 1),
        "prompt_tokens": sum(r["prompt_tokens"] for r in results), "completion_tokens": sum(r["completion_tokens"] for r in results),
    }


def render(results: list[dict], summary: dict, meta: dict) -> str:
    lo, hi = summary["usable_interval"]
    out = [f"# Fix quality on JavaScript and TypeScript: {meta['when']}", "",
           f"- Corrector: {meta['corrector']}", f"- Cases: {len({r['id'] for r in results})} (8 JavaScript, 3 TypeScript), {summary['attempts']} attempt(s)", "",
           "## Result", "",
           f"- **Usable fixes on the {summary['fixable_attempts']} attempts that have a correct small fix: {summary['usable_fixable']}** (Wilson 95%: {lo:.0%} to {hi:.0%})",
           f"- **Passed the service's four checks but changed behavior: {summary['behavior_changed']}**: the failure the service cannot see today",
           f"- Failed the service's own checks: {summary['failed_checks']}; declined where a fix exists: {summary['declined']}; unreadable answers: {summary['unusable_answer']}",
           f"- Dynamic-code cases ({summary['dynamic_attempts']} attempts, declining is correct there): declined {summary['dynamic_declined_ok']}, gave a usable edit {summary['dynamic_usable']}",
           f"- Behavior check skipped (no Node or no TypeScript support): {summary['behavior_skipped']}",
           f"- Cost about ${summary['cost']:.4f}, {summary['prompt_tokens']} tokens in, {summary['completion_tokens']} out (thinking included), {summary['seconds']} s of model time", "",
           "## Per case", "", "| case | status | changed lines | behavior | s | what failed or what the model said |", "|---|---|---|---|---|---|"]
    for r in results:
        detail = "; ".join(r["failed"]) or r["behavior_detail"] or r["model_said"] or ""
        out.append(f"| `{r['id']}` | {r['status']} | {r['changed'] or ''} | {r['behavior'] or ''} | {r['seconds']} | {detail.replace('|', '/')[:160]} |")
    out += ["", "## The edits, to read with your own eyes", ""]
    for r in results:
        if r["diff"]:
            out += [f"### `{r['id']}`: {r['status']}", "", "```diff", r["diff"], "```", ""]
    out += ["## Limits of this measurement", "",
            "- These are DEVELOPMENT cases written by the author of the prompt. Nothing here is held out, and the correction prompt may be tuned after reading this. A tuned prompt needs new cases to be judged.",
            f"- {len(CASES)} cases, small and single-function. Fixes in large files, across several functions or across files are not measured. The intervals are wide.",
            "- The behavior check runs ONE benign input per case with the dangerous functions replaced by recorders. It catches a fix that drops an argument or changes what is called; it does not prove equivalence on every input.",
            "- The model is not deterministic. One attempt per case is a sample, not a rate; use --repeat 3 for a steadier picture.",
            "- Only fixes the rules flagged at medium or above are asked for. Low findings and hardcoded secrets are never corrected."]
    return "\n".join(out) + "\n"


class ScriptedCorrector:
    """A stand-in that answers from a script, for the self-test: no model, no key."""

    def __init__(self, modes: dict[str, str]):
        self.modes = modes

    def propose_detailed(self, file, findings, constraints):
        case = next(c for c in CASES if c["path"] == file.path)
        mode = self.modes.get(case["id"], "good")
        if mode == "error":
            raise BadProposal("the stand-in produced an unreadable answer")
        if mode == "decline" or (mode == "good" and case["good"] is None):
            return SimpleNamespace(fixed_code=None, patches=[], unfixed=[{"finding_id": findings[0].id, "reason": "cannot be fixed safely by a small edit"}], reply=None)
        base = case["good"] or case["bad"]
        code = {"good": case["good"], "bad": case["bad"], "unchanged": case["code"], "unparsable": base + "\n{{{ (\n",
                "huge": base + "".join(f"// padding line {i}\n" for i in range(50)),
                "introduces": base + '\nconst { exec: unsafeRun } = require("child_process");\nfunction extraCommand(arg) {\n  unsafeRun("echo " + arg);\n}\n'}[mode]
        return SimpleNamespace(fixed_code=code, patches=[object()], unfixed=[], reply=None)


def selftest() -> None:
    assert node_path(), "Node must be on PATH: the behavior check needs it"
    service = ScanService()
    run = lambda mode: {c["id"]: run_case(c, ScriptedCorrector({k["id"]: mode for k in CASES}), service) for c in CASES}

    good = run("good")
    for case in CASES:
        got = good[case["id"]]
        want = "declined_ok" if case["good"] is None else "usable"
        assert got["status"] == want, (case["id"], got["status"], got["failed"], got["behavior_detail"])
        if want == "usable":
            assert got["behavior"] == "same" and 0 < got["changed"] <= MAX_CHANGED_LINES, (case["id"], got)
    bad = run("bad")
    for case in CASES:                                         # a wrong fix passes the service's four checks and is caught ONLY by the behavior probe
        got = bad[case["id"]]
        assert got["status"] == "behavior_changed" and got["behavior"] in ("different", "error"), (case["id"], got["status"], got["failed"], got["behavior_detail"])
    unchanged = run("unchanged")
    assert all(unchanged[c["id"]]["status"] == "failed_checks" and any("still there" in f for f in unchanged[c["id"]]["failed"]) for c in CASES)
    unparsable = run("unparsable")
    assert all(unparsable[c["id"]]["status"] == "failed_checks" and any("does not parse" in f for f in unparsable[c["id"]]["failed"]) for c in CASES if c["good"] or c["bad"])
    declined = run("decline")
    assert [declined[c["id"]]["status"] for c in CASES] == ["declined_ok" if c["decline_ok"] else "declined" for c in CASES]
    assert all(r["status"] == "unusable_answer" for r in run("error").values())

    # an edit that is too large, and an edit that fixes the finding but introduces a new one (a different rule), are both failures of the service's own checks
    huge = run("huge")
    assert all(huge[c["id"]]["status"] == "failed_checks" and any("too large" in f for f in huge[c["id"]]["failed"]) for c in CASES if c["good"] or c["bad"])
    introduces = run("introduces")
    for case in CASES:
        got = introduces[case["id"]]
        if case["rule"] != "JS-EXEC":
            assert got["status"] == "failed_checks" and any("something new" in f and "JS-EXEC" in f for f in got["failed"]), (case["id"], got["status"], got["failed"])

    # a case whose ORIGINAL code does not run under the probe is a broken case, and the harness refuses to measure it instead of blaming the model
    broken = {**CASES[0], "probe": 'throw new Error("this probe is broken");'}
    try:
        run_case(broken, ScriptedCorrector({}), service)
        raise AssertionError("a broken case was measured")
    except AssertionError as refusal:
        assert "ORIGINAL code does not run" in str(refusal)

    # the probes really compare what they claim to: a fix that keeps the call but changes its argument, and one that only looks equivalent
    sql = next(c for c in CASES if c["id"] == "fx-js-sql-concat")
    ok_events = run_probe(sql, sql["good"])[1]
    assert same_behavior(sql, run_probe(sql, sql["code"])[1], ok_events) == (True, "")
    assert same_behavior(sql, [["sql", "a"]], [["sql", "b"]])[0] is False
    tls = next(c for c in CASES if c["id"] == "fx-js-tls-off")
    assert same_behavior(tls, [["https", "x"]], [["https", "x"], ["tls_verified", False]])[0] is False       # verification still off after the fix: caught by expect_after
    assert changed_lines("a\nb\nc\n", "a\nB\nc\nd\n") == 1 + 1 and changed_lines("a\n", "a\n") == 0

    summary = summarize(list(good.values()) + list(bad.values()))
    assert summary["attempts"] == 22 and summary["fixable_attempts"] == 18 and summary["usable_fixable"] == 9 and summary["behavior_changed"] == 11 - 0, summary
    lo, hi = summary["usable_interval"]
    assert 0.0 < lo < 0.5 < hi < 1.0
    text = render(list(good.values()), summarize(list(good.values())), {"when": "self-test", "corrector": "scripted stand-in"})
    assert "DEVELOPMENT cases" in text and "changed behavior" in text and "```diff" in text
    print("fix_eval OK: known-good fixes are usable and behave the same, known-bad fixes pass the four checks and are caught by behavior, unchanged and unparsable fixes fail, "
          "declines are scored right on both kinds of case, unreadable answers are counted, in 11 cases (8 JavaScript, 3 TypeScript)")


def real_corrector(settings):
    from security_service.adapters.foundry_chat import FoundryChat
    from security_service.adapters.foundry_corrector import FoundryCorrector

    chat = FoundryChat(settings.corrector_deployment, settings.corrector_resolved_endpoint, settings.corrector_resolved_key, route=settings.corrector_api,
                       reasoning_effort=settings.corrector_reasoning_effort, max_output_tokens=settings.corrector_max_output_tokens, timeout=settings.corrector_timeout)
    return FoundryCorrector(chat), chat.deployment


def main(argv: list[str]) -> int:
    selftest()
    if "--real" not in argv:
        return 0
    import os

    from security_service.config import Settings, load_env_file

    load_env_file()
    settings = Settings.from_env(os.environ)
    print("\n" + settings.describe_corrector())
    if settings.corrector_problems():
        print("The corrector is not ready. Add the missing setting to .env (see .env.example), then run this again.")
        return 2
    corrector, deployment = real_corrector(settings)
    only = argv[argv.index("--only") + 1] if "--only" in argv else None
    repeat = int(argv[argv.index("--repeat") + 1]) if "--repeat" in argv else 1
    cases = [c for c in CASES if only in (None, c["id"])]
    if not cases:
        print(f"No case called {only!r}. Choose from: {', '.join(c['id'] for c in CASES)}")
        return 2
    service, results = ScanService(), []
    for case in cases:
        for attempt in range(repeat):
            result = run_case(case, corrector, service)
            results.append(result)
            print(f"{case['id']:26} attempt {attempt + 1}: {result['status']:17} {('; '.join(result['failed']) or result['behavior_detail'] or result['model_said'])[:90]}")
    summary = summarize(results)
    text = render(results, summary, {"when": date.today().isoformat(), "corrector": f"{deployment} (route {settings.corrector_api}, effort {settings.corrector_reasoning_effort})"})
    RESULTS.mkdir(exist_ok=True)
    target = RESULTS / f"fix_eval_{date.today().isoformat()}.md"
    target.write_text(text, encoding="utf-8")
    print(f"\n{summary['usable_fixable']} of {summary['fixable_attempts']} usable, {summary['behavior_changed']} passed the four checks but changed behavior, cost about ${summary['cost']:.3f}.")
    print(f"Report written to {target.relative_to(Path(__file__).parent.parent)}. Send me that file.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
