"""
benchmark/bakeoff.py

Compares models on the SAME benchmark cases, with the same prompt, parser,
evidence check and decision policy, so the only thing that differs is the
model. "rules only" (Bandit plus the secrets check) is always the first row, as the reference point.

Run from the repo root.

  Self-test (no credentials, no network; needs only Bandit). It uses an
  oracle and a noisy scripted model to prove the harness math is right:
      python -m benchmark.bakeoff

  Real comparison of Foundry deployments. Needs FOUNDRY_ENDPOINT and FOUNDRY_API_KEY in the
  environment and the optional azure-ai-inference package; each argument is a deployment name:
      python -m benchmark.bakeoff gpt-6-sol gpt-6-luna MAI-Thinking-1
      python -m benchmark.bakeoff gpt-6-sol --limit 10     (quick smoke test)
      python -m benchmark.bakeoff gpt-6-sol --runs 3 --agree 2

Other vendors: wrap their SDK in llm_client.CallableLLM and pass it to
run_bakeoff({...}) from a small script. Check each vendor's data terms first.

Columns:
  found / alarmed   vulnerable cases flagged with the right category / that
                    ended in REVIEW_REQUIRED or BLOCK (higher is better)
  false alarms      safe cases that ended in REVIEW_REQUIRED or BLOCK (lower is better)
  failed            scans that could not complete (model errors)
  halluc.           share of the model's proposed findings dropped because the
                    quoted line was not in the code (lower is better)
  avg s / p95 s     seconds per model call

If a reasoning model returns "empty content", it likely spent its token
budget thinking; that shows up here as failed scans.
"""

from __future__ import annotations

import re
import sys
from typing import Callable

from security_service.adapters.bandit import BanditAnalyzer
from security_service.adapters.secrets import SecretsAnalyzer
from security_service.adapters.llm_detector import LLMDetector
from benchmark.cases_python import CASES
from benchmark.run_benchmark import run, score
from security_service.adapters.foundry_llm import FoundryLLM
from security_service.adapters.llm_clients import CallableLLM
from security_service.ports.llm import LLMClient
from security_service.core.scan_service import ScanService


def _pct(n: int, d: int) -> str:
    return f"{n}/{d}"


def _p95(values: list[int]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[int(0.95 * (len(ordered) - 1))] / 1000


def run_bakeoff(
    candidates: dict[str, Callable[[], LLMClient]],
    runs: int = 1,
    min_agreement: int = 1,
    cases: list[dict] | None = None,
    out: Callable[[str], None] = print,
) -> dict[str, dict]:
    cases = cases or CASES
    results: dict[str, dict] = {}

    base = score(run(ScanService([BanditAnalyzer(), SecretsAnalyzer()]), cases))
    results["rules only"] = {**base, "halluc": None, "avg_s": None, "p95_s": None, "error": None}

    for label, make_llm in candidates.items():
        detector = LLMDetector(make_llm(), runs=runs, min_agreement=min_agreement)
        totals = score(run(ScanService([BanditAnalyzer(), SecretsAnalyzer(), detector]), cases))
        proposed = detector.totals["proposed"]
        results[label] = {
            **totals,
            "halluc": (detector.totals["dropped_bad_evidence"] / proposed) if proposed else None,
            "avg_s": (sum(detector.latencies_ms) / len(detector.latencies_ms) / 1000) if detector.latencies_ms else None,
            "p95_s": _p95(detector.latencies_ms),
            "error": detector.last_error,
        }

    out(f"\n{'setup':<30}{'found':>8}{'alarmed':>9}{'false alarms':>14}{'failed':>8}{'halluc.':>9}{'avg s':>8}{'p95 s':>8}")
    for label, r in results.items():
        halluc = "-" if r["halluc"] is None else f"{r['halluc']:.0%}"
        avg = "-" if r["avg_s"] is None else f"{r['avg_s']:.1f}"
        p95 = "-" if r["p95_s"] is None else f"{r['p95_s']:.1f}"
        out(f"{label:<30}{_pct(r['found'], r['vuln']):>8}{_pct(r['alarmed'], r['vuln']):>9}"
            f"{_pct(r['false_alarms'], r['neg']):>14}{r['failed']:>8}{halluc:>9}{avg:>8}{p95:>8}")
    for label, r in results.items():
        if r["error"]:
            out(f"\nlast error for {label}: {r['error']}")
    return results


# ---------------------------------------------------------------- self-test
# An oracle that "knows" the answers, and a noisy model that only hallucinates.
# (category, quoted line, severity, text whose presence means the code is the SAFE version)
_ORACLE = {
    "ssrf": ("ssrf", "return requests.get(url, timeout=5).text", "high", "ALLOWED_HOSTS"),
    "path": ("path_traversal", "with open(os.path.join(BASE_DIR, filename)) as handle:", "high", None),
    "ssti": ("xss_or_template_injection", 'return render_template_string("<h1>Hello " + name + "</h1>")', "high", None),
    "apikey": ("hardcoded_credentials", 'API_KEY = "<REDACTED_SECRET>"', "high", None),
    "cmd": ("command_injection", 'os.system("ping -c 1 " + host)', "high", None),   # overlaps Bandit -> corroborated
}


def _oracle(system: str, user: str) -> dict:
    findings = []
    for vuln_type, quote, severity, safe_marker in _ORACLE.values():
        if quote in user and not (safe_marker and safe_marker in user):
            findings.append({"vulnerability_type": vuln_type, "line": 1, "evidence": quote,
                             "explanation": "oracle", "severity": severity, "confidence": "high"})
    return {"findings": findings}


def _noisy(system: str, user: str) -> dict:
    return {"findings": [{"vulnerability_type": "command_injection", "line": 3,
                          "evidence": "subprocess.Popen(user_cmd, shell=True)",
                          "explanation": "invented", "severity": "critical", "confidence": "high"}]}


def selftest() -> None:
    lines: list[str] = []
    results = run_bakeoff({"oracle (scripted)": lambda: CallableLLM("oracle", _oracle),
                           "noisy (scripted)": lambda: CallableLLM("noisy", _noisy)}, out=lines.append)
    print("\n".join(lines))
    base, oracle, noisy = results["rules only"], results["oracle (scripted)"], results["noisy (scripted)"]

    assert oracle["found"] == oracle["vuln"], oracle                  # the model covers every category the rules miss
    assert oracle["alarmed"] == base["alarmed"] + 3, (oracle, base)   # +3: path traversal, SSRF, template injection (the secrets check already caught the API key)
    assert oracle["false_alarms"] == base["false_alarms"]             # an honest model adds no false alarms
    assert oracle["failed"] == 0 and oracle["halluc"] == 0.0

    assert noisy["halluc"] == 1.0                                     # every proposed finding was invented...
    assert (noisy["found"], noisy["alarmed"], noisy["false_alarms"]) == (base["found"], base["alarmed"], base["false_alarms"])
    print("\nbakeoff self-test OK: harness math verified; invented findings change nothing")


def _flag(args: list[str], name: str, default: int) -> int:
    return int(args[args.index(name) + 1]) if name in args else default


def main(argv: list[str]) -> None:
    if not argv:
        selftest()
        return
    runs, agree, limit = _flag(argv, "--runs", 1), _flag(argv, "--agree", 1), _flag(argv, "--limit", 0)
    flags = {"--runs", "--agree", "--limit"}
    deployments, skip = [], False
    for i, arg in enumerate(argv):
        if skip:
            skip = False
        elif arg in flags:
            skip = True
        else:
            deployments.append(arg)

    def make(deployment: str) -> Callable[[], LLMClient]:
        return lambda: FoundryLLM(deployment)

    cases = CASES[:limit] if limit else CASES
    run_bakeoff({d: make(d) for d in deployments}, runs=runs, min_agreement=agree, cases=cases)


if __name__ == "__main__":
    main(sys.argv[1:])
