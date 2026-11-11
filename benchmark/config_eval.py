"""
benchmark/config_eval.py

Measures the configuration-file secrets scanner end to end: each case is one whole file, sent through the real ScanService, and judged at FILE level.
  vulnerable file  -> found when the scan reports at least one hardcoded_credentials finding
  safe file        -> a false alarm when the scan reports ANY finding

Also checked on every finding: the evidence line is not the raw line (the secret value is masked), unless it is a private-key header.

    python -m benchmark.config_eval                 # self-test of the metric code only (no verdict)
    python -m benchmark.config_eval --heldout       # THE final run, once; refuses to run again

GATE, fixed BEFORE the final run (2026-11-11): at least 16 of the 20 vulnerable files found AND at most 1 false alarm among the 20 safe files. Two of the vulnerable files are outside
the detector's design on purpose, so 18 is the most a perfect-to-design detector can score.
"""

from __future__ import annotations

import hashlib
import math
import sys
import time
from pathlib import Path
from typing import Callable

from benchmark.cases_heldout_config import HELDOUT_CASES, PINNED_FINGERPRINT, config_fingerprint

GATE_MIN_FOUND = 16
GATE_MAX_FALSE_ALARMS = 1
VERDICT = Path(__file__).parent / "results" / "config_heldout_verdict.md"
DETECTOR = Path(__file__).parent.parent / "security_service" / "core" / "config_secrets.py"

Scanner = Callable[[str, str], list[dict]]          # (path, content) -> findings as dicts with at least "vulnerability_type", "line", "evidence"


def wilson(successes: int, total: int, z: float = 1.96) -> tuple[float, float]:
    if total == 0:
        return (0.0, 0.0)
    p = successes / total
    denom = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denom
    half = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def real_scanner() -> Scanner:
    from security_service.core.files import SourceFile
    from security_service.core.scan_service import ScanService

    service = ScanService()

    def scan(path: str, content: str) -> list[dict]:
        report = service.scan([SourceFile(path, content)])
        return [f.to_dict() for f in report.findings]
    return scan


def evaluate_files(cases: list[dict], scan: Scanner) -> dict:
    found, missed, false_alarms, leaks, started = [], [], [], [], time.monotonic()
    for case in cases:
        findings = [f for f in scan(case["path"], case["code"]) if f["vulnerability_type"] == "hardcoded_credentials"]
        lines = case["code"].split("\n")
        for f in findings:
            raw = lines[f["line"] - 1].strip() if 1 <= f["line"] <= len(lines) else ""
            if f["evidence"] == raw and not raw.startswith("-----BEGIN"):
                leaks.append(case["id"])
        if case["kind"] == "vulnerable":
            (found if findings else missed).append(case["id"])
        elif findings:
            false_alarms.append((case["id"], [(f["line"], f["rule_id"]) for f in findings]))
    vulnerable = sum(c["kind"] == "vulnerable" for c in cases)
    safe = len(cases) - vulnerable
    return {"vulnerable": vulnerable, "safe": safe, "found": found, "missed": missed, "false_alarms": false_alarms, "leaks": sorted(set(leaks)),
            "seconds": round(time.monotonic() - started, 2)}


def passes_gate(result: dict) -> bool:
    return len(result["found"]) >= GATE_MIN_FOUND and len(result["false_alarms"]) <= GATE_MAX_FALSE_ALARMS and not result["leaks"]


def render(result: dict, note_by_id: dict[str, str]) -> str:
    f, v, a, s = len(result["found"]), result["vulnerable"], len(result["false_alarms"]), result["safe"]
    lo, hi = wilson(f, v)
    alo, ahi = wilson(a, s)
    out = [
        "# Configuration-file secrets scanner: held-out verdict", "",
        f"- Cases fingerprint: `{config_fingerprint()}` (pinned `{PINNED_FINGERPRINT}`)",
        f"- Detector file `security_service/core/config_secrets.py` sha256 prefix: `{hashlib.sha256(DETECTOR.read_bytes()).hexdigest()[:16]}`",
        f"- Gate (fixed before the run): at least {GATE_MIN_FOUND} of {v} vulnerable files found, at most {GATE_MAX_FALSE_ALARMS} false alarm among {s} safe files, no evidence line equal to its raw line",
        f"- **Vulnerable files found: {f} of {v}** (Wilson 95%: {lo:.0%} to {hi:.0%})",
        f"- **False alarms on safe files: {a} of {s}** (Wilson 95%: {alo:.0%} to {ahi:.0%})",
        f"- Evidence lines that leak the raw line: {len(result['leaks'])}",
        f"- Scan time for all {v + s} files: {result['seconds']} s",
        f"- **Gate: {'PASSED' if passes_gate(result) else 'NOT PASSED'}**", "",
        "## Missed vulnerable files", "",
    ]
    out += [f"- `{cid}`: {note_by_id[cid]}" for cid in result["missed"]] or ["- none"]
    out += ["", "## False alarms", ""]
    out += [f"- `{cid}`: {note_by_id[cid]}; reported at {where}" for cid, where in result["false_alarms"]] or ["- none"]
    out += ["", "## Limits of this measurement", "",
            "- The author of the detector also wrote the cases. They are held out from tuning, not from the author's idea of what a secret looks like.",
            "- Whole files, 40 of them: the intervals are wide. This is evidence the detector behaves sensibly on realistic files, not an accuracy figure.",
            "- Two vulnerable files are outside the design on purpose (abbreviated key name, pure dictionary passphrase); they are expected misses and are counted as misses.",
            "- Only hardcoded secrets are measured. Nothing else about a configuration file is judged by Phylax."]
    return "\n".join(out) + "\n"


def selftest() -> None:
    cases = HELDOUT_CASES
    perfect = lambda path, content: [{"vulnerability_type": "hardcoded_credentials", "line": 1, "evidence": "***", "rule_id": "X"}] if any(c["path"] == path and c["kind"] == "vulnerable" for c in cases) else []
    everything = lambda path, content: [{"vulnerability_type": "hardcoded_credentials", "line": 1, "evidence": "***", "rule_id": "X"}]
    nothing = lambda path, content: []
    leaky = lambda path, content: [{"vulnerability_type": "hardcoded_credentials", "line": 1, "evidence": content.split("\n")[0].strip(), "rule_id": "X"}]
    ok = evaluate_files(cases, perfect)
    assert len(ok["found"]) == 20 and not ok["false_alarms"] and not ok["leaks"] and passes_gate(ok)
    flag_all = evaluate_files(cases, everything)
    assert len(flag_all["found"]) == 20 and len(flag_all["false_alarms"]) == 20 and not passes_gate(flag_all)
    none = evaluate_files(cases, nothing)
    assert len(none["found"]) == 0 and len(none["missed"]) == 20 and not none["false_alarms"] and not passes_gate(none)
    assert evaluate_files(cases, leaky)["leaks"] and not passes_gate(evaluate_files(cases, leaky))                     # a scanner that echoes the raw line can never pass
    borderline = {**ok, "found": ok["found"][:16]}
    assert passes_gate(borderline) and not passes_gate({**ok, "found": ok["found"][:15]})                      # the gate is exactly 16
    assert passes_gate({**ok, "false_alarms": [("a", [])]}) and not passes_gate({**ok, "false_alarms": [("a", []), ("b", [])]})   # and at most one false alarm
    lo, hi = wilson(13, 14)
    assert abs(lo - 0.685) < 0.01 and abs(hi - 0.987) < 0.01, (lo, hi)                                          # matches the Python held-out interval already published
    assert wilson(0, 0) == (0.0, 0.0) and wilson(20, 20)[1] == 1.0 and wilson(0, 20)[0] == 0.0
    text = render(ok, {c["id"]: c["note"] for c in cases})
    assert "Gate: PASSED" in text and "no evidence line equal to its raw line" in text and "Limits of this measurement" in text
    print("config_eval OK: oracle scores 20/20 and passes, flag-everything and flag-nothing both fail, a leaking scanner can never pass, the gate is exactly 16 and 1, Wilson matches the published interval")


def main() -> None:
    if "--heldout" not in sys.argv:
        selftest()
        return
    selftest()
    assert PINNED_FINGERPRINT == config_fingerprint(), "the held-out cases changed since they were pinned"
    if VERDICT.exists():
        sys.exit(f"{VERDICT} already exists: the held-out run is done. A second run would not be held out. Write new cases instead.")
    result = evaluate_files(HELDOUT_CASES, real_scanner())
    text = render(result, {c["id"]: c["note"] for c in HELDOUT_CASES})
    VERDICT.write_text(text, encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
