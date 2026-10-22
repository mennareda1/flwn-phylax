"""
benchmark/run_benchmark.py

Scores a ScanService against the labeled Python cases and prints a
scoreboard. Run from the repo root:

    python -m benchmark.run_benchmark

Two different questions are measured, because they matter differently:

  found    - did any finding carry the right vulnerability category?
             (measures the analyzers)
  alarmed  - did the final DECISION become REVIEW_REQUIRED or BLOCK?
             (measures analyzers + decision policy together)

On the negatives (fixed code and safe lookalikes), any decision other than
PASS counts as a false alarm.

With only a few dozen hand-written cases these numbers are a compass for
choosing between approaches, not a claim about real-world accuracy.
"""

from __future__ import annotations

import sys
from collections import defaultdict

from benchmark.cases_python import CASES, summary
from security_service.core.scan_service import ScanService
from security_service.core.schema import Decision

ALARM = (Decision.BLOCK, Decision.REVIEW_REQUIRED)


def run(scanner: ScanService | None = None, cases: list[dict] | None = None) -> list[dict]:
    scanner = scanner or ScanService()
    rows = []
    for case in cases or CASES:
        report = scanner.scan_snippet(case["code"], "python")
        types = {f.vulnerability_type for f in report.findings}
        rows.append({
            "case": case,
            "decision": report.decision,
            "types": types,
            "rules": [f"{f.rule_id}:{f.severity.value[0]}" for f in report.findings],
            "found": case["category"] in types,
            "alarmed": report.decision in ALARM,
            "reasons": report.decision_reasons,
        })
    return rows


def score(rows: list[dict]) -> dict:
    vuln = [r for r in rows if r["case"]["kind"] == "vulnerable"]
    neg = [r for r in rows if r["case"]["kind"] != "vulnerable"]
    return {
        "vuln": len(vuln),
        "neg": len(neg),
        "found": sum(r["found"] for r in vuln),
        "alarmed": sum(r["alarmed"] for r in vuln),
        "false_alarms": sum(r["alarmed"] for r in neg),
        "failed": sum(r["decision"] == Decision.SCAN_FAILED for r in rows),
    }


def _pct(n: int, d: int) -> str:
    return f"{n}/{d} ({(100 * n / d):.0f}%)" if d else "n/a"


def print_scoreboard(rows: list[dict]) -> None:
    vuln = [r for r in rows if r["case"]["kind"] == "vulnerable"]
    neg = [r for r in rows if r["case"]["kind"] != "vulnerable"]

    print(f"\n=== per-case results ({summary()}) ===")
    for r in rows:
        c = r["case"]
        mark = {"vulnerable": "V", "fixed": "F", "lookalike": "L"}[c["kind"]]
        flag = ""
        if c["kind"] == "vulnerable" and not r["alarmed"]:
            flag = "  <-- MISSED (no alarm)" if not r["found"] else "  <-- found but no alarm"
        if c["kind"] != "vulnerable" and r["alarmed"]:
            flag = "  <-- FALSE ALARM"
        print(f"{mark} {c['id']:<24} {r['decision'].value:<16} {' '.join(r['rules']) or '-'}{flag}")

    print("\n=== vulnerable cases, by category ===")
    by_cat = defaultdict(list)
    for r in vuln:
        by_cat[r["case"]["category"]].append(r)
    print(f"{'category':<28}{'found':>8}{'alarmed':>9}")
    for cat, items in sorted(by_cat.items()):
        print(f"{cat:<28}{sum(r['found'] for r in items):>5}/{len(items):<3}{sum(r['alarmed'] for r in items):>5}/{len(items)}")

    totals = score(rows)
    found, alarmed = totals["found"], totals["alarmed"]
    false_alarms, failed = totals["false_alarms"], totals["failed"]

    print("\n=== overall ===")
    print(f"vulnerable cases flagged with the right category : {_pct(found, len(vuln))}")
    print(f"vulnerable cases that raised an alarm             : {_pct(alarmed, len(vuln))}")
    print(f"safe cases (fixed + lookalike) falsely alarmed    : {_pct(false_alarms, len(neg))}")
    if alarmed + false_alarms:
        print(f"alarm precision (true alarms / all alarms)        : {_pct(alarmed, alarmed + false_alarms)}")
    if failed:
        print(f"scans that FAILED (should be 0 on valid code)     : {failed}")

    base_rows = [r for r in rows if r["case"].get("group", "base") == "base"]
    if len(base_rows) != len(rows):
        b = score(base_rows)
        print(f"\n=== the original {len(base_rows)} cases only (comparable with earlier runs) ===")
        print(f"flagged with the right category: {_pct(b['found'], b['vuln'])}   "
              f"alarmed: {_pct(b['alarmed'], b['vuln'])}   false alarms: {_pct(b['false_alarms'], b['neg'])}")


if __name__ == "__main__":
    print_scoreboard(run())
    sys.exit(0)
