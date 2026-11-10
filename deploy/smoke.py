#!/usr/bin/env python3
"""
deploy/smoke.py

The check you run against a DEPLOYED Phylax to know it really works. Standard library only (copy this one file anywhere).

    export PHYLAX_API_KEY=...                       (PowerShell: $env:PHYLAX_API_KEY = "...")
    python deploy/smoke.py --url https://phylax.example.azurecontainerapps.io
    python deploy/smoke.py --url https://... --fix  also asks for one correction and checks it came back verified (this costs a model call)

What it checks, in order: the service is alive and ready; a request with no key, and one with a wrong key, are REFUSED; the capabilities say what is
switched on; a Python scan and a JavaScript scan of a deliberately vulnerable snippet BLOCK, each finding says whether a correction is offered; with
--fix, a correction comes back verified, with the hashes a client needs. It removes the scans it made. The key is read from the environment, never from
the command line, and is never printed.

Exit code: 0 everything passed, 1 something failed, 2 it could not run (bad arguments, no key).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from typing import Any, Callable

PYTHON_SAMPLE = "import os\n\ndef ping(host):\n    os.system('ping ' + host)\n"
JAVASCRIPT_SAMPLE = 'const { exec } = require("child_process");\n\nfunction run(dir) {\n  exec(`ls ${dir}`);\n}\n'


def call(base: str, method: str, path: str, key: str | None = None, body: Any = None, wait: int = 0, timeout: float = 60.0) -> tuple[int, Any]:
    """One request. Returns (status, parsed JSON or None). A refused connection returns (0, None)."""
    headers = {"Accept": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json; charset=utf-8"
    if wait:
        headers["Prefer"] = f"wait={wait}"
    request = urllib.request.Request(base + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
            return response.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as error:
        raw = error.read()
        try:
            return error.code, (json.loads(raw) if raw else None)
        except ValueError:
            return error.code, None
    except (urllib.error.URLError, OSError, TimeoutError):
        return 0, None


def describe(status: int, body: Any) -> str:
    """What an answer was, in a few safe words: the status, and the service's own error code or readiness checks. Never the rest of the body."""
    if status == 0:
        return "the service did not answer"
    if isinstance(body, dict) and isinstance(body.get("code"), str):
        return f"status {status}, code {body['code']!r}" + (f", request {body['request_id']}" if isinstance(body.get("request_id"), str) else "")
    if isinstance(body, dict) and isinstance(body.get("checks"), dict):
        return f"status {status}, " + ", ".join(f"{name}: {value}" for name, value in body["checks"].items())
    return f"status {status}"


def engine_notes(report: dict) -> str:
    """Why the service's own checks could not run, in the words the engines gave (they contain no code): for example 'bandit: bandit timed out after 30s'."""
    failed = (report.get("coverage") or {}).get("analyzers_failed") or {}
    notes = "; ".join(f"{name}: {' '.join(str(reason).split())[:200]}" for name, reason in failed.items())
    return f" [{notes}]" if notes else ""


def wait_until_ready(base: str, seconds: float, sleep: Callable[[float], None], clock: Callable[[], float]) -> tuple[bool, str]:
    """A service that has only just started can need a moment (its checks run on first use), so /readyz is asked again until it says yes or the time is up."""
    deadline = clock() + seconds
    while True:
        status, body = call(base, "GET", "/readyz")
        if status == 200:
            return True, ""
        if clock() >= deadline:
            return False, describe(status, body)
        sleep(2.0)


def wait_for_job(base: str, key: str, prefix: str, job: dict, seconds: float, sleep: Callable[[float], None], clock: Callable[[], float]) -> tuple[dict | None, str]:
    """A job still running (the service answered 202) is asked about until it has finished or the time is up."""
    deadline = clock() + seconds
    while job.get("status") in ("queued", "running"):
        if clock() >= deadline:
            return None, f"still running after {int(seconds)} s"
        sleep(1.0)
        status, body = call(base, "GET", prefix + str(job.get("id")), key=key)
        if status != 200 or not isinstance(body, dict):
            return None, describe(status, body)
        job = body
    return job, ""


def run(base: str, key: str, fix: bool, say: Callable[[str], None] = print, ready_seconds: float = 60.0, job_seconds: float = 90.0,
        sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.monotonic) -> bool:
    """Run every check. Prints one PASS or FAIL line per check and returns True only if all passed."""
    results: list[tuple[str, bool, str]] = []

    def check(name: str, passed: bool, detail: str = "") -> bool:
        results.append((name, passed, detail))
        say(f"  {'PASS' if passed else 'FAIL'}  {name}" + (f": {detail}" if detail and not passed else ""))      # the detail is the hint for a failure, so only a failure shows it
        return passed

    scans: list[str] = []
    say(f"Checking {base}\n")

    status, body = call(base, "GET", "/healthz")
    if not check("the service is alive (/healthz)", status == 200, "" if status == 200 else f"answered {status or 'nothing'}: is the address right and the service running?"):
        say("\nThe service did not answer, so the other checks were skipped.")
        return False
    ready, why = wait_until_ready(base, ready_seconds, sleep, clock)
    check("the service is ready (/readyz)", ready, f"{why}. It is running but one of its own checks is failing: look at its logs" if not ready else "")

    status, _ = call(base, "GET", "/v1/capabilities")
    check("a request with NO key is refused", status == 401, f"answered {status}, expected 401")
    status, _ = call(base, "GET", "/v1/capabilities", key="not-a-real-key-not-a-real-key-0000")
    check("a request with a WRONG key is refused", status == 401, f"answered {status}, expected 401")

    status, capabilities = call(base, "GET", "/v1/capabilities", key=key)
    if not check("your key is accepted and capabilities answer", status == 200 and isinstance(capabilities, dict), f"answered {status}: is PHYLAX_API_KEY the key for this service?"):
        say("\nYour key was not accepted, so the remaining checks were skipped.")
        return False
    languages = {item["id"] for item in capabilities.get("languages", [])}
    features = capabilities.get("features") or {}
    say(f"      contract {capabilities.get('contract_version')}, languages: {', '.join(sorted(languages))}, corrections: {'on' if features.get('fixes') else 'OFF'}")
    check("Python scanning is available", "python" in languages)

    problems: dict[str, str] = {}

    def scan(path: str, content: str) -> dict | None:
        status, result = call(base, "POST", "/v1/scans", key=key, body={"files": [{"path": path, "content": content}]}, wait=25)
        if status in (200, 202) and isinstance(result, dict) and result.get("id"):
            scans.append(result["id"])
            finished, why = wait_for_job(base, key, "/v1/scans/", result, job_seconds, sleep, clock)
            if finished is not None:
                return finished
            problems[path] = why
            return None
        problems[path] = describe(status, result)
        return None

    result = scan("ping.py", PYTHON_SAMPLE)
    report = (result or {}).get("report") or {}
    findings = report.get("findings") or []
    check("a vulnerable Python snippet is BLOCKED", report.get("decision") == "block" and any(f.get("vulnerability_type") == "command_injection" for f in findings),
          f"decision {report.get('decision')!r}, {len(findings)} finding(s)" + (f" ({problems['ping.py']})" if "ping.py" in problems else "") + engine_notes(report))
    check("each finding says whether a correction is offered (and why)", bool(findings) and all(isinstance(f.get("fix"), dict) and "eligible" in f["fix"] and f["fix"].get("reason") for f in findings))
    python_scan = result

    if "javascript" in languages:
        js = scan("run.js", JAVASCRIPT_SAMPLE)
        js_report = (js or {}).get("report") or {}
        check("a vulnerable JavaScript snippet is BLOCKED", js_report.get("decision") == "block", f"decision {js_report.get('decision')!r}" + (f" ({problems['run.js']})" if "run.js" in problems else "") + engine_notes(js_report))
    else:
        say("      (JavaScript scanning is not available on this deployment, so that check was skipped)")

    if fix:
        if not features.get("fixes"):
            check("corrections are switched on", False, "this deployment has SERVICE_FIXES_ENABLED off, so --fix cannot work")
        else:
            target = scan("run.js", JAVASCRIPT_SAMPLE) if "javascript" in languages else python_scan
            ids = [f["id"] for f in ((target or {}).get("report") or {}).get("findings", []) if (f.get("fix") or {}).get("eligible")]
            status, fixed = call(base, "POST", f"/v1/scans/{(target or {}).get('id')}/fixes", key=key, body={"finding_ids": ids[:1]}, wait=30, timeout=120)
            patches = (fixed or {}).get("patches") or [] if isinstance(fixed, dict) else []
            ok = status == 200 and isinstance(fixed, dict) and fixed.get("applicable") is True and bool(patches)
            check("a correction comes back verified (applicable)", ok, "" if ok else f"status {status}, applicable={None if not isinstance(fixed, dict) else fixed.get('applicable')}, reason: {None if not isinstance(fixed, dict) else fixed.get('failure_reason')} (the model can vary: run it again before worrying)")
            if ok:
                patch = patches[0]
                hashes = all(isinstance(patch.get(name), str) and len(patch[name]) == 64 for name in ("base_sha256", "corrected_sha256"))
                check("the correction carries the file hashes and the whole corrected file", hashes and bool(patch.get("corrected_content")))

    for scan_id in scans:                                                      # leave nothing behind
        call(base, "DELETE", f"/v1/scans/{scan_id}", key=key)

    failed = [name for name, passed, _ in results if not passed]
    say(f"\n{len(results) - len(failed)} of {len(results)} checks passed." + ("" if not failed else "  FAILED: " + "; ".join(failed)))
    return not failed


def main(argv: list[str], environ: dict[str, str] | None = None, out: Callable[[str], None] = print) -> int:
    environ = os.environ if environ is None else environ
    parser = argparse.ArgumentParser(description="Smoke test a deployed Phylax.", add_help=True)
    parser.add_argument("--url", required=True, help="the address, for example https://phylax.example.azurecontainerapps.io")
    parser.add_argument("--fix", action="store_true", help="also ask for one correction (costs a model call)")
    parser.add_argument("--key-env", default="PHYLAX_API_KEY", help="the environment variable that holds the key (default PHYLAX_API_KEY)")
    try:
        args = parser.parse_args(argv)
    except SystemExit as stop:
        return int(stop.code or 0) if stop.code in (0, None) else 2
    key = environ.get(args.key_env, "").strip()
    if not key:
        out(f"Set {args.key_env} to your Phylax API key first (it is never taken from the command line).")
        return 2
    base = args.url.rstrip("/")
    if not base.startswith(("http://", "https://")):
        out("The address must start with https:// (or http:// for a service on this computer).")
        return 2
    if base.startswith("http://") and not any(base.startswith(f"http://{h}") for h in ("localhost", "127.0.0.1", "[::1]")):
        out("Refusing to send the key over plain http to a remote address. Use https.")
        return 2
    return 0 if run(base, key, args.fix, out) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
