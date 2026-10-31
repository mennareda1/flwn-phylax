"""
tests/live_corrector.py

The first real contact with GPT-6 Astra as the corrector. It makes ONE fix request (two with --both) and shows everything that
came back, so a problem is visible in one run instead of guessed at:

    python -m tests.live_corrector               one request, on the route in CORRECTOR_API
    python -m tests.live_corrector --both        try both routes, say which works, and what to put in .env
    python -m tests.live_corrector --sample upload   a path-traversal sample instead (the rules cannot verify that one)
    python -m tests.live_corrector --show-raw    also print the model's raw reply

What it does, in order: shows your settings (never the key), scans a small built-in sample with the RULES ONLY to get a real
finding, asks Astra to fix it, then checks the answer the way the fix service will: does the patch fit the file, does the patched
code still parse, and does a re-scan show the problem gone. It reports the time, the tokens (thinking included) and the cost.

It sends only the built-in sample, never your files. One request costs a few cents at most (thinking is billed as output).
Exit code: 0 a route worked end to end, 1 none did, 2 the settings are not ready.
"""

from __future__ import annotations

import ast
import sys

from security_service.adapters.bandit import BanditAnalyzer
from security_service.adapters.foundry_chat import ROUTES, FoundryChat
from security_service.adapters.foundry_corrector import FoundryCorrector
from security_service.adapters.secrets_check import SecretsAnalyzer
from security_service.config import Settings, load_env_file
from security_service.core.files import SourceFile
from security_service.core.scan_service import ScanService
from security_service.core.schema import Severity
from security_service.ports.corrector import BadProposal, CorrectorError, FixConstraints

PRICE_INPUT_PER_MILLION = 10.0       # US dollars, Global Standard, short context (Data Zone is about 10 percent more)
PRICE_OUTPUT_PER_MILLION = 50.0

SAMPLES = {
    "ping": SourceFile("net.py", 'import os\n\n\ndef ping(host):\n    os.system("ping " + host)\n    return True\n'),
    "upload": SourceFile("upload.py", 'import os\n\n\ndef read_upload(name):\n    with open(os.path.join("/srv/uploads", name)) as handle:\n        return handle.read()\n'),
}


def cost(prompt_tokens: int, completion_tokens: int) -> float:
    return (prompt_tokens * PRICE_INPUT_PER_MILLION + completion_tokens * PRICE_OUTPUT_PER_MILLION) / 1_000_000


def try_route(settings: Settings, route: str, sample: SourceFile, findings, show_raw: bool, out=print) -> bool:
    """One fix request on one route. True only if the answer fits the file, parses, and the re-scan shows the finding gone."""
    out(f"\n=== route {route} ===")
    chat = FoundryChat(settings.corrector_deployment, settings.corrector_resolved_endpoint, settings.corrector_resolved_key, route=route,
                       reasoning_effort=settings.corrector_reasoning_effort, max_output_tokens=settings.corrector_max_output_tokens,
                       timeout=settings.corrector_timeout)
    corrector = FoundryCorrector(chat)
    out(f"calling {chat.url}")
    try:
        proposal = corrector.propose_detailed(sample, findings, FixConstraints())
    except BadProposal as problem:
        out(f"The model answered, but the answer is unusable: {problem}")
        reply = corrector.last_reply
        if reply:
            out(f"  finish_reason {reply.finish_reason!r}, {reply.completion_tokens} output tokens ({reply.reasoning_tokens} of them thinking), {reply.seconds:.1f} s")
            out("  what the model said (this is the built-in sample, not your code):\n    " + (reply.text[:1500].replace("\n", "\n    ") or "(nothing)"))
        return False
    except CorrectorError as problem:
        out(f"FAILED: {type(problem).__name__}: {problem}")
        return False

    reply = proposal.reply
    out(f"answered by {reply.model} in {reply.seconds:.1f} s; finish_reason {reply.finish_reason!r}")
    out(f"tokens: {reply.prompt_tokens} in, {reply.completion_tokens} out ({reply.reasoning_tokens} of those were thinking); "
        f"cost about ${cost(reply.prompt_tokens, reply.completion_tokens):.4f}")
    if show_raw:
        out("raw reply:\n    " + reply.text.replace("\n", "\n    "))
    for unfixed in proposal.unfixed:
        out(f"the model could not fix {unfixed['finding_id']}: {unfixed['reason']}")
    if not proposal.patches:
        out("The model proposed no edit (it judged the finding not safely fixable by a small change).")
        return False
    patch = proposal.patches[0]
    out(f"patch for {patch.path}, fixing {', '.join(patch.finding_ids)}; the model says: {patch.explanation}\n")
    out(patch.unified_diff.rstrip())

    # the checks the fix service will make
    try:
        ast.parse(proposal.fixed_code)
        parses = True
    except SyntaxError as problem:
        parses = False
        out(f"\nCHECK failed: the patched file does not parse ({problem.msg} at line {problem.lineno})")
    rescan = ScanService([BanditAnalyzer(), SecretsAnalyzer()]).scan([SourceFile(sample.path, proposal.fixed_code)])
    before = {f.vulnerability_type for f in findings}
    after = {f.vulnerability_type for f in rescan.findings if f.severity.rank >= Severity.MEDIUM.rank}
    gone = not (before & after)
    out(f"\nCHECK parses: {'yes' if parses else 'NO'}")
    out(f"CHECK re-scan with the rules: decision {rescan.decision.value}; problem types before {sorted(before)}, still present at medium or above: {sorted(before & after) or 'none'}"
        f"; new at medium or above: {sorted(after - before) or 'none'}")
    ok = parses and gone and not (after - before)
    out(f"RESULT on route {route}: {'the fix is usable end to end' if ok else 'NOT usable: see the checks above'}")
    return ok


def main(argv: list[str], environ=None, out=print) -> int:
    if environ is None:
        import os

        load_env_file()
        environ = os.environ
    settings = Settings.from_env(environ)
    out(settings.describe_corrector())
    for warning in settings.warnings:
        out(f"warning: {warning}")
    problems = settings.corrector_problems()
    if problems:
        out("\nThe corrector is not ready. Add the missing setting to .env (see .env.example), then run this again.")
        return 2
    sample_name = argv[argv.index("--sample") + 1] if "--sample" in argv and argv.index("--sample") + 1 < len(argv) else "ping"
    if sample_name not in SAMPLES:
        out(f"Unknown sample {sample_name!r}; choose one of: {', '.join(SAMPLES)}")
        return 2
    sample = SAMPLES[sample_name]
    base = ScanService([BanditAnalyzer(), SecretsAnalyzer()]).scan([sample])
    findings = [f for f in base.findings if f.severity.rank >= Severity.MEDIUM.rank]
    out(f"\nsample {sample.path}: the rules alone say {base.decision.value} with {len(findings)} finding(s) at medium or above"
        + (f" ({', '.join(sorted({f.vulnerability_type for f in findings}))})" if findings else ""))
    if not findings:
        out("The rules find nothing in this sample, so there is nothing to ask the model to fix. Try --sample ping.")
        return 2

    routes = list(ROUTES) if "--both" in argv else [settings.corrector_api]
    worked = [route for route in routes if try_route(settings, route, sample, findings, "--show-raw" in argv, out)]
    out("")
    if worked:
        out(f"RESULT: {', '.join(worked)} worked. Put  CORRECTOR_API={worked[0]}  in .env" + ("" if worked[0] == settings.corrector_api else " (it is different from your current setting)") + ".")
        return 0
    out("RESULT: no route worked. Paste me this output (it contains no key) and I will read it.")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
