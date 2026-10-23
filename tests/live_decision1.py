"""
tests/live_decision1.py

First contact with a REAL Microsoft-Decision-1 deployment. Makes one real call (a tiny fraction of
a cent) through the same adapter code production will use, then prints what came back.

Set the variables in your own terminal (never paste a key into a chat), then run it from the repo
root. FOUNDRY_ENDPOINT may be the resource host or the full .../providers/microsoft/v1/systemone URL.

PowerShell, with an API key:
    $env:FOUNDRY_ENDPOINT     = "https://YOUR-RESOURCE.services.ai.azure.com"
    $env:FOUNDRY_API_KEY      = "YOUR-KEY"
    $env:DECISION1_DEPLOYMENT = "YOUR-DEPLOYMENT-NAME"   # the name you chose, NOT "Microsoft-Decision-1"
    python -m tests.live_decision1

PowerShell, with Microsoft Entra ID (recommended by Microsoft; no key needed):
    az login
    pip install azure-identity
    $env:FOUNDRY_ENDPOINT     = "https://YOUR-RESOURCE.services.ai.azure.com"
    $env:DECISION1_DEPLOYMENT = "YOUR-DEPLOYMENT-NAME"
    $env:DECISION1_AUTH       = "entra"
    python -m tests.live_decision1

It prints the state that was actually sent (secrets already masked), the raw reply, and the parsed
answers. If the adapter cannot read the reply, it still prints the raw reply, because that is
exactly what is needed to fix the parser. The raw reply holds no key; check it, then paste it.

    python -m tests.live_decision1 --selftest     runs this script against a scripted network (no key needed)
"""

from __future__ import annotations

import json
import os
import sys
from typing import Callable

from security_service.adapters.decision1 import Decision1Classifier
from security_service.ports.classifier import ClassifierError, Question

STATE = 'DB_PASSWORD = "SuperSecret123!"\nimport os\n\ndef ping(host):\n    os.system("ping -c 1 " + host)\n'

QUESTIONS = [
    Question("hardcoded_secret", "yes_no", "Does the code contain a hardcoded password, key or token?"),
    Question("shell_injection", "yes_no", "Does the code build a shell command from a variable?"),
    Question("worst_problem", "choice", "Which is the most serious security problem in this code?", {
        "hardcoded_secret": "A password, key or token is written into the source",
        "command_injection": "A shell command is built from a variable",
        "none": "There is no security problem",
        "cannot_tell": "The code is too unclear to say",
    }),
]


def run(classifier: Decision1Classifier, out: Callable[[str], None] = print) -> int:
    try:
        payload = classifier.build_request(STATE, QUESTIONS)
    except ClassifierError as problem:
        out(f"Not ready: {problem}")
        return 2
    sent = json.loads(payload)
    out(f"deployment: {sent['model']}")
    out("state sent (secrets already masked):\n" + sent["state"])

    try:
        raw = classifier.send(payload)
    except ClassifierError as problem:
        out(f"\nThe call failed: {problem}")
        return 1
    out("\nraw reply:")
    try:
        out(json.dumps(json.loads(raw), indent=2))
    except ValueError:
        out(raw.decode("utf-8", errors="replace")[:2000])

    try:
        result = classifier._parse(raw, QUESTIONS)
    except ClassifierError as problem:
        out(f"\nThe adapter could not read the reply: {problem}")
        out("Send the raw reply above (it contains no key) so the parser can be adjusted.")
        return 1

    out(f"\nparsed OK. model reported as {result.model}, input tokens {result.input_tokens}")
    for question in QUESTIONS:
        answer = result.answers[question.id]
        shown = f"P(yes) = {answer.probability:.3f}" if answer.kind == "yes_no" else f"choice = {answer.choice}, probabilities = {answer.probabilities}"
        out(f"  {question.id}: {shown}")
    return 0


def _selftest() -> int:
    reply = {"answers": {"hardcoded_secret": {"noul": 0.96}, "shell_injection": {"noul": 0.94},
                         "worst_problem": {"choice": "command_injection", "confidence": 0.7,
                                           "probabilities": {"hardcoded_secret": 0.2, "command_injection": 0.7, "none": 0.05, "cannot_tell": 0.05}}},
             "usage": {"input_tokens": 88}}
    lines: list[str] = []
    ok = Decision1Classifier(endpoint="https://r.services.ai.azure.com", api_key="k", transport=lambda *a: (200, {}, json.dumps(reply).encode()))
    assert run(ok, lines.append) == 0
    text = "\n".join(lines)
    assert "SuperSecret123" not in text and "<REDACTED_SECRET>" in text and "parsed OK" in text and "command_injection" in text

    lines.clear()
    odd = Decision1Classifier(endpoint="https://r.services.ai.azure.com", api_key="k", transport=lambda *a: (200, {}, b'{"results": [1]}'))
    assert run(odd, lines.append) == 1 and "raw reply" in "\n".join(lines) and "results" in "\n".join(lines)

    lines.clear()
    denied = Decision1Classifier(endpoint="https://r.services.ai.azure.com", api_key="k", transport=lambda *a: (401, {}, b"{}"))
    assert run(denied, lines.append) == 1 and "authentication failed" in "\n".join(lines)

    lines.clear()
    assert run(Decision1Classifier(endpoint="", api_key=""), lines.append) == 2 and "Not ready" in lines[0]
    print("tests.live_decision1 OK: prints masked state, raw reply and parsed answers; still shows the raw reply when parsing fails")
    return 0


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(_selftest())
    entra = os.getenv("DECISION1_AUTH", "key").strip().lower() == "entra"
    missing = [name for name in (("FOUNDRY_ENDPOINT",) if entra else ("FOUNDRY_ENDPOINT", "FOUNDRY_API_KEY")) if not os.getenv(name)]
    if missing:
        print("Set these environment variables first: " + ", ".join(missing) + "\n(see the instructions at the top of this file)")
        sys.exit(2)
    sys.exit(run(Decision1Classifier.from_env()))