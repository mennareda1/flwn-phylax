"""
security_service/core/questions.py

The questions a decision model (Microsoft-Decision-1) is asked about a piece of code.

One yes/no question per vulnerability category, so each category gets its own probability. There is NO question
about hardcoded secrets: code is masked before it reaches any model, so the model cannot tell a real secret from a
harmless masked value (a header name, an environment variable name), and the deterministic secrets check, which
reads the original code locally, owns that category. An optional verdict question ("what is the most serious
problem?") exists but is off by default; it was measurably noisy.

Version 2 (2026-10-23): secrets and the verdict were removed from the default, and three questions were made more
exact by reading them against the first run's misses (unsafe YAML loaders named; template-from-text named;
SSRF limited to HTTP clients, so a ping does not count). The first run is a development set: judge version 2 on
benchmark/cases_heldout.py, which no model had seen when it was written.

How the questions are written, and why:
  - Each states an exact, literal condition. Microsoft documents that scores change with wording, and
    models read literally, so "is this code insecure?" would be useless.
  - Each carries true/false criteria, which Microsoft documents as the way to sharpen borderline cases.
  - Each names the safe alternative ("instead of passing the values as parameters") so a safe look-alike
    is a clear "no".
  - The verdict has an abstention option, as Microsoft's guidance recommends for forced choices.

These are a first draft. The evaluation (benchmark/classifier_eval.py) measures them; change the
wording only with a measurement to justify it, and re-run the evaluation after any change.
"""

from __future__ import annotations

from typing import Iterable

from security_service.ports.classifier import Question, validate_questions

VERDICT_ID = "worst_problem"

# category -> (the question, what "true" means, what "false" means)
_CATEGORY_TEXT = {
    "command_injection": (
        "Does the code build an operating-system command from a variable or other changing value (for example by "
        "joining text into a string passed to os.system, os.popen, or subprocess with shell=True) instead of "
        "running a fixed program with its arguments passed as a list?",
        "A command is built from changing text.",
        "Commands are fixed, or arguments are passed as a list without a shell, or no command is run.",
    ),
    "sql_injection": (
        "Does the code build an SQL query by joining, formatting or interpolating a variable or other changing "
        "value (not a fixed constant) into the query text, using string concatenation, an f-string, % formatting "
        "or .format, instead of passing the values as separate query parameters?",
        "Changing text becomes part of the SQL string.",
        "Values are passed as parameters, the SQL text is fixed, or no SQL is used.",
    ),
    "code_injection": (
        "Does the code run text as program code with eval, exec or compile, where that text comes from a variable "
        "or from input rather than being a fixed literal?",
        "Changing text is evaluated as code.",
        "Nothing is evaluated, or only a fixed literal is, or safe parsing such as ast.literal_eval is used.",
    ),
    "insecure_deserialization": (
        "Does the code load data with pickle or marshal, or with an unsafe YAML loader (yaml.load with yaml.Loader, "
        "yaml.UnsafeLoader, yaml.FullLoader or no Loader argument), where the data could come from outside the program?",
        "Data is deserialized with an unsafe loader.",
        "Only safe formats or loaders are used (json, yaml.safe_load, or yaml.load with yaml.SafeLoader), or nothing is deserialized.",
    ),
    "weak_crypto": (
        "Does the code use a weak or broken algorithm for a security purpose, such as MD5 or SHA-1 to hash passwords "
        "or sign data, or DES or RC4 to encrypt?",
        "A weak algorithm protects something security-relevant.",
        "Modern algorithms are used, or a weak hash is used only for a non-security purpose such as a cache key.",
    ),
    "insecure_random": (
        "Does the code use the random module (random.choice, random.randint, random.random and similar) to "
        "generate a password, token, key or other security-sensitive value?",
        "Predictable randomness creates a security-sensitive value.",
        "The secrets module or os.urandom is used, or the randomness is not security-sensitive (for example a greeting).",
    ),
    "path_traversal": (
        "Does the code open or read a file whose path is built from a variable or from input, without checking that "
        "the final path stays inside an intended directory?",
        "A file path built from changing text is used without a check.",
        "The path is fixed, or it is resolved and checked against a base directory.",
    ),
    "ssrf": (
        "Running a command such as ping is not an HTTP request and does not count here. Does the code send an HTTP or "
        "HTTPS request (with requests, urllib, httpx, aiohttp or a similar library) to a URL that comes from a "
        "variable or from input, without checking the host against an allow-list?",
        "An HTTP request goes to a URL supplied from outside without a check.",
        "The URL is a fixed literal, or its host is validated against an allow-list, or no HTTP request is made.",
    ),
    "xss_or_template_injection": (
        "Does the code build a template from variable text, for example by joining or formatting variable text into the "
        "string given to render_template_string, Template(...) or env.from_string, or does it switch off HTML "
        "auto-escaping in a template environment?",
        "Template source comes from changing text, or auto-escaping is off.",
        "Template text is a fixed literal, values are passed as template variables, and auto-escaping is on.",
    ),
    "tls_verification_disabled": (
        "Does the code switch off TLS or SSL certificate verification, for example verify=False in a requests call "
        "or an unverified SSL context?",
        "Certificate checking is switched off.",
        "Certificates are verified, which is the default.",
    ),
    "debug_enabled": (
        "Does the code turn on a web framework's debug mode, for example app.run(debug=True) or DEBUG = True in a "
        "configuration that could be deployed?",
        "Debug mode is switched on.",
        "Debug mode is off or not set.",
    ),
    "insecure_temp_file": (
        "Does the code create a temporary file or directory with a predictable name, for example tempfile.mktemp or "
        "a fixed path under /tmp, instead of tempfile.mkstemp or NamedTemporaryFile?",
        "A temporary file with a predictable name is used.",
        "Secure temporary-file functions are used, or no temporary file is created.",
    ),
}

CATEGORY_IDS = tuple(_CATEGORY_TEXT)


def build_questions(categories: Iterable[str] | None = None, include_verdict: bool = False) -> list[Question]:
    """The yes/no questions (one per category), ready to send. The verdict question is off by default: in the first real
    run it named a problem on 14 of 27 safe cases, including clean fixes the yes/no questions judged safe."""
    chosen = tuple(categories) if categories is not None else CATEGORY_IDS
    unknown = [c for c in chosen if c not in _CATEGORY_TEXT]
    if unknown:
        raise ValueError(f"no question for category {unknown[0]!r}")
    questions = [
        Question(name, "yes_no", _CATEGORY_TEXT[name][0], {"true": _CATEGORY_TEXT[name][1], "false": _CATEGORY_TEXT[name][2]})
        for name in chosen
    ]
    if include_verdict:
        options = {name: _CATEGORY_TEXT[name][1] for name in chosen}
        options["none"] = "There is no security problem in this code."
        options["cannot_tell"] = "The code is too unclear to decide."
        questions.append(Question(
            VERDICT_ID, "choice",
            "Which one is the most serious security problem in this code? Choose none if there is no security problem, "
            "and cannot_tell if the code is too unclear to decide.",
            options,
        ))
    validate_questions(questions)
    return questions


def demo() -> None:
    from security_service.core.schema import VULN_TYPES

    # every category the classifier is asked about has a question. "other" is a catch-all with no testable
    # condition, and hardcoded_credentials belongs to the deterministic secrets check, not to a model
    assert "hardcoded_credentials" not in CATEGORY_IDS
    assert set(CATEGORY_IDS) == set(VULN_TYPES) - {"other", "hardcoded_credentials"}, set(VULN_TYPES) ^ set(CATEGORY_IDS)

    everything = build_questions()
    assert len(everything) == len(CATEGORY_IDS) == 12 and VERDICT_ID not in {q.id for q in everything}   # verdict is off by default
    assert len({q.id for q in everything}) == len(everything)
    validate_questions(everything)

    for question in everything:
        assert question.kind == "yes_no" and set(question.options) == {"true", "false"}
        assert question.instructions.endswith("?") and len(question.instructions) > 60, question.id
        assert "REDACTED" not in question.instructions and "secret" not in question.instructions.lower().replace("secrets module", ""), question.id

    # the three questions rewritten in version 2 say what they were rewritten to say
    text = {q.id: q.instructions for q in everything}
    assert all(name in text["insecure_deserialization"] for name in ("yaml.Loader", "yaml.UnsafeLoader", "yaml.FullLoader"))
    assert "render_template_string" in text["xss_or_template_injection"] and "env.from_string" in text["xss_or_template_injection"]
    assert "ping" in text["ssrf"] and "HTTP" in text["ssrf"]

    # the optional verdict question can still abstain, as Microsoft advises for forced choices
    with_verdict = build_questions(include_verdict=True)
    verdict = with_verdict[-1]
    assert verdict.id == VERDICT_ID and verdict.kind == "choice" and len(with_verdict) == 13
    assert set(verdict.options) == set(CATEGORY_IDS) | {"none", "cannot_tell"}

    # every text is plain ASCII, so it prints safely in any Windows console
    for question in with_verdict:
        for piece in (question.id, question.instructions, *(question.options or {}).values()):
            assert piece.isascii(), (question.id, piece[:40])

    # a subset, and an unknown category (including the one that is deliberately not asked)
    subset = build_questions(["ssrf", "path_traversal"])
    assert [q.id for q in subset] == ["ssrf", "path_traversal"]
    for unknown in ("telepathy", "hardcoded_credentials"):
        try:
            build_questions([unknown])
            raise AssertionError(f"expected {unknown!r} to be rejected")
        except ValueError:
            pass

    size = sum(len(q.instructions) + sum(len(v) for v in (q.options or {}).values()) for q in everything)
    print(f"core.questions OK: {len(CATEGORY_IDS)} yes/no questions, none about secrets, verdict off by default; all valid and ASCII, "
          f"about {size // 4} tokens of question text per request")


if __name__ == "__main__":
    demo()
