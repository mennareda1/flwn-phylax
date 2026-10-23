"""
security_service/core/questions.py

The questions a decision model (Microsoft-Decision-1) is asked about a piece of code.

One yes/no question per vulnerability category, so each category gets its own probability, plus one
verdict question ("what is the most serious problem?") that can answer `none` or `cannot_tell`.

How the questions are written, and why:
  - Each states an exact, literal condition. Microsoft documents that scores change with wording, and
    models read literally, so "is this code insecure?" would be useless.
  - Each carries true/false criteria, which Microsoft documents as the way to sharpen borderline cases.
  - Each names the safe alternative ("instead of passing the values as parameters") so a safe look-alike
    is a clear "no".
  - The secrets question explains the marker <REDACTED_SECRET>: code is masked before it reaches any
    model, so a hidden secret must count as a secret.
  - The verdict has an abstention option, as Microsoft's guidance recommends for forced choices.

These are a first draft. The evaluation (benchmark/classifier_eval.py) measures them; change the
wording only with a measurement to justify it, and re-run the evaluation after any change.
"""

from __future__ import annotations

from typing import Iterable

from security_service.core.redaction import PLACEHOLDER
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
    "hardcoded_credentials": (
        f"The marker {PLACEHOLDER} stands for a real secret that was hidden, and counts as a secret written in the "
        "source. Does the code contain a password, API key, access token or other secret written directly as a "
        "literal value in the source, instead of being read from the environment or a secrets store?",
        f"A secret literal, or the marker {PLACEHOLDER}, is written in the source.",
        "Secrets are read from the environment or a store, or the only literals are not secrets (names, URLs, paths, versions).",
    ),
    "insecure_deserialization": (
        "Does the code load data with pickle, marshal, or an unsafe YAML loader (yaml.load without a safe loader), "
        "where the data could come from outside the program?",
        "Data is deserialized with an unsafe loader.",
        "Only safe formats or loaders are used (for example json or yaml.safe_load), or nothing is deserialized.",
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
        "Does the code send a network request to a URL or host that comes from a variable or from input, without "
        "checking it against an allow-list of permitted hosts?",
        "A request goes to a URL supplied from outside without a check.",
        "The URL is fixed, or it is validated against an allow-list.",
    ),
    "xss_or_template_injection": (
        "Does the code build a template from variable text (for example a template created from user text, or an "
        "f-string passed to a template engine as the template itself), or switch off HTML auto-escaping in a "
        "template environment?",
        "Template source comes from changing text, or auto-escaping is off.",
        "Templates are fixed, values are passed as template variables, and auto-escaping is on.",
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


def build_questions(categories: Iterable[str] | None = None, include_verdict: bool = True) -> list[Question]:
    """The yes/no questions (one per category) and, by default, the verdict question, ready to send."""
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

    # every concrete vulnerability category has a question; "other" is a catch-all with no testable condition
    assert set(CATEGORY_IDS) == set(VULN_TYPES) - {"other"}, set(VULN_TYPES) ^ set(CATEGORY_IDS)

    everything = build_questions()
    assert len(everything) == len(CATEGORY_IDS) + 1 and everything[-1].id == VERDICT_ID
    assert len({q.id for q in everything}) == len(everything)
    validate_questions(everything)

    for question in everything[:-1]:
        assert question.kind == "yes_no" and set(question.options) == {"true", "false"}
        assert question.instructions.endswith("?") and len(question.instructions) > 60, question.id
    verdict = everything[-1]
    assert set(verdict.options) == set(CATEGORY_IDS) | {"none", "cannot_tell"}      # it can abstain, as Microsoft advises

    # the masked-secret marker is explained, using the very marker the masking produces
    secrets_question = next(q for q in everything if q.id == "hardcoded_credentials")
    assert PLACEHOLDER in secrets_question.instructions and PLACEHOLDER in secrets_question.options["true"]

    # every text is plain ASCII, so it prints safely in any Windows console
    for question in everything:
        for text in (question.id, question.instructions, *(question.options or {}).values()):
            assert text.isascii(), (question.id, text[:40])

    # a subset, without the verdict, and an unknown category
    subset = build_questions(["ssrf", "path_traversal"], include_verdict=False)
    assert [q.id for q in subset] == ["ssrf", "path_traversal"]
    try:
        build_questions(["telepathy"])
        raise AssertionError("expected an unknown category to be rejected")
    except ValueError:
        pass

    size = sum(len(q.instructions) + sum(len(v) for v in (q.options or {}).values()) for q in everything)
    print(f"core.questions OK: {len(CATEGORY_IDS)} category questions plus a verdict that can abstain; all valid, ASCII, "
          f"about {size // 4} tokens of question text per request")


if __name__ == "__main__":
    demo()
