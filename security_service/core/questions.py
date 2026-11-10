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

JavaScript and TypeScript (2026-11, "js-1"): the same twelve categories with the same shape, worded for that language (child_process.exec,
innerHTML, $where, Math.random...). Written BEFORE any model saw a JavaScript case, and judged the way the Python set was: tuned on
benchmark/cases_javascript.py, then judged once on benchmark/cases_heldout_js.py. Until that held-out run passes, Decision-1 is NOT
asked about JavaScript in scans (CLASSIFIER_LANGUAGES stays "python").

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

# The same categories, worded for JavaScript and TypeScript (a TypeScript file is asked the JavaScript questions).
_CATEGORY_TEXT_JS = {
    "command_injection": (
        "Does the code build an operating-system command from a variable or other changing value (for example by joining text into the string "
        "given to child_process.exec or execSync, by passing a built string to spawn or execFile with shell: true, or by running sh -c or "
        "cmd /c on a built string) instead of running a fixed program with its arguments passed as an array and no shell?",
        "A command is built from changing text.",
        "Commands are fixed, or arguments are passed as an array without a shell, or no command is run.",
    ),
    "sql_injection": (
        "Does the code build an SQL query (or a MongoDB $where clause) by joining or interpolating a variable or other changing value (not a "
        "fixed constant) into the query text, using string concatenation or a template literal with ${...}, instead of passing the values as "
        "separate query parameters (placeholders such as $1, ? or :name) or query operators?",
        "Changing text becomes part of the query string.",
        "Values are passed as parameters or operators, the query text is fixed, or no query is built.",
    ),
    "code_injection": (
        "Does the code run text as program code with eval, new Function, the vm module, or setTimeout or setInterval given a string, where "
        "that text comes from a variable or from input rather than being a fixed literal?",
        "Changing text is evaluated as code.",
        "Nothing is evaluated, or only a fixed literal is, or data is parsed safely with JSON.parse.",
    ),
    "insecure_deserialization": (
        "Does the code load data with an unsafe deserializer, such as node-serialize unserialize, or js-yaml load with DEFAULT_FULL_SCHEMA "
        "(a schema that can create functions), where the data could come from outside the program?",
        "Data is deserialized with an unsafe loader.",
        "Only safe formats or loaders are used (JSON.parse, or js-yaml safeLoad), or nothing is deserialized.",
    ),
    "weak_crypto": (
        "Does the code use a weak or broken algorithm for a security purpose, such as MD5 or SHA-1 to hash passwords or sign data, DES, 3DES "
        "or RC4 to encrypt, or ECB mode, including when the algorithm name is kept in a variable or constant?",
        "A weak algorithm protects something security-relevant.",
        "Modern algorithms are used, or a weak hash is used only for a non-security purpose such as a cache key or an ETag.",
    ),
    "insecure_random": (
        "Does the code use Math.random to generate a password, token, session or reset identifier, one-time code, key or other "
        "security-sensitive value?",
        "Predictable randomness creates a security-sensitive value.",
        "crypto.randomBytes, crypto.randomUUID or crypto.randomInt is used, or the randomness is not security-sensitive (for example an animation or a display shuffle).",
    ),
    "path_traversal": (
        "Does the code open, read, write, delete or serve a file (for example with fs.readFile, fs.createReadStream or res.sendFile) whose path "
        "is built from a variable or from input, including a function parameter that a request handler fills from the request, without "
        "checking that the final path stays inside an intended directory?",
        "A file path built from changing text is used without a check.",
        "The path is fixed, or it is resolved and checked against a base directory.",
    ),
    "ssrf": (
        "Running a command is not an HTTP request and does not count here. Does the code send an HTTP or HTTPS request (with fetch, axios, "
        "got, node-fetch, http.get or a similar library) to a URL that comes from a variable or from input, without checking the host "
        "against an allow-list?",
        "An HTTP request goes to a URL supplied from outside without a check.",
        "The URL is a fixed literal, or its host is validated against an allow-list, or no HTTP request is made.",
    ),
    "xss_or_template_injection": (
        "Does the code insert markup built from variable text into a page (for example by assigning it to innerHTML or outerHTML, or with "
        "document.write, insertAdjacentHTML or React dangerouslySetInnerHTML), or build a template from variable text (for example by "
        "giving it to ejs.render, pug.compile, Handlebars.compile or _.template), instead of setting textContent or passing values as "
        "template data?",
        "Markup or template source comes from changing text.",
        "Text is set with textContent, values are passed as template data, markup is sanitized with a vetted sanitizer such as DOMPurify, or the markup is a fixed literal.",
    ),
    "tls_verification_disabled": (
        "Does the code switch off TLS certificate verification, for example rejectUnauthorized: false in an https agent or in request "
        "options, strictSSL: false, or setting process.env.NODE_TLS_REJECT_UNAUTHORIZED to 0?",
        "Certificate checking is switched off.",
        "Certificates are verified, which is the default.",
    ),
    "debug_enabled": (
        "Does the code turn on debug or development behaviour that could be deployed, for example forcing NODE_ENV to development, "
        "error-handler options such as showStack or dumpExceptions, or sending err.stack to the client in a response?",
        "Debug behaviour or a stack trace is exposed.",
        "Debug is off or depends on the deployment environment, and the client gets a generic error message.",
    ),
    "insecure_temp_file": (
        "Does the code create a temporary file or directory with a predictable name, for example a fixed or guessable path under /tmp or "
        "os.tmpdir(), instead of fs.mkdtemp or a library such as tmp that creates a unique name?",
        "A temporary file with a predictable name is used.",
        "A unique temporary name is created (fs.mkdtemp or a library), or no temporary file is created.",
    ),
}
assert tuple(_CATEGORY_TEXT_JS) == CATEGORY_IDS

# What the model's suggestion says to do, for a JavaScript or TypeScript file (the Python wording names pickle, ast and the secrets module).
RECOMMENDATIONS_JS = {
    "command_injection": "Use execFile or spawn with an argument array and no shell, and validate or allow-list any user-controlled value.",
    "sql_injection": "Use placeholders and pass the values separately ($1 or ?), never string building; for MongoDB use query operators instead of $where.",
    "code_injection": "Do not evaluate text as code. Parse data with JSON.parse or a purpose-built parser.",
    "insecure_deserialization": "Do not deserialize untrusted data with node-serialize or an unsafe YAML schema. Use JSON.parse or a safe loader.",
    "weak_crypto": "Use SHA-256 or better; for passwords use a dedicated slow hash such as argon2, bcrypt or scrypt; for encryption use AES-256-GCM.",
    "insecure_random": "Use crypto.randomBytes, crypto.randomUUID or crypto.randomInt for tokens, codes and anything security-sensitive.",
    "path_traversal": "Resolve the final path with path.resolve and check it stays inside the intended base folder before opening it.",
    "ssrf": "Validate user-supplied URLs against an allow-list of hosts and block internal address ranges.",
    "xss_or_template_injection": "Set text with textContent or pass values as template data; if markup is needed, sanitize it with a vetted library such as DOMPurify.",
    "tls_verification_disabled": "Keep certificate verification enabled; fix the certificate chain instead of disabling checks.",
    "debug_enabled": "Disable debug behaviour outside local development, and send the client a generic error message instead of a stack trace.",
    "insecure_temp_file": "Create a unique temporary file or folder with fs.mkdtemp instead of a predictable name.",
}


def question_family(language: str) -> str:
    """Which wording a language is asked: TypeScript shares JavaScript's."""
    return "javascript" if language in ("javascript", "typescript") else language

def build_questions(categories: Iterable[str] | None = None, include_verdict: bool = False, language: str = "python") -> list[Question]:
    """The yes/no questions (one per category), ready to send. The verdict question is off by default: in the first real
    run it named a problem on 14 of 27 safe cases, including clean fixes the yes/no questions judged safe."""
    family = question_family(language)
    if family not in ("python", "javascript"):
        raise ValueError(f"no questions are written for language {language!r}")
    text = _CATEGORY_TEXT_JS if family == "javascript" else _CATEGORY_TEXT
    chosen = tuple(categories) if categories is not None else CATEGORY_IDS
    unknown = [c for c in chosen if c not in text]
    if unknown:
        raise ValueError(f"no question for category {unknown[0]!r}")
    questions = [
        Question(name, "yes_no", text[name][0], {"true": text[name][1], "false": text[name][2]})
        for name in chosen
    ]
    if include_verdict:
        options = {name: text[name][1] for name in chosen}
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

    # the JavaScript set: the same twelve categories in the same order and shape, in JavaScript's words and none of Python's
    js = build_questions(language="javascript")
    assert [q.id for q in js] == [q.id for q in everything] == list(CATEGORY_IDS) and [q.id for q in build_questions(language="typescript")] == list(CATEGORY_IDS)
    assert [q.instructions for q in build_questions(language="typescript")] == [q.instructions for q in js] != [q.instructions for q in everything]
    for question in js:
        assert question.kind == "yes_no" and set(question.options) == {"true", "false"} and question.instructions.endswith("?") and len(question.instructions) > 60, question.id
        assert question.instructions.isascii() and all(piece.isascii() for piece in question.options.values()), question.id
        assert "REDACTED" not in question.instructions and "secret" not in question.instructions.lower(), question.id
        for python_word in ("os.system", "subprocess", "pickle", "yaml.safe_load", "f-string", "render_template_string", "requests", "tempfile", "random module", "ast.literal_eval", "DEBUG = True"):
            assert python_word not in question.instructions, (question.id, python_word)
    js_text = {q.id: q.instructions for q in js}
    assert "child_process.exec" in js_text["command_injection"] and "sh -c" in js_text["command_injection"] and "$where" in js_text["sql_injection"]
    assert "new Function" in js_text["code_injection"] and "setTimeout" in js_text["code_injection"] and "DEFAULT_FULL_SCHEMA" in js_text["insecure_deserialization"]
    assert "Math.random" in js_text["insecure_random"] and "innerHTML" in js_text["xss_or_template_injection"] and "rejectUnauthorized" in js_text["tls_verification_disabled"]
    assert "ping" not in js_text["ssrf"] and "not an HTTP request" in js_text["ssrf"] and "fetch" in js_text["ssrf"] and "variable or constant" in js_text["weak_crypto"]
    assert set(RECOMMENDATIONS_JS) == set(CATEGORY_IDS) and all(r.endswith(".") and r.isascii() and not any(word in r for word in ("pickle", "secrets module", "ast.", "literal_eval", "safe_load", "shell=True", "tempfile", "subprocess", "random module", "os.urandom")) for r in RECOMMENDATIONS_JS.values())
    assert question_family("typescript") == question_family("javascript") == "javascript" and question_family("python") == "python"
    try:
        build_questions(language="cobol")
        raise AssertionError("an unknown language must be refused")
    except ValueError:
        pass
    for unknown in ("hardcoded_credentials", "telepathy"):
        try:
            build_questions([unknown], language="javascript")
            raise AssertionError(f"expected {unknown!r} to be rejected")
        except ValueError:
            pass
    size = sum(len(q.instructions) + sum(len(v) for v in (q.options or {}).values()) for q in everything)
    print(f"core.questions OK: {len(CATEGORY_IDS)} yes/no questions, none about secrets, verdict off by default; all valid and ASCII, "
          f"about {size // 4} tokens of question text per request")


if __name__ == "__main__":
    demo()
