"""
security_service/api/__main__.py

Start the HTTP service, or prepare to:

    python -m security_service.api --new-key     make a strong random API key, and show the line to put in .env
    python -m security_service.api --check       show the service settings and any problem, without starting it
    python -m security_service.api               start the service (Ctrl+C stops it)

Settings come from your terminal and .env, as everywhere else. The service refuses to start, and says why, when there is no
valid API key or when Decision-1 is switched on but not configured. It never starts without authentication.

Submitted code and results are kept in memory only, for SERVICE_RETENTION_HOURS. Stopping the service forgets all of it.
"""

from __future__ import annotations

import os
import sys

from security_service.api.auth import new_key
from security_service.config import Settings, load_env_file

COULD_NOT_START = 4


def main(argv: list[str], environ=None, out=print, serve=None) -> int:
    if "--new-key" in argv:
        key = new_key()
        out("A new API key (shown once; this program does not store it):\n")
        out(f"    {key}\n")
        out("Put it in .env on the machine that runs the service, giving the caller a name and its scopes:\n")
        out(f"    SERVICE_API_KEYS=flwn-ai:scan+fix+read:{key}\n")
        out("Give the same key only to the service that will call this one, as  Authorization: Bearer <key>.")
        out("Several callers: separate entries with commas. Never commit .env, and never paste a key into a chat or a ticket.")
        return 0

    if environ is None:
        load_env_file()
        environ = os.environ
    settings = Settings.from_env(environ)
    if "--check" in argv:
        out(settings.describe_service())
        return 0 if not settings.service_problems() else COULD_NOT_START

    problems = settings.service_problems()
    if problems:
        out("The service cannot start:\n" + "\n".join(f"  - {p}" for p in problems))
        out("Run  python -m security_service.api --check  to see the settings, or  --new-key  to make a key.")
        return COULD_NOT_START
    from security_service.api.app import build_app
    try:
        app = build_app(settings)
    except ValueError as problem:
        out(f"The service cannot start: {problem}")
        return COULD_NOT_START
    out(settings.describe_service())
    out("\nStarting. Press Ctrl+C to stop.")
    if serve is None:
        import logging

        import uvicorn

        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")      # one line per request, never a body or a key
        serve = lambda application: uvicorn.run(application, host=settings.service_host, port=settings.service_port, log_level="info", access_log=False)
    try:
        serve(app)
    except KeyboardInterrupt:
        pass
    return 0


def selftest() -> None:
    from security_service.api.auth import parse_api_keys

    lines: list[str] = []
    say = lines.append

    # --new-key prints a key that this service then accepts, and never needs a settings file
    assert main(["--new-key"], environ={}, out=say) == 0
    text = "\n".join(lines)
    key = next(line.strip() for line in lines if line.strip() and " " not in line.strip() and len(line.strip()) >= 24)
    ring, problems = parse_api_keys(f"x:scan+fix+read:{key}")
    assert not problems and ring.authenticate(key) is not None and f"SERVICE_API_KEYS=flwn-ai:scan+fix+read:{key}" in text and "Never commit" in text
    lines.clear()
    main(["--new-key"], environ={}, out=say)
    assert key not in "\n".join(lines)                                       # every call is a fresh key

    # --check shows the settings without a key, and a clear problem when there is none
    assert main(["--check"], environ={}, out=say) == COULD_NOT_START
    assert "NONE" in lines[-1] and "SERVICE_API_KEYS is empty" in lines[-1]
    good = {"SERVICE_API_KEYS": f"flwn-ai:scan+fix+read:{key}", "SERVICE_PORT": "9001"}
    lines.clear()
    assert main(["--check"], environ=good, out=say) == 0
    assert "http://127.0.0.1:9001" in lines[-1] and "flwn-ai (scan+fix+read)" in lines[-1] and key not in lines[-1] and "Problems: none" in lines[-1]

    # it refuses to start without a key, or with Decision-1 switched on but not configured, and says why without a stack trace
    lines.clear()
    started: list[object] = []
    assert main([], environ={}, out=say, serve=started.append) == COULD_NOT_START and not started and "cannot start" in lines[0]
    lines.clear()
    assert main([], environ={**good, "CLASSIFIER_ENABLED": "true"}, out=say, serve=started.append) == COULD_NOT_START and not started
    assert "CLASSIFIER_ENABLED is on but" in lines[0] and "Traceback" not in "\n".join(lines)

    # a valid configuration builds the app and hands it to the server, printing the settings (never the key)
    lines.clear()
    assert main([], environ=good, out=say, serve=started.append) == 0 and len(started) == 1
    assert key not in "\n".join(lines) and "Starting" in "\n".join(lines)
    started[0].state  # a real application object
    print("api.__main__ OK: new keys are accepted by the service, --check never shows a key, it will not start without a key or with a broken Decision-1 setup")


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        selftest()
    else:
        sys.exit(main(sys.argv[1:]))
