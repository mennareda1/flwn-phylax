"""
tests/check_interop.py

Phylax against Oqelira's REAL change-application code, run by Node. tests/fixtures/oqelira_changes.mjs is an unmodified copy of Oqelira's
changes.mjs (snapshotFile, applyFileChange, readFileChange). The test proves, on real files, the things the integration depends on:

  1. Phylax's `scanned_files[].sha256` equals Oqelira's snapshot hash, for LF files, Windows (CRLF) files and non-ASCII text.
  2. A Phylax patch (`corrected_content` with `base_sha256` as the expected hash) is accepted by Oqelira's applyFileChange, and the hash Oqelira
     reports afterwards equals Phylax's `corrected_sha256`. A Windows file stays a Windows file.
  3. The same patch is REFUSED when the file changed after the scan (the stale-write guard works with Phylax's hash).
  4. Oqelira's own revert restores the file exactly, and the restored file hashes to Phylax's `base_sha256` again.

Needs Node.js. Without it the test says so and passes nothing silently: it prints SKIPPED.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from security_service.core.fix_service import FixService
from security_service.core.files import SourceFile
from security_service.core.patching import make_unified_diff
from security_service.core.scan_service import ScanService
from security_service.ports.corrector import Patch

HERE = Path(__file__).resolve().parent
CHANGES = HERE / "fixtures" / "oqelira_changes.mjs"

DRIVER = """
import { pathToFileURL } from 'node:url'
const [, , modulePath, cwd, operation, payload] = process.argv
const changes = await import(pathToFileURL(modulePath).href)
try {
  const input = payload ? JSON.parse(payload) : undefined
  let result
  if (operation === 'snapshot') result = await changes.snapshotFile(cwd, input.path)
  else if (operation === 'apply') result = JSON.parse(await changes.applyFileChange(cwd, input))
  else if (operation === 'read') result = await changes.readFileChange(cwd, input.change_id)
  else if (operation === 'revert') result = JSON.parse(await changes.applyFileChange(cwd, input, true))
  process.stdout.write(JSON.stringify({ ok: true, result }))
} catch (error) {
  process.stdout.write(JSON.stringify({ ok: false, error: String(error.message) }))
}
"""


class Scripted:
    """A stand-in for the model: swaps the shell call for an argument list, answering in LF like the real model does."""
    role, name = "corrector", "scripted"

    def propose_fix(self, file, findings, constraints):
        new = file.content.replace("os.system('ping ' + host)", "subprocess.run(['ping', host], check=True)").replace("import os\n", "import subprocess\n")
        return [Patch(file.path, tuple(f.id for f in findings), make_unified_diff(file.path, file.content, new), "Replaced the shell call.")]


def run() -> str:
    if shutil.which("node") is None:
        return "check_interop SKIPPED: Node.js is not installed, so Oqelira's changes.mjs cannot be run (install Node 20+ to run this test)"

    with tempfile.TemporaryDirectory() as folder:
        project = Path(folder) / "project"
        (project / "app").mkdir(parents=True)
        driver = Path(folder) / "driver.mjs"
        driver.write_text(DRIVER, encoding="utf-8")

        def oqelira(operation: str, payload: dict | None = None) -> dict:
            done = subprocess.run(["node", str(driver), str(CHANGES), str(project), operation, json.dumps(payload) if payload is not None else ""],
                                  capture_output=True, text=True, encoding="utf-8", timeout=60)
            assert done.returncode == 0, done.stderr
            return json.loads(done.stdout)

        ping = "import os\r\n\r\ndef ping(host):\r\n    os.system('ping ' + host)\r\n"
        files = {"app/win.py": ping, "app/unix.py": ping.replace("\r\n", "\n"), "app/text.py": '# caf\u00e9 \u2014 \u65e5\u672c\u8a9e \U0001f600\nx = 1\n'}
        for name, text in files.items():
            (project / name).write_bytes(text.encode("utf-8"))                                           # exact bytes: no newline translation

        # ---- 1. the hashes agree, file by file, for LF, CRLF and non-ASCII text
        service = ScanService()
        for name in files:
            text = (project / name).read_bytes().decode("utf-8")
            theirs = oqelira("snapshot", {"path": name})
            assert theirs["ok"] and theirs["result"]["content"] == text, (name, theirs)
            ours = {f["path"]: f["sha256"] for f in service.scan([SourceFile(name, text)]).coverage.to_dict()["scanned_files"]}
            assert ours[name] == theirs["result"]["sha256"], f"{name}: Phylax and Oqelira disagree on the hash"

        # ---- 2. a Phylax patch is accepted by Oqelira's applyFileChange; Windows line endings survive
        for name in ("app/win.py", "app/unix.py"):
            text = (project / name).read_bytes().decode("utf-8")
            report = service.scan([SourceFile(name, text)])
            fix = FixService(service, Scripted()).fix([SourceFile(name, text)], report.findings)
            assert fix.applicable, fix.failure_reason
            patch = fix.patches[0]
            assert patch.base_sha256 == oqelira("snapshot", {"path": name})["result"]["sha256"]             # the expected hash is exactly what Oqelira sees now
            applied = oqelira("apply", {"path": name, "expected_sha256": patch.base_sha256, "content": patch.corrected_content})
            assert applied["ok"], applied
            on_disk = (project / name).read_bytes().decode("utf-8")
            assert on_disk == patch.corrected_content and applied["result"]["sha256"] == patch.corrected_sha256, name
            assert ("\r\n" in on_disk) == (name == "app/win.py") and ("\n" in on_disk.replace("\r\n", "")) == (name == "app/unix.py"), "line endings must survive"
            assert "subprocess.run" in on_disk and "os.system" not in on_disk

            # ---- 4. Oqelira's own revert restores the file, and it hashes to Phylax's base hash again
            recorded = oqelira("read", {"change_id": applied["result"]["change_id"]})
            assert recorded["ok"] and recorded["result"]["content"] == text
            reverted = oqelira("revert", recorded["result"])
            assert reverted["ok"], reverted
            assert (project / name).read_bytes().decode("utf-8") == text and reverted["result"]["sha256"] == patch.base_sha256

            # ---- 3. the stale-write guard: the file changed after the scan, so the same patch is refused and nothing is overwritten
            (project / name).write_bytes((text + "# a human edited this after the scan\n").encode("utf-8"))
            stale = oqelira("apply", {"path": name, "expected_sha256": patch.base_sha256, "content": patch.corrected_content})
            assert not stale["ok"] and "File changed since preview" in stale["error"], stale
            assert (project / name).read_bytes().decode("utf-8") == text + "# a human edited this after the scan\n"

    return ("check_interop OK: Oqelira's real changes.mjs under Node agrees with Phylax on the hash (LF, CRLF, non-ASCII), applies a Phylax patch and keeps Windows "
            "line endings, refuses a stale patch, and reverts exactly")


if __name__ == "__main__":
    try:
        message = run()
    except AssertionError as problem:
        print("INTEROP CHECK FAILED:", problem)
        sys.exit(1)
    print(message)
