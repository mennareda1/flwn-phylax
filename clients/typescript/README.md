# phylax-review: the Phylax review client (TypeScript)

Phylax is a separate security service. It scans code, and it never touches your files. This package is the small client that lets **any coding agent**
(Oqelira today, others later) offer a security review **after** the agent has finished its task, and apply a correction **only after a person approves it**.

It is optional by design: nothing here runs inside an agent's execution loop. The user asks for a review; the review runs.

## The workflow

1. The agent finishes its task as usual.
2. The user asks for a security review.
3. The client reads the files they chose and sends them to Phylax (rules and the decision model run together).
4. It lists what was found. Each finding says whether a **correction is offered** (`finding.fix`), independent of the overall verdict:
   medium severity and above, yes; low and informational, reported only; a hardcoded secret is never edited away (rotate it).
5. The user picks which findings to correct. Only those are sent for a correction (each one is a model call that costs money).
6. Each correction is shown as a diff. **Nothing is written without an explicit yes to that file's diff.**
7. An approved correction is applied through the host's own change mechanism (the `FileChanger` below), which refuses if the file changed since the scan.
8. Phylax verifies what is now on disk against the original scan and reports resolved, still present, and new findings.

## Use it from a terminal (no agent needed)

```
npm install
npm run build
export PHYLAX_API_KEY=...                  # PowerShell: $env:PHYLAX_API_KEY = "..."   (never put the key on the command line)
node dist/src/cli.js                       # review the project in this folder
node dist/src/cli.js src/app.js src/db.ts  # or just these files
node dist/src/cli.js --report-only         # scan and report, never ask about corrections
node dist/src/cli.js --apply-with oqelira --oqelira-changes path/to/changes.mjs
```

It reads `PHYLAX_URL` (default `http://127.0.0.1:8080`). There is deliberately no `--yes`. Exit code: 0 clean, 1 findings remain or something was not scanned, 2 it could not run.

## Use it from an agent: write an adapter in four methods

Phylax asks two things of a host, and nothing else. Implement them and the review works with your agent.

```ts
import { SecurityReview, HttpPhylaxApi, type FileChanger, type Approver } from 'phylax-review';

const files: FileChanger = {
  capabilities: { maxContentChars: 10000 },           // optional: the largest file your change mechanism accepts
  listFiles(selection) { /* { kind: 'project' } or { kind: 'files', paths } -> project-relative paths, stable order */ },
  read(path)           { /* -> { path, content, sha256 }: sha256 is SHA-256 (hex) of the exact UTF-8 text, line endings included */ },
  apply(change)        { /* { path, expectedSha256, content }: replace the file ONLY if it still has that hash; throw StaleFileError if not;
                           write the text exactly as given (no line-ending translation); -> { path, sha256, changeId? } */ },
  revert(changeId)     { /* optional undo */ },
};

const approver: Approver = {
  chooseCorrections(candidates) { /* show the findings, return the keys the person picked */ },
  approveChange(proposal)       { /* show proposal.diff, return { approved: true } only on an explicit yes */ },
};

const review = new SecurityReview({ phylax: new HttpPhylaxApi({ baseUrl, apiKey }), files });
const result = await review.runInteractive({ kind: 'project' }, approver);
```

Or drive the steps yourself: `scan()`, `proposeCorrections(keys)`, `applyProposal(proposal, approver)`, `verify(outcomes)`. If the host's hash of a file differs from Phylax's,
the review stops with `hash_mismatch` (a correction could never be applied safely), so get the hashing right first: SHA-256 of the exact text.

Two adapters are included:

- `DiskFileChanger(root)`: a plain folder. Atomic writes, hash-checked, exact bytes, never outside the project, never `.env`, keys or `.git`. Works with any agent.
- `OqeliraFileChanger({ cwd, changes })`: writes through Oqelira's own reviewed change mechanism (`changes.mjs`), so every correction is in Oqelira's ledger and can be reverted
  with Oqelira's own revert. You pass Oqelira's module in; this package never imports Oqelira. Oqelira accepts files of up to 10,000 characters: larger files can still be
  scanned, but a correction to them is shown and not applied (the review says so before asking anything).

## What the review promises (each is covered by a test)

- Which findings can be corrected comes from each finding, never from the verdict.
- A correction is requested only for findings the person chose, and applied only after an explicit yes. There is no "approve all" and no way to apply without an `Approver`.
- A correction for a file that changed since the scan (or while the person was reading the diff) is not applied; the person is not asked about one that is already stale.
- What is verified is what is on disk, and the scans are removed from the service afterwards, even if something fails half way.
- A file that cannot be scanned (not UTF-8, too large) is listed and stops a clean pass.
- The API key travels only in an `Authorization` header, only over https (or to this computer), and appears in no error or log line.

## Limits

Corrections are checked for safety, not behaviour: run the project's tests after applying. Phylax scans `.py .js .jsx .mjs .cjs .ts .tsx`; HTML and CSS are not scanned. Findings
from several batches of a large project are corrected one batch at a time. A file with mixed line endings comes back with LF.

## Tests

`npm test` (Node 20 or newer) builds and runs everything: the adapters, the HTTP client against a local server, the workflow with a scripted person, the Oqelira adapter against
Oqelira's real `changes.mjs`, and end-to-end tests against the real Python service (these start `python -m tests.serve_for_clients`; set `PHYLAX_PYTHON` to choose the Python, and
they are skipped with a reason if Python or its packages are missing).
