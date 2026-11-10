#!/usr/bin/env node
/**
 * src/cli.ts
 *
 * `phylax-review`: the review workflow in a terminal, for use after ANY coding agent has finished (or with none). It reads the files you choose,
 * asks Phylax to scan them, lists what it found, asks which findings you want corrected, shows each correction as a diff, and applies it only if
 * you type y. There is deliberately no --yes flag: nothing is ever applied without your explicit answer to that file's diff.
 *
 *     export PHYLAX_API_KEY=...            (never put the key on the command line)
 *     phylax-review                        review the whole project in this folder
 *     phylax-review src/app.js src/db.ts   review just these files
 *     phylax-review --report-only          scan and report; never ask about corrections
 *
 * Exit code: 0 the review finished clean (nothing at medium severity or above left unresolved, nothing unscanned); 1 it did not; 2 it could not run.
 */

import { stdin, stdout, stderr, argv, env, exit } from 'node:process';
import path from 'node:path';
import { createInterface } from 'node:readline/promises';
import { pathToFileURL } from 'node:url';

import { HttpPhylaxApi } from './api.js';
import { DiskFileChanger } from './adapters/disk.js';
import { OqeliraFileChanger, type OqeliraChangesModule } from './adapters/oqelira.js';
import { PhylaxError } from './errors.js';
import { formatOutcomes, formatProposal, formatSummary, formatVerification } from './format.js';
import type { Approver, FileChanger, FileSelection } from './interfaces.js';
import { SecurityReview, type ReviewResult } from './review.js';

const HELP = `phylax-review: ask Phylax to review the code your coding agent wrote.

Usage: phylax-review [FILE ...] [options]

  FILE ...                  review just these files (default: every source file in the project)
  --project DIR             the project folder (default: the current folder)
  --server URL              the Phylax address (default: $PHYLAX_URL, else http://127.0.0.1:8080)
  --report-only             scan and report; never ask about corrections
  --apply-with disk|oqelira how approved corrections are written (default: disk)
  --oqelira-changes FILE    Oqelira's changes.mjs, for --apply-with oqelira
  -h, --help                this text

The API key is read from $PHYLAX_API_KEY. Nothing is applied without your explicit yes to that file's diff.
`;

export interface Parsed {
  files: string[];
  project: string;
  server: string;
  reportOnly: boolean;
  applyWith: 'disk' | 'oqelira';
  oqeliraChanges: string | null;
  help: boolean;
}

export function parseArguments(args: string[], environment: Record<string, string | undefined>): Parsed {
  const parsed: Parsed = { files: [], project: '.', server: environment['PHYLAX_URL'] ?? 'http://127.0.0.1:8080', reportOnly: false, applyWith: 'disk', oqeliraChanges: null, help: false };
  const value = (i: number, flag: string): string => {
    const next = args[i + 1];
    if (next === undefined || next.startsWith('--')) throw new PhylaxError('usage', `${flag} needs a value.`);
    return next;
  };
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i] as string;
    if (arg === '-h' || arg === '--help') parsed.help = true;
    else if (arg === '--report-only') parsed.reportOnly = true;
    else if (arg === '--project') parsed.project = value(i++, arg);
    else if (arg === '--server') parsed.server = value(i++, arg);
    else if (arg === '--oqelira-changes') parsed.oqeliraChanges = value(i++, arg);
    else if (arg === '--apply-with') {
      const mode = value(i++, arg);
      if (mode !== 'disk' && mode !== 'oqelira') throw new PhylaxError('usage', '--apply-with must be disk or oqelira.');
      parsed.applyWith = mode;
    } else if (arg === '--key' || arg.startsWith('--key=') || arg === '--yes' || arg === '-y' || arg.startsWith('--yes=')) {
      throw new PhylaxError('usage', arg.startsWith('--key') ? 'Do not put the key on the command line: set PHYLAX_API_KEY.' : 'There is no --yes: every correction needs your explicit answer.');
    } else if (arg.startsWith('-')) throw new PhylaxError('usage', `Unknown option ${arg}. Try --help.`);
    else parsed.files.push(arg);
  }
  return parsed;
}

/** The person at the terminal. Everything they are asked, they answer; nothing has a default that writes. */
export function terminalApprover(ask: (question: string) => Promise<string>, say: (text: string) => void): Approver {
  return {
    async chooseCorrections(candidates) {
      say('');
      candidates.forEach((c, i) => say(`  ${i + 1}. ${c.finding.severity.toUpperCase()} ${c.finding.vulnerability_type} at ${c.finding.path ?? '?'}${c.finding.line ? `:${c.finding.line}` : ''}`));
      const answer = (await ask('\nCorrect which? Numbers like 1,3, "all", or Enter to skip: ')).trim().toLowerCase();
      if (answer === '') return [];
      if (answer === 'all') return candidates.map((c) => c.key);
      const picked = new Set<string>();
      for (const part of answer.split(/[\s,]+/)) {
        const index = Number(part);
        const chosen = Number.isInteger(index) ? candidates[index - 1] : undefined;
        if (chosen) picked.add(chosen.key);
        else if (part) say(`  (ignoring "${part}")`);
      }
      return [...picked];
    },
    async approveChange(proposal) {
      say(`\n${formatProposal(proposal)}\n`);
      const answer = (await ask(`Apply this correction to ${proposal.path}? [y/N] `)).trim().toLowerCase();
      return answer === 'y' || answer === 'yes' ? { approved: true } : { approved: false, reason: 'you answered no' };
    },
  };
}

async function buildFiles(parsed: Parsed): Promise<FileChanger> {
  const project = path.resolve(parsed.project);
  if (parsed.applyWith === 'disk') return new DiskFileChanger(project);
  if (!parsed.oqeliraChanges) throw new PhylaxError('usage', '--apply-with oqelira needs --oqelira-changes FILE (Oqelira\'s changes.mjs).');
  const changes = (await import(pathToFileURL(path.resolve(parsed.oqeliraChanges)).href)) as OqeliraChangesModule;
  return new OqeliraFileChanger({ cwd: project, changes });
}

export function toSelection(parsed: Parsed): FileSelection {
  if (parsed.files.length === 0) return { kind: 'project' };
  const project = path.resolve(parsed.project);
  return { kind: 'files', paths: parsed.files.map((file) => path.relative(project, path.resolve(project, file)).split(path.sep).join('/')) };
}

/** 0 only if the review is clean: nothing at medium severity or above is left unresolved, nothing could not be scanned, and no check failed to run. */
export function exitCodeFor(result: ReviewResult): number {
  const { summary } = result;
  if (summary.decision === 'scan_failed' || summary.unscanned.some((u) => u.blocksPass) || summary.engineProblems.length > 0) return 1;
  const resolved = new Set(result.verification.flatMap((v) => v.resolved.map((f) => `${v.scanId}:${f.id}`)));
  return summary.correctable.every((f) => resolved.has(f.key)) ? 0 : 1;
}

export async function main(args: string[], environment: Record<string, string | undefined> = env, out: (text: string) => void = (t) => stdout.write(`${t}\n`)): Promise<number> {
  let parsed: Parsed;
  try {
    parsed = parseArguments(args, environment);
  } catch (error) {
    stderr.write(`${(error as Error).message}\n`);
    return 2;
  }
  if (parsed.help) {
    out(HELP);
    return 0;
  }
  const apiKey = environment['PHYLAX_API_KEY'];
  if (!apiKey) {
    stderr.write('Set PHYLAX_API_KEY to your Phylax API key first (it is never taken from the command line).\n');
    return 2;
  }
  const readline = stdin.isTTY ? createInterface({ input: stdin, output: stdout }) : null;
  try {
    const review = new SecurityReview({
      phylax: new HttpPhylaxApi({ baseUrl: parsed.server, apiKey }),
      files: await buildFiles(parsed),
      onProgress: (message) => out(message),
    });
    if (parsed.reportOnly || !readline) {
      const summary = await review.scan(toSelection(parsed));
      out(`\n${formatSummary(summary)}`);
      if (!parsed.reportOnly) out('\nThis is not an interactive terminal, so no corrections were offered. Run it in a terminal to review and approve corrections.');
      await review.close();
      return summary.decision === 'pass' ? 0 : 1;
    }
    const result = await review.runInteractive(toSelection(parsed), terminalApprover((q) => readline.question(q), out));
    out(`\n${formatSummary(result.summary)}`);
    if (result.proposals) {
      for (const n of result.proposals.notCorrected) out(`\nNo correction for ${n.findings.map((f) => f.vulnerability_type).join(', ')}: ${n.reason}`);
      out(`\n${formatOutcomes(result.outcomes)}`);
      out(`\n${formatVerification(result.verification)}`);
    }
    return exitCodeFor(result);
  } catch (error) {
    stderr.write(`${error instanceof PhylaxError ? error.message : `Unexpected problem: ${(error as Error).message}`}\n`);
    return 2;
  } finally {
    readline?.close();
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(argv.slice(2)).then((code) => exit(code), (error: unknown) => {
    stderr.write(`${(error as Error).message}\n`);
    exit(2);
  });
}
