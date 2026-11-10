// Runs every compiled test file with Node's built-in test runner, ONE FILE AT A TIME, so that a stall names the file instead of freezing the whole run.
// Portable: it lists the files itself (PowerShell, cmd and bash differ on wildcards, and Node versions differ on what `node --test` accepts).
// A file that runs longer than PHYLAX_TEST_FILE_TIMEOUT_MS (default 120 s) is stopped together with everything it started, and reported by name.
import { spawn, spawnSync } from 'node:child_process';
import { readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const folder = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'dist', 'test');
const files = readdirSync(folder).filter((name) => name.endsWith('.test.js')).sort();
if (files.length === 0) {
  console.error('No compiled tests found in dist/test. Run "npm run build" first.');
  process.exit(2);
}

const fileTimeout = Number(process.env.PHYLAX_TEST_FILE_TIMEOUT_MS ?? 120_000);
const totalTimeout = Number(process.env.PHYLAX_TEST_TOTAL_TIMEOUT_MS ?? 240_000);
const [major = 0, minor = 0] = process.versions.node.split('.').map(Number);
const hasTestTimeout = major > 22 || major === 22 || major === 21 && minor >= 2 || major === 20 && minor >= 11;      // --test-timeout: one test can never run forever

function killTree(child) {
  if (child.pid === undefined) return;
  if (process.platform === 'win32') spawnSync('taskkill', ['/pid', String(child.pid), '/T', '/F'], { stdio: 'ignore' });   // Windows: killing a process leaves its children running
  else child.kill('SIGKILL');
}

// Node prints its totals as "# pass 10" (TAP) or "\u2139 pass 10" (the spec reporter, the default on newer versions); read either.
const countOf = (output, key) => Number((output.match(new RegExp(`(?:#|\\u2139)\\s+${key}\\s+(\\d+)`)) ?? [0, 0])[1]);

const started = Date.now();
const totals = { tests: 0, pass: 0, fail: 0, cancelled: 0, skipped: 0 };
const problems = [];

for (const name of files) {
  const remaining = totalTimeout - (Date.now() - started);
  if (remaining <= 0) { problems.push(`${name}: not run (the ${totalTimeout / 1000} s total time limit was reached)`); continue; }
  const limit = Math.min(fileTimeout, remaining);
  console.log(`\n=== ${name} ===`);
  const result = await new Promise((resolve) => {
    const args = ['--test', ...(hasTestTimeout ? ['--test-timeout=90000'] : []), path.join(folder, name)];
    const child = spawn(process.execPath, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let output = '';
    let timedOut = false;
    for (const stream of [child.stdout, child.stderr]) stream.on('data', (chunk) => { output += chunk; process.stdout.write(chunk); });
    const timer = setTimeout(() => { timedOut = true; killTree(child); }, limit);
    child.on('exit', (code) => { clearTimeout(timer); resolve({ code, output, timedOut }); });
  });
  for (const key of Object.keys(totals)) totals[key] += countOf(result.output, key);
  if (result.timedOut) problems.push(`${name}: STALLED, stopped after ${limit / 1000} s (look at the last test named above)`);
  else if (result.code !== 0) problems.push(`${name}: failed (exit code ${result.code})`);
}

console.log('\n=== summary ===');
if (problems.length > 0) console.log(problems.map((p) => `  - ${p}`).join('\n'));
console.log(`# tests ${totals.tests}\n# pass ${totals.pass}\n# fail ${totals.fail + totals.cancelled + problems.length}\n# skipped ${totals.skipped}`);
process.exit(problems.length === 0 && totals.fail === 0 && totals.cancelled === 0 ? 0 : 1);
