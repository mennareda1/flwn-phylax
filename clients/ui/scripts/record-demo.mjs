// Records the demo's data from the REAL Phylax pipeline: the real scanner, verifier and contract, with the correction model played by the test stand-in.
// It starts the real service (python -m tests.serve_for_clients), scans the sample project in every state the demo can reach, asks for the corrections,
// verifies them, and writes src/api/demo/recorded.json. Needs Python with the Phylax packages, and the TypeScript client built (npm run build in ../typescript).
//
//   npm run record-demo            (set PHYLAX_PYTHON to choose the Python)
import { spawn } from 'node:child_process';
import { writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { SAMPLE_PROJECT } from './sample-project.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '..', '..', '..');
const client = await import(pathToFileURL(path.resolve(root, 'clients', 'typescript', 'dist', 'src', 'index.js')).href);

const python = process.env.PHYLAX_PYTHON ?? (process.platform === 'win32' ? 'python' : 'python3');
const helper = spawn(python, ['-m', 'tests.serve_for_clients'], { cwd: root, env: { ...process.env, PYTHONUNBUFFERED: '1' } });
const info = await new Promise((resolve, reject) => {
  let buffer = '';
  helper.stdout.on('data', (chunk) => { buffer += chunk; if (buffer.includes('\n')) resolve(JSON.parse(buffer.split('\n')[0])); });
  helper.on('error', reject);
  helper.on('exit', () => reject(new Error('the service did not start')));
  setTimeout(() => reject(new Error('the service did not start in time')), 60_000);
});

try {
  const api = new client.HttpPhylaxApi({ baseUrl: info.url, apiKey: info.key, pollIntervalMs: 50 });
  const capabilities = await api.capabilities();
  const toInput = (files) => Object.entries(files).sort(([a], [b]) => (a < b ? -1 : 1)).map(([p, content]) => ({ path: p, content }));
  const original = SAMPLE_PROJECT.files;

  // 1. the scan of the project as it is, and the corrections for everything that is eligible
  const first = await api.scan(toInput(original));
  const eligible = first.report.findings.filter((f) => f.fix.eligible);
  const key = (paths) => (paths.length === 0 ? 'none' : [...paths].sort().join('+'));

  // 2. a correction for EVERY combination of eligible files, so the checks shown for one file are the checks of that file alone
  const eligiblePaths = [...new Set(eligible.map((f) => f.path))].sort();
  const combinations = [];
  for (let mask = 1; mask < 1 << eligiblePaths.length; mask += 1) combinations.push(eligiblePaths.filter((_, i) => mask & (1 << i)));
  const fixes = {};
  for (const combo of combinations) {
    const ids = eligible.filter((f) => combo.includes(f.path)).map((f) => f.id);
    const result = await api.fix(first.id, { findingIds: ids });
    if (!result.applicable) throw new Error(`the recorded correction for ${key(combo)} was not applicable: ${result.failure_reason}`);
    fixes[key(combo)] = result;
  }
  const fix = fixes[key(eligiblePaths)];

  // 3. every state the demo can reach: which of the corrected files have been applied
  const subsets = [[], ...combinations];
  const scans = { none: first };
  const verifications = {};
  for (const subset of subsets) {
    const files = { ...original };
    for (const patch of fix.patches) if (subset.includes(patch.path)) files[patch.path] = patch.corrected_content;
    if (subset.length > 0) {
      scans[key(subset)] = await api.scan(toInput(files));
      const changed = Object.fromEntries(subset.map((p) => [p, files[p]]));
      verifications[key(subset)] = await api.verify(first.id, toInput(changed));
    }
  }

  const recorded = {
    recorded_with: `Phylax contract ${capabilities.contract_version}: the real scanner and verifier, the correction model played by the test stand-in`,
    project: SAMPLE_PROJECT,
    capabilities,
    scans,
    fixes,
    verifications,
  };
  const out = path.resolve(here, '..', 'src', 'api', 'demo', 'recorded.json');
  await writeFile(out, JSON.stringify(recorded, null, 1) + '\n', 'utf8');
  const summary = Object.entries(scans).map(([k, s]) => `${k}: ${s.report.decision}, ${s.report.findings.length} finding(s)`).join(' | ');
  console.log(`Recorded ${Object.keys(scans).length} scans, ${Object.keys(fixes).length} sets of corrections, ${Object.keys(verifications).length} verifications.\n${summary}\nWrote ${path.relative(root, out)}`);
} finally {
  helper.stdin.end();
  setTimeout(() => helper.kill(), 5000).unref();
}
