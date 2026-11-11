// The demo's backend. It replays what the REAL Phylax said about the sample project (src/api/demo/recorded.json, made by `npm run record-demo`): the real scanner's findings and
// reasons, the real corrections as diffs, the real checks. Nothing here talks to a network. It keeps the real rules: a correction is offered only for a file that is not
// already corrected, and what is verified is the set of files applied so far.
import recorded from './demo/recorded.json';

const DELAYS = { scan: 1500, propose: 1800, apply: 1000 };
const pathsKey = (paths) => (paths.length === 0 ? 'none' : [...paths].sort().join('+'));
const keyOf = (scan, finding) => `${scan.id}:${finding.id}`;

/**
 * @param {{ latency?: number }} options latency 1 is the demo's pace; 0 makes every call instant (tests).
 * The backend contract every screen uses: info(), scan(), propose(keys), apply(id), reset(), failNext(). A live backend can replace this file and nothing else changes.
 */
export function createDemoBackend({ latency = 1 } = {}) {
  let applied = new Set();
  let currentScan = null;
  let counter = 0;
  let failing = false;
  const proposals = new Map();
  const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms * latency));
  const maybeFail = () => {
    if (!failing) return;
    failing = false;
    throw Object.assign(new Error('Could not reach Phylax. Check the address and that the service is running.'), { code: 'unreachable' });
  };
  const firstScan = recorded.scans.none;
  const describe = (id) => {
    const finding = firstScan.report.findings.find((f) => f.id === id);
    return finding ? { path: finding.path, type: finding.vulnerability_type } : { path: null, type: 'other' };
  };

  return {
    mode: 'demo',

    async info() {
      return {
        mode: 'demo',
        projectName: recorded.project.name,
        files: Object.keys(recorded.project.files).sort(),
        corrections: recorded.capabilities.features?.fixes !== false,
        contractVersion: recorded.capabilities.contract_version,
        recordedWith: recorded.recorded_with,
      };
    },

    async scan() {
      await pause(DELAYS.scan);
      maybeFail();
      const scan = recorded.scans[pathsKey([...applied])];
      currentScan = scan;
      const { report } = scan;
      return {
        scanId: scan.id,
        decision: report.decision,
        riskLevel: report.risk_level,
        reasons: report.decision_reasons,
        findings: report.findings.map((f) => ({ ...f, key: keyOf(scan, f) })),
        coverage: report.coverage,
      };
    },

    async propose(keys) {
      await pause(DELAYS.propose);
      maybeFail();
      if (!currentScan) throw new Error('There is no scan yet. Scan first.');
      const wanted = currentScan.report.findings.filter((f) => keys.includes(keyOf(currentScan, f)));
      if (wanted.length === 0) throw new Error('None of those findings is part of the current scan. Scan again.');
      const notCorrected = wanted.filter((f) => !f.fix.eligible).map((f) => ({ keys: [keyOf(currentScan, f)], reason: f.fix.reason }));
      const paths = [...new Set(wanted.filter((f) => f.fix.eligible && !applied.has(f.path)).map((f) => f.path))].sort();
      if (paths.length === 0) return { proposals: [], notCorrected };
      const fix = recorded.fixes[pathsKey(paths)];
      if (!fix) throw new Error('No correction was recorded for that combination of files.');
      const made = fix.patches.map((patch) => {
        const proposal = {
          id: `prop_${++counter}`,
          path: patch.path,
          diff: patch.unified_diff,
          explanation: patch.explanation,
          findingKeys: wanted.filter((f) => f.path === patch.path).map((f) => keyOf(currentScan, f)),
          checks: fix.verification.checks,
          checkedTogether: fix.patches.map((p) => p.path),
        };
        proposals.set(proposal.id, proposal);
        return proposal;
      });
      return { proposals: made, notCorrected };
    },

    async apply(proposalId) {
      await pause(DELAYS.apply);
      maybeFail();
      const proposal = proposals.get(proposalId);
      if (!proposal) return { status: 'stale', message: 'That correction is not part of this review any more. Scan again.' };
      if (applied.has(proposal.path)) return { status: 'stale', message: `${proposal.path} was already corrected. Scan again.` };
      applied.add(proposal.path);
      const verification = recorded.verifications[pathsKey([...applied])];
      return {
        status: 'applied',
        message: `Applied the correction to ${proposal.path}.`,
        verification: {
          outcome: verification.outcome,
          resolved: verification.resolved_finding_ids.map(describe),
          introduced: verification.new_findings.map((f) => ({ path: f.path, type: f.vulnerability_type })),
          checks: verification.checks,
        },
      };
    },

    async reset() {
      applied = new Set();
      currentScan = null;
      counter = 0;
      proposals.clear();
    },

    /** Demo only: the next call fails as if the service could not be reached, so the error states can be shown. */
    failNext() {
      failing = true;
    },
  };
}
