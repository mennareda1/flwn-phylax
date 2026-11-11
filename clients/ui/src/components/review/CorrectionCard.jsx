import { TriangleAlert } from 'lucide-react';

import { changedLines } from '../../lib/diff.js';
import Button from '../ui/Button.jsx';
import Callout from '../ui/Callout.jsx';
import Chip from '../ui/Chip.jsx';

/** A correction waiting for a decision (lavender: decisions are lavender). It never applies itself: "Review correction" opens the diff, and the person decides there. */
export default function CorrectionCard({ proposal, onOpen }) {
  const passed = proposal.checks.filter((c) => c.result === 'pass').length;
  const changed = changedLines(proposal.diff);
  return (
    <article data-proposal={proposal.id} className="lift rounded-flwn bg-pastel-lavender p-6 shadow-flwn hover:-translate-y-0.5">
      <div className="flex items-center justify-between gap-3">
        <Chip>Correction</Chip>
        <span className="text-sm text-ink-72">{passed} of {proposal.checks.length} checks passed</span>
      </div>
      <h3 className="mt-4 text-lg font-semibold leading-snug">Fix <span className="break-all font-mono text-base">{proposal.path}</span>.</h3>
      <p className="mt-2 text-[0.9375rem] text-ink-72">{proposal.explanation}</p>
      {proposal.state === 'failed' ? (
        <Callout tone="warning" role="alert" icon={TriangleAlert} className="mt-4">{proposal.result?.message ?? 'The correction was not applied.'} Nothing was changed.</Callout>
      ) : null}
      <footer className="mt-4 flex items-center justify-between gap-3">
        <span className="text-sm text-ink-72">{changed} {changed === 1 ? 'line' : 'lines'} changed</span>
        <Button onClick={() => onOpen(proposal.id)} loading={proposal.state === 'applying'}>Review correction</Button>
      </footer>
    </article>
  );
}
