import { Check, TriangleAlert } from 'lucide-react';

import { typeLabel } from '../../lib/severity.js';
import Chip from '../ui/Chip.jsx';

/** A correction that was applied and checked again (green: tip). Says what was resolved and what the check found. */
export default function FixedCard({ proposal }) {
  const verification = proposal.result?.verification;
  const passed = verification?.outcome === 'passed';
  const resolved = (verification?.resolved ?? []).filter((r) => r.path === proposal.path).map((r) => typeLabel(r.type));
  const Icon = passed ? Check : TriangleAlert;
  return (
    <article data-fixed={proposal.id} className="anim-enter rounded-flwn bg-pastel-green p-6 shadow-flwn">
      <div className="flex items-center justify-between gap-3">
        <Chip>Fixed</Chip>
        <span className="text-sm text-ink-72">{proposal.checks.length} checks passed before applying</span>
      </div>
      <h3 className="mt-4 break-all font-mono text-base font-semibold">{proposal.path}</h3>
      <p className="mt-2 text-[0.9375rem] text-ink-72">{resolved.length > 0 ? `${resolved.join(', ')} resolved.` : 'The correction was applied.'}</p>
      <p className="mt-4 flex items-center gap-2 text-[0.9375rem] font-semibold">
        <Icon className={passed ? 'anim-draw h-4 w-4' : 'h-4 w-4'} strokeWidth={3} aria-hidden="true" />
        {passed ? 'Verification passed on the file as it is now.' : `Verification ${verification?.outcome ?? 'did not run'}: look at this file.`}
      </p>
    </article>
  );
}
