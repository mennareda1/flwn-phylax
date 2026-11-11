import { Info, Lock } from 'lucide-react';

import { cx } from '../../lib/cx.js';
import { CARD_FILL, SEVERITY_LABEL, typeLabel } from '../../lib/severity.js';
import Checkbox from '../ui/Checkbox.jsx';
import Chip from '../ui/Chip.jsx';

/**
 * One finding, on a pastel fill that follows its severity. A finding that can be corrected has a checkbox. One that cannot (low severity, or a hardcoded secret) says why,
 * in the service's own words, and has none.
 */
export default function FindingCard({ finding, selected, onToggle, locked }) {
  const where = finding.line ? `${finding.path}:${finding.line}` : finding.path;
  const eligible = finding.fix.eligible;
  const secret = finding.vulnerability_type === 'hardcoded_credentials';
  const Reported = secret ? Lock : Info;
  return (
    <article data-finding={finding.key} className={cx('lift rounded-flwn p-6 shadow-flwn hover:-translate-y-0.5', CARD_FILL[finding.severity] ?? 'bg-pastel-blue')}>
      <div className="flex items-center justify-between gap-3">
        <Chip>{typeLabel(finding.vulnerability_type)}</Chip>
        {eligible ? (
          <Checkbox checked={selected} onChange={() => onToggle(finding.key)} disabled={locked} label={`Select the ${typeLabel(finding.vulnerability_type).toLowerCase()} in ${where} for a correction`} />
        ) : (
          <span className="grid h-11 w-11 place-items-center text-ink-72" role="img" aria-label="Reported only, no correction offered">
            <Reported className="h-5 w-5" aria-hidden="true" />
          </span>
        )}
      </div>
      <h3 className="mt-4 text-lg font-semibold leading-snug">{finding.description}</h3>
      <code className="mt-4 block whitespace-pre-wrap break-words rounded-flwn-sm bg-white/60 px-3 py-2 font-mono text-[0.8125rem] leading-6">{finding.evidence}</code>
      <p className="mt-4 text-sm text-ink-72">{finding.fix.reason}</p>
      <footer className="mt-4 flex items-center justify-between gap-3 text-[0.9375rem] text-ink-72">
        <span className="min-w-0 truncate font-mono text-sm" title={where}>{where}</span>
        <span className="shrink-0 font-semibold text-ink">{SEVERITY_LABEL[finding.severity] ?? finding.severity}</span>
      </footer>
    </article>
  );
}
