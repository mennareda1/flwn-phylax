import { cx } from '../../lib/cx.js';
import { parseDiff } from '../../lib/diff.js';

const ROW = {
  add: 'bg-pastel-green/60',
  del: 'bg-pastel-salmon/60',
  ctx: 'bg-white',
  hunk: 'bg-cream text-ink-soft',
};
const SIGN = { add: '+', del: '-', ctx: ' ', hunk: '' };
const SPOKEN = { add: 'Added: ', del: 'Removed: ' };

/** A diff a person can read: what is removed on salmon, what is added on green, line numbers, no dark block. Long lines scroll inside the box, never the page. */
export default function CodeDiff({ diff, label = 'Changes' }) {
  const rows = parseDiff(diff);
  return (
    <div role="group" aria-label={label} className="overflow-x-auto rounded-flwn border-hair border-line bg-white font-mono text-[0.8125rem] leading-6">
      <div className="min-w-max">
        {rows.map((row, index) => (
          <div key={index} className={cx('grid grid-cols-[2.5rem_2.5rem_1.5rem_1fr] pr-4', ROW[row.kind])}>
            <span className="select-none pr-2 text-right text-ink-soft" aria-hidden="true">{row.oldNo ?? ''}</span>
            <span className="select-none pr-2 text-right text-ink-soft" aria-hidden="true">{row.newNo ?? ''}</span>
            <span className="select-none text-center font-semibold" aria-hidden="true">{SIGN[row.kind]}</span>
            <span className="whitespace-pre">
              {SPOKEN[row.kind] ? <span className="sr-only">{SPOKEN[row.kind]}</span> : null}
              {row.text}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
