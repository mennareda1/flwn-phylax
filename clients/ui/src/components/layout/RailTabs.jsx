import { ListChecks, RotateCcw, ScanSearch } from 'lucide-react';

import { cx } from '../../lib/cx.js';

/** The three things the rail does, in order. The same three appear as pennants on a wide screen and as a bottom bar on a phone. */
function items({ onBoard, onCoverage, onReset, canReset }) {
  return [
    { id: 'board', label: 'Review board', icon: ScanSearch, fill: 'bg-pastel-gold', onClick: onBoard },
    { id: 'coverage', label: 'Coverage', icon: ListChecks, fill: 'bg-pastel-salmon', onClick: onCoverage },
    { id: 'reset', label: 'Reset sample', icon: RotateCcw, fill: 'bg-pastel-green', onClick: onReset, hidden: !canReset },
  ].filter((item) => !item.hidden);
}

/** Pennants pinned to the left edge: wide screens. */
export function SideTabs(props) {
  return (
    <nav aria-label="Review" className="fixed inset-y-0 left-0 z-20 hidden flex-col justify-center gap-3.5 lg:flex">
      {items(props).map(({ id, label, icon: Icon, fill, onClick }) => (
        <button key={id} type="button" aria-label={label} title={label} onClick={onClick} className={cx('pennant group relative grid h-[3.875rem] w-[4.875rem] place-items-center pr-2.5', fill)}>
          <span aria-hidden="true" className="absolute inset-0 bg-white/0 transition-colors duration-fast ease-out group-hover:bg-white/35 group-active:bg-white/50" />
          <Icon className="relative h-6 w-6" aria-hidden="true" />
        </button>
      ))}
    </nav>
  );
}

/** A bar at the bottom of the screen: phones and tablets. Keeps clear of the home indicator. */
export function BottomBar(props) {
  const list = items(props);
  return (
    <nav aria-label="Review" className="fixed inset-x-0 bottom-0 z-20 border-t border-hair border-line bg-white pb-[env(safe-area-inset-bottom)] lg:hidden">
      <ul className="mx-auto grid max-w-[30rem]" style={{ gridTemplateColumns: `repeat(${list.length}, minmax(0, 1fr))` }} /* brand-ok: a computed value */>
        {list.map(({ id, label, icon: Icon, onClick }) => (
          <li key={id}>
            <button type="button" onClick={onClick} className="press flex min-h-[3.5rem] w-full flex-col items-center justify-center gap-1 text-xs font-semibold text-ink-soft transition-colors duration-fast ease-out hover:text-ink">
              <Icon className="h-6 w-6" aria-hidden="true" />
              {label}
            </button>
          </li>
        ))}
      </ul>
    </nav>
  );
}

