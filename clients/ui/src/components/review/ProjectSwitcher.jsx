import { Check, ChevronDown } from 'lucide-react';

import { cx } from '../../lib/cx.js';
import Popover from '../ui/Popover.jsx';

/** The blue block that names the project. It overlaps the banner on a wide screen. Opens a short list; only the sample project exists in the demo, and it says so. */
export default function ProjectSwitcher({ name, mode }) {
  return (
    <div className="lg:absolute lg:right-6 lg:top-6 lg:z-10">
      <Popover
        align="right"
        label="Projects"
        trigger={({ open, toggle }) => (
          <button type="button" aria-haspopup="dialog" aria-expanded={open} onClick={toggle} className="lift press flex h-14 w-full items-center justify-between gap-6 rounded-flwn bg-pastel-blue px-5 text-lg font-bold shadow-flwn lg:h-[4.5rem] lg:w-[13.25rem]">
            <span className="truncate">{name ?? 'Project'}</span>
            <ChevronDown className={cx('h-4 w-4 shrink-0 transition-transform duration-fast ease-in-out', open && 'rotate-180')} aria-hidden="true" />
          </button>
        )}
      >
        <p className="px-2 pb-2 text-sm text-ink-soft">Projects</p>
        <div className="flex min-h-[2.75rem] items-center justify-between gap-3 rounded-flwn-sm bg-cream px-3 text-[0.9375rem] font-semibold">
          <span className="truncate">{name}</span>
          <Check className="h-4 w-4 shrink-0" aria-hidden="true" />
        </div>
        <p className="mt-3 px-2 text-sm text-ink-soft">{mode === 'demo' ? 'The demo has one project. Opening your own folder is in the live app.' : 'Open a project folder from the command line.'}</p>
      </Popover>
    </div>
  );
}
