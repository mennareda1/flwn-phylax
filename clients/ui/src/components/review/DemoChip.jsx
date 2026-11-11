import { FlaskConical } from 'lucide-react';

import Button from '../ui/Button.jsx';
import Popover from '../ui/Popover.jsx';

/** A visible, honest label: this is recorded data. It opens a short explanation and the two demo controls (start over, and show an error). */
export default function DemoChip({ recordedWith, onReset, onFail }) {
  return (
    <Popover
      label="About the demo data"
      trigger={({ open, toggle }) => (
        <button type="button" aria-expanded={open} onClick={toggle} className="lift press inline-flex min-h-[2.75rem] items-center gap-2 rounded-flwn-sm border-hair border-line bg-white px-3 text-sm font-semibold">
          <FlaskConical className="h-4 w-4" aria-hidden="true" />
          Demo data
        </button>
      )}
    >
      {({ close }) => (
        <div className="flex flex-col gap-3">
          <p className="text-[0.9375rem]">Everything here was recorded from the real Phylax on a small sample project, and replayed in this page. Nothing leaves your computer.</p>
          {recordedWith ? <p className="text-sm text-ink-soft">{recordedWith}.</p> : null}
          <p className="text-sm text-ink-soft">Applying a correction changes a copy kept in this page, not any file on disk.</p>
          <div className="flex flex-col gap-2 sm:flex-row">
            <Button onClick={() => { close(); onReset(); }}>Start over</Button>
            <Button onClick={() => { close(); onFail(); }}>Show an error</Button>
          </div>
        </div>
      )}
    </Popover>
  );
}
