import { useState } from 'react';

import Button from '../ui/Button.jsx';
import Callout from '../ui/Callout.jsx';
import ChecksList from '../ui/ChecksList.jsx';
import CodeDiff from '../ui/CodeDiff.jsx';
import Drawer from '../ui/Drawer.jsx';

/**
 * The one place a correction is approved. It shows what Phylax checked and the exact change, and nothing is written until "Apply correction" is pressed. Closing (X, Escape, the scrim)
 * leaves the correction waiting; "Not now" sends the findings back to the first column.
 */
export default function CorrectionDrawer({ proposal, mode, onClose, onApply, onDismiss }) {
  const [kept, setKept] = useState(proposal);       // the last correction shown, so the drawer keeps its content while it fades out
  if (proposal && proposal !== kept) setKept(proposal);
  const shown = proposal ?? kept;
  const applying = proposal?.state === 'applying';
  return (
    <Drawer
      open={Boolean(proposal)}
      onClose={onClose}
      labelledBy="correction-title"
      locked={applying}
      footer={shown ? (
        <div className="flex flex-col gap-4">
          <p className="text-sm text-ink-soft">
            Phylax never changes a file by itself. Nothing is applied until you press Apply correction.
            {mode === 'demo' ? ' In this demo it changes a copy kept in this page.' : ''}
          </p>
          <div className="flex flex-col-reverse gap-3 sm:flex-row sm:justify-end">
            <Button onClick={() => onDismiss(shown.id)} disabled={applying}>Not now</Button>
            <Button variant="primary" loading={applying} onClick={() => onApply(shown.id)}>Apply correction</Button>
          </div>
        </div>
      ) : null}
    >
      {shown ? (
        <div className="flex flex-col gap-6">
          <header>
            <p className="text-[0.8125rem] font-semibold uppercase tracking-[0.12em] text-ink-soft">Correction</p>
            <h2 id="correction-title" className="mt-2 break-words text-[1.75rem] font-bold leading-tight tracking-[-0.01em]">Fix {shown.path}.</h2>
          </header>
          <Callout tone="decision" title="What changes">{shown.explanation}</Callout>
          <section className="flex flex-col gap-3">
            <h3 className="text-lg font-semibold">What Phylax checked</h3>
            <ChecksList checks={shown.checks} />
            {shown.checkedTogether?.length > 1 ? <p className="text-sm text-ink-soft">These checks covered {shown.checkedTogether.join(' and ')} together, because they were requested together. Whatever you apply is checked again afterwards.</p> : null}
          </section>
          <section className="flex flex-col gap-3">
            <h3 className="text-lg font-semibold">The change</h3>
            <CodeDiff diff={shown.diff} label={`Changes to ${shown.path}`} />
          </section>
        </div>
      ) : null}
    </Drawer>
  );
}
