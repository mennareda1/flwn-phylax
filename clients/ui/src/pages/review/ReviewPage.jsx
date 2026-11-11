import { useState } from 'react';

import { useReview } from '../../api/useReview.js';
import { BottomBar, SideTabs } from '../../components/layout/RailTabs.jsx';
import Canvas from '../../components/layout/Canvas.jsx';
import UserBadge from '../../components/layout/UserBadge.jsx';
import Wordmark from '../../components/layout/Wordmark.jsx';
import CorrectionDrawer from '../../components/review/CorrectionDrawer.jsx';
import CoveragePanel from '../../components/review/CoveragePanel.jsx';
import DemoChip from '../../components/review/DemoChip.jsx';
import ErrorCallout from '../../components/review/ErrorCallout.jsx';
import ProjectSwitcher from '../../components/review/ProjectSwitcher.jsx';
import ReviewBoard from '../../components/review/ReviewBoard.jsx';
import SumUpBanner from '../../components/review/SumUpBanner.jsx';
import TopActions from '../../components/review/TopActions.jsx';
import ToastStack from '../../components/ui/Toast.jsx';
import { sumUp } from '../../lib/sumUp.js';

const scrollTo = (id) => {
  const reduced = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
  document.getElementById(id)?.scrollIntoView({ behavior: reduced ? 'auto' : 'smooth', block: 'start' });
};

/** The review: header, board, coverage. Thin on purpose: the state lives in useReview, the pieces in components. */
export default function ReviewPage({ backend }) {
  const { state, info, openProposal, columns, actions } = useReview(backend);
  const [coverageOpen, setCoverageOpen] = useState(false);
  const summary = sumUp(state);
  const showCoverage = () => {
    setCoverageOpen(true);
    scrollTo('coverage');
  };
  const demo = info?.mode === 'demo';

  return (
    <Canvas>
      <SideTabs onBoard={() => scrollTo('board')} onCoverage={showCoverage} onReset={actions.reset} canReset={demo} />
      <BottomBar onBoard={() => scrollTo('board')} onCoverage={showCoverage} onReset={actions.reset} canReset={demo} />
      <UserBadge />

      <div className="mx-auto w-full max-w-page px-4 pb-44 pt-6 md:px-10 lg:px-28 lg:pb-16">
        <header className="grid grid-cols-1 gap-6 lg:grid-cols-[1fr_minmax(0,56rem)_1fr] lg:items-start lg:gap-10">
          <Wordmark className="shrink-0 lg:mt-3" />
          <SumUpBanner phase={state.phase} text={summary}>
            <ProjectSwitcher name={info?.projectName} mode={info?.mode} />
          </SumUpBanner>
        </header>

        <div className="mt-10 flex flex-col gap-6 md:flex-row md:items-end md:justify-between">
          <div className="min-w-0">
            <p className="text-[0.8125rem] font-semibold uppercase tracking-[0.12em] text-ink-soft">Security review</p>
            <h1 className="mt-2 text-3xl font-bold tracking-[-0.01em] md:text-4xl lg:text-5xl">What Phylax found.</h1>
            <p className="mt-3 max-w-[42rem] text-[0.9375rem] text-ink-soft">Phylax scans, proposes and checks. It never changes a file until you approve that correction.</p>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            {demo ? <DemoChip recordedWith={info.recordedWith} onReset={actions.reset} onFail={actions.simulateError} /> : null}
            {/* Below lg the primary action floats just above the bottom bar so it is never hidden behind it; from lg it sits here in the header row. */}
            <div className="fixed inset-x-4 bottom-[calc(3.5rem+env(safe-area-inset-bottom)+0.75rem)] z-20 md:inset-x-10 lg:static lg:inset-auto lg:z-auto [&_button]:shadow-flwn lg:[&_button]:shadow-none">
              <TopActions phase={state.phase} hasScan={Boolean(state.scan)} selectedCount={state.selected.length} onScan={actions.scan} onPrepare={actions.prepare} />
            </div>
          </div>
        </div>

        {state.error ? <div className="mt-8"><ErrorCallout message={state.error} onRetry={actions.retry} /></div> : null}

        <div className="mt-8">
          <ReviewBoard phase={state.phase} hasScan={Boolean(state.scan)} columns={columns} selected={state.selected} onToggle={actions.toggle} onOpen={actions.open} />
        </div>

        {state.notes.length > 0 ? (
          <ul className="mt-6 flex flex-col gap-2 text-[0.9375rem] text-ink-soft">
            {state.notes.map((note) => <li key={note.keys.join()}>{note.reason}</li>)}
          </ul>
        ) : null}

        <div className="mt-10">
          <CoveragePanel scan={state.scan} open={coverageOpen} onToggle={() => setCoverageOpen((was) => !was)} />
        </div>
      </div>

      <CorrectionDrawer proposal={openProposal} mode={info?.mode} onClose={actions.close} onApply={actions.apply} onDismiss={actions.dismiss} />
      <ToastStack toasts={state.toasts} onDismiss={actions.dismissToast} />
      <p className="sr-only" role="status">{summary}</p>
    </Canvas>
  );
}
