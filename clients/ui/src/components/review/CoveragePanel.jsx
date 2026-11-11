import { ChevronDown } from 'lucide-react';

import { cx } from '../../lib/cx.js';

function Section({ title, children }) {
  return (
    <div className="min-w-0">
      <h3 className="text-[0.9375rem] font-semibold">{title}</h3>
      <div className="mt-2 text-[0.9375rem] text-ink-soft">{children}</div>
    </div>
  );
}

/** What was and was not looked at. A scan that quietly skipped something would be worse than no scan, so this is always one click away. The body opens by grid rows, never by animating height. */
export default function CoveragePanel({ scan, open, onToggle }) {
  const coverage = scan?.coverage;
  const failed = Object.entries(coverage?.analyzers_failed ?? {});
  const skipped = coverage?.skipped_files ?? [];
  const limited = coverage?.limited_scope ?? [];
  return (
    <section id="coverage" aria-labelledby="coverage-title" className="rounded-flwn border-hair border-line bg-white">
      <h2 id="coverage-title">
        <button type="button" aria-expanded={open} aria-controls="coverage-body" onClick={onToggle} className="press flex min-h-[3.375rem] w-full items-center gap-3 px-5 text-left text-lg font-semibold">
          Coverage
          <span className="text-[0.9375rem] font-normal text-ink-soft">{coverage ? `${coverage.files_scanned.length} files scanned` : 'what was and was not checked'}</span>
          <ChevronDown className={cx('ml-auto h-4 w-4 shrink-0 transition-transform duration-fast ease-in-out', open && 'rotate-180')} aria-hidden="true" />
        </button>
      </h2>
      <div id="coverage-body" className={cx('grid transition-[grid-template-rows] duration-slow ease-in-out', open ? 'grid-rows-[1fr]' : 'grid-rows-[0fr]')}>
        <div className="overflow-hidden">
          <div inert={open ? undefined : ''} className="grid gap-6 px-5 pb-6 pt-2 md:grid-cols-2">
            {!coverage ? (
              <p className="text-[0.9375rem] text-ink-soft md:col-span-2">Scan the project and this shows which files were checked, which checks ran, and what no scan can judge.</p>
            ) : (
              <>
                <Section title="Files scanned">
                  <ul className="flex flex-wrap gap-2">
                    {coverage.files_scanned.map((file) => <li key={file} className="rounded-flwn-sm bg-cream px-2 py-1 font-mono text-[0.8125rem] text-ink">{file}</li>)}
                  </ul>
                </Section>
                <Section title="Files not scanned">{skipped.length === 0 ? 'Every file that was sent was scanned.' : skipped.map((s) => `${s.path}: ${s.reason}`).join('. ')}</Section>
                {limited.length > 0 && (
                  <Section title="Checked for secrets only">
                    {`${limited.map((item) => item.path).join(', ')}: configuration and text files are checked for hardcoded secrets and nothing else, so a clean result here says nothing about the rest of what they contain.`}
                  </Section>
                )}
                <Section title="Checks that ran">{coverage.analyzers_run.join(', ') || 'None'}.{failed.length > 0 ? ` Did not run: ${failed.map(([name, why]) => `${name} (${why})`).join('; ')}.` : ' None failed.'}</Section>
                <Section title="What no scan can judge">
                  <ul className="flex list-disc flex-col gap-1 pl-5">
                    {coverage.not_assessable.map((item) => <li key={item}>{item}</li>)}
                  </ul>
                </Section>
              </>
            )}
          </div>
        </div>
      </div>
    </section>
  );
}
