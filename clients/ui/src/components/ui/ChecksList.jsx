import { Check, X } from 'lucide-react';

const CHECK_LABEL = {
  scope: 'Stays inside the files that were scanned',
  syntax: 'The file still parses',
  patch_size: 'A small change that can be reviewed',
  rescan: 'The problem is gone and nothing new appears',
};

/** What Phylax checked about a correction before showing it: each line ticks with a drawn check, or says what failed. */
export default function ChecksList({ checks, label = 'What Phylax checked' }) {
  return (
    <ul aria-label={label} className="stagger flex flex-col gap-3">
      {checks.map((check) => {
        const passed = check.result === 'pass';
        const Icon = passed ? Check : X;
        return (
          <li key={check.name} className="flex items-start gap-3">
            <span className="mt-0.5 grid h-5 w-5 shrink-0 place-items-center rounded-full bg-white">
              <Icon className={passed ? 'anim-draw h-3.5 w-3.5' : 'h-3.5 w-3.5'} strokeWidth={3} aria-hidden="true" />
            </span>
            <span className="min-w-0 text-[0.9375rem]">
              <span className="font-semibold">{CHECK_LABEL[check.name] ?? check.name}.</span>{' '}
              <span className="sr-only">{passed ? 'Passed. ' : 'Failed. '}</span>
              <span className="text-ink-soft">{check.detail}</span>
            </span>
          </li>
        );
      })}
    </ul>
  );
}
