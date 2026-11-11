import { SCAN_LINES, PROPOSE_LINES } from '../../api/useReview.js';
import AiAvatar from '../ui/AiAvatar.jsx';
import ThinkingIndicator from '../ui/ThinkingIndicator.jsx';

/** The gold strip at the top: the review's state in one sentence. While Phylax works it shows the thinking indicator instead. `children` is the project switcher, which overlaps the strip's right edge. */
export default function SumUpBanner({ phase, text, children }) {
  const working = phase === 'scanning' || phase === 'proposing';
  return (
    <div className="relative flex flex-col gap-3">
      <div className="flex min-h-[4.75rem] items-center gap-4 rounded-flwn bg-pastel-gold px-5 py-3 shadow-flwn lg:pr-[15.5rem]">
        <AiAvatar thinking={working} />
        <div className="flex min-w-0 flex-1 flex-col gap-1 md:flex-row md:items-center md:gap-4">
          <p className="shrink-0 text-xl font-bold">Review sum-up</p>
          {working ? (
            <ThinkingIndicator key={phase} lines={phase === 'scanning' ? SCAN_LINES : PROPOSE_LINES} />
          ) : (
            <p key={text} className="anim-fade line-clamp-2 min-w-0 text-[0.9375rem] leading-snug text-ink-72" title={text}>{text}</p>
          )}
        </div>
      </div>
      {children}
    </div>
  );
}
