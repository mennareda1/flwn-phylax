import { cx } from '../../lib/cx.js';

/** The navy "AI" circle: one of the two dark elements on a view. While Phylax works it gives off a soft ring. */
export default function AiAvatar({ thinking = false, className = '' }) {
  return (
    <span className={cx('relative grid h-11 w-11 shrink-0 place-items-center', className)}>
      {thinking ? <span className="anim-pulse-ring absolute inset-0 rounded-full bg-navy" aria-hidden="true" /> : null}
      <span className="relative grid h-11 w-11 place-items-center rounded-full bg-navy text-xs font-bold text-cream">AI</span>
    </span>
  );
}
