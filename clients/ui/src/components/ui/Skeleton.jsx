import { cx } from '../../lib/cx.js';

/** A placeholder with the final content's shape, so nothing shifts when the real content arrives. `tone="pastel"` is for use on a coloured card. */
export default function Skeleton({ tone = 'paper', className = '' }) {
  return <div aria-hidden="true" className={cx('anim-skeleton rounded-flwn-sm', tone === 'pastel' ? 'bg-white/50' : 'bg-line', className)} />;
}
