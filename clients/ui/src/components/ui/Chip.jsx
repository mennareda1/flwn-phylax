import { cx } from '../../lib/cx.js';

/** A small tag: the kind of thing a card is about. */
export default function Chip({ className = '', children }) {
  return <span className={cx('inline-flex items-center gap-1 rounded-flwn-sm bg-white/70 px-2 py-1 text-xs font-semibold text-ink', className)}>{children}</span>;
}
