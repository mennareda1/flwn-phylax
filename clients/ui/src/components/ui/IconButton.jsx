import { cx } from '../../lib/cx.js';
import Tooltip from './Tooltip.jsx';

/** An icon-only control: always has a label for screen readers, and a tooltip for everyone else. */
export default function IconButton({ icon: Icon, label, className = '', ...rest }) {
  return (
    <Tooltip label={label}>
      <button
        type="button"
        aria-label={label}
        className={cx('lift press grid h-11 w-11 place-items-center rounded-flwn text-ink-soft enabled:hover:bg-ink/10 enabled:hover:text-ink disabled:cursor-not-allowed disabled:opacity-50', className)}
        {...rest}
      >
        <Icon className="h-5 w-5" aria-hidden="true" />
      </button>
    </Tooltip>
  );
}
