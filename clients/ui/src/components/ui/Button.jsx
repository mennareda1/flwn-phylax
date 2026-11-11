import { cx } from '../../lib/cx.js';
import Spinner from './Spinner.jsx';

const VARIANT = {
  primary: 'bg-ink text-cream enabled:hover:-translate-y-[0.0625rem]',
  secondary: 'bg-white text-ink border-hair border-line enabled:hover:bg-cream',
  ghost: 'bg-transparent text-ink-soft enabled:hover:bg-ink/10 enabled:hover:text-ink',
};

/**
 * The one button. `primary` is the dark one: at most one on a view. `loading` swaps the label for a spinner without changing the button's width.
 * @param {{ variant?: 'primary'|'secondary'|'ghost', icon?: import('react').ElementType, loading?: boolean }} props
 */
export default function Button({ variant = 'secondary', icon: Icon, loading = false, disabled = false, className = '', children, ...rest }) {
  return (
    <button
      type="button"
      disabled={disabled || loading}
      aria-busy={loading || undefined}
      className={cx(
        'lift press relative inline-flex min-h-[2.75rem] items-center justify-center gap-2 rounded-flwn px-6 py-3 text-[0.9375rem] font-semibold',
        disabled ? 'cursor-not-allowed opacity-50' : loading && 'cursor-progress',      // loading keeps full strength: it is working, not unavailable
        VARIANT[variant],
        className,
      )}
      {...rest}
    >
      <span className={cx('inline-flex items-center gap-2', loading && 'invisible')}>
        {Icon ? <Icon className="h-4 w-4" aria-hidden="true" /> : null}
        {children}
      </span>
      {loading ? <Spinner className="absolute" /> : null}
    </button>
  );
}
