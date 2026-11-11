import { cx } from '../../lib/cx.js';

const TONE = {
  tip: 'bg-pastel-green',
  decision: 'bg-pastel-lavender',
  note: 'bg-pastel-gold',
  warning: 'bg-pastel-salmon',
  info: 'bg-pastel-blue',
};

/** A pastel block with a meaning: green tip, lavender decision, gold note, salmon warning, blue info. No border. */
export default function Callout({ tone = 'info', icon: Icon, title, role, className = '', children }) {
  return (
    <div role={role} className={cx('flex items-start gap-3 rounded-flwn px-6 py-5 text-[0.9375rem]', TONE[tone], className)}>
      {Icon ? <Icon className="mt-0.5 h-5 w-5 shrink-0" aria-hidden="true" /> : null}
      <div className="min-w-0 flex-1">
        {title ? <p className="font-semibold">{title}</p> : null}
        <div className={cx(title && 'mt-1', 'text-ink-72')}>{children}</div>
      </div>
    </div>
  );
}
