import { useEffect, useRef, useState } from 'react';

import { cx } from '../../lib/cx.js';

/**
 * A panel that opens from its trigger and closes on Escape, on a click outside, or when asked. It fades and rises in, and fades out before it is removed (nothing vanishes in one frame).
 * `trigger({ open, toggle })` draws the button; children are the panel.
 */
export default function Popover({ trigger, children, align = 'left', className = '', label }) {
  const [phase, setPhase] = useState('closed');   // closed, open, closing
  const root = useRef(null);
  const open = phase === 'open';
  const close = () => setPhase((p) => (p === 'open' ? 'closing' : p));
  const toggle = () => setPhase((p) => (p === 'open' ? 'closing' : 'open'));

  useEffect(() => {
    if (phase !== 'closing') return undefined;
    const timer = setTimeout(() => setPhase('closed'), 160);
    return () => clearTimeout(timer);
  }, [phase]);

  useEffect(() => {
    if (!open) return undefined;
    const onKey = (event) => event.key === 'Escape' && close();
    const onDown = (event) => root.current && !root.current.contains(event.target) && close();
    document.addEventListener('keydown', onKey);
    document.addEventListener('pointerdown', onDown);
    return () => {
      document.removeEventListener('keydown', onKey);
      document.removeEventListener('pointerdown', onDown);
    };
  }, [open]);

  return (
    <div ref={root} className="relative">
      {trigger({ open, toggle })}
      {phase !== 'closed' ? (
        <div
          role="dialog"
          aria-label={label}
          className={cx(
            'absolute top-full z-30 mt-2 w-[min(22rem,calc(100vw-2rem))] rounded-flwn bg-white p-4 shadow-flwn',
            align === 'right' ? 'right-0 origin-top-right' : 'left-0 origin-top-left',
            phase === 'open' ? 'anim-enter' : 'anim-exit',
            className,
          )}
        >
          {typeof children === 'function' ? children({ close }) : children}
        </div>
      ) : null}
    </div>
  );
}
