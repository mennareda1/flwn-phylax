import { X } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';

import { cx } from '../../lib/cx.js';
import IconButton from './IconButton.jsx';

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), [tabindex]:not([tabindex="-1"])';

/**
 * A panel that slides in from the right (a full-screen sheet on a phone). The scrim and panel fade in, and fade out before they are removed. Escape and the scrim close it unless
 * `locked`; Tab stays inside it; focus goes to it on open and back to what opened it on close. `footer` stays visible at the bottom while the content scrolls (the decision buttons).
 */
export default function Drawer({ open, onClose, labelledBy, locked = false, footer = null, children }) {
  const [phase, setPhase] = useState(open ? 'open' : 'closed');   // closed, open, closing
  if (open && phase !== 'open') setPhase('open');
  if (!open && phase === 'open') setPhase('closing');
  const panel = useRef(null);
  const opener = useRef(null);

  useEffect(() => {
    if (phase !== 'closing') return undefined;
    const timer = setTimeout(() => setPhase('closed'), 160);
    return () => clearTimeout(timer);
  }, [phase]);

  useEffect(() => {
    if (phase !== 'open') return undefined;
    opener.current = document.activeElement;
    panel.current?.focus();      // the panel itself, not its first button: nothing lights up or opens a tooltip just because the panel opened
    return () => opener.current?.focus?.();
  }, [phase]);

  useEffect(() => {
    if (phase !== 'open') return undefined;
    const onKey = (event) => {
      if (event.key === 'Escape' && !locked) onClose();
      if (event.key !== 'Tab' || !panel.current) return;
      const items = [...panel.current.querySelectorAll(FOCUSABLE)];
      if (items.length === 0) return;
      const first = items[0];
      const last = items[items.length - 1];
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [phase, locked, onClose]);

  if (phase === 'closed') return null;
  const entering = phase === 'open';
  return (
    <div className="fixed inset-0 z-40">
      <div aria-hidden="true" onClick={locked ? undefined : onClose} className={cx('absolute inset-0 bg-ink/40', entering ? 'anim-scrim-in' : 'anim-scrim-out')} />
      <div
        ref={panel}
        role="dialog"
        aria-modal="true"
        aria-labelledby={labelledBy}
        tabIndex={-1}
        className={cx('absolute right-0 top-0 flex h-dvh w-full flex-col bg-cream shadow-flwn focus:outline-none md:max-w-[38rem]', entering ? 'anim-slide-in' : 'anim-slide-out')}
      >
        <div className="flex shrink-0 justify-end px-4 pt-4 md:px-6">
          <IconButton icon={X} label="Close" onClick={onClose} disabled={locked} />
        </div>
        <div className="min-h-0 flex-1 overflow-y-auto px-4 pb-6 md:px-6">{children}</div>
        {footer ? <div className="shrink-0 border-t border-hair border-line bg-cream px-4 pb-[max(1rem,env(safe-area-inset-bottom))] pt-4 md:px-6">{footer}</div> : null}
      </div>
    </div>
  );
}
