import { Check, Info, TriangleAlert } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';

import { cx } from '../../lib/cx.js';

const TONE_ICON = { success: Check, info: Info, error: TriangleAlert };
const LIFETIME = 5000;

function Toast({ toast, onDone }) {
  const [leaving, setLeaving] = useState(false);
  const Icon = TONE_ICON[toast.tone] ?? Info;
  const done = useRef(onDone);                       // the latest callback, without restarting the timers each time the list re-renders
  useEffect(() => {
    done.current = onDone;
  });
  useEffect(() => {
    const leave = setTimeout(() => setLeaving(true), LIFETIME);
    return () => clearTimeout(leave);
  }, []);
  useEffect(() => {
    if (!leaving) return undefined;
    const gone = setTimeout(() => done.current(), 160);
    return () => clearTimeout(gone);
  }, [leaving]);
  return (
    <li className={cx('pointer-events-none relative overflow-hidden rounded-flwn bg-white shadow-flwn', leaving ? 'anim-exit' : 'anim-toast-in')}>
      <div className="flex items-start gap-3 px-5 py-4 text-[0.9375rem]">
        <Icon className="mt-0.5 h-5 w-5 shrink-0" aria-hidden="true" />
        <p className="min-w-0 flex-1">{toast.text}</p>
      </div>
      <div className="anim-countdown absolute inset-x-0 bottom-0 h-[0.1875rem] bg-ink" aria-hidden="true" />
    </li>
  );
}

/** Messages that slide in, count down with a thin line, and leave on their own. */
export default function ToastStack({ toasts, onDismiss }) {
  return (
    <ul role="status" aria-live="polite" className="pointer-events-none fixed bottom-[calc(8.5rem+env(safe-area-inset-bottom))] right-4 z-50 flex w-[min(24rem,calc(100vw-2rem))] flex-col gap-3 pb-[env(safe-area-inset-bottom)] lg:bottom-6 lg:right-6">
      {toasts.map((toast) => <Toast key={toast.id} toast={toast} onDone={() => onDismiss(toast.id)} />)}
    </ul>
  );
}
