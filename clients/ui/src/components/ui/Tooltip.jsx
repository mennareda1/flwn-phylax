import { useEffect, useRef, useState } from 'react';

let lastClosedAt = 0;   // moving between neighbours opens the next tooltip at once

/** Opens after a short pause on hover or focus (no pause when you move from one tooltip to the next), and leaves quickly. */
export default function Tooltip({ label, children }) {
  const [open, setOpen] = useState(false);
  const timer = useRef(null);
  const shown = useRef(false);
  const show = () => {
    clearTimeout(timer.current);
    const wait = Date.now() - lastClosedAt < 300 ? 0 : 400;
    timer.current = setTimeout(() => {
      shown.current = true;
      setOpen(true);
    }, wait);
  };
  const hide = () => {
    clearTimeout(timer.current);
    if (shown.current) lastClosedAt = Date.now();
    shown.current = false;
    setOpen(false);
  };
  useEffect(() => () => clearTimeout(timer.current), []);
  return (
    <span className="relative inline-flex" onMouseEnter={show} onMouseLeave={hide} onFocus={show} onBlur={hide}>
      {children}
      {open ? (
        <span role="tooltip" className="anim-fade pointer-events-none absolute left-1/2 top-full z-50 mt-2 -translate-x-1/2 whitespace-nowrap rounded-flwn-sm bg-white px-3 py-2 text-xs font-semibold text-ink shadow-flwn">
          {label}
        </span>
      ) : null}
    </span>
  );
}
