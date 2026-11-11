import { useEffect, useState } from 'react';

/** Three dots that bounce in turn, and a status line that moves on by crossfade ("Reading the files", then "Running the checks"). It stops on the last line until the work ends. */
export default function ThinkingIndicator({ lines }) {
  const [index, setIndex] = useState(0);
  useEffect(() => {
    const timer = setInterval(() => setIndex((i) => Math.min(i + 1, lines.length - 1)), 700);
    return () => clearInterval(timer);
  }, [lines]);
  return (
    <span className="flex min-w-0 items-center gap-3">
      <span className="flex shrink-0 items-center gap-1" aria-hidden="true">
        {[0, 1, 2].map((n) => <span key={n} className="anim-dot h-1.5 w-1.5 rounded-full bg-ink" style={{ animationDelay: `${n * 150}ms` }} /* brand-ok: a computed stagger */ />)}
      </span>
      <span key={lines[index]} className="anim-fade truncate text-ink-72">{lines[index]}</span>
    </span>
  );
}
