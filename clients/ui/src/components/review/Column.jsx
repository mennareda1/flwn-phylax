import { Children } from 'react';

import { cx } from '../../lib/cx.js';
import Counter from '../ui/Counter.jsx';

const DOT = { salmon: 'bg-pastel-salmon', lavender: 'bg-pastel-lavender', green: 'bg-pastel-green' };

/** One column of the board: a white header with a pastel square, the title and a count that crossfades, then the cards. `empty` is what to say when there are none. */
export default function Column({ id, title, count, dot, empty, children }) {
  return (
    <section aria-labelledby={`${id}-title`} className="min-w-0">
      <header className="flex h-[3.375rem] items-center gap-3 rounded-flwn border-hair border-line bg-white px-5">
        <span className={cx('h-3.5 w-3.5 rounded-flwn-sm outline outline-[1.5px] -outline-offset-[1.5px] outline-ink/20', DOT[dot])} aria-hidden="true" />
        <h2 id={`${id}-title`} className="text-lg font-semibold">{title}</h2>
        <Counter value={count} className="text-[0.9375rem] text-ink-soft" />
      </header>
      <div className="mt-5 flex flex-col gap-5">
        {Children.toArray(children).length === 0 && empty ? (
          <p className="anim-fade rounded-flwn border-hair border-dashed border-ink/35 px-6 py-8 text-center text-[0.9375rem] text-ink-soft">{empty}</p>
        ) : (
          children
        )}
      </div>
    </section>
  );
}
