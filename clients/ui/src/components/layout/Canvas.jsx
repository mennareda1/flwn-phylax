/** The cream page with the dotted grid and the thin rounded frame (SKILL.md section 4). Everything sits on it. */
export default function Canvas({ children }) {
  return (
    <div className="canvas relative min-h-dvh">
      <div aria-hidden="true" className="pointer-events-none fixed inset-2 rounded-flwn border-hair border-line" />
      {children}
    </div>
  );
}
