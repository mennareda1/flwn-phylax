/** A number that crossfades when it changes. */
export default function Counter({ value, className = '' }) {
  return <span key={value} className={`anim-fade inline-block tabular-nums ${className}`}>{value}</span>;
}
