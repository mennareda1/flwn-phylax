import { Check } from 'lucide-react';

/** A real checkbox (keyboard and screen reader friendly) drawn as a rounded square. The mark draws in when it is ticked. The whole 2.75rem square is the target. */
export default function Checkbox({ checked, onChange, label, disabled = false }) {
  return (
    <label className="relative grid h-11 w-11 shrink-0 cursor-pointer place-items-center has-[:disabled]:cursor-not-allowed has-[:disabled]:opacity-50">
      <input type="checkbox" className="peer sr-only" checked={checked} disabled={disabled} onChange={(event) => onChange(event.target.checked)} aria-label={label} />
      <span className="grid h-6 w-6 place-items-center rounded-flwn-sm border-hair border-ink/35 bg-white transition-colors duration-fast ease-out peer-checked:border-ink peer-checked:bg-ink peer-focus-visible:outline peer-focus-visible:outline-2 peer-focus-visible:outline-offset-2 peer-focus-visible:outline-navy">
        {checked ? <Check className="anim-draw h-4 w-4 text-cream" strokeWidth={3} aria-hidden="true" /> : null}
      </span>
    </label>
  );
}
