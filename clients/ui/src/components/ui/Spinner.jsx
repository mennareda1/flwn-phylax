import { LoaderCircle } from 'lucide-react';

/** A 1rem ring that turns. Used inside buttons and next to waiting text. */
export default function Spinner({ className = '' }) {
  return <LoaderCircle className={`anim-spin h-4 w-4 ${className}`} aria-hidden="true" />;
}
