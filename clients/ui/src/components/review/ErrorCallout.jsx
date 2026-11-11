import { TriangleAlert } from 'lucide-react';

import Button from '../ui/Button.jsx';
import Callout from '../ui/Callout.jsx';

/** A salmon block with what went wrong, a statement that nothing was changed, and a way to try again. It shakes once, then stays still. */
export default function ErrorCallout({ message, onRetry }) {
  return (
    <Callout tone="warning" role="alert" icon={TriangleAlert} title="That did not work." className="anim-shake">
      <p>{message} Nothing was changed.</p>
      <Button className="mt-3" onClick={onRetry}>Try again</Button>
    </Callout>
  );
}
