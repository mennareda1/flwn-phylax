import Button from '../ui/Button.jsx';

/** The primary action changes with where the review is, so there is only ever one dark button: Scan project, then Prepare corrections once findings are ticked. The page floats it above the bottom bar on small screens. */
export default function TopActions({ phase, hasScan, selectedCount, onScan, onPrepare }) {
  const proposing = phase === 'proposing';
  const scanning = phase === 'scanning';
  if (selectedCount > 0 || proposing) {
    return (
      <div className="flex w-full items-center gap-3 lg:w-auto">
        <Button className="flex-1 lg:flex-none" disabled={scanning || proposing} onClick={onScan}>Scan again</Button>
        <Button className="flex-[2] lg:flex-none" variant="primary" loading={proposing} onClick={onPrepare}>Prepare corrections ({selectedCount})</Button>
      </div>
    );
  }
  return <Button className="w-full lg:w-auto" variant="primary" loading={scanning} onClick={onScan}>{hasScan ? 'Scan again' : 'Scan project'}</Button>;
}
