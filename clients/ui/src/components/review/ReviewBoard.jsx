import CardSkeleton from '../ui/CardSkeleton.jsx';
import Column from './Column.jsx';
import CorrectionCard from './CorrectionCard.jsx';
import FindingCard from './FindingCard.jsx';
import FixedCard from './FixedCard.jsx';

/** Found, then Needs your decision, then Fixed. While Phylax works the column that is waiting shows the shape of what is coming, so nothing jumps when it arrives. */
export default function ReviewBoard({ phase, hasScan, columns, selected, onToggle, onOpen }) {
  const scanning = phase === 'scanning';
  const proposing = phase === 'proposing';
  const busy = scanning || proposing;
  return (
    <div id="board" className="grid grid-cols-1 gap-10 md:grid-cols-[repeat(auto-fit,minmax(18rem,1fr))]">
      <Column id="found" title="Found" dot="salmon" count={scanning ? 0 : columns.found.length} empty={hasScan ? 'Nothing left to look at here.' : 'Nothing yet. Scan the project to see what Phylax finds.'}>
        {scanning ? [0, 1, 2].map((n) => <CardSkeleton key={n} />) : null}
        {!scanning && columns.found.length > 0 ? (
          <div className="stagger flex flex-col gap-5">
            {columns.found.map((finding) => <FindingCard key={finding.key} finding={finding} selected={selected.includes(finding.key)} onToggle={onToggle} locked={busy} />)}
          </div>
        ) : null}
      </Column>
      <Column id="decide" title="Needs your decision" dot="lavender" count={columns.decide.length} empty="Tick the findings you want corrected, then prepare the corrections. They wait here for your decision.">
        {columns.decide.length > 0 ? (
          <div className="flex flex-col gap-5">
            {columns.decide.map((proposal) => <CorrectionCard key={proposal.id} proposal={proposal} onOpen={onOpen} />)}
          </div>
        ) : null}
        {proposing ? <CardSkeleton /> : null}
      </Column>
      <Column id="fixed" title="Fixed" dot="green" count={columns.fixed.length} empty="Corrections you apply appear here once Phylax has checked the file again.">
        {columns.fixed.length > 0 ? (
          <div className="flex flex-col gap-5">
            {columns.fixed.map((proposal) => <FixedCard key={proposal.id} proposal={proposal} />)}
          </div>
        ) : null}
      </Column>
    </div>
  );
}
