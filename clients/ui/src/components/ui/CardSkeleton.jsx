import Skeleton from './Skeleton.jsx';

/** The shape of a finding or correction card while its content is on the way. */
export default function CardSkeleton() {
  return (
    <div aria-hidden="true" className="flex flex-col gap-4 rounded-flwn bg-white/60 p-6">
      <Skeleton className="h-6 w-28" />
      <Skeleton className="h-5 w-4/5" />
      <Skeleton className="h-10 w-full" />
      <Skeleton className="h-4 w-1/2" />
    </div>
  );
}
