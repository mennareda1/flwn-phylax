/** Who is signed in: a lavender circle with navy initials, bottom left, on wide screens. */
export default function UserBadge({ initials = 'AY' }) {
  return (
    <span role="img" aria-label={`Signed in as ${initials}`} className="fixed bottom-6 left-6 z-20 hidden h-[3.25rem] w-[3.25rem] place-items-center rounded-full bg-pastel-lavender text-lg font-semibold text-navy shadow-flwn ring-2 ring-white lg:grid">
      {initials}
    </span>
  );
}
