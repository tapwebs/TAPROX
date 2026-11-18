/** Placeholder for content whose shape is known (rows of a panel). Hidden from assistive tech. */
export function Skeleton({ className = "" }: { className?: string }) {
  return (
    <div
      aria-hidden="true"
      className={`animate-pulse rounded-sm bg-raised motion-reduce:animate-none ${className}`}
    />
  );
}
