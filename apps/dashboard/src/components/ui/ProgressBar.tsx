interface Props {
  label: string;
  value: number;
  /** The total. 0 or less means it is not known yet, so no percentage is shown. */
  max: number;
}

/** Determinate when the total is known; otherwise an honest "working" bar with no made-up number. */
export function ProgressBar({ label, value, max }: Props) {
  const determinate = max > 0;
  const current = determinate ? Math.min(Math.max(value, 0), max) : 0;
  const percent = determinate ? Math.round((current / max) * 100) : 0;
  return (
    <div
      role="progressbar"
      aria-label={label}
      aria-valuemin={0}
      aria-valuemax={determinate ? max : undefined}
      aria-valuenow={determinate ? current : undefined}
      aria-valuetext={
        determinate ? `${String(current)} of ${String(max)} (${String(percent)}%)` : undefined
      }
      className="h-2 w-full overflow-hidden rounded-sm bg-raised"
    >
      <div
        className={`h-full rounded-sm bg-accent-strong transition-[width] duration-200 ${
          determinate ? "" : "w-1/3 animate-pulse motion-reduce:animate-none"
        }`}
        style={determinate ? { width: `${String(percent)}%` } : undefined}
      />
    </div>
  );
}
