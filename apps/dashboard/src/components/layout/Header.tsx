import { forwardRef } from "react";
import { StatusBadge } from "@/components/ui/StatusBadge";
import { useBackend } from "@/lib/connection/BackendProvider";

function ConnectionBadge() {
  const backend = useBackend();
  if (backend.phase === "ready") return <StatusBadge tone="success">Backend connected</StatusBadge>;
  if (backend.phase === "connecting") return <StatusBadge tone="info">Connecting to backend</StatusBadge>;
  return <StatusBadge tone="critical">Backend unavailable</StatusBadge>;
}

/** The h1 is focusable (tabIndex -1) so focus can move to it after navigation. */
export const Header = forwardRef<HTMLHeadingElement, { title: string }>(function Header({ title }, ref) {
  return (
    <header className="flex h-12 shrink-0 items-center justify-between gap-3 border-b border-line/80 bg-surface/80 px-4 backdrop-blur-sm lg:px-6">
      <div className="flex items-center gap-2">
        <span className="font-mono text-xs uppercase tracking-wider text-fg-subtle">TAPROX /</span>
        <h1 ref={ref} tabIndex={-1} className="truncate text-sm font-semibold tracking-wide text-fg focus:outline-none">
          {title}
        </h1>
      </div>
      <ConnectionBadge />
    </header>
  );
});
