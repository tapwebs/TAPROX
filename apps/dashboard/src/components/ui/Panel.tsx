import { useId, type ReactNode } from "react";

interface Props {
  title: string;
  description?: string;
  /** Controls aligned to the right of the heading (e.g. a refresh button). */
  actions?: ReactNode;
  children: ReactNode;
}

export function Panel({ title, description, actions, children }: Props) {
  const headingId = useId();
  return (
    <section
      aria-labelledby={headingId}
      className="min-w-0 rounded-lg border border-line/90 bg-surface shadow-[0_4px_20px_-4px_rgba(0,0,0,0.5)] transition-all duration-200"
    >
      <header className="flex items-start justify-between gap-3 border-b border-line/80 bg-raised/40 px-4 py-3">
        <div className="min-w-0">
          <h2 id={headingId} className="text-sm font-semibold tracking-wide text-fg">
            {title}
          </h2>
          {description && <p className="mt-0.5 text-xs text-fg-muted">{description}</p>}
        </div>
        {actions && <div className="shrink-0">{actions}</div>}
      </header>
      <div className="p-4">{children}</div>
    </section>
  );
}
