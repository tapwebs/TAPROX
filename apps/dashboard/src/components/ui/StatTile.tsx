/** One labelled figure with an optional note. Use inside a `<dl>`. */
export function StatTile({ label, value, note }: { label: string; value: string; note?: string }) {
  return (
    <div className="rounded-md border border-line/80 bg-inset/80 px-3.5 py-2.5 shadow-[inset_0_1px_2px_rgba(0,0,0,0.3)] transition-colors hover:border-line-strong">
      <dt className="text-[11px] font-medium uppercase tracking-wider text-fg-muted">{label}</dt>
      <dd className="mt-1 font-mono text-xl font-semibold tracking-tight text-fg">{value}</dd>
      {note && <dd className="mt-0.5 text-xs text-fg-subtle">{note}</dd>}
    </div>
  );
}
