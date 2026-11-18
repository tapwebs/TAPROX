import type { ReactNode } from "react";

export interface DefinitionItem {
  label: string;
  value: ReactNode;
  /** Monospace for addresses, paths and versions. */
  mono?: boolean;
}

/** Dense label/value rows; stacks on narrow containers, two columns when there is room. */
export function DefinitionList({ items }: { items: DefinitionItem[] }) {
  return (
    <dl className="@container grid gap-y-2">
      {items.map((item) => (
        <div key={item.label} className="grid gap-0.5 @sm:grid-cols-[11rem_1fr] @sm:gap-3">
          <dt className="text-xs font-medium text-fg-muted">{item.label}</dt>
          <dd className={`min-w-0 break-words text-fg ${item.mono ? "font-mono text-[13px]" : ""}`}>
            {item.value}
          </dd>
        </div>
      ))}
    </dl>
  );
}
