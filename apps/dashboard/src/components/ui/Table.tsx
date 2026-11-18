import { ArrowDown, ArrowUp, ChevronsUpDown } from "lucide-react";
import type { ReactNode } from "react";

/**
 * A real <table> inside a scroll region. The region is focusable so a keyboard user can scroll a
 * table that is wider than the window, and it carries the table's name.
 */
export function Table({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div
      role="region"
      aria-label={label}
      tabIndex={0}
      className="relative overflow-x-auto rounded-md border border-line bg-surface/50 shadow-[0_2px_10px_rgba(0,0,0,0.3)]"
    >
      <table className="w-full min-w-max border-collapse text-left">
        <caption className="sr-only">{label}</caption>
        {children}
      </table>
    </div>
  );
}

const HEAD_CELL = "border-b border-line bg-inset/90 px-3.5 py-2.5 text-[11px] font-semibold uppercase tracking-wider text-fg-muted";

export function Th({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <th scope="col" className={`${HEAD_CELL} ${className}`}>
      {children}
    </th>
  );
}

export interface SortState {
  key: string;
  order: "asc" | "desc";
}

/** A column header that sorts when activated. The direction is exposed through `aria-sort`. */
export function SortTh({
  label,
  sortKey,
  sort,
  onSort,
}: {
  label: string;
  sortKey: string;
  sort: SortState;
  onSort: (key: string) => void;
}) {
  const active = sort.key === sortKey;
  const ariaSort = !active ? "none" : sort.order === "asc" ? "ascending" : "descending";
  const Icon = !active ? ChevronsUpDown : sort.order === "asc" ? ArrowUp : ArrowDown;
  return (
    <th scope="col" aria-sort={ariaSort} className={HEAD_CELL}>
      <button
        type="button"
        onClick={() => {
          onSort(sortKey);
        }}
        className={`-mx-1 inline-flex cursor-pointer items-center gap-1 rounded-sm px-1 hover:text-fg ${
          active ? "text-fg" : ""
        }`}
      >
        {label}
        <Icon aria-hidden="true" className="size-3.5 shrink-0" />
      </button>
    </th>
  );
}

/** The first cell of a row, so a screen reader announces which row the other cells belong to. */
export function RowTh({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <th
      scope="row"
      className={`border-b border-line/60 px-3.5 py-2.5 text-left align-middle font-medium text-fg transition-colors group-hover:bg-raised/30 ${className}`}
    >
      {children}
    </th>
  );
}

export function Td({
  children,
  mono = false,
  className = "",
}: {
  children: ReactNode;
  mono?: boolean;
  className?: string;
}) {
  return (
    <td
      className={`border-b border-line/60 px-3.5 py-2.5 align-middle transition-colors group-hover:bg-raised/30 ${
        mono ? "font-mono text-[13px] tracking-tight" : ""
      } ${className}`}
    >
      {children}
    </td>
  );
}
