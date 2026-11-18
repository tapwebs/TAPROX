import { ChevronLeft, ChevronRight } from "lucide-react";
import { Button } from "./Button";

interface Props {
  total: number;
  limit: number;
  offset: number;
  onChange: (offset: number) => void;
  /** Distinguishes several paginators on one screen. */
  label?: string;
}

export function Pagination({ total, limit, offset, onChange, label = "Pagination" }: Props) {
  const from = total === 0 ? 0 : Math.min(offset + 1, total);
  const to = Math.min(offset + limit, total);
  return (
    <nav aria-label={label} className="flex flex-wrap items-center justify-between gap-3">
      <p aria-live="polite" className="text-xs text-fg-muted">
        {total === 0 ? "No results" : `Showing ${String(from)}–${String(to)} of ${String(total)}`}
      </p>
      <div className="flex gap-2">
        <Button
          aria-label="Previous page"
          disabled={offset <= 0}
          onClick={() => {
            onChange(Math.max(0, offset - limit));
          }}
        >
          <ChevronLeft aria-hidden="true" className="size-4" />
          Previous
        </Button>
        <Button
          aria-label="Next page"
          disabled={offset + limit >= total}
          onClick={() => {
            onChange(offset + limit);
          }}
        >
          Next
          <ChevronRight aria-hidden="true" className="size-4" />
        </Button>
      </div>
    </nav>
  );
}
