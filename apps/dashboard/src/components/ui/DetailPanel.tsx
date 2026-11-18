import { X } from "lucide-react";
import { useEffect, useId, useRef, type ReactNode } from "react";
import { Button } from "./Button";

interface Props {
  title: string;
  onClose: () => void;
  children: ReactNode;
}

/**
 * A non-modal details panel that sits beside the list, so the list stays usable. Focus moves to
 * the heading when it opens; Escape or the Close button dismisses it. Escape typed inside a
 * text field or select is left alone because it belongs to that control.
 */
export function DetailPanel({ title, onClose, children }: Props) {
  const headingId = useId();
  const headingRef = useRef<HTMLHeadingElement>(null);
  const closeRef = useRef(onClose);

  useEffect(() => {
    closeRef.current = onClose;
  });

  useEffect(() => {
    headingRef.current?.focus();
  }, []);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key !== "Escape" || event.defaultPrevented) return;
      const target = event.target;
      if (target instanceof HTMLElement && ["INPUT", "SELECT", "TEXTAREA"].includes(target.tagName)) {
        return;
      }
      closeRef.current();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => {
      window.removeEventListener("keydown", onKeyDown);
    };
  }, []);

  return (
    <aside aria-labelledby={headingId} className="rounded-lg border border-line bg-surface">
      <header className="flex items-start justify-between gap-3 border-b border-line px-4 py-3">
        <h2
          id={headingId}
          ref={headingRef}
          tabIndex={-1}
          className="min-w-0 break-words text-sm font-semibold text-fg focus:outline-none"
        >
          {title}
        </h2>
        <Button variant="ghost" aria-label="Close details" onClick={onClose}>
          <X aria-hidden="true" className="size-4" />
        </Button>
      </header>
      <div className="p-4">{children}</div>
    </aside>
  );
}
