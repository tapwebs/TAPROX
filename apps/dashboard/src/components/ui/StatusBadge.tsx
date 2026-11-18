import { CircleCheck, CircleX, Info, Minus, TriangleAlert, type LucideIcon } from "lucide-react";
import type { ReactNode } from "react";

export type Tone = "success" | "warning" | "critical" | "info" | "neutral";

const TONES: Record<Tone, { icon: LucideIcon; classes: string }> = {
  success: { icon: CircleCheck, classes: "text-success border-success/40 bg-success/15" },
  warning: { icon: TriangleAlert, classes: "text-warning border-warning/40 bg-warning/15" },
  critical: { icon: CircleX, classes: "text-critical border-critical/40 bg-critical/15" },
  info: { icon: Info, classes: "text-link border-link/40 bg-link/15" },
  neutral: { icon: Minus, classes: "text-neutral border-line-strong bg-raised/70" },
};

export const TONE_TEXT: Record<Tone, string> = {
  success: "text-success",
  warning: "text-warning",
  critical: "text-critical",
  info: "text-link",
  neutral: "text-neutral",
};

/** Status is conveyed by icon + text; colour only reinforces it. */
export function StatusBadge({ tone, children }: { tone: Tone; children: ReactNode }) {
  const { icon: Icon, classes } = TONES[tone];
  return (
    <span
      data-tone={tone}
      className={`inline-flex items-center gap-1.5 rounded-sm border px-1.5 py-0.5 text-xs font-medium ${classes}`}
    >
      <Icon aria-hidden="true" className="size-3.5 shrink-0" />
      {children}
    </span>
  );
}
