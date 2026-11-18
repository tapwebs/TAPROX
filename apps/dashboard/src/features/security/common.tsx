import { Eye, Gauge, ShieldQuestion } from "lucide-react";
import type { ReactNode } from "react";
import { StatusBadge, type Tone } from "@/components/ui/StatusBadge";
import type { AlertSeverity, AlertStatus } from "@/lib/api/types";

const SEVERITY_TONE: Record<AlertSeverity, Tone> = {
  info: "info",
  low: "neutral",
  medium: "warning",
  high: "critical",
  critical: "critical",
};
const SEVERITY_STEPS: Record<AlertSeverity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
export const SEVERITIES: readonly AlertSeverity[] = ["info", "low", "medium", "high", "critical"];

/** The visible text is always the level name; the step marker adds a second, non-colour cue. */
export function SeverityBadge({ level }: { level: AlertSeverity }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      <StatusBadge tone={SEVERITY_TONE[level]}>{level[0]?.toUpperCase()}{level.slice(1)}</StatusBadge>
      <span aria-hidden="true" className="font-mono text-[10px] tracking-tighter text-fg-subtle">
        {"▮".repeat(SEVERITY_STEPS[level] + 1)}
        {"▯".repeat(4 - SEVERITY_STEPS[level])}
      </span>
    </span>
  );
}

/** Deliberately not a tone colour, so it is never confused with severity. */
export function ConfidenceChip({ level }: { level: "low" | "medium" | "high" }) {
  return (
    <span className="inline-flex items-center gap-1 rounded-sm border border-line-strong px-1.5 py-0.5 text-xs text-fg-muted">
      <ShieldQuestion aria-hidden="true" className="size-3.5" />
      Confidence: {level}
    </span>
  );
}

export function RiskScore({ value }: { value: number }) {
  return (
    <span className="inline-flex items-center gap-1 font-mono text-[13px] text-fg">
      <Gauge aria-hidden="true" className="size-3.5 text-fg-muted" />
      {value}
    </span>
  );
}

export const RISK_NOTE = "A score orders alerts. It is not a probability.";

const BASIS_TEXT: Record<string, string> = {
  observed: "Observed",
  inferred: "Inferred",
  inventory: "Inventory",
};
export function BasisBadge({ basis }: { basis: string }) {
  return (
    <span className="inline-flex items-center gap-1 text-xs text-fg-muted">
      <Eye aria-hidden="true" className="size-3.5" />
      {BASIS_TEXT[basis] ?? "Unknown"}
    </span>
  );
}

const STATUS_LABEL: Record<AlertStatus, string> = {
  open: "Open",
  acknowledged: "Acknowledged",
  investigating: "Investigating",
  resolved: "Resolved",
  false_positive: "False positive",
  suppressed: "Suppressed",
};
export const STATUSES: readonly AlertStatus[] = [
  "open",
  "acknowledged",
  "investigating",
  "resolved",
  "false_positive",
  "suppressed",
];
export function statusLabel(status: AlertStatus): string {
  return STATUS_LABEL[status];
}
export function StatusTag({ status }: { status: AlertStatus }) {
  const tone: Tone = status === "open" ? "warning" : status === "investigating" || status === "acknowledged" ? "info" : "neutral";
  return <StatusBadge tone={tone}>{STATUS_LABEL[status]}</StatusBadge>;
}

const SECTIONS = [
  { href: "#/threats", label: "Overview", route: "threats" },
  { href: "#/alerts", label: "Alerts", route: "alerts" },
  { href: "#/history", label: "History", route: "history" },
] as const;

/** Links between the Threat Detection screens. This is navigation, not a tab panel. */
export function SectionNav({ current }: { current: "threats" | "alerts" | "history" }) {
  return (
    <nav aria-label="Threat detection sections" className="mb-4 flex gap-1">
      {SECTIONS.map((s) => (
        <a
          key={s.route}
          href={s.href}
          aria-current={s.route === current ? "page" : undefined}
          className={`rounded-md border px-3 py-1.5 text-sm ${
            s.route === current ? "border-accent bg-raised text-fg" : "border-line text-fg-muted hover:text-fg"
          }`}
        >
          {s.label}
        </a>
      ))}
    </nav>
  );
}

/** A time stamp from the server, shown in local time. Packet time of a replayed file is old, and says so. */
export function When({ iso, file }: { iso: string; file?: boolean }) {
  return (
    <time dateTime={iso} className="whitespace-nowrap">
      {new Date(iso).toLocaleString()}
      {file ? " (file replay)" : ""}
    </time>
  );
}

export function Footnote({ children }: { children: ReactNode }) {
  return <p className="mt-3 text-xs text-fg-subtle">{children}</p>;
}

/** Accepts only a positive whole number written without sign or padding. */
export function parseId(raw: string | null): number | null {
  return raw !== null && /^[1-9]\d{0,15}$/.test(raw) ? Number(raw) : null;
}
