import {
  Activity,
  ArrowRight,
  ArrowUpRight,
  CheckCircle,
  FolderKanban,
  Layers,
  Radio,
  RefreshCw,
  Server,
  Shield,
  ShieldAlert,
} from "lucide-react";
import { RequestError, StaleNotice } from "@/components/RequestError";
import { Button } from "@/components/ui/Button";
import { DefinitionList } from "@/components/ui/DefinitionList";
import { Panel } from "@/components/ui/Panel";
import { Skeleton } from "@/components/ui/Skeleton";
import { StateView } from "@/components/ui/StateView";
import { StatusBadge } from "@/components/ui/StatusBadge";
import { Table, Td, Th } from "@/components/ui/Table";
import { formatDateTime, formatMac, formatRelative, formatUptime } from "@/lib/format";
import { formatBytes, formatPacketTime } from "@/features/packets/hexdump";
import { ConfidenceBadge } from "@/features/flows/common";
import { useReadyBackend } from "@/lib/connection/BackendProvider";
import { usePolling } from "@/lib/usePolling";
import { useRequest } from "@/lib/useRequest";
import type {
  AlertListItem,
  AlertSummary,
  ApplicationStat,
  CaseSummary,
  Device,
  FlowSummary,
  FlowTimeline,
  InterfaceEvent,
} from "@/lib/api/types";

function PanelSkeleton({ label }: { label: string }) {
  return (
    <div role="status" aria-label={label} aria-busy="true" className="space-y-3">
      <Skeleton className="h-4 w-1/3" />
      <Skeleton className="h-4 w-2/3" />
      <Skeleton className="h-4 w-1/2" />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Section 1: Dashboard Header
// ---------------------------------------------------------------------------

function DashboardHeader({
  status,
  updatedAt,
  isRefreshing,
  onRefresh,
}: {
  status?: string;
  updatedAt?: number;
  isRefreshing: boolean;
  onRefresh: () => void;
}) {
  const isHealthy = status === "ok";

  return (
    <header className="flex flex-wrap items-center justify-between gap-4 border-b border-ops-border pb-4">
      <div>
        <div className="flex items-center gap-2">
          <span className="font-mono text-xs font-semibold tracking-wider text-ops-crimson uppercase">
            TAPROX
          </span>
          <span className="text-ops-border">/</span>
          <h1 className="text-base font-semibold tracking-wide text-ops-text">
            Security Operations Center
          </h1>
        </div>
        <p className="mt-0.5 text-xs text-ops-muted">
          Real-time network security monitoring and operational intelligence.
        </p>
      </div>

      <div className="flex flex-wrap items-center gap-3 text-xs">
        <div className="flex items-center gap-2 rounded-md border border-ops-border bg-ops-card px-2.5 py-1">
          <span
            className={`inline-block size-2 rounded-full ${
              isHealthy
                ? "bg-success shadow-[0_0_8px_rgba(118,166,138,0.6)]"
                : "bg-ops-crimson shadow-[0_0_8px_rgba(229,32,58,0.6)]"
            }`}
          />
          <span className="font-mono text-[11px] font-medium tracking-wider uppercase text-ops-text">
            {isHealthy ? "SYSTEM OPERATIONAL" : "BACKEND PENDING"}
          </span>
        </div>

        {updatedAt && (
          <span className="hidden font-mono text-[11px] text-ops-muted sm:inline-block">
            UPDATED {new Date(updatedAt).toLocaleTimeString()}
          </span>
        )}

        <Button
          variant="secondary"
          loading={isRefreshing}
          onClick={onRefresh}
          className="h-7 text-xs border-ops-border bg-ops-card hover:bg-raised"
          aria-label="Refresh operational dashboard"
        >
          <RefreshCw className="size-3 text-ops-muted" aria-hidden="true" />
          <span>Refresh</span>
        </Button>
      </div>
    </header>
  );
}

// ---------------------------------------------------------------------------
// Section 2: Operational KPI Strip
// ---------------------------------------------------------------------------

interface KpiItemProps {
  label: string;
  value: string | number;
  note: string;
  href: string;
  icon: React.ComponentType<{ className?: string; "aria-hidden"?: boolean | "true" | "false" }>;
  critical?: boolean;
}

function KpiCard({ label, value, note, href, icon: Icon, critical }: KpiItemProps) {
  return (
    <a
      href={href}
      className={`group relative flex flex-col justify-between rounded-lg border p-3.5 transition-all duration-150 hover:-translate-y-0.5 hover:shadow-md ${
        critical
          ? "border-ops-crimson/50 bg-ops-crimson/10 shadow-[0_0_12px_-3px_rgba(229,32,58,0.25)]"
          : "border-ops-border bg-ops-card hover:border-line-strong hover:bg-surface/80"
      }`}
    >
      <div className="flex items-center justify-between gap-2">
        <span className="text-[11px] font-semibold tracking-wider text-ops-muted uppercase">
          {label}
        </span>
        <Icon
          className={`size-4 transition-colors ${
            critical ? "text-ops-crimson" : "text-ops-muted group-hover:text-ops-text"
          }`}
          aria-hidden="true"
        />
      </div>

      <div className="my-2">
        <span
          className={`font-mono text-2xl font-bold tracking-tight ${
            critical ? "text-ops-crimson" : "text-ops-text"
          }`}
        >
          {value}
        </span>
      </div>

      <div className="flex items-center justify-between text-xs text-ops-muted">
        <span className="truncate">{note}</span>
        <ArrowUpRight
          className="size-3.5 shrink-0 opacity-0 transition-opacity group-hover:opacity-100"
          aria-hidden="true"
        />
      </div>
    </a>
  );
}

// ---------------------------------------------------------------------------
// Section 3: Central Network Activity Overview
// ---------------------------------------------------------------------------

function NetworkActivitySection({
  summary,
  timeline,
}: {
  summary?: FlowSummary;
  timeline?: FlowTimeline;
}) {
  const points = timeline?.points ?? [];
  const hasPoints = points.length > 0;
  const totals = points.map((p) => p.sent_bytes + p.received_bytes + p.other_bytes);
  const max = Math.max(1, ...totals);
  const width = 800;
  const height = 130;
  const bar = width / Math.max(1, points.length);

  return (
    <Panel
      title="Network Traffic Activity"
      description={
        summary?.session
          ? `Current capture session (${summary.session.interface_name || "Endpoint"}) · ${formatBytes(
              summary.bytes,
            )} observed`
          : "Traffic volume over time at current capture point"
      }
      actions={
        <a
          href="#/activity"
          className="inline-flex items-center gap-1 text-xs text-link underline underline-offset-2 hover:text-fg"
        >
          Full Activity <ArrowRight className="size-3" aria-hidden="true" />
        </a>
      }
    >
      {hasPoints ? (
        <div className="space-y-3">
          <div className="overflow-hidden rounded-md border border-ops-border bg-ops-bg p-2">
            <svg
              role="img"
              aria-label={`Traffic time-series graph: ${points.length} intervals, peak ${formatBytes(max)}`}
              viewBox={`0 0 ${width} ${height}`}
              className="h-32 w-full"
              preserveAspectRatio="none"
            >
              {points.map((p, i) => {
                const parts = [
                  { value: p.sent_bytes, fill: "#E5203A" }, // Crimson: host transmitted
                  { value: p.received_bytes, fill: "#8BA9B8" }, // Blue: host received
                  { value: p.other_bytes, fill: "#84796A" }, // Neutral: broadcast/other
                ];
                let y = height;
                return (
                  <g key={p.start}>
                    {parts.map((part) => {
                      const h = (part.value / max) * (height - 6);
                      y -= h;
                      return h > 0 ? (
                        <rect
                          key={part.fill}
                          x={i * bar}
                          y={y}
                          width={Math.max(1, bar - 1)}
                          height={h}
                          fill={part.fill}
                        />
                      ) : null;
                    })}
                  </g>
                );
              })}
            </svg>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3 text-xs text-ops-muted">
            <ul className="flex flex-wrap gap-4">
              <li className="flex items-center gap-1.5">
                <span className="size-2 rounded-sm bg-ops-crimson" aria-hidden="true" />
                <span>Sent (Host PC)</span>
              </li>
              <li className="flex items-center gap-1.5">
                <span className="size-2 rounded-sm bg-[#8BA9B8]" aria-hidden="true" />
                <span>Received</span>
              </li>
              <li className="flex items-center gap-1.5">
                <span className="size-2 rounded-sm bg-[#84796A]" aria-hidden="true" />
                <span>Subnet / Broadcast</span>
              </li>
            </ul>
            <span className="font-mono text-[11px]">
              Step: {timeline?.width_seconds ?? 1}s · Total: {formatBytes(summary?.bytes ?? 0)}
            </span>
          </div>

          <details>
            <summary className="cursor-pointer text-xs text-ops-muted hover:text-ops-text">
              Show traffic data table
            </summary>
            <div className="mt-2 max-h-48 overflow-y-auto">
              <Table label="Traffic per interval">
                <thead>
                  <tr>
                    <Th>Start Time</Th>
                    <Th>Packets</Th>
                    <Th>Sent</Th>
                    <Th>Received</Th>
                    <Th>Other</Th>
                  </tr>
                </thead>
                <tbody>
                  {points.slice(-10).map((p) => (
                    <tr key={p.start}>
                      <Td mono>{formatPacketTime(new Date(p.start).getTime() / 1000).text}</Td>
                      <Td mono>{p.packets.toLocaleString()}</Td>
                      <Td mono>{formatBytes(p.sent_bytes)}</Td>
                      <Td mono>{formatBytes(p.received_bytes)}</Td>
                      <Td mono>{formatBytes(p.other_bytes)}</Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            </div>
          </details>
        </div>
      ) : (
        <StateView
          variant="empty"
          title="No traffic recorded in current session"
          description="Traffic activity is collected during live packet captures or capture file analysis."
        />
      )}
    </Panel>
  );
}

// ---------------------------------------------------------------------------
// Section 4: Network Intelligence (Devices & Applications)
// ---------------------------------------------------------------------------

function DevicesSection({ devices }: { devices?: Device[] }) {
  const items = devices?.slice(0, 5) ?? [];

  return (
    <Panel
      title="Discovered Devices"
      description="Recent endpoints identified on the local network segment"
      actions={
        <a
          href="#/devices"
          className="inline-flex items-center gap-1 text-xs text-link underline underline-offset-2 hover:text-fg"
        >
          View all devices <ArrowRight className="size-3" aria-hidden="true" />
        </a>
      }
    >
      {items.length > 0 ? (
        <ul className="divide-y divide-ops-border text-xs">
          {items.map((dev) => {
            const primaryIp = dev.observed.ip || "—";
            const displayName = dev.observed.hostname || dev.inferred.vendor || primaryIp || `Device #${dev.id}`;
            return (
              <li key={dev.id} className="flex items-center justify-between py-2.5">
                <div className="space-y-0.5">
                  <div className="flex items-center gap-2">
                    <a
                      href={`#/devices?device=${dev.id}`}
                      className="font-medium text-ops-text hover:text-link hover:underline"
                    >
                      {displayName}
                    </a>
                    {dev.is_local && (
                      <span className="rounded bg-accent/20 px-1 py-0.2 font-mono text-[10px] text-accent">
                        THIS PC
                      </span>
                    )}
                    {dev.inferred.state === "active" && (
                      <span className="rounded bg-success/20 px-1 py-0.2 font-mono text-[10px] text-success">
                        ACTIVE
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-2 font-mono text-[11px] text-ops-muted">
                    <span>{primaryIp}</span>
                    <span>·</span>
                    <span>{formatMac(dev.mac)}</span>
                  </div>
                </div>
                <div className="text-right">
                  <span className="text-[11px] text-ops-muted">
                    {formatRelative(dev.observed.last_seen)}
                  </span>
                </div>
              </li>
            );
          })}
        </ul>
      ) : (
        <StateView
          variant="empty"
          title="No devices discovered yet"
          description="Run active discovery or start packet capture to populate device inventory."
        />
      )}
    </Panel>
  );
}

function ApplicationSection({ applications }: { applications?: ApplicationStat[] }) {
  const items = applications?.filter((a) => a.application !== "Unclassified").slice(0, 5) ?? [];

  return (
    <Panel
      title="Application Intelligence"
      description="Active services and decoded network application protocols"
      actions={
        <a
          href="#/applications"
          className="inline-flex items-center gap-1 text-xs text-link underline underline-offset-2 hover:text-fg"
        >
          View applications <ArrowRight className="size-3" aria-hidden="true" />
        </a>
      }
    >
      {items.length > 0 ? (
        <ul className="divide-y divide-ops-border text-xs">
          {items.map((app) => (
            <li key={app.application} className="flex items-center justify-between py-2.5">
              <div className="space-y-0.5">
                <div className="flex items-center gap-2">
                  <a
                    href={`#/flows?application=${encodeURIComponent(app.application)}`}
                    className="font-medium text-ops-text hover:text-link hover:underline"
                  >
                    {app.application}
                  </a>
                  <ConfidenceBadge value={app.confidence} />
                </div>
                <p className="text-[11px] text-ops-muted">{app.category}</p>
              </div>

              <div className="text-right">
                <div className="font-mono text-xs font-semibold text-ops-text">
                  {formatBytes(app.bytes)}
                </div>
                <div className="font-mono text-[11px] text-ops-muted">
                  {app.packets.toLocaleString()} pkts · {app.flows} flows
                </div>
              </div>
            </li>
          ))}
        </ul>
      ) : (
        <StateView
          variant="empty"
          title="No applications identified"
          description="Application decoding requires observable packet streams or capture file replay."
        />
      )}
    </Panel>
  );
}

// ---------------------------------------------------------------------------
// Section 5: Security Operations (Alerts & Threat Detection)
// ---------------------------------------------------------------------------

function SecurityAlertsSection({
  summary,
  recentAlerts,
}: {
  summary?: AlertSummary;
  recentAlerts?: AlertListItem[];
}) {
  const bySev = summary?.by_severity ?? { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const crit = bySev.critical ?? 0;
  const high = bySev.high ?? 0;
  const med = bySev.medium ?? 0;
  const low = bySev.low ?? 0;
  const info = bySev.info ?? 0;
  const items = recentAlerts?.slice(0, 4) ?? [];

  return (
    <Panel
      title="Security Alerts"
      description="Threat detections, rule violations, and risk scoring"
      actions={
        <a
          href="#/threats"
          className="inline-flex items-center gap-1 text-xs text-link underline underline-offset-2 hover:text-fg"
        >
          Threat Detection <ArrowRight className="size-3" aria-hidden="true" />
        </a>
      }
    >
      <div className="space-y-4">
        {/* Severity distribution strip */}
        <div className="grid grid-cols-4 gap-2 text-center text-xs">
          <div
            className={`rounded border p-2 ${
              crit > 0
                ? "border-ops-crimson/60 bg-ops-crimson/15 text-ops-crimson font-bold"
                : "border-ops-border bg-ops-bg text-ops-muted"
            }`}
          >
            <div className="text-[10px] tracking-wider uppercase">Critical</div>
            <div className="font-mono text-base">{crit}</div>
          </div>
          <div
            className={`rounded border p-2 ${
              high > 0
                ? "border-warning/60 bg-warning/15 text-warning font-bold"
                : "border-ops-border bg-ops-bg text-ops-muted"
            }`}
          >
            <div className="text-[10px] tracking-wider uppercase">High</div>
            <div className="font-mono text-base">{high}</div>
          </div>
          <div className="rounded border border-ops-border bg-ops-bg p-2 text-ops-muted">
            <div className="text-[10px] tracking-wider uppercase">Medium</div>
            <div className="font-mono text-base text-ops-text">{med}</div>
          </div>
          <div className="rounded border border-ops-border bg-ops-bg p-2 text-ops-muted">
            <div className="text-[10px] tracking-wider uppercase">Low / Info</div>
            <div className="font-mono text-base text-ops-text">{low + info}</div>
          </div>
        </div>

        {items.length > 0 ? (
          <ul className="divide-y divide-ops-border text-xs">
            {items.map((al) => (
              <li key={al.id} className="flex items-center justify-between py-2">
                <div className="space-y-0.5">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-[10px] font-semibold text-ops-crimson">
                      {al.rule_id}
                    </span>
                    <a
                      href={`#/threats?alert=${al.id}`}
                      className="font-medium text-ops-text hover:text-link hover:underline"
                    >
                      {al.title}
                    </a>
                  </div>
                  <p className="font-mono text-[11px] text-ops-muted">
                    Target: {al.entity_key} {al.entity_kind ? `(${al.entity_kind})` : ""}
                  </p>
                </div>
                <div className="text-right">
                  <span
                    className={`rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase ${
                      al.severity === "critical"
                        ? "bg-ops-crimson text-white"
                        : al.severity === "high"
                          ? "bg-warning/20 text-warning"
                          : "bg-surface text-ops-muted border border-ops-border"
                    }`}
                  >
                    {al.severity}
                  </span>
                  <div className="mt-0.5 text-[10px] text-ops-muted">
                    {formatRelative(al.observed_end || al.created_at)}
                  </div>
                </div>
              </li>
            ))}
          </ul>
        ) : (
          <div className="rounded border border-ops-border bg-ops-bg p-3 text-center text-xs text-ops-muted">
            <CheckCircle className="mx-auto mb-1.5 size-4 text-success" aria-hidden="true" />
            No active threat alerts detected in the current window.
          </div>
        )}
      </div>
    </Panel>
  );
}

function ThreatEnginePanel() {
  return (
    <Panel
      title="Threat Detection Engine"
      description="Active heuristic rules, baseline behavioral profiles, and detection state"
      actions={
        <a
          href="#/threats/rules"
          className="inline-flex items-center gap-1 text-xs text-link underline underline-offset-2 hover:text-fg"
        >
          Rule Config <ArrowRight className="size-3" aria-hidden="true" />
        </a>
      }
    >
      <div className="space-y-3 text-xs">
        <div className="flex items-center justify-between rounded-md border border-ops-border bg-ops-bg p-2.5">
          <div className="flex items-center gap-2">
            <Shield className="size-4 text-ops-crimson" aria-hidden="true" />
            <div>
              <div className="font-medium text-ops-text">Heuristic Behavioral Analyzer</div>
              <div className="text-[11px] text-ops-muted">18 built-in inspection rules</div>
            </div>
          </div>
          <span className="rounded bg-success/15 px-2 py-0.5 font-mono text-[11px] font-medium text-success border border-success/30">
            ARMED
          </span>
        </div>

        <div className="grid grid-cols-2 gap-2 text-ops-muted">
          <div className="rounded border border-ops-border bg-ops-bg p-2">
            <div className="text-[10px] tracking-wider uppercase">Reconnaissance</div>
            <div className="mt-1 font-mono text-xs text-ops-text">Port scan & sweep monitoring</div>
          </div>
          <div className="rounded border border-ops-border bg-ops-bg p-2">
            <div className="text-[10px] tracking-wider uppercase">Anomalous Traffic</div>
            <div className="mt-1 font-mono text-xs text-ops-text">Beaconing & volume bursts</div>
          </div>
          <div className="rounded border border-ops-border bg-ops-bg p-2">
            <div className="text-[10px] tracking-wider uppercase">Insecure Protocols</div>
            <div className="mt-1 font-mono text-xs text-ops-text">Plaintext auth & unencrypted flows</div>
          </div>
          <div className="rounded border border-ops-border bg-ops-bg p-2">
            <div className="text-[10px] tracking-wider uppercase">DNS Hygiene</div>
            <div className="mt-1 font-mono text-xs text-ops-text">Tunneling & DGA detection</div>
          </div>
        </div>
      </div>
    </Panel>
  );
}

// ---------------------------------------------------------------------------
// Section 6: Recent Network Events
// ---------------------------------------------------------------------------

interface CombinedEvent {
  id: string;
  type: "interface" | "alert" | "case";
  title: string;
  detail: string;
  timestamp: string;
  href: string;
}

function RecentEventsSection({
  interfaceEvents,
  alerts,
  cases,
}: {
  interfaceEvents?: InterfaceEvent[];
  alerts?: AlertListItem[];
  cases?: CaseSummary[];
}) {
  const events: CombinedEvent[] = [];

  for (const ev of interfaceEvents ?? []) {
    events.push({
      id: `iface-${ev.sequence}`,
      type: "interface",
      title: `${ev.interface_name}: ${ev.kind.replace(/_/g, " ")}`,
      detail: ev.detail || "Network adapter status change recorded",
      timestamp: ev.at,
      href: "#/interfaces",
    });
  }

  for (const al of alerts ?? []) {
    events.push({
      id: `alert-${al.id}`,
      type: "alert",
      title: `Threat alert: ${al.title}`,
      detail: `Severity: ${al.severity} · Target: ${al.entity_key}`,
      timestamp: al.created_at,
      href: `#/threats?alert=${al.id}`,
    });
  }

  for (const cs of cases ?? []) {
    events.push({
      id: `case-${cs.case_uid}`,
      type: "case",
      title: `Case ${cs.case_ref}: ${cs.title}`,
      detail: `Status: ${cs.status} · Severity: ${cs.severity}`,
      timestamp: cs.created_at,
      href: "#/investigations",
    });
  }

  events.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
  const displayEvents = events.slice(0, 6);

  return (
    <Panel
      title="Recent Network Events"
      description="Chronological event log across interfaces, detection alerts, and investigations"
    >
      {displayEvents.length > 0 ? (
        <ul className="divide-y divide-ops-border text-xs">
          {displayEvents.map((ev) => (
            <li key={ev.id} className="flex items-start justify-between gap-3 py-2.5">
              <div className="flex items-start gap-2.5">
                <div className="mt-0.5 rounded bg-ops-bg p-1 border border-ops-border shrink-0">
                  {ev.type === "alert" ? (
                    <ShieldAlert className="size-3.5 text-ops-crimson" aria-hidden="true" />
                  ) : ev.type === "case" ? (
                    <FolderKanban className="size-3.5 text-warning" aria-hidden="true" />
                  ) : (
                    <Radio className="size-3.5 text-link" aria-hidden="true" />
                  )}
                </div>
                <div>
                  <a
                    href={ev.href}
                    className="font-medium text-ops-text hover:text-link hover:underline"
                  >
                    {ev.title}
                  </a>
                  <p className="text-[11px] text-ops-muted">{ev.detail}</p>
                </div>
              </div>
              <span className="shrink-0 text-[11px] text-ops-muted">
                {formatRelative(ev.timestamp)}
              </span>
            </li>
          ))}
        </ul>
      ) : (
        <StateView
          variant="empty"
          title="No recent network events recorded"
          description="Interface transitions, threat findings, and investigation logs appear here."
        />
      )}
    </Panel>
  );
}

// ---------------------------------------------------------------------------
// Section 7: System Health (Backend & Packet Capture Panels)
// ---------------------------------------------------------------------------

function BackendPanel() {
  const { client, baseUrl } = useReadyBackend();
  const request = useRequest((signal) => client.getHealth(signal), [client]);
  const health = request.data;

  return (
    <Panel
      title="Backend"
      description="Local service that powers TAPROX"
      actions={
        health && (
          <Button loading={request.isRefreshing} onClick={request.reload}>
            Refresh
          </Button>
        )
      }
    >
      {request.isLoading && <PanelSkeleton label="Loading backend status" />}
      {!health && request.error && (
        <RequestError error={request.error} what="backend status" onRetry={request.reload} />
      )}
      {health && request.error && (
        <StaleNotice
          error={request.error}
          what="backend status"
          asOf={request.dataUpdatedAt}
          onRetry={request.reload}
        />
      )}
      {health && (
        <DefinitionList
          items={[
            {
              label: "Status",
              value:
                health.status === "ok" ? (
                  <StatusBadge tone="success">Healthy</StatusBadge>
                ) : (
                  <StatusBadge tone="critical">Unhealthy</StatusBadge>
                ),
            },
            { label: "Version", value: health.version, mono: true },
            { label: "API version", value: health.api_version, mono: true },
            { label: "Listening on", value: `${new URL(baseUrl).host} (loopback only)`, mono: true },
            { label: "Uptime", value: formatUptime(health.uptime_seconds) },
            { label: "Started", value: formatDateTime(health.started_at) },
            {
              label: "Database",
              value: (
                <span className="inline-flex flex-wrap items-center gap-2">
                  {health.database.status === "ok" ? (
                    <StatusBadge tone="success">Ready</StatusBadge>
                  ) : (
                    <StatusBadge tone="critical">Unavailable</StatusBadge>
                  )}
                  {health.database.schema_version && (
                    <span className="font-mono text-xs text-fg-muted">
                      schema {health.database.schema_version}
                    </span>
                  )}
                </span>
              ),
            },
            { label: "Database created", value: formatDateTime(health.database.initialized_at) },
          ]}
        />
      )}
      {health && (
        <p aria-live="polite" className="mt-3 text-xs text-fg-subtle">
          As of {formatDateTime(request.dataUpdatedAt)}
        </p>
      )}
    </Panel>
  );
}

function CapturePanel() {
  const { client } = useReadyBackend();
  const request = useRequest((signal) => client.getCapturePrerequisites(signal), [client]);
  const prerequisites = request.data;
  const problems = prerequisites?.checks.filter((check) => check.status !== "ok") ?? [];

  return (
    <Panel title="Packet capture" description="Native capture tools on this computer">
      {request.isLoading && <PanelSkeleton label="Loading capture tools" />}
      {!prerequisites && request.error && (
        <RequestError error={request.error} what="capture tools" onRetry={request.reload} />
      )}
      {prerequisites && (
        <div className="space-y-3">
          {problems.length === 0 ? (
            <StatusBadge tone="success">Capture tools detected</StatusBadge>
          ) : (
            <StatusBadge tone="warning">Capture tools incomplete</StatusBadge>
          )}
          {problems.length > 0 && (
            <p className="text-fg">
              Missing or not working: <strong>{problems.map((check) => check.name).join(", ")}</strong>.
            </p>
          )}
          <p className="text-fg-muted">Packet capture sessions are not available in this version yet.</p>
          <a
            href="#/settings"
            className="inline-block text-link underline underline-offset-2 hover:text-fg"
          >
            View capture prerequisites
          </a>
        </div>
      )}
    </Panel>
  );
}

// ---------------------------------------------------------------------------
// Main Overview Page
// ---------------------------------------------------------------------------

export function OverviewPage({ pollMs = 10000 }: { pollMs?: number }) {
  const { client } = useReadyBackend();

  // Core requests
  const healthReq = useRequest((signal) => client.getHealth(signal), [client]);
  const prereqReq = useRequest((signal) => client.getCapturePrerequisites(signal), [client]);

  // Operational requests (each fails independently without blocking the dashboard)
  const devicesReq = useRequest((signal) => client.getDevices({ limit: 6 }, signal), [client]);
  const flowSummaryReq = useRequest((signal) => client.getFlowSummary("current", signal), [client]);
  const timelineReq = useRequest((signal) => client.getFlowTimeline("current", signal), [client]);
  const appsReq = useRequest((signal) => client.getFlowApplications("current", signal), [client]);
  const alertsSummaryReq = useRequest((signal) => client.getAlertSummary("24h", signal), [client]);
  const alertsReq = useRequest((signal) => client.getAlerts({ limit: 5 }, signal), [client]);
  const casesReq = useRequest((signal) => client.listCases({ limit: 5 }, signal), [client]);
  const ifaceEventsReq = useRequest((signal) => client.getInterfaceEvents(5, signal), [client]);

  const live = flowSummaryReq.data?.session?.status === "running";

  usePolling(() => {
    if (!healthReq.isPending) healthReq.reloadQuietly();
    if (!prereqReq.isPending) prereqReq.reloadQuietly();
    if (!devicesReq.isPending) devicesReq.reloadQuietly();
    if (!flowSummaryReq.isPending) flowSummaryReq.reloadQuietly();
    if (!timelineReq.isPending) timelineReq.reloadQuietly();
    if (!appsReq.isPending) appsReq.reloadQuietly();
    if (!alertsSummaryReq.isPending) alertsSummaryReq.reloadQuietly();
    if (!alertsReq.isPending) alertsReq.reloadQuietly();
    if (!casesReq.isPending) casesReq.reloadQuietly();
    if (!ifaceEventsReq.isPending) ifaceEventsReq.reloadQuietly();
  }, live ? Math.min(pollMs, 3000) : pollMs);

  const reloadAll = () => {
    healthReq.reload();
    prereqReq.reload();
    devicesReq.reload();
    flowSummaryReq.reload();
    timelineReq.reload();
    appsReq.reload();
    alertsSummaryReq.reload();
    alertsReq.reload();
    casesReq.reload();
    ifaceEventsReq.reload();
  };

  const isRefreshing =
    healthReq.isRefreshing ||
    devicesReq.isRefreshing ||
    flowSummaryReq.isRefreshing ||
    alertsSummaryReq.isRefreshing;

  const criticalAlerts = alertsSummaryReq.data?.by_severity?.critical ?? 0;
  const highAlerts = alertsSummaryReq.data?.by_severity?.high ?? 0;
  const namedAppsCount = appsReq.data?.applications.filter((a) => a.application !== "Unclassified").length ?? 0;
  const activeDevicesCount = devicesReq.data?.devices.filter((d) => d.inferred.state === "active").length ?? 0;
  const activeCasesCount = casesReq.data?.items.filter((c) => c.status === "active").length ?? 0;

  return (
    <div className="space-y-6">
      {/* Section 1: Dashboard Header */}
      <DashboardHeader
        status={healthReq.data?.status}
        updatedAt={healthReq.dataUpdatedAt}
        isRefreshing={isRefreshing}
        onRefresh={reloadAll}
      />

      {/* Section 2: Operational KPI Strip */}
      <section aria-label="Operational Metrics" className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-6">
        <KpiCard
          label="Network Devices"
          value={devicesReq.data ? devicesReq.data.total.toLocaleString() : devicesReq.isLoading ? "..." : "0"}
          note={`${activeDevicesCount} active`}
          href="#/devices"
          icon={Server}
        />
        <KpiCard
          label="Active Flows"
          value={flowSummaryReq.data ? flowSummaryReq.data.active_flows.toLocaleString() : flowSummaryReq.isLoading ? "..." : "0"}
          note={`${flowSummaryReq.data?.observed_flows ?? 0} observed`}
          href="#/flows"
          icon={Activity}
        />
        <KpiCard
          label="Traffic Volume"
          value={flowSummaryReq.data ? formatBytes(flowSummaryReq.data.bytes) : flowSummaryReq.isLoading ? "..." : "0 B"}
          note={`${(flowSummaryReq.data?.packets ?? 0).toLocaleString()} pkts`}
          href="#/activity"
          icon={Radio}
        />
        <KpiCard
          label="Applications"
          value={appsReq.data ? String(namedAppsCount) : appsReq.isLoading ? "..." : "0"}
          note={`${appsReq.data?.identified_flows ?? 0} flows`}
          href="#/applications"
          icon={Layers}
        />
        <KpiCard
          label="Security Alerts"
          value={alertsSummaryReq.data ? String(alertsSummaryReq.data.total) : alertsSummaryReq.isLoading ? "..." : "0"}
          note={`${criticalAlerts} crit · ${highAlerts} high`}
          href="#/threats"
          icon={ShieldAlert}
          critical={criticalAlerts > 0}
        />
        <KpiCard
          label="Investigations"
          value={casesReq.data ? String(casesReq.data.total) : casesReq.isLoading ? "..." : "0"}
          note={`${activeCasesCount} active`}
          href="#/investigations"
          icon={FolderKanban}
        />
      </section>

      {/* Section 3: Central Network Activity Overview */}
      <NetworkActivitySection
        summary={flowSummaryReq.data}
        timeline={timelineReq.data}
      />

      {/* Section 4: Network Intelligence (Devices & Applications) */}
      <div className="grid gap-6 lg:grid-cols-2">
        <DevicesSection devices={devicesReq.data?.devices} />
        <ApplicationSection applications={appsReq.data?.applications} />
      </div>

      {/* Section 5: Security Operations (Alerts & Engine) */}
      <div className="grid gap-6 lg:grid-cols-2">
        <SecurityAlertsSection
          summary={alertsSummaryReq.data}
          recentAlerts={alertsReq.data?.items}
        />
        <ThreatEnginePanel />
      </div>

      {/* Section 6: Recent Network Events */}
      <RecentEventsSection
        interfaceEvents={ifaceEventsReq.data?.events}
        alerts={alertsReq.data?.items}
        cases={casesReq.data?.items}
      />

      {/* Section 7: System Health (Backend & Packet Capture) */}
      <div className="grid gap-6 lg:grid-cols-2">
        <BackendPanel />
        <CapturePanel />
      </div>
    </div>
  );
}
