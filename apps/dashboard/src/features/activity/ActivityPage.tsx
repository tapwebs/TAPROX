import { useState } from "react";
import { RequestError, StaleNotice } from "@/components/RequestError";
import { Panel } from "@/components/ui/Panel";
import { StateView } from "@/components/ui/StateView";
import { StatTile } from "@/components/ui/StatTile";
import { Table, Td, Th } from "@/components/ui/Table";
import type { FlowSummary, FlowTimeline } from "@/lib/api/types";
import { useReadyBackend } from "@/lib/connection/BackendProvider";
import { usePolling } from "@/lib/usePolling";
import { useRequest } from "@/lib/useRequest";
import { formatBytes, formatPacketTime } from "@/features/packets/hexdump";
import { ConfidenceBadge, EndpointLabel, SessionPicker } from "@/features/flows/common";

/** Stacked bars of bytes per time bucket. The data table below it carries the same numbers. */
function TrafficChart({ timeline }: { timeline: FlowTimeline }) {
  const points = timeline.points;
  const width = 600;
  const height = 120;
  const totals = points.map((p) => p.sent_bytes + p.received_bytes + p.other_bytes);
  const max = Math.max(1, ...totals);
  const bar = width / Math.max(1, points.length);
  const summary = `Traffic over time in ${String(timeline.width_seconds)} second steps: ${formatBytes(
    totals.reduce((a, b) => a + b, 0),
  )} in ${String(points.length)} intervals.`;
  return (
    <div className="grid gap-2">
      <svg
        role="img"
        aria-label={summary}
        viewBox={`0 0 ${String(width)} ${String(height)}`}
        className="h-32 w-full rounded-md border border-line bg-inset"
        preserveAspectRatio="none"
      >
        {points.map((p, i) => {
          const parts = [
            { value: p.sent_bytes, className: "fill-accent" },
            { value: p.received_bytes, className: "fill-link" },
            { value: p.other_bytes, className: "fill-neutral" },
          ];
          let y = height;
          return (
            <g key={p.start}>
              {parts.map((part) => {
                const h = (part.value / max) * (height - 4);
                y -= h;
                return h > 0 ? (
                  <rect key={part.className} x={i * bar} y={y} width={Math.max(1, bar - 1)} height={h} className={part.className} />
                ) : null;
              })}
            </g>
          );
        })}
      </svg>
      <ul className="flex flex-wrap gap-4 text-xs text-fg-muted">
        <li><span aria-hidden="true" className="mr-1 inline-block size-2 bg-accent" />Sent by this computer</li>
        <li><span aria-hidden="true" className="mr-1 inline-block size-2 bg-link" />Received by this computer</li>
        <li><span aria-hidden="true" className="mr-1 inline-block size-2 bg-neutral" />Other or direction unknown</li>
      </ul>
      <details>
        <summary className="cursor-pointer text-xs text-fg-muted">Show the data as a table</summary>
        <div className="mt-2 max-h-64 overflow-y-auto">
          <Table label="Traffic per interval">
            <thead>
              <tr>
                <Th>Interval start</Th>
                <Th>Packets</Th>
                <Th>Sent</Th>
                <Th>Received</Th>
                <Th>Other</Th>
              </tr>
            </thead>
            <tbody>
              {points.map((p) => (
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
  );
}

function Bars({ items }: { items: { label: string; bytes: number; detail: string }[] }) {
  const max = Math.max(1, ...items.map((i) => i.bytes));
  return (
    <ul className="grid gap-2">
      {items.map((item) => (
        <li key={item.label} className="grid gap-0.5">
          <div className="flex justify-between gap-3 text-sm">
            <span className="min-w-0 break-words">{item.label}</span>
            <span className="shrink-0 font-mono text-[13px] text-fg-muted">{item.detail}</span>
          </div>
          <div aria-hidden="true" className="h-1.5 rounded-sm bg-inset">
            <div className="h-1.5 rounded-sm bg-accent-strong" style={{ width: `${String((item.bytes / max) * 100)}%` }} />
          </div>
        </li>
      ))}
    </ul>
  );
}

function Totals({ s }: { s: FlowSummary }) {
  return (
    <dl className="grid grid-cols-2 gap-3 md:grid-cols-3 lg:grid-cols-4">
      <StatTile label="Active flows" value={s.active_flows.toLocaleString()} />
      <StatTile label="Observed flows" value={s.observed_flows.toLocaleString()} />
      <StatTile label="Packets processed" value={s.packets.toLocaleString()} note={s.non_ip_packets ? `${s.non_ip_packets.toLocaleString()} are not IP (not flows)` : undefined} />
      <StatTile label="Bytes transferred" value={formatBytes(s.bytes)} />
      <StatTile label="Sent by this computer" value={s.direction_known ? formatBytes(s.sent_bytes) : "Unknown"} note={s.direction_known ? undefined : "This file has no local address"} />
      <StatTile label="Received by this computer" value={s.direction_known ? formatBytes(s.received_bytes) : "Unknown"} />
      <StatTile label="Other traffic" value={formatBytes(s.other_bytes)} note="Neither end is this computer" />
      <StatTile label="Flows with an application" value={`${s.flows_with_application.toLocaleString()} of ${s.observed_flows.toLocaleString()}`} />
    </dl>
  );
}

export function ActivityPage({ pollMs = 1000 }: { pollMs?: number }) {
  const { client } = useReadyBackend();
  const [session, setSession] = useState("current");
  const summary = useRequest((signal) => client.getFlowSummary(session, signal), [client, session]);
  const timeline = useRequest((signal) => client.getFlowTimeline(session, signal), [client, session]);
  const live = summary.data?.session?.status === "running";
  usePolling(() => {
    if (!summary.isPending) summary.reloadQuietly();
    if (!timeline.isPending) timeline.reloadQuietly();
  }, live ? pollMs : null);

  const data = summary.data;
  return (
    <div className="grid grid-cols-1 gap-4">
      <Panel
        title="Network activity"
        description="Everything on this screen is added up from the packets captured in the session you choose."
      >
        <div className="mb-4 max-w-sm">
          <SessionPicker value={session} onChange={setSession} />
        </div>
        {summary.isLoading && <StateView variant="loading" title="Loading network activity" />}
        {!data && summary.error && <RequestError error={summary.error} what="network activity" onRetry={summary.reload} />}
        {data && summary.error && <StaleNotice error={summary.error} what="network activity" asOf={summary.dataUpdatedAt} onRetry={summary.reload} />}
        {data && data.session === null && (
          <StateView
            variant="empty"
            title="No traffic has been processed yet"
            description="Start a capture or open a capture file in the Packet Explorer. Flows are built from its packets."
            action={{ label: "Open the Packet Explorer", onClick: () => { window.location.hash = "#/packets"; } }}
          />
        )}
        {data && data.session && (
          <div className="grid gap-4">
            <p className="text-sm text-fg-muted">
              {data.session.source === "file" ? `File ${data.session.file_name ?? ""}` : `Interface ${data.session.interface_name ?? ""}`}
              {" · "}
              {data.session.status === "running" ? "capturing now" : data.session.status === "failed" ? "capture failed (packets before the failure are included)" : "capture finished"}
            </p>
            <Totals s={data} />
            {data.flows_evicted > 0 && (
              <p className="text-xs text-warning">
                The flow table holds {data.limits.max_flows.toLocaleString()} flows; {data.flows_evicted.toLocaleString()} of the oldest were dropped. Packet and byte totals still include them.
              </p>
            )}
            {data.session.warnings.map((w) => (
              <p key={w} className="text-xs text-warning">{w}</p>
            ))}
          </div>
        )}
      </Panel>

      {data?.session && (
        <>
          <Panel title="Traffic over time" description="Bytes per interval. Intervals widen as a long capture grows, so the graph stays a fixed size.">
            {timeline.data && timeline.data.points.length > 0 ? (
              <TrafficChart timeline={timeline.data} />
            ) : (
              <p className="text-fg-muted">No traffic recorded yet.</p>
            )}
          </Panel>

          <div className="grid gap-4 lg:grid-cols-2">
            <Panel title="Top communicating devices" description="By bytes sent and received.">
              {data.top_endpoints.length === 0 ? (
                <p className="text-fg-muted">No IP traffic yet.</p>
              ) : (
                <Table label="Devices by traffic">
                  <thead>
                    <tr><Th>Endpoint</Th><Th>Flows</Th><Th>Sent</Th><Th>Received</Th></tr>
                  </thead>
                  <tbody>
                    {data.top_endpoints.map((e) => (
                      <tr key={e.endpoint.address}>
                        <Td><EndpointLabel endpoint={e.endpoint} /></Td>
                        <Td mono>{e.flows.toLocaleString()}</Td>
                        <Td mono>{formatBytes(e.sent_bytes)}</Td>
                        <Td mono>{formatBytes(e.received_bytes)}</Td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              )}
            </Panel>

            <Panel title="Top protocols" description="The most specific protocol tshark decoded in each flow.">
              <Bars items={data.top_protocols.map((p) => ({ label: p.protocol, bytes: p.bytes, detail: `${formatBytes(p.bytes)} · ${p.flows.toLocaleString()} flows` }))} />
            </Panel>

            <Panel title="Top destinations" description="Remote addresses. A name appears only if the flow revealed one.">
              <Table label="Destinations by traffic">
                <thead>
                  <tr><Th>Address</Th><Th>Name seen</Th><Th>Flows</Th><Th>Bytes</Th></tr>
                </thead>
                <tbody>
                  {data.top_destinations.map((d) => (
                    <tr key={d.address}>
                      <Td mono>{d.address}</Td>
                      <Td>
                        {d.hostname ? (
                          <span title={d.hostname_source ?? undefined}>{d.hostname}</span>
                        ) : (
                          <span className="text-fg-subtle">None</span>
                        )}
                      </Td>
                      <Td mono>{d.flows.toLocaleString()}</Td>
                      <Td mono>{formatBytes(d.bytes)}</Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            </Panel>

            <Panel
              title="Application and service distribution"
              description="Only what the packets themselves show. Unclassified is not a problem; it means nothing identified the application."
              actions={<a href="#/applications" className="text-link underline underline-offset-2 hover:text-fg">Details</a>}
            >
              <ul className="grid gap-2">
                {data.top_applications.map((a) => (
                  <li key={a.application} className="flex items-center justify-between gap-3">
                    <span>{a.application}</span>
                    <span className="flex items-center gap-2">
                      <ConfidenceBadge value={a.confidence} />
                      <span className="font-mono text-[13px] text-fg-muted">{formatBytes(a.bytes)}</span>
                    </span>
                  </li>
                ))}
              </ul>
            </Panel>
          </div>
        </>
      )}
    </div>
  );
}
