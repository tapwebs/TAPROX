import { RequestError } from "@/components/RequestError";
import { DefinitionList } from "@/components/ui/DefinitionList";
import { Panel } from "@/components/ui/Panel";
import { StateView } from "@/components/ui/StateView";
import { StatTile } from "@/components/ui/StatTile";
import { Table, Td, Th } from "@/components/ui/Table";
import type { AlertSummary, AlertSummaryRange } from "@/lib/api/types";
import { useState } from "react";
import { SelectField } from "@/components/ui/Fields";
import { useReadyBackend } from "@/lib/connection/BackendProvider";
import { usePolling } from "@/lib/usePolling";
import { useRequest } from "@/lib/useRequest";
import { Footnote, RISK_NOTE, RiskScore, SectionNav, SeverityBadge } from "./common";

const RANGES: readonly { value: AlertSummaryRange; label: string; phrase: string }[] = [
  { value: "24h", label: "24 hours", phrase: "in the last 24 hours" },
  { value: "7d", label: "7 days", phrase: "per day over the last 7 days" },
  { value: "30d", label: "30 days", phrase: "per day over the last 30 days" },
  { value: "all", label: "All time", phrase: "over all the time covered" },
];

function AlertsChart({ summary, phrase }: { summary: AlertSummary; phrase: string }) {
  const buckets = summary.timeline;
  const step = summary.timeline_step;
  const width = 600;
  const height = 100;
  const max = Math.max(1, ...buckets.map((b) => b.count));
  const bar = width / Math.max(1, buckets.length);
  const total = buckets.reduce((sum, b) => sum + b.count, 0);
  const label = `Alerts created ${phrase}${step === "week" ? " (per week)" : ""}: ${String(total)} in total, at most ${String(max)} in one ${step}.`;
  return (
    <div>
      <svg role="img" aria-label={label} viewBox={`0 0 ${String(width)} ${String(height)}`} className="h-28 w-full">
        {buckets.map((b, i) => {
          const h = (b.count / max) * (height - 4);
          return <rect key={b.start} x={i * bar + 1} y={height - h} width={Math.max(1, bar - 2)} height={h} className="fill-current text-accent" />;
        })}
      </svg>
      <details className="mt-2">
        <summary className="cursor-pointer text-xs text-fg-muted">Data table</summary>
        <Table label={`Alerts created per ${step}`}>
          <thead><tr><Th>{step === "hour" ? "Hour" : step === "day" ? "Day" : "Week"} starting</Th><Th>Alerts</Th></tr></thead>
          <tbody>
            {buckets.map((b) => (<tr key={b.start}><Td>{new Date(b.start).toLocaleString()}</Td><Td mono>{b.count}</Td></tr>))}
          </tbody>
        </Table>
      </details>
    </div>
  );
}

export function ThreatOverviewPage({ pollMs = 5000 }: { pollMs?: number }) {
  const { client } = useReadyBackend();
  const status = useRequest((s) => client.getDetectionStatus(s), [client]);
  const [range, setRange] = useState<AlertSummaryRange>("24h");
  const summary = useRequest((s) => client.getAlertSummary(range, s), [client, range]);
  const top = useRequest((s) => client.getAlerts({ status: "open", sort: "risk", order: "desc", limit: 5 }, s), [client]);
  const risk = useRequest((s) => client.getDeviceRisks(s), [client]);
  const networks = useRequest((s) => client.getNetworks(s), [client]);
  const running = status.data?.runs.some((r) => r.status === "running") ?? false;
  usePolling(() => {
    for (const r of [status, summary, top, risk]) if (!r.isPending) r.reloadQuietly();
  }, running ? pollMs : null);

  if (status.isLoading || summary.isLoading) return <div className="grid gap-4"><SectionNav current="threats" /><StateView variant="loading" title="Loading threat detection" /></div>;
  const error = status.error ?? summary.error;
  if (!status.data || !summary.data) {
    return <div className="grid gap-4"><SectionNav current="threats" />{error && <RequestError error={error} what="threat detection" onRetry={() => { status.reload(); summary.reload(); }} />}</div>;
  }
  const st = status.data;
  const sum = summary.data;
  const run = st.runs[0];
  const open = sum.by_status.open ?? 0;
  const high = (sum.by_severity.high ?? 0) + (sum.by_severity.critical ?? 0);
  const medium = sum.by_severity.medium ?? 0;
  const low = (sum.by_severity.low ?? 0) + (sum.by_severity.info ?? 0);
  const notEvaluated = st.rules.filter((r) => r.state === "not_evaluated");
  const evaluating = st.rules.filter((r) => r.state === "evaluating").length;
  const disabled = st.rules.filter((r) => r.state === "disabled").length;
  const dropped = run?.queue.dropped ?? 0;
  const readyNetworks = networks.data?.items.filter((n) => n.baseline_ready).length ?? 0;

  return (
    <div className="grid gap-4">
      <SectionNav current="threats" />
      <Panel title="Detection status" description="What has been analysed, and how completely.">
        <DefinitionList
          items={[
            {
              label: "Analysis",
              value: run
                ? `${run.source === "live" ? "Live capture" : "Opened file"}, ${run.status}; ${run.events_processed.toLocaleString()} events processed`
                : "No capture has been analysed yet",
            },
            { label: "Rules", value: `${String(evaluating)} evaluating, ${String(disabled)} switched off, ${String(notEvaluated.length)} not evaluated` },
            { label: "Baselines", value: networks.data ? `${String(readyNetworks)} of ${String(networks.data.items.length)} networks have a ready baseline` : "Not loaded" },
            { label: "Storage", value: st.persistence.enabled ? "Alerts are stored in the database" : "Alerts are kept in memory only" },
          ]}
        />
        {dropped > 0 && <p role="status" className="mt-2 text-sm text-warning">Coverage reduced during the last run: {String(dropped)} events were dropped because the detection queue was full.</p>}
        <p className="mt-2 text-sm"><a className="text-link underline underline-offset-2" href="#/rules">Open Detection Rules</a></p>
      </Panel>

      <dl className="grid grid-cols-2 gap-3 md:grid-cols-3 lg:grid-cols-5">
        <StatTile label="Open alerts" value={String(open)} />
        <StatTile label="High or critical" value={String(high)} />
        <StatTile label="Medium" value={String(medium)} />
        <StatTile label="Low or info" value={String(low)} />
        <StatTile label="Devices with alerts" value={String(risk.data?.items.length ?? 0)} />
      </dl>
      <p className="text-sm text-fg-muted">
        Open the list: <a className="text-link underline underline-offset-2" href="#/alerts?status=open">open alerts</a>, <a className="text-link underline underline-offset-2" href="#/alerts?severity=high">high</a>, <a className="text-link underline underline-offset-2" href="#/alerts?severity=medium">medium</a>, <a className="text-link underline underline-offset-2" href="#/alerts?severity=low">low</a>.
      </p>

      {sum.total === 0 ? (
        <Panel title="Alerts">
          <StateView
            variant="empty"
            title="No alerts from the sessions analysed"
            description={run ? "The rules that were evaluated found no pattern in the traffic analysed. That is not a statement that nothing happened." : "Start a capture or open a capture file in the Packet Explorer."}
          />
        </Panel>
      ) : (
        <div className="grid gap-4 lg:grid-cols-2">
          <Panel title="Alerts over time" description="When alerts were first created.">
            <div className="mb-3 max-w-[12rem]">
              <SelectField label="Range" value={range} onChange={(e) => { setRange(e.target.value as AlertSummaryRange); }}>
                {RANGES.map((r) => (<option key={r.value} value={r.value}>{r.label}</option>))}
              </SelectField>
            </div>
            <AlertsChart summary={sum} phrase={RANGES.find((r) => r.value === range)?.phrase ?? ""} />
          </Panel>
          <Panel title="Highest-risk open alerts">
            {top.data && top.data.items.length > 0 ? (
              <ol className="grid gap-2">
                {top.data.items.map((a) => (
                  <li key={a.id} className="flex flex-wrap items-center gap-2 text-sm">
                    <SeverityBadge level={a.severity} />
                    <RiskScore value={a.risk_score} />
                    <a className="text-link underline underline-offset-2" href={`#/alerts/${String(a.id)}`}>{a.title}</a>
                    <span className="font-mono text-xs text-fg-subtle">{a.entity_key}</span>
                  </li>
                ))}
              </ol>
            ) : (
              <p className="text-sm text-fg-muted">No open alerts.</p>
            )}
            <Footnote>{RISK_NOTE}</Footnote>
          </Panel>
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Devices by risk" description="Built from each device's open alerts, older ones counting less.">
          {risk.data && risk.data.items.length > 0 ? (
            <Table label="Devices by risk">
              <thead><tr><Th>Device</Th><Th>Risk</Th><Th>Alerts counted</Th></tr></thead>
              <tbody>
                {risk.data.items.slice(0, 10).map((d) => (
                  <tr key={d.device_id}>
                    <Td><a className="text-link underline underline-offset-2" href={`#/risk/${String(d.device_id)}`}>{d.hostname ?? d.ip ?? d.mac}</a></Td>
                    <Td><RiskScore value={d.score} /></Td>
                    <Td mono>{d.alerts_counted}</Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          ) : (
            <p className="text-sm text-fg-muted">No device has counted alerts.</p>
          )}
        </Panel>
        <Panel title="What was not analysed">
          {notEvaluated.length === 0 ? (
            <p className="text-sm text-fg-muted">All enabled rules were evaluated.</p>
          ) : (
            <ul className="list-disc pl-5 text-sm">
              {notEvaluated.map((r) => (<li key={r.id}>{r.id} {r.name}: {r.reason}</li>))}
            </ul>
          )}
        </Panel>
      </div>
    </div>
  );
}
