import { useState } from "react";
import { RequestError, StaleNotice } from "@/components/RequestError";
import { Button } from "@/components/ui/Button";
import { Pagination } from "@/components/ui/Pagination";
import { Panel } from "@/components/ui/Panel";
import { StateView } from "@/components/ui/StateView";
import { Table, Td, Th } from "@/components/ui/Table";
import { ApiError } from "@/lib/api/client";
import { useReadyBackend } from "@/lib/connection/BackendProvider";
import { useRequest } from "@/lib/useRequest";
import { SectionNav, When } from "./common";

const PAGE = 25;

export function HistoryPage() {
  const { client } = useReadyBackend();
  const [offset, setOffset] = useState(0);
  const runs = useRequest((signal) => client.getDetectionRuns({ limit: PAGE, offset }, signal), [client, offset]);
  const [asking, setAsking] = useState(false);
  const [result, setResult] = useState<string | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const wipe = async () => {
    setBusy(true);
    setProblem(null);
    try {
      const r = await client.deleteDetectionHistory();
      setResult(`Deleted ${String(r.alerts_deleted)} alerts and ${String(r.runs_deleted)} runs. Learned baselines were reset too.`);
      setAsking(false);
      setOffset(0);
      runs.reload();
    } catch (cause) {
      setProblem(cause instanceof ApiError ? cause.message : "The history could not be deleted.");
    } finally {
      setBusy(false);
    }
  };

  const data = runs.data;
  return (
    <div className="grid gap-4">
      <SectionNav current="history" />
      <Panel title="Detection history" description="One row for every session the rules analysed, with what was and was not covered.">
        {runs.isLoading && <StateView variant="loading" title="Loading detection history" />}
        {!data && runs.error && <RequestError error={runs.error} what="the detection history" onRetry={runs.reload} />}
        {data && runs.error && <StaleNotice error={runs.error} what="the detection history" asOf={runs.dataUpdatedAt} onRetry={runs.reload} />}
        {data && data.items.length === 0 && (
          <StateView variant="empty" title="No session has been analysed yet" description="Start a capture or open a capture file in the Packet Explorer." />
        )}
        {data && data.items.length > 0 && (
          <div className="grid gap-3">
            <Table label="Detection runs">
              <thead>
                <tr><Th>Started</Th><Th>Source</Th><Th>Status</Th><Th>Events</Th><Th>Dropped</Th><Th>Alerts</Th><Th>Suppressed</Th><Th>Baseline</Th><Th>Notes</Th></tr>
              </thead>
              <tbody>
                {data.items.map((r) => (
                  <tr key={r.id}>
                    <Td><When iso={r.started_at} /></Td>
                    <Td>{r.source === "live" ? "Live capture" : "Opened file"}</Td>
                    <Td>{r.status}</Td>
                    <Td mono>{r.events_processed.toLocaleString()}</Td>
                    <Td mono>{r.events_dropped.toLocaleString()}</Td>
                    <Td mono>{r.alerts_created} new, {r.alerts_updated} updated</Td>
                    <Td mono>{r.findings_suppressed}</Td>
                    <Td>{r.baseline_updated ? "Updated" : "Not changed"}</Td>
                    <Td>{r.warnings.length ? r.warnings.join(" ") : "None"}</Td>
                  </tr>
                ))}
              </tbody>
            </Table>
            <Pagination total={data.total} limit={PAGE} offset={offset} onChange={setOffset} label="Run pages" />
          </div>
        )}
      </Panel>

      <Panel title="Delete security history" description="Removes alerts with their evidence, finished runs and learned baselines. Inventory, flows, captures and rule settings stay.">
        {result && <p role="status" className="mb-2 text-sm text-fg-muted">{result}</p>}
        {problem && <p role="alert" className="mb-2 text-sm text-critical">{problem}</p>}
        {asking ? (
          <div className="grid gap-2 rounded-md border border-line-strong p-3">
            <p className="text-sm text-fg">Delete all alerts, runs and baselines? This cannot be undone.</p>
            <div className="flex gap-2">
              <Button variant="primary" loading={busy} onClick={() => { void wipe(); }}>Delete everything</Button>
              <Button onClick={() => { setAsking(false); }}>Cancel</Button>
            </div>
          </div>
        ) : (
          <Button onClick={() => { setAsking(true); setResult(null); }}>Delete security history</Button>
        )}
      </Panel>
    </div>
  );
}
