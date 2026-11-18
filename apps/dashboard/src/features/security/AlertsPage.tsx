import { useState } from "react";
import { RequestError, StaleNotice } from "@/components/RequestError";
import { Button } from "@/components/ui/Button";
import { SelectField, TextField } from "@/components/ui/Fields";
import { Pagination } from "@/components/ui/Pagination";
import { Panel } from "@/components/ui/Panel";
import { StateView } from "@/components/ui/StateView";
import { SortTh, Table, Td, Th, type SortState } from "@/components/ui/Table";
import type { AlertQuery, AlertSeverity, AlertStatus } from "@/lib/api/types";
import { useReadyBackend } from "@/lib/connection/BackendProvider";
import { useDebouncedValue } from "@/lib/useDebouncedValue";
import { usePolling } from "@/lib/usePolling";
import { useRequest } from "@/lib/useRequest";
import { useHashQuery } from "@/features/flows/common";
import {
  ConfidenceChip,
  RiskScore,
  SectionNav,
  SeverityBadge,
  SEVERITIES,
  STATUSES,
  StatusTag,
  When,
  statusLabel,
  RISK_NOTE,
  Footnote,
} from "./common";

const PAGE = 50;
const RANGES = [
  { value: "24h", label: "24 hours", ms: 86_400_000 },
  { value: "7d", label: "7 days", ms: 7 * 86_400_000 },
  { value: "30d", label: "30 days", ms: 30 * 86_400_000 },
  { value: "all", label: "All time", ms: 0 },
] as const;
type Range = (typeof RANGES)[number]["value"];
const DEFAULT_RANGE: Range = "7d";
const CATEGORIES = ["recon", "traffic", "dns", "device", "app"] as const;
type StatusFilter = "active" | "all" | AlertStatus;

function pick<T extends string>(raw: string | null, allowed: readonly T[]): T | "" {
  return raw !== null && (allowed as readonly string[]).includes(raw) ? (raw as T) : "";
}

export function AlertsPage({ pollMs = 5000 }: { pollMs?: number }) {
  const { client } = useReadyBackend();
  const initial = useHashQuery();
  const [status, setStatus] = useState<StatusFilter>(
    pick(initial.get("status"), STATUSES) || "active",
  );
  const [severity, setSeverity] = useState<AlertSeverity | "">(pick(initial.get("severity"), SEVERITIES));
  const [category, setCategory] = useState(pick(initial.get("category"), CATEGORIES));
  const [text, setText] = useState(initial.get("search") ?? "");
  const [minRisk, setMinRisk] = useState("");
  const [range, setRange] = useState<Range>(DEFAULT_RANGE);
  const [device, setDevice] = useState(/^[1-9]\d{0,15}$/.test(initial.get("device") ?? "") ? (initial.get("device") ?? "") : "");
  const [sort, setSort] = useState<SortState>({ key: "risk", order: "desc" });
  const [offset, setOffset] = useState(0);
  const search = useDebouncedValue(text, 300);
  const riskNumber = /^\d{1,3}$/.test(minRisk) && Number(minRisk) <= 100 ? Number(minRisk) : undefined;
  const devices = useRequest((signal) => client.getDeviceRisks(signal), [client]);
  const deviceOptions = devices.data?.items ?? [];

  const base: AlertQuery = {
    severity: severity || undefined,
    category: category || undefined,
    search: search.trim() || undefined,
    min_risk: riskNumber,
    device_id: device ? Number(device) : undefined,
    sort: sort.key as AlertQuery["sort"],
    order: sort.order,
    limit: PAGE,
    offset,
  };
  const alerts = useRequest(
    async (signal) => {
      // The window moves with the clock, so a polled reload never keeps an old cut-off.
      const span = RANGES.find((r) => r.value === range)?.ms ?? 0;
      const since = span ? new Date(Date.now() - span).toISOString() : undefined;
      const query = { ...base, since };
      if (status === "active") {
        // The default view is every alert that still needs a decision: one request per state, merged by risk.
        const parts = await Promise.all(
          (["open", "acknowledged", "investigating"] as const).map((s) =>
            client.getAlerts({ ...query, status: s, offset: 0, limit: 200 }, signal),
          ),
        );
        const unique = new Map(parts.flatMap((p) => p.items).map((a) => [a.id, a] as const));
        const items = [...unique.values()].sort((a, b) => b.risk_score - a.risk_score || b.id - a.id);
        const total = parts.reduce((sum, p) => sum + p.total, 0);
        return { items: items.slice(offset, offset + PAGE), total, limit: PAGE, offset };
      }
      return client.getAlerts({ ...query, status: status === "all" ? undefined : status }, signal);
    },
    [client, status, severity, category, search, riskNumber, sort.key, sort.order, offset, device, range],
  );
  usePolling(() => {
    if (!alerts.isPending) alerts.reloadQuietly();
  }, pollMs);

  const data = alerts.data;
  const filtered =
    status !== "active" || severity !== "" || category !== "" || search.trim() !== "" || riskNumber !== undefined || device !== "" || range !== DEFAULT_RANGE;
  const reset = () => {
    setStatus("active");
    setSeverity("");
    setCategory("");
    setText("");
    setMinRisk("");
    setRange(DEFAULT_RANGE);
    setDevice("");
    setOffset(0);
  };
  const toggleSort = (key: string) => {
    setSort((s) => ({ key, order: s.key === key && s.order === "desc" ? "asc" : "desc" }));
    setOffset(0);
  };

  return (
    <div className="grid gap-4">
      <SectionNav current="alerts" />
      <Panel
        title="Security alerts"
        description="Patterns found in analysed traffic. An alert describes what was observed; it does not say what caused it."
        actions={<Button onClick={alerts.reload}>Refresh</Button>}
      >
        <div className="mb-4 grid gap-3 md:grid-cols-3">
          <TextField
            label="Search"
            value={text}
            onChange={(e) => {
              setText(e.target.value);
              setOffset(0);
            }}
            placeholder="Title, address or note"
            maxLength={100}
          />
          <SelectField
            label="Status"
            value={status}
            onChange={(e) => {
              setStatus(e.target.value as StatusFilter);
              setOffset(0);
            }}
          >
            <option value="active">Needs a decision</option>
            <option value="all">Any status</option>
            {STATUSES.map((s) => (
              <option key={s} value={s}>
                {statusLabel(s)}
              </option>
            ))}
          </SelectField>
          <SelectField
            label="Severity"
            value={severity}
            onChange={(e) => {
              setSeverity(e.target.value as AlertSeverity | "");
              setOffset(0);
            }}
          >
            <option value="">All</option>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </SelectField>
          <SelectField
            label="Category"
            value={category}
            onChange={(e) => {
              setCategory(e.target.value as (typeof CATEGORIES)[number] | "");
              setOffset(0);
            }}
          >
            <option value="">All</option>
            {CATEGORIES.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </SelectField>
          <TextField
            label="Minimum risk"
            inputMode="numeric"
            value={minRisk}
            onChange={(e) => {
              setMinRisk(e.target.value);
              setOffset(0);
            }}
            placeholder="0 to 100"
            error={minRisk !== "" && riskNumber === undefined ? "Use a whole number from 0 to 100." : undefined}
          />
          <SelectField
            label="Range"
            value={range}
            onChange={(e) => {
              setRange(e.target.value as Range);
              setOffset(0);
            }}
          >
            {RANGES.map((r) => (
              <option key={r.value} value={r.value}>
                {r.label}
              </option>
            ))}
          </SelectField>
          <SelectField
            label="Device"
            value={device}
            onChange={(e) => {
              setDevice(e.target.value);
              setOffset(0);
            }}
          >
            <option value="">Any device</option>
            {device !== "" && !deviceOptions.some((d) => String(d.device_id) === device) && (
              <option value={device}>{`Device ${device}`}</option>
            )}
            {deviceOptions.map((d) => (
              <option key={d.device_id} value={String(d.device_id)}>
                {d.hostname && d.ip ? `${d.hostname} (${d.ip})` : (d.hostname ?? d.ip ?? d.mac)}
              </option>
            ))}
          </SelectField>
        </div>

        {alerts.isLoading && <StateView variant="loading" title="Loading alerts" />}
        {!data && alerts.error && <RequestError error={alerts.error} what="alerts" onRetry={alerts.reload} />}
        {data && alerts.error && (
          <StaleNotice error={alerts.error} what="alerts" asOf={alerts.dataUpdatedAt} onRetry={alerts.reload} />
        )}
        {data && data.items.length === 0 && (
          <StateView
            variant="empty"
            title={filtered ? "No alerts match these filters" : "No alerts from the sessions analysed"}
            description={
              filtered
                ? "Change or clear the filters to see more."
                : range === "all"
                  ? "Alerts appear here when a capture or an opened file is analysed and a rule finds a pattern."
                  : "Only alerts updated in the chosen range are listed. Choose All time to see older ones."
            }
            action={filtered ? { label: "Clear filters", onClick: reset } : undefined}
          />
        )}
        {data && data.items.length > 0 && (
          <div className="grid gap-3">
            <Table label="Alerts">
              <thead>
                <tr>
                  <SortTh label="Severity" sortKey="severity" sort={sort} onSort={toggleSort} />
                  <SortTh label="Risk" sortKey="risk" sort={sort} onSort={toggleSort} />
                  <Th>Alert</Th>
                  <Th>About</Th>
                  <Th>Status</Th>
                  <SortTh label="Last seen" sortKey="updated" sort={sort} onSort={toggleSort} />
                  <Th>Confidence</Th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((a) => (
                  <tr key={a.id}>
                    <Td><SeverityBadge level={a.severity} /></Td>
                    <Td><RiskScore value={a.risk_score} /></Td>
                    <Td>
                      <a href={`#/alerts/${String(a.id)}`} className="font-medium text-link underline underline-offset-2 hover:text-fg">
                        {a.title}
                      </a>
                      <p className="text-xs text-fg-subtle">
                        {a.rule_id} · seen {a.occurrence_count} {a.occurrence_count === 1 ? "time" : "times"}
                      </p>
                    </Td>
                    <Td mono>
                      {a.entity_key}
                      {a.secondary_key ? ` → ${a.secondary_key}` : ""}
                    </Td>
                    <Td><StatusTag status={a.status} /></Td>
                    <Td><When iso={a.updated_at} file={a.source === "file"} /></Td>
                    <Td><ConfidenceChip level={a.confidence} /></Td>
                  </tr>
                ))}
              </tbody>
            </Table>
            <Pagination total={data.total} limit={PAGE} offset={offset} onChange={setOffset} label="Alert pages" />
            <Footnote>{RISK_NOTE}</Footnote>
          </div>
        )}
      </Panel>
    </div>
  );
}
