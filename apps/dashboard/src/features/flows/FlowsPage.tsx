import { useState } from "react";
import { RequestError, StaleNotice } from "@/components/RequestError";
import { Button } from "@/components/ui/Button";
import { DefinitionList } from "@/components/ui/DefinitionList";
import { DetailPanel } from "@/components/ui/DetailPanel";
import { SelectField, TextField } from "@/components/ui/Fields";
import { Pagination } from "@/components/ui/Pagination";
import { Panel } from "@/components/ui/Panel";
import { StateView } from "@/components/ui/StateView";
import { SortTh, Table, Td, Th, type SortState } from "@/components/ui/Table";
import type { Flow, FlowDetail, FlowSort, FlowState } from "@/lib/api/types";
import { useReadyBackend } from "@/lib/connection/BackendProvider";
import { formatDateTime } from "@/lib/format";
import { useDebouncedValue } from "@/lib/useDebouncedValue";
import { usePolling } from "@/lib/usePolling";
import { useRequest } from "@/lib/useRequest";
import { formatBytes } from "@/features/packets/hexdump";
import { AttachToCasePanel } from "@/features/investigations/AttachToCaseModal";
import { buildWebInspectorHref } from "@/features/web_inspector/prefill";
import {
  ConfidenceBadge,
  EndpointLabel,
  FLOW_STATES,
  FlowStateBadge,
  IDENTIFICATION_METHODS,
  SessionPicker,
  formatFlowDuration,
  formatTimeOfDay,
  isValidIp,
  useHashQuery,
} from "./common";

const PAGE_SIZE = 50;

const COLUMNS: { key: FlowSort; label: string }[] = [
  { key: "source", label: "Source" },
  { key: "destination", label: "Destination" },
  { key: "src_port", label: "Src port" },
  { key: "dst_port", label: "Dst port" },
  { key: "protocol", label: "Protocol" },
  { key: "application", label: "Application" },
  { key: "packets", label: "Packets" },
  { key: "bytes", label: "Bytes" },
  { key: "duration", label: "Duration" },
  { key: "first_seen", label: "First seen" },
  { key: "last_seen", label: "Last seen" },
  { key: "state", label: "State" },
];

function FlowDetails({ flowId, onClose }: { flowId: string; onClose: () => void }) {
  const { client } = useReadyBackend();
  const detail = useRequest((signal) => client.getFlow(flowId, signal), [client, flowId]);
  return (
    <DetailPanel title="Flow details" onClose={onClose}>
      {detail.isLoading && <StateView variant="loading" title="Loading flow" />}
      {!detail.data && detail.error && (
        <RequestError error={detail.error} what="the flow" onRetry={detail.reload} />
      )}
      {detail.data && <FlowDetailBody flow={detail.data} />}
    </DetailPanel>
  );
}

function FlowDetailBody({ flow }: { flow: FlowDetail }) {
  const tuple = (e: Flow["source"]) =>
    `${e.address}${e.port !== null ? ` : ${String(e.port)}` : ""}`;
  return (
    <div className="grid gap-5">
      <DefinitionList
        items={[
          { label: "Source", value: <EndpointLabel endpoint={flow.source} showPort /> },
          { label: "Destination", value: <EndpointLabel endpoint={flow.destination} showPort /> },
          { label: "Connection", mono: true, value: `${flow.transport.toUpperCase()}  ${tuple(flow.source)}  →  ${tuple(flow.destination)}` },
          {
            label: "Source chosen by",
            value:
              flow.initiator_basis === "syn"
                ? "The TCP SYN sender"
                : flow.initiator_basis === "syn_ack"
                  ? "The receiver of the SYN-ACK (the SYN was not captured)"
                  : "Whoever sent the first packet captured (a guess: the start of the conversation was not seen)",
          },
          { label: "State", value: <FlowStateBadge state={flow.state} /> },
          { label: "First seen", value: formatDateTime(flow.first_seen) },
          { label: "Last seen", value: formatDateTime(flow.last_seen) },
          { label: "Duration", value: formatFlowDuration(flow.duration_seconds) },
          {
            label: "Started by",
            value: {
              this_computer: "This computer",
              another_device: "Another device (an inbound connection)",
              neither: "Neither end is this computer",
              unknown: "Unknown (this capture has no local address)",
            }[flow.started_by],
          },
        ]}
      />

      <section aria-labelledby="flow-counters">
        <h3 id="flow-counters" className="mb-1 text-xs font-medium text-fg-muted">Traffic</h3>
        <Table label="Traffic counters">
          <thead>
            <tr>
              <Th>Direction</Th>
              <Th>Packets</Th>
              <Th>Bytes</Th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <Td>Source → destination</Td>
              <Td mono>{flow.packets_forward.toLocaleString()}</Td>
              <Td mono>{flow.bytes_forward.toLocaleString()}</Td>
            </tr>
            <tr>
              <Td>Destination → source</Td>
              <Td mono>{flow.packets_reverse.toLocaleString()}</Td>
              <Td mono>{flow.bytes_reverse.toLocaleString()}</Td>
            </tr>
            <tr>
              <Td>Total</Td>
              <Td mono>{flow.packets.toLocaleString()}</Td>
              <Td mono>{flow.bytes.toLocaleString()}</Td>
            </tr>
          </tbody>
        </Table>
        {flow.one_sided && (
          <p className="mt-1 text-xs text-warning">
            Packets were seen in one direction only. The other side may not have answered, or its
            packets were not captured.
          </p>
        )}
      </section>

      {flow.tcp && (
        <DefinitionList
          items={[
            { label: "TCP handshake", value: { complete: "Seen (SYN and SYN-ACK)", partial: "Partly seen", not_seen: "Not seen (the connection began before the capture)" }[flow.tcp.handshake] },
            { label: "FIN from source", value: flow.tcp.fin_from_source ? "Yes" : "No" },
            { label: "FIN from destination", value: flow.tcp.fin_from_destination ? "Yes" : "No" },
            { label: "Reset (RST)", value: flow.tcp.reset ? "Yes" : "No" },
          ]}
        />
      )}

      <section aria-labelledby="flow-app" className="grid gap-2">
        <h3 id="flow-app" className="text-xs font-medium text-fg-muted">Protocol and application</h3>
        <DefinitionList
          items={[
            { label: "Protocol", value: flow.protocol },
            { label: "Layers decoded", value: flow.protocols.length ? flow.protocols.join(" › ") : "None" },
            { label: "Application", value: flow.application ?? "Not identified" },
            { label: "Category", value: flow.category },
            { label: "Confidence", value: <ConfidenceBadge value={flow.confidence} /> },
            { label: "Method", value: IDENTIFICATION_METHODS[flow.method] ?? flow.method },
            ...(flow.server_name ? [{ label: "TLS server name", mono: true, value: flow.server_name }] : []),
            ...(flow.http_host ? [{ label: "HTTP Host", mono: true, value: flow.http_host }] : []),
            ...(flow.dns_names.length ? [{ label: "DNS names", mono: true, value: flow.dns_names.join(", ") }] : []),
            ...(flow.dns_hostname ? [{ label: "Earlier DNS answer", mono: true, value: flow.dns_hostname }] : []),
            ...(() => {
              const href = buildWebInspectorHref(flow.server_name ?? flow.http_host, {
                scheme: flow.http_host && !flow.server_name ? "http" : "https",
              });
              return href
                ? [
                    {
                      label: "Web Inspector",
                      value: (
                        <a className="text-link underline underline-offset-2" href={href}>
                          Inspect in Web Inspector
                        </a>
                      ),
                    },
                  ]
                : [];
            })(),
          ]}
        />
        <div>
          <h4 className="text-xs font-medium text-fg-muted">Evidence</h4>
          <ul className="list-disc pl-5">
            {flow.evidence.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        </div>
        {flow.limitations.length > 0 && (
          <div>
            <h4 className="text-xs font-medium text-fg-muted">What this cannot tell you</h4>
            <ul className="list-disc pl-5 text-fg-muted">
              {flow.limitations.map((line) => (
                <li key={line}>{line}</li>
              ))}
            </ul>
          </div>
        )}
      </section>

      <section aria-labelledby="flow-packets" className="grid gap-1 text-xs text-fg-muted">
        <h3 id="flow-packets" className="font-medium">Packets</h3>
        <p>
          Packet numbers {flow.first_packet.toLocaleString()} to {flow.last_packet.toLocaleString()}
          .
        </p>
        {flow.packet_explorer_filter ? (
          <p>
            In the Packet Explorer, use the display filter{" "}
            <code className="select-all break-all rounded-sm bg-inset px-1 font-mono text-fg">
              {flow.packet_explorer_filter}
            </code>
          </p>
        ) : (
          <p>This session's packets are no longer loaded in the Packet Explorer.</p>
        )}
      </section>
    </div>
  );
}

export function FlowsPage({ pollMs = 1000 }: { pollMs?: number }) {
  const { client } = useReadyBackend();
  const query = useHashQuery();
  const [session, setSession] = useState("current");
  const [search, setSearch] = useState("");
  const debouncedSearch = useDebouncedValue(search.trim(), 300);
  const [protocol, setProtocol] = useState(query.get("protocol") ?? "");
  const [application, setApplication] = useState(query.get("application") ?? "");
  const [stateFilter, setStateFilter] = useState(query.get("state") ?? "");
  const [transport, setTransport] = useState("");
  const [confidence, setConfidence] = useState("");
  const [address, setAddress] = useState(query.get("ip") ?? "");
  const [deviceId, setDeviceId] = useState(query.get("device") ?? "");
  const [offset, setOffset] = useState(0);
  const [sort, setSort] = useState<SortState>({ key: "last_seen", order: "desc" });
  const [selected, setSelected] = useState<string | null>(null);
  const [attachSessionOpen, setAttachSessionOpen] = useState(false);

  const summary = useRequest((signal) => client.getFlowSummary(session, signal), [client, session]);
  const protocols = useRequest((signal) => client.getFlowProtocols(session, signal), [client, session]);
  const apps = useRequest((signal) => client.getFlowApplications(session, signal), [client, session]);

  const live = summary.data?.session?.status === "running";
  const addressText = address.trim();
  const debouncedAddress = useDebouncedValue(addressText, 300);
  const isExactIp = isValidIp(debouncedAddress);
  const effectiveIp = isExactIp ? debouncedAddress : undefined;
  const effectiveSearch = debouncedSearch || (!isExactIp && debouncedAddress ? debouncedAddress : undefined);
  const addressHint = addressText && !isValidIp(addressText)
    ? debouncedSearch
      ? "Enter a complete IP (e.g. 192.168.1.7) to combine with search."
      : "Matching address prefix. Enter complete IP for exact filter."
    : undefined;

  const flows = useRequest(
    (signal) =>
      client.getFlows(
        {
          session,
          offset,
          limit: PAGE_SIZE,
          sort: sort.key as FlowSort,
          order: sort.order,
          search: effectiveSearch,
          protocol: protocol || undefined,
          application: application || undefined,
          state: (stateFilter || undefined) as FlowState | undefined,
          transport: transport || undefined,
          confidence: (confidence || undefined) as "confirmed" | "probable" | "unknown" | undefined,
          ip: effectiveIp,
          device_id: deviceId ? Number(deviceId) : undefined,
        },
        signal,
      ),
    [client, session, offset, sort.key, sort.order, effectiveSearch, protocol, application, stateFilter, transport, confidence, effectiveIp, deviceId],
  );

  usePolling(() => {
    if (!flows.isPending) flows.reloadQuietly();
    if (!summary.isPending) summary.reloadQuietly();
  }, live ? pollMs : null);

  const change = <T,>(set: (value: T) => void) => (value: T) => {
    setOffset(0);
    set(value);
  };
  const onSort = (key: string) => {
    setOffset(0);
    setSort((previous) =>
      previous.key === key ? { key, order: previous.order === "asc" ? "desc" : "asc" } : { key, order: "desc" },
    );
  };

  const devices = new Map<number, string>();
  for (const top of summary.data?.top_endpoints ?? []) {
    if (top.endpoint.device) {
      const d = top.endpoint.device;
      devices.set(d.id, `${d.hostname ?? d.vendor ?? d.mac} (${top.endpoint.address})`);
    }
  }
  if (deviceId && !devices.has(Number(deviceId))) devices.set(Number(deviceId), `Device ${deviceId}`);
  const filtered = Boolean(effectiveSearch || protocol || application || stateFilter || transport || confidence || effectiveIp || deviceId);
  const noSession = summary.data !== undefined && summary.data.session === null;

  const savedSession = summary.data?.session && summary.data.session.status !== "running" ? summary.data.session : null;

  return (
    <div className="grid grid-cols-1 gap-4">
      <Panel
        title="Flows"
        description="Conversations between addresses, built from the captured packets. Counters are per direction."
        actions={
          savedSession ? (
            <Button
              className="h-7 px-2.5 text-xs"
              onClick={() => {
                setAttachSessionOpen(true);
              }}
            >
              Attach Session to Investigation…
            </Button>
          ) : undefined
        }
      >
        {attachSessionOpen && savedSession && (
          <div className="mb-4">
            <AttachToCasePanel
              target={{
                kind: "flow_session",
                sourceId: savedSession.id,
                label: `Flow Session #${String(savedSession.id)} (${savedSession.source})`,
              }}
              onClose={() => {
                setAttachSessionOpen(false);
              }}
            />
          </div>
        )}
        <div className="mb-4 grid gap-3 md:grid-cols-3">
          <SessionPicker value={session} onChange={change(setSession)} />
          <TextField label="Search" value={search} placeholder="Address, port, name, protocol…" autoComplete="off" onChange={(e) => { change(setSearch)(e.target.value); }} />
          <TextField label="Address" value={address} placeholder="192.168.1.7" autoComplete="off" spellCheck={false} hint={addressHint} onChange={(e) => { change(setAddress)(e.target.value); }} />
          <SelectField label="Protocol" value={protocol} onChange={(e) => { change(setProtocol)(e.target.value); }}>
            <option value="">All protocols</option>
            {(protocols.data?.protocols ?? []).map((p) => (
              <option key={p.protocol} value={p.protocol}>{p.protocol}</option>
            ))}
          </SelectField>
          <SelectField label="Application" value={application} onChange={(e) => { change(setApplication)(e.target.value); }}>
            <option value="">All applications</option>
            {(apps.data?.applications ?? []).map((a) => (
              <option key={a.application} value={a.application}>{a.application}</option>
            ))}
          </SelectField>
          <SelectField label="Device" value={deviceId} onChange={(e) => { change(setDeviceId)(e.target.value); }}>
            <option value="">All devices</option>
            {[...devices].map(([id, label]) => (
              <option key={id} value={String(id)}>{label}</option>
            ))}
          </SelectField>
          <SelectField label="Transport" value={transport} onChange={(e) => { change(setTransport)(e.target.value); }}>
            <option value="">All</option>
            {["tcp", "udp", "icmp", "icmpv6"].map((t) => (
              <option key={t} value={t}>{t.toUpperCase()}</option>
            ))}
          </SelectField>
          <SelectField label="State" value={stateFilter} onChange={(e) => { change(setStateFilter)(e.target.value); }}>
            <option value="">All states</option>
            {Object.entries(FLOW_STATES).map(([value, entry]) => (
              <option key={value} value={value}>{entry.label}</option>
            ))}
          </SelectField>
          <SelectField label="Confidence" value={confidence} onChange={(e) => { change(setConfidence)(e.target.value); }}>
            <option value="">Any</option>
            <option value="confirmed">Confirmed</option>
            <option value="probable">Probable</option>
            <option value="unknown">Unknown</option>
          </SelectField>
        </div>

        {flows.isLoading && <StateView variant="loading" title="Loading flows" />}
        {!flows.data && flows.error && (
          <RequestError error={flows.error} what="flows" onRetry={flows.reload} />
        )}
        {flows.data && flows.error && (
          <StaleNotice error={flows.error} what="the flow list" asOf={flows.dataUpdatedAt} onRetry={flows.reload} />
        )}
        {flows.data && flows.data.total === 0 && (
          <StateView
            variant="empty"
            title={filtered ? "No flows match" : noSession ? "No flows yet" : live ? "Waiting for traffic" : "This session has no flows"}
            description={
              filtered
                ? "Change or clear the filters to see more."
                : "Start a capture or open a capture file in the Packet Explorer. Flows appear here as packets are processed."
            }
          />
        )}
        {flows.data && flows.data.flows.length > 0 && (
          <div className="grid gap-3">
            {summary.data && summary.data.flows_evicted > 0 && (
              <p className="text-xs text-warning">
                The flow table holds {summary.data.limits.max_flows.toLocaleString()} flows;{" "}
                {summary.data.flows_evicted.toLocaleString()} of the oldest were dropped. Their
                packets are still counted in the totals.
              </p>
            )}
            <Table label="Flow list">
              <thead>
                <tr>
                  {COLUMNS.map((c) => (
                    <SortTh key={c.key} label={c.label} sortKey={c.key} sort={sort} onSort={onSort} />
                  ))}
                </tr>
              </thead>
              <tbody>
                {flows.data.flows.map((flow) => (
                  <tr key={flow.id} className={selected === flow.id ? "bg-raised" : "hover:bg-raised/60"}>
                    <Td>
                      <button
                        type="button"
                        aria-pressed={selected === flow.id}
                        aria-label={`Flow from ${flow.source.address} to ${flow.destination.address}, show details`}
                        onClick={() => { setSelected(flow.id); }}
                        className="block cursor-pointer text-left hover:text-link"
                      >
                        <EndpointLabel endpoint={{ ...flow.source, device_note: null }} />
                      </button>
                    </Td>
                    <Td><EndpointLabel endpoint={{ ...flow.destination, device_note: null }} /></Td>
                    <Td mono>{flow.source.port ?? "—"}</Td>
                    <Td mono>{flow.destination.port ?? "—"}</Td>
                    <Td>{flow.protocol}</Td>
                    <Td>
                      <div>{flow.application ?? "Unclassified"}</div>
                      <div className="mt-0.5"><ConfidenceBadge value={flow.confidence} /></div>
                    </Td>
                    <Td mono>{flow.packets.toLocaleString()}</Td>
                    <Td mono>{formatBytes(flow.bytes)}</Td>
                    <Td>{formatFlowDuration(flow.duration_seconds)}</Td>
                    <Td mono><time dateTime={flow.first_seen} title={formatDateTime(flow.first_seen)}>{formatTimeOfDay(flow.first_seen)}</time></Td>
                    <Td mono><time dateTime={flow.last_seen} title={formatDateTime(flow.last_seen)}>{formatTimeOfDay(flow.last_seen)}</time></Td>
                    <Td><FlowStateBadge state={flow.state} /></Td>
                  </tr>
                ))}
              </tbody>
            </Table>
            <Pagination total={flows.data.total} limit={PAGE_SIZE} offset={offset} onChange={setOffset} label="Flow pages" />
          </div>
        )}
      </Panel>

      {selected !== null && (
        <FlowDetails key={selected} flowId={selected} onClose={() => { setSelected(null); }} />
      )}
    </div>
  );
}
