import { useMemo, useState } from "react";
import { Network, Radio, Wifi } from "lucide-react";
import { RequestError, StaleNotice } from "@/components/RequestError";
import { Panel } from "@/components/ui/Panel";
import { StateView } from "@/components/ui/StateView";
import { Table, Td, Th } from "@/components/ui/Table";
import { SelectField, TextField } from "@/components/ui/Fields";
import { Button } from "@/components/ui/Button";
import type { ApplicationStat } from "@/lib/api/types";
import { useReadyBackend } from "@/lib/connection/BackendProvider";
import { usePolling } from "@/lib/usePolling";
import { useRequest } from "@/lib/useRequest";
import { formatBytes } from "@/features/packets/hexdump";
import { formatDateTime } from "@/lib/format";
import {
  ConfidenceBadge,
  EndpointLabel,
  IDENTIFICATION_METHODS,
  SessionPicker,
} from "@/features/flows/common";

function VantageNotice({
  captureSource,
  interfaceName,
  isWifi,
}: {
  captureSource?: string | null;
  interfaceName?: string | null;
  isWifi?: boolean;
}) {
  if (!captureSource) return null;

  const isWifiSource = Boolean(isWifi || captureSource.toLowerCase().includes("wi-fi"));
  const isMirror = Boolean(captureSource.toLowerCase().includes("mirror") || captureSource.toLowerCase().includes("tap"));

  return (
    <div
      role="region"
      aria-label="Capture vantage and network coverage"
      className="rounded-lg border border-line-strong/80 bg-surface-subtle p-3.5 text-xs text-fg-muted shadow-sm"
    >
      <div className="flex items-start gap-2.5">
        <div className="mt-0.5 rounded p-1 bg-surface border border-line shrink-0 text-fg">
          {isWifiSource ? (
            <Wifi className="size-4 text-warning" aria-hidden="true" />
          ) : isMirror ? (
            <Network className="size-4 text-accent" aria-hidden="true" />
          ) : (
            <Radio className="size-4 text-link" aria-hidden="true" />
          )}
        </div>
        <div className="space-y-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-semibold text-fg">
              Capture Vantage: {captureSource}
            </span>
            {interfaceName && (
              <span className="rounded bg-inset px-1.5 py-0.5 font-mono text-[11px] text-fg-subtle border border-line">
                {interfaceName}
              </span>
            )}
          </div>
          {isWifiSource ? (
            <p className="leading-relaxed">
              <strong className="text-fg font-medium">Wi-Fi Managed-Mode Observation:</strong> Station-to-station traffic is isolated by 802.11 Access Points. Unicast traffic between other wireless clients and the router does not physically reach this wireless NIC. Applications shown below reflect traffic observed directly on this host and broadcast/multicast packets. For complete network-wide traffic inspection across all wireless clients, configure an upstream switch SPAN mirror or hardware TAP.
            </p>
          ) : isMirror ? (
            <p className="leading-relaxed">
              <strong className="text-fg font-medium">Full Network Mirror / TAP:</strong> Traffic from multiple network segments and switch ports is mirrored directly into this capture interface. Multi-device bidirectional packet visibility active.
            </p>
          ) : (
            <p className="leading-relaxed">
              <strong className="text-fg font-medium">Physical Endpoint Capture:</strong> Capturing traffic directly sent or received by this host machine ({interfaceName || "Ethernet"}), in addition to subnet broadcast and multicast communications.
            </p>
          )}
        </div>
      </div>
    </div>
  );
}

function AppRow({ app }: { app: ApplicationStat }) {
  const unclassified = app.application === "Unclassified";
  return (
    <li className="rounded-md border border-line bg-surface p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <div className="flex items-center gap-2">
            <h3 className="text-sm font-semibold text-fg">{app.application}</h3>
            {app.capture_source && (
              <span className="rounded border border-line bg-inset px-1.5 py-0.5 text-[11px] text-fg-subtle font-mono">
                {app.capture_source}
              </span>
            )}
          </div>
          <p className="text-xs text-fg-muted">{app.category}</p>
        </div>
        <div className="flex items-center gap-3">
          <ConfidenceBadge value={app.confidence} />
          <span className="font-mono text-[13px] text-fg-muted">
            {formatBytes(app.bytes)} · {app.packets.toLocaleString()} packets · {app.flows.toLocaleString()} flows
          </span>
          <a
            href={`#/flows?application=${encodeURIComponent(app.application)}`}
            className="text-link underline underline-offset-2 hover:text-fg"
            aria-label={`View the flows of ${app.application}`}
          >
            View flows
          </a>
        </div>
      </div>

      {unclassified && (
        <p className="mt-2 text-xs text-fg-muted">
          These flows have no decoded application protocol and no visible server name. Port numbers
          alone are never used to name an application. Protocols seen: {app.protocols.join(", ") || "none"}.
        </p>
      )}

      <dl className="mt-3 grid gap-2 text-sm md:grid-cols-2">
        <div>
          <dt className="text-xs font-medium text-fg-muted">Identification method</dt>
          <dd>
            {app.methods.length
              ? app.methods.map((m) => IDENTIFICATION_METHODS[m] ?? m).join(", ")
              : "None"}
            {app.probable_flows > 0 && (
              <span className="text-fg-muted"> · {String(app.probable_flows)} probable, {String(app.confirmed_flows)} confirmed</span>
            )}
          </dd>
        </div>
        <div>
          <dt className="text-xs font-medium text-fg-muted">Protocols</dt>
          <dd>{app.protocols.join(", ")}</dd>
        </div>
        <div>
          <dt className="text-xs font-medium text-fg-muted">Started by</dt>
          <dd className="grid gap-1">
            {app.devices.map((d) => (
              <EndpointLabel key={d.address} endpoint={d} />
            ))}
          </dd>
        </div>
        <div>
          <dt className="text-xs font-medium text-fg-muted">Main destinations</dt>
          <dd>
            <ul className="grid gap-0.5">
              {app.destinations.map((d) => (
                <li key={d.address} className="flex flex-wrap gap-x-2">
                  <span className="font-mono text-[13px]">{d.address}</span>
                  {d.hostname && <span className="break-all text-fg-muted">{d.hostname}</span>}
                  <span className="text-fg-subtle">{formatBytes(d.bytes)}</span>
                </li>
              ))}
            </ul>
          </dd>
        </div>
      </dl>

      {app.device_stats && app.device_stats.length > 0 && (
        <div className="mt-3 rounded border border-line/70 bg-inset/40 p-2.5">
          <h4 className="text-xs font-semibold uppercase tracking-wider text-fg-subtle mb-1.5">
            Per-Device Traffic Attribution
          </h4>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-line text-fg-muted">
                  <th className="pb-1 font-medium">Device Endpoint</th>
                  <th className="pb-1 font-medium font-mono">Flows</th>
                  <th className="pb-1 font-medium font-mono">Packets</th>
                  <th className="pb-1 font-medium font-mono">Bytes</th>
                  <th className="pb-1 font-medium">Last Observed</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line/40">
                {app.device_stats.map((stat) => (
                  <tr key={stat.endpoint.address} className="hover:bg-surface/50">
                    <td className="py-1">
                      <EndpointLabel endpoint={stat.endpoint} />
                    </td>
                    <td className="py-1 font-mono text-fg-muted">{stat.flows.toLocaleString()}</td>
                    <td className="py-1 font-mono text-fg-muted">{stat.packets.toLocaleString()}</td>
                    <td className="py-1 font-mono text-fg-muted">{formatBytes(stat.bytes)}</td>
                    <td className="py-1 text-fg-subtle">
                      {stat.last_seen ? formatDateTime(stat.last_seen) : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {app.evidence.length > 0 && (
        <details className="mt-3">
          <summary className="cursor-pointer text-xs text-fg-muted">Supporting evidence</summary>
          <ul className="mt-1 list-disc pl-5 text-sm">
            {app.evidence.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        </details>
      )}
    </li>
  );
}

export function ApplicationsPage({ pollMs = 1000 }: { pollMs?: number }) {
  const { client } = useReadyBackend();
  const [session, setSession] = useState("current");
  const [deviceFilter, setDeviceFilter] = useState("all");
  const [confidenceFilter, setConfidenceFilter] = useState("all");
  const [searchQuery, setSearchQuery] = useState("");

  const apps = useRequest((signal) => client.getFlowApplications(session, signal), [client, session]);
  const summary = useRequest((signal) => client.getFlowSummary(session, signal), [client, session]);
  const live = summary.data?.session?.status === "running";
  usePolling(() => {
    if (!apps.isPending) apps.reloadQuietly();
    if (!summary.isPending) summary.reloadQuietly();
  }, live ? pollMs : null);

  const data = apps.data;

  const availableDevices = useMemo(() => {
    if (!data) return [];
    const map = new Map<string, string>();
    for (const app of data.applications) {
      for (const dev of app.devices) {
        if (!map.has(dev.address)) {
          const name = dev.hostname || dev.device?.hostname || dev.device?.vendor;
          const label = name ? `${name} (${dev.address})` : dev.address;
          map.set(dev.address, label);
        }
      }
    }
    return Array.from(map.entries()).map(([address, label]) => ({ address, label }));
  }, [data]);

  const filteredApps = useMemo(() => {
    if (!data) return [];
    return data.applications.filter((a) => {
      if (deviceFilter !== "all" && !a.devices.some((d) => d.address === deviceFilter)) {
        return false;
      }
      if (confidenceFilter !== "all" && a.confidence !== confidenceFilter) {
        return false;
      }
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchesName = a.application.toLowerCase().includes(q);
        const matchesCategory = a.category.toLowerCase().includes(q);
        const matchesProtocols = a.protocols.some((p) => p.toLowerCase().includes(q));
        const matchesDests = a.destinations.some(
          (d) => d.address.includes(q) || (d.hostname && d.hostname.toLowerCase().includes(q)),
        );
        if (!matchesName && !matchesCategory && !matchesProtocols && !matchesDests) {
          return false;
        }
      }
      return true;
    });
  }, [data, deviceFilter, confidenceFilter, searchQuery]);

  const named = filteredApps.filter((a) => a.application !== "Unclassified");
  const unclassified = filteredApps.find((a) => a.application === "Unclassified");
  const hasActiveFilters = deviceFilter !== "all" || confidenceFilter !== "all" || searchQuery.trim().length > 0;

  return (
    <div className="grid grid-cols-1 gap-4">
      <Panel
        title="Applications and services"
        description="Identified conservatively from decoded protocols and visible names. This describes traffic; it is not a security verdict."
      >
        <div className="space-y-4">
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <div className="max-w-sm">
              <SessionPicker value={session} onChange={setSession} />
            </div>
            <SelectField
              label="Device filter"
              value={deviceFilter}
              onChange={(e) => setDeviceFilter(e.target.value)}
            >
              <option value="all">All devices</option>
              {availableDevices.map((d) => (
                <option key={d.address} value={d.address}>
                  {d.label}
                </option>
              ))}
            </SelectField>
            <SelectField
              label="Confidence"
              value={confidenceFilter}
              onChange={(e) => setConfidenceFilter(e.target.value)}
            >
              <option value="all">All confidence levels</option>
              <option value="confirmed">Confirmed</option>
              <option value="probable">Probable</option>
              <option value="unknown">Unknown</option>
            </SelectField>
            <TextField
              label="Search applications"
              placeholder="Name, port, domain..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>

          {data && (
            <VantageNotice
              captureSource={data.capture_source}
              interfaceName={data.interface_name}
              isWifi={data.is_wifi}
            />
          )}
        </div>

        {apps.isLoading && <StateView variant="loading" title="Loading applications" />}
        {!data && apps.error && <RequestError error={apps.error} what="applications" onRetry={apps.reload} />}
        {data && apps.error && <StaleNotice error={apps.error} what="applications" asOf={apps.dataUpdatedAt} onRetry={apps.reload} />}
        {data && data.applications.length === 0 && (
          <StateView
            variant="empty"
            title="No traffic has been processed yet"
            description="Start a capture or open a capture file in the Packet Explorer."
          />
        )}
        {data && data.applications.length > 0 && (
          <div className="mt-3 flex flex-wrap items-center justify-between gap-2 text-sm text-fg-muted">
            <p>
              {data.identified_flows.toLocaleString()} flows were identified; {data.unclassified_flows.toLocaleString()} are unclassified.
              {hasActiveFilters && ` Showing ${filteredApps.length} of ${data.applications.length} applications.`}
            </p>
            {hasActiveFilters && (
              <Button
                variant="ghost"
                onClick={() => {
                  setDeviceFilter("all");
                  setConfidenceFilter("all");
                  setSearchQuery("");
                }}
              >
                Reset filters
              </Button>
            )}
          </div>
        )}
      </Panel>

      {data && data.applications.length > 0 && filteredApps.length === 0 && (
        <Panel title="Filtered results">
          <StateView
            variant="empty"
            title="No matching applications"
            description="Try adjusting your device, confidence, or search query filter."
          />
        </Panel>
      )}

      {named.length > 0 && (
        <Panel title="Identified" description="Each entry lists the evidence it rests on.">
          <ul className="grid gap-3">
            {named.map((a) => (
              <AppRow key={a.application} app={a} />
            ))}
          </ul>
        </Panel>
      )}

      {unclassified && (
        <Panel title="Unclassified" description="Traffic nothing in the packets identifies.">
          <ul className="grid gap-3">
            <AppRow app={unclassified} />
          </ul>
        </Panel>
      )}

      {data && data.applications.length > 0 && (
        <Panel title="Summary table">
          <Table label="Applications by traffic">
            <thead>
              <tr><Th>Application</Th><Th>Category</Th><Th>Confidence</Th><Th>Flows</Th><Th>Packets</Th><Th>Bytes</Th></tr>
            </thead>
            <tbody>
              {filteredApps.map((a) => (
                <tr key={a.application}>
                  <Td>{a.application}</Td>
                  <Td>{a.category}</Td>
                  <Td><ConfidenceBadge value={a.confidence} /></Td>
                  <Td mono>{a.flows.toLocaleString()}</Td>
                  <Td mono>{a.packets.toLocaleString()}</Td>
                  <Td mono>{formatBytes(a.bytes)}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
        </Panel>
      )}
    </div>
  );
}
