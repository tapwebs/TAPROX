import { useRef } from "react";
import { RequestError, StaleNotice } from "@/components/RequestError";
import { Button } from "@/components/ui/Button";
import { DefinitionList, type DefinitionItem } from "@/components/ui/DefinitionList";
import { Panel } from "@/components/ui/Panel";
import { StateView } from "@/components/ui/StateView";
import { StatusBadge } from "@/components/ui/StatusBadge";
import { RowTh, Table, Td, Th } from "@/components/ui/Table";
import type { InterfaceEvent, NetworkInterface } from "@/lib/api/types";
import { useReadyBackend } from "@/lib/connection/BackendProvider";
import { formatDateTime, formatMac, formatRelative, formatSpeed } from "@/lib/format";
import { useSelectedInterface } from "@/lib/selectedInterface";
import { usePolling } from "@/lib/usePolling";
import { useRequest } from "@/lib/useRequest";
import { ConnectionBadge } from "../badges";

const HARDWARE: Record<NetworkInterface["hardware"], string> = {
  physical: "Physical",
  usb: "USB",
  virtual: "Virtual",
  unknown: "Unknown hardware",
};
const KIND: Record<NetworkInterface["kind"], string> = {
  ethernet: "Ethernet",
  wifi: "Wi-Fi",
  loopback: "Loopback",
  tunnel: "Tunnel",
  other: "Other",
};

function eventText(event: InterfaceEvent): string {
  const name = event.interface_name;
  switch (event.kind) {
    case "appeared":
      return `${name} appeared`;
    case "removed":
      return `${name} was removed`;
    case "connected":
      return `${name} connected`;
    case "disconnected":
      return `${name} disconnected`;
    case "address_changed":
      return `${name} address changed`;
  }
}

function addresses(nic: NetworkInterface): string {
  return nic.ipv4.map((a) => `${a.address}/${String(a.prefix_length)}`).join(", ") || "—";
}

/**
 * Windows keeps the last DHCP lease on an adapter that has since been disconnected. It is real data
 * but not an address in use, so it is labelled instead of being shown as if it were.
 */
function isLeftover(nic: NetworkInterface): boolean {
  return nic.connection !== "connected" && nic.ipv4.length > 0;
}

function Details({ nic }: { nic: NetworkInterface }) {
  const items: DefinitionItem[] = [
    {
      label: "Status",
      value: (
        <span className="inline-flex flex-wrap items-center gap-2">
          <ConnectionBadge connection={nic.connection} present={nic.present} />
          {nic.support === "unsupported" && <StatusBadge tone="neutral">Unsupported</StatusBadge>}
        </span>
      ),
    },
    { label: "Type", value: `${HARDWARE[nic.hardware]} · ${KIND[nic.kind]}` },
    { label: "Description", value: nic.description ?? "Not reported" },
    {
      label: "MAC address",
      mono: true,
      value: (
        <>
          {formatMac(nic.mac)}
          {nic.mac_locally_administered && (
            <span className="mt-0.5 block font-sans text-xs text-fg-muted">
              Locally administered: a virtual adapter or a randomised address, not one assigned by a
              manufacturer.
            </span>
          )}
        </>
      ),
    },
    {
      label: "IPv4",
      mono: true,
      value: (
        <>
          {addresses(nic)}
          {isLeftover(nic) && (
            <span className="mt-0.5 block font-sans text-xs text-fg-muted">
              Left over from an earlier connection. The adapter is not connected, so this address is
              not in use.
            </span>
          )}
        </>
      ),
    },
    {
      label: "IPv6",
      mono: true,
      value: nic.ipv6.map((a) => `${a.address}/${String(a.prefix_length)}`).join(", ") || "—",
    },
    { label: "Default gateway", mono: true, value: nic.gateways.join(", ") || "—" },
    { label: "DNS servers", mono: true, value: nic.dns_servers.join(", ") || "—" },
    {
      label: "Addressing",
      value: nic.dhcp_enabled === null ? "Not reported" : nic.dhcp_enabled ? "DHCP" : "Static",
    },
    { label: "Link speed", value: formatSpeed(nic.link_speed_mbps) },
    { label: "MTU", value: nic.mtu === null ? "Not reported" : String(nic.mtu) },
    ...(nic.kind === "wifi" && nic.wireless
      ? [
          {
            label: "Wireless network",
            value: nic.wireless.ssid ? (
              <span className="space-y-0.5">
                <span className="font-semibold text-fg">{nic.wireless.ssid}</span>
                {nic.wireless.bssid && (
                  <span className="block font-mono text-xs text-fg-muted">
                    AP BSSID: {nic.wireless.bssid}
                  </span>
                )}
              </span>
            ) : (
              "Disconnected"
            ),
          },
          ...(nic.wireless.signal_percent !== null && nic.wireless.signal_percent !== undefined
            ? [
                {
                  label: "Signal quality",
                  value: `${nic.wireless.signal_percent}%`,
                },
              ]
            : []),
          ...(nic.wireless.band || nic.wireless.channel
            ? [
                {
                  label: "Band & Channel",
                  value: `${nic.wireless.band ?? "Unknown"} ${nic.wireless.channel ? `· Channel ${nic.wireless.channel}` : ""}`,
                },
              ]
            : []),
          ...(nic.wireless.radio_type
            ? [
                {
                  label: "Radio standard",
                  value: nic.wireless.radio_type,
                },
              ]
            : []),
        ]
      : []),
    {
      label: "Device discovery",
      value: nic.discovery.passive ? (
        <span className="space-y-1">
          <a href="#/discovery" className="block text-link underline underline-offset-2 hover:text-fg">
            Discover devices on this interface
          </a>
          {nic.discovery.needs_subnet && (
            <span className="block text-xs text-fg-muted">
              Its network is larger than the scan limit; choose a narrower subnet to scan actively.
            </span>
          )}
        </span>
      ) : (
        (nic.discovery.reason ?? "Not available on this interface.")
      ),
    },
    {
      label: "Packet capture",
      value:
        nic.capture.status === "unsupported" ? (
          <>Not supported. {nic.capture.note}</>
        ) : (
          <span className="space-y-1">
            <span>
              {nic.kind === "wifi"
                ? "Not verified. Checked when a capture starts (Phase 2). Managed mode decapsulates 802.11 to Ethernet frames."
                : "Not verified. It is checked when a capture starts (Phase 2)."}
            </span>
            {nic.kind === "wifi" && (
              <span className="block text-xs text-fg-muted">
                Monitor mode: Driver limitation (Npcap on Windows cannot enter monitor mode on this adapter). Station-to-station wireless traffic between other devices is not captured.
              </span>
            )}
          </span>
        ),
    },
  ];
  if (nic.support_reason) items.splice(2, 0, { label: "Why unsupported", value: nic.support_reason });
  return <DefinitionList items={items} />;
}

export function InterfacesPage({ pollMs = 5000 }: { pollMs?: number | null }) {
  const { client } = useReadyBackend();
  const { selectedId, select } = useSelectedInterface();
  const forceRead = useRef(false);

  // Interface changes are noticed whenever the list is read, so the change log is read right
  // after the list and a failure there never hides the interfaces themselves.
  const request = useRequest(
    async (signal) => {
      const refresh = forceRead.current;
      forceRead.current = false;
      const list = await client.getInterfaces({ refresh, signal });
      const events = await client.getInterfaceEvents(50, signal).then(
        (result) => result.events,
        () => null,
      );
      return { list, events };
    },
    [client],
  );
  usePolling(() => {
    if (!request.isPending) request.reloadQuietly();
  }, pollMs);

  const data = request.data;
  const interfaces = data?.list.interfaces ?? [];
  const selected = interfaces.find((nic) => nic.id === selectedId && nic.present);
  const selectionLost = data !== undefined && selectedId !== null && !selected;

  return (
    <div className="grid grid-cols-1 gap-4">
      {selectionLost && (
        <div
          role="status"
          aria-label="Selected interface unavailable"
          className="flex flex-wrap items-center justify-between gap-3 rounded-md border border-warning/40 bg-warning/10 p-3"
        >
          <p className="text-fg">
            The interface you selected earlier is not present on this computer right now.
          </p>
          <Button
            onClick={() => {
              select(null);
            }}
          >
            Clear selection
          </Button>
        </div>
      )}

      <Panel
        title="Interfaces"
        description="Network adapters on this computer. Select one to see its details."
        actions={
          <span className="flex items-center gap-3">
            {data?.list.stale && <StatusBadge tone="warning">Out of date</StatusBadge>}
            <Button
              loading={request.isRefreshing}
              onClick={() => {
                forceRead.current = true;
                request.reload();
              }}
            >
              Refresh
            </Button>
          </span>
        }
      >
        {request.isLoading && <StateView variant="loading" title="Loading network interfaces" />}
        {!data && request.error && (
          <RequestError error={request.error} what="network interfaces" onRetry={request.reload} />
        )}
        {data && request.error && (
          <StaleNotice
            error={request.error}
            what="network interfaces"
            asOf={request.dataUpdatedAt}
            onRetry={request.reload}
          />
        )}
        {data?.list.stale && (
          <div
            role="alert"
            className="mb-4 rounded-md border border-warning/40 bg-warning/10 p-3 text-fg"
          >
            {data.list.warnings.map((warning) => (
              <p key={warning}>{warning}</p>
            ))}
          </div>
        )}
        {data && !data.list.stale && data.list.warnings.length > 0 && (
          <ul className="mb-4 space-y-1 text-xs text-fg-muted">
            {data.list.warnings.map((warning) => (
              <li key={warning}>{warning}</li>
            ))}
          </ul>
        )}
        {data && interfaces.length === 0 && (
          <StateView
            variant="empty"
            title="No network interfaces were found"
            description="The operating system did not report any network adapters."
          />
        )}
        {interfaces.length > 0 && (
          <Table label="Network interfaces">
            <thead>
              <tr>
                <Th>Name</Th>
                <Th>Type</Th>
                <Th>Status</Th>
                <Th>IPv4</Th>
                <Th>Gateway</Th>
                <Th>
                  <span className="sr-only">Select</span>
                </Th>
              </tr>
            </thead>
            <tbody>
              {interfaces.map((nic) => {
                const chosen = nic.id === selectedId;
                return (
                  <tr key={nic.id} className={chosen ? "bg-raised" : undefined}>
                    <RowTh>
                      {nic.name}
                      {nic.kind === "wifi" && nic.wireless?.ssid && (
                        <span className="block text-xs font-normal text-fg-muted">
                          {nic.wireless.ssid}
                        </span>
                      )}
                    </RowTh>
                    <Td>
                      {HARDWARE[nic.hardware]} · {KIND[nic.kind]}
                    </Td>
                    <Td>
                      <span className="inline-flex flex-wrap items-center gap-1.5">
                        <ConnectionBadge connection={nic.connection} present={nic.present} />
                        {nic.present && nic.support === "unsupported" && (
                          <StatusBadge tone="neutral">Unsupported</StatusBadge>
                        )}
                      </span>
                    </Td>
                    <Td mono>
                      {addresses(nic)}
                      {isLeftover(nic) && (
                        <span className="block font-sans text-xs text-fg-muted">not in use</span>
                      )}
                    </Td>
                    <Td mono>{isLeftover(nic) ? "—" : (nic.gateways[0] ?? "—")}</Td>
                    <Td>
                      <Button
                        variant={chosen ? "primary" : "secondary"}
                        aria-label={`Select ${nic.name}`}
                        aria-pressed={chosen}
                        disabled={!nic.present}
                        onClick={() => {
                          select(nic.id);
                        }}
                      >
                        {chosen ? "Selected" : "Select"}
                      </Button>
                    </Td>
                  </tr>
                );
              })}
            </tbody>
          </Table>
        )}
        {data && (
          <p className="mt-3 text-xs text-fg-subtle">
            Read from {data.list.provider} at {formatDateTime(data.list.collected_at)}.
          </p>
        )}
      </Panel>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Panel title="Interface details">
          {selected ? (
            <Details nic={selected} />
          ) : (
            <p className="text-fg-muted">Select an interface to see its details.</p>
          )}
        </Panel>

        <Panel
          title="Recent changes"
          description="Noticed while this screen is open, newest first."
        >
          {data?.events === null && (
            <p className="text-fg-muted">The change log could not be loaded.</p>
          )}
          {data?.events?.length === 0 && (
            <p className="text-fg-muted">No changes since TAPROX started.</p>
          )}
          {data?.events && data.events.length > 0 && (
            <ul className="space-y-2">
              {data.events.map((event) => (
                <li key={event.sequence} className="flex flex-wrap justify-between gap-x-3">
                  <span>
                    <span className="text-fg">{eventText(event)}</span>
                    {event.detail && (
                      <span className="block font-mono text-xs text-fg-muted">{event.detail}</span>
                    )}
                  </span>
                  <time dateTime={event.at} className="text-xs text-fg-subtle">
                    {formatRelative(event.at)}
                  </time>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>
    </div>
  );
}
