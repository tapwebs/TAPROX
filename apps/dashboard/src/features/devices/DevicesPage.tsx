import { useRef, useState } from "react";
import { RequestError, StaleNotice } from "@/components/RequestError";
import { Button } from "@/components/ui/Button";
import { DefinitionList } from "@/components/ui/DefinitionList";
import { DetailPanel } from "@/components/ui/DetailPanel";
import { SelectField, TextField } from "@/components/ui/Fields";
import { Pagination } from "@/components/ui/Pagination";
import { Panel } from "@/components/ui/Panel";
import { StateView } from "@/components/ui/StateView";
import { StatusBadge } from "@/components/ui/StatusBadge";
import { RowTh, SortTh, Table, Td, Th, type SortState } from "@/components/ui/Table";
import { ApiError } from "@/lib/api/client";
import { AttachToCasePanel } from "@/features/investigations/AttachToCaseModal";
import type { Device, DeviceDetail, DeviceQuery, DeviceSort, DeviceState } from "@/lib/api/types";
import { useReadyBackend } from "@/lib/connection/BackendProvider";
import { formatDateTime, formatMac, formatRelative } from "@/lib/format";
import { useDebouncedValue } from "@/lib/useDebouncedValue";
import { useRequest } from "@/lib/useRequest";
import {
  ConfidenceBadge,
  DeviceStateBadge,
  confidenceExplanation,
  sourceLabel,
} from "../badges";

const PAGE_SIZE = 50;
const HISTORY_SIZE = 20;

const STATES: { value: DeviceState; label: string }[] = [
  { value: "active", label: "Active" },
  { value: "inactive", label: "Not seen recently" },
  { value: "previously_observed", label: "Previously observed" },
];

const SORTABLE: DeviceSort[] = ["last_seen", "first_seen", "ip", "hostname", "vendor", "mac"];
const isSortKey = (key: string): key is DeviceSort => (SORTABLE as string[]).includes(key);

/** `#/devices[/id][?scan=…]` for links that must preserve the scan filter. */
function devicesHash(id: number | null, scan: string | null): string {
  return `#/devices${id === null ? "" : `/${String(id)}`}${scan ? `?scan=${encodeURIComponent(scan)}` : ""}`;
}

function parseId(param: string | null): number | null {
  return param !== null && /^[1-9]\d{0,15}$/.test(param) ? Number(param) : null;
}

type InterfaceNames = ReadonlyMap<string, string>;

function interfaceName(names: InterfaceNames, id: string | null): string {
  if (id === null) return "—";
  return names.get(id) ?? "Unknown interface";
}

// --- the detail panel --------------------------------------------------------------------------

function DeviceDetails({
  id,
  names,
  onClose,
}: {
  id: number | null;
  names: InterfaceNames;
  onClose: () => void;
}) {
  const { client } = useReadyBackend();
  const detail = useRequest(
    (signal) => (id === null ? Promise.resolve<DeviceDetail | null>(null) : client.getDevice(id, signal)),
    [client, id],
  );
  const [historyOffset, setHistoryOffset] = useState(0);
  const [attachOpen, setAttachOpen] = useState(false);
  const history = useRequest(
    (signal) =>
      id === null
        ? Promise.resolve(null)
        : client.getDeviceObservations(id, { limit: HISTORY_SIZE, offset: historyOffset }, signal),
    [client, id, historyOffset],
  );

  const notFound =
    id === null || (detail.error instanceof ApiError && detail.error.code === "device_not_found");
  const device = detail.data;
  const title = device
    ? (device.observed.hostname ?? device.observed.ip ?? formatMac(device.mac))
    : "Device details";

  return (
    <DetailPanel title={title} onClose={onClose}>
      {notFound && (
        <StateView
          variant="empty"
          title="Device not found"
          description="This device is not in the inventory. It may have been removed, or the link is wrong."
        />
      )}
      {!notFound && detail.isLoading && <StateView variant="loading" title="Loading device details" />}
      {!notFound && !device && detail.error && (
        <RequestError error={detail.error} what="device details" onRetry={detail.reload} />
      )}
      {device && (
        <div className="grid gap-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            {device.is_local ? <StatusBadge tone="info">This computer</StatusBadge> : <span />}
            <Button
              className="h-7 px-2.5 text-xs"
              onClick={() => {
                setAttachOpen(true);
              }}
            >
              Attach to Investigation…
            </Button>
          </div>
          {attachOpen && (
            <AttachToCasePanel
              target={{
                kind: "device",
                sourceId: device.id,
                label: `Device #${String(device.id)}: ${device.observed.hostname ?? device.observed.ip ?? formatMac(device.mac)}`,
              }}
              onClose={() => {
                setAttachOpen(false);
              }}
            />
          )}

          <Panel
            title="Observed"
            description="What the network showed us. These came from replies and tables, not guesses."
          >
            <DefinitionList
              items={[
                { label: "MAC address", mono: true, value: formatMac(device.mac) },
                { label: "IP address", mono: true, value: device.observed.ip ?? "—" },
                { label: "Interface", value: interfaceName(names, device.observed.interface_id) },
                {
                  label: "Host name",
                  value: device.observed.hostname ? (
                    <>
                      <span className="font-mono text-[13px]">{device.observed.hostname}</span>
                      <span className="block text-xs text-fg-muted">
                        From {device.observed.hostname_source === "reverse_dns" ? "a reverse DNS lookup" : (device.observed.hostname_source ?? "the network")}
                        : the name a DNS server gave for this address, not proof of identity.
                      </span>
                    </>
                  ) : (
                    "None found"
                  ),
                },
                { label: "First seen", value: formatDateTime(device.observed.first_seen) },
                { label: "Last seen", value: formatDateTime(device.observed.last_seen) },
                { label: "How it was seen", value: sourceLabel(device.observed.source) },
                {
                  label: "Confidence",
                  value: (
                    <>
                      <ConfidenceBadge confidence={device.observed.confidence} />
                      <span className="mt-1 block text-xs text-fg-muted">
                        {confidenceExplanation(device.observed.confidence, device.observed.source)}
                      </span>
                    </>
                  ),
                },
              ]}
            />
          </Panel>

          <Panel
            title="Inferred"
            description="Conclusions drawn from what was observed. Treat them as hints."
          >
            <DefinitionList
              items={[
                {
                  label: "Manufacturer",
                  value: device.inferred.vendor ? (
                    <>
                      {device.inferred.vendor}
                      <span className="block text-xs text-fg-muted">
                        Taken from the first bits of the MAC address. It names who made the network
                        chip and does not say what the device is.
                      </span>
                    </>
                  ) : device.inferred.mac_randomized ? (
                    "None: the address is randomised"
                  ) : (
                    "Unknown: this MAC prefix is not in the registry"
                  ),
                },
                {
                  label: "Address type",
                  value: device.inferred.mac_randomized ? (
                    <>
                      Randomised or virtual
                      <span className="block text-xs text-fg-muted">
                        This MAC is not manufacturer-assigned, so no manufacturer can be derived, and
                        the same device may appear under other MAC addresses. They are not merged.
                      </span>
                    </>
                  ) : (
                    "Manufacturer-assigned"
                  ),
                },
                {
                  label: "Recent activity",
                  value: (
                    <>
                      <DeviceStateBadge state={device.inferred.state} />
                      {device.inferred.state !== "active" && (
                        <span className="mt-1 block text-xs text-fg-muted">
                          Not seen recently is not proof that it is offline: it may be asleep or
                          ignoring requests.
                        </span>
                      )}
                    </>
                  ),
                },
              ]}
            />
          </Panel>

          <div className="grid gap-2">
            <h3 className="text-xs font-semibold text-fg">Addresses this device has had</h3>
            <Table label="Address history">
              <thead>
                <tr>
                  <Th>Address</Th>
                  <Th>Interface</Th>
                  <Th>First seen</Th>
                  <Th>Last seen</Th>
                </tr>
              </thead>
              <tbody>
                {device.addresses.map((address) => (
                  <tr key={`${address.ip}/${address.interface_id}`}>
                    <RowTh>
                      <span className="font-mono text-[13px] font-normal">{address.ip}</span>
                    </RowTh>
                    <Td>{interfaceName(names, address.interface_id)}</Td>
                    <Td>{formatDateTime(address.first_seen)}</Td>
                    <Td>{formatDateTime(address.last_seen)}</Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          </div>

          <div className="grid gap-2">
            <h3 className="text-xs font-semibold text-fg">Observation history</h3>
            {history.isLoading && <StateView variant="loading" title="Loading observation history" />}
            {!history.data && history.error && (
              <RequestError
                error={history.error}
                what="observation history"
                onRetry={history.reload}
              />
            )}
            {history.data && (
              <>
                <Table label="Observation history">
                  <thead>
                    <tr>
                      <Th>When</Th>
                      <Th>How</Th>
                      <Th>Address</Th>
                      <Th>Confidence</Th>
                    </tr>
                  </thead>
                  <tbody>
                    {history.data.observations.map((observation) => (
                      <tr key={observation.id}>
                        <RowTh>
                          <time dateTime={observation.observed_at} className="font-normal">
                            {formatDateTime(observation.observed_at)}
                          </time>
                        </RowTh>
                        <Td>{sourceLabel(observation.source)}</Td>
                        <Td mono>{observation.ip ?? "—"}</Td>
                        <Td>
                          <ConfidenceBadge confidence={observation.confidence} />
                        </Td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
                <Pagination
                  label="Observation history pages"
                  total={history.data.total}
                  limit={HISTORY_SIZE}
                  offset={historyOffset}
                  onChange={setHistoryOffset}
                />
              </>
            )}
          </div>
        </div>
      )}
    </DetailPanel>
  );
}

// --- the page ----------------------------------------------------------------------------------

export function DevicesPage({ param, scan }: { param: string | null; scan: string | null }) {
  const { client } = useReadyBackend();
  const openId = parseId(param);
  const panelOpen = param !== null;

  const [searchText, setSearchText] = useState("");
  const search = useDebouncedValue(searchText.trim(), 300);
  const [state, setState] = useState<DeviceState | "">("");
  const [interfaceId, setInterfaceId] = useState("");
  const [sort, setSort] = useState<SortState>({ key: "last_seen", order: "desc" });

  // The page is remembered together with the filters it was chosen under, so changing a filter or
  // the sort automatically means "first page" without any reset logic.
  const filterKey = JSON.stringify([search, state, interfaceId, sort, scan]);
  const [page, setPage] = useState({ filterKey, offset: 0 });
  const effectiveOffset = page.filterKey === filterKey ? page.offset : 0;
  const setOffset = (next: number) => {
    setPage({ filterKey, offset: next });
  };

  const query: DeviceQuery = {
    search: search || undefined,
    state: state || undefined,
    interface_id: interfaceId || undefined,
    scan_id: scan ?? undefined,
    sort: isSortKey(sort.key) ? sort.key : "last_seen",
    order: sort.order,
    limit: PAGE_SIZE,
    offset: effectiveOffset || undefined,
  };
  const devices = useRequest(
    (signal) => client.getDevices(query, signal),
    [client, search, state, interfaceId, sort.key, sort.order, scan, effectiveOffset],
  );

  // Interface names make the table readable. They are a nicety: a failure here never hides devices.
  const interfaces = useRequest((signal) => client.getInterfaces({ signal }), [client]);
  const names: InterfaceNames = new Map(
    (interfaces.data?.interfaces ?? []).map((nic) => [nic.id, nic.name] as const),
  );

  const filtered = Boolean(search || state || interfaceId);
  const data = devices.data;
  const lastOpener = useRef<string | null>(null);

  const toggleSort = (key: string) => {
    setSort((current) =>
      current.key === key
        ? { key, order: current.order === "asc" ? "desc" : "asc" }
        : { key, order: key === "last_seen" || key === "first_seen" ? "desc" : "asc" },
    );
  };

  const clearFilters = () => {
    setSearchText("");
    setState("");
    setInterfaceId("");
  };

  const closePanel = () => {
    window.location.hash = devicesHash(null, scan);
    const opener = lastOpener.current;
    // Return focus to the link that opened the panel once the list has re-rendered.
    queueMicrotask(() => {
      if (opener) document.querySelector<HTMLElement>(`[data-device-link="${opener}"]`)?.focus();
    });
  };

  return (
    <div className={`grid items-start gap-4 ${panelOpen ? "grid-cols-1 xl:grid-cols-[minmax(0,1fr)_28rem]" : "grid-cols-1"}`}>
      <div className="grid min-w-0 gap-4">
        {scan && (
          <div className="flex flex-wrap items-center justify-between gap-3 rounded-md border border-line bg-surface p-3">
            <p className="text-fg">Showing only the devices found by one scan.</p>
            <Button
              onClick={() => {
                window.location.hash = devicesHash(openId, null);
              }}
            >
              Show all devices
            </Button>
          </div>
        )}

        <Panel
          title="Devices"
          description="Everything this computer has seen on the networks it is connected to."
          actions={
            <Button
              loading={devices.isRefreshing}
              onClick={devices.reload}
            >
              Refresh
            </Button>
          }
        >
          <div className="mb-4 grid gap-3 sm:grid-cols-[minmax(0,2fr)_repeat(2,minmax(0,1fr))]">
            <TextField
              label="Search"
              type="search"
              value={searchText}
              placeholder="IP address, MAC, name or manufacturer"
              autoComplete="off"
              spellCheck={false}
              maxLength={100}
              onChange={(event) => {
                setSearchText(event.target.value);
              }}
            />
            <SelectField
              label="State"
              value={state}
              onChange={(event) => {
                setState(event.target.value as DeviceState | "");
              }}
            >
              <option value="">Any</option>
              {STATES.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </SelectField>
            <SelectField
              label="Interface"
              value={interfaceId}
              onChange={(event) => {
                setInterfaceId(event.target.value);
              }}
            >
              <option value="">Any</option>
              {[...names].map(([id, name]) => (
                <option key={id} value={id}>
                  {name}
                </option>
              ))}
            </SelectField>
          </div>

          {devices.isLoading && <StateView variant="loading" title="Loading devices" />}
          {!data && devices.error && (
            <RequestError error={devices.error} what="devices" onRetry={devices.reload} />
          )}
          {data && devices.error && (
            <StaleNotice
              error={devices.error}
              what="devices"
              asOf={devices.dataUpdatedAt}
              onRetry={devices.reload}
            />
          )}
          {data && data.total === 0 && !filtered && !scan && (
            <StateView
              variant="empty"
              title="No devices yet"
              description="Nothing has been discovered. TAPROX only lists devices it has actually seen on your network."
            />
          )}
          {data && data.total === 0 && !filtered && !scan && (
            <p className="text-center">
              <a href="#/discovery" className="text-link underline underline-offset-2 hover:text-fg">
                Run a scan
              </a>
            </p>
          )}
          {data && data.total === 0 && (filtered || scan) && (
            <StateView
              variant="empty"
              title="No devices match"
              description="Nothing in the inventory fits these filters."
              action={filtered ? { label: "Clear filters", onClick: clearFilters } : undefined}
            />
          )}

          {data && data.devices.length > 0 && (
            <div className="grid gap-3">
              <Table label="Device inventory">
                <thead>
                  <tr>
                    <SortTh label="Address" sortKey="ip" sort={sort} onSort={toggleSort} />
                    <SortTh label="MAC address" sortKey="mac" sort={sort} onSort={toggleSort} />
                    <SortTh label="Name" sortKey="hostname" sort={sort} onSort={toggleSort} />
                    <SortTh label="Manufacturer" sortKey="vendor" sort={sort} onSort={toggleSort} />
                    <Th>Interface</Th>
                    <Th>State</Th>
                    <SortTh label="Last seen" sortKey="last_seen" sort={sort} onSort={toggleSort} />
                  </tr>
                </thead>
                <tbody>
                  {data.devices.map((item: Device) => {
                    const label = item.observed.ip ?? formatMac(item.mac);
                    return (
                      <tr key={item.id} className={item.id === openId ? "bg-raised" : undefined}>
                        <RowTh>
                          <a
                            href={devicesHash(item.id, scan)}
                            data-device-link={String(item.id)}
                            onClick={() => {
                              lastOpener.current = String(item.id);
                            }}
                            className={`text-link underline underline-offset-2 hover:text-fg ${
                              item.observed.ip ? "font-mono text-[13px] font-normal" : "font-mono text-[13px]"
                            }`}
                          >
                            {label}
                          </a>
                          {item.is_local && (
                            <>
                              {" "}
                              <span className="ml-1 align-middle">
                                <StatusBadge tone="info">This computer</StatusBadge>
                              </span>
                            </>
                          )}
                        </RowTh>
                        <Td mono>{formatMac(item.mac)}</Td>
                        <Td>{item.observed.hostname ?? <span className="text-fg-subtle">—</span>}</Td>
                        <Td>
                          {item.inferred.vendor ??
                            (item.inferred.mac_randomized ? (
                              <span className="text-fg-muted">Randomised address</span>
                            ) : (
                              <span className="text-fg-muted">Unknown vendor</span>
                            ))}
                        </Td>
                        <Td>{interfaceName(names, item.observed.interface_id)}</Td>
                        <Td>
                          <DeviceStateBadge state={item.inferred.state} />
                        </Td>
                        <Td>
                          <time
                            dateTime={item.observed.last_seen}
                            title={formatDateTime(item.observed.last_seen)}
                          >
                            {formatRelative(item.observed.last_seen)}
                          </time>
                        </Td>
                      </tr>
                    );
                  })}
                </tbody>
              </Table>
              <Pagination
                total={data.total}
                limit={PAGE_SIZE}
                offset={effectiveOffset}
                onChange={setOffset}
              />
            </div>
          )}
        </Panel>
      </div>

      {panelOpen && (
        // Keyed by the device so nothing from the previous one (data, history page) can show.
        <DeviceDetails key={param} id={openId} names={names} onClose={closePanel} />
      )}
    </div>
  );
}
