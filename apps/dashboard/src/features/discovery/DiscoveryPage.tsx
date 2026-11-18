import { useState, type FormEvent } from "react";
import { RequestError, StaleNotice } from "@/components/RequestError";
import { Button } from "@/components/ui/Button";
import { CheckboxField, RadioField, SelectField, TextField } from "@/components/ui/Fields";
import { Panel } from "@/components/ui/Panel";
import { Pagination } from "@/components/ui/Pagination";
import { ProgressBar } from "@/components/ui/ProgressBar";
import { StateView } from "@/components/ui/StateView";
import { StatusBadge, type Tone } from "@/components/ui/StatusBadge";
import { RowTh, Table, Td, Th } from "@/components/ui/Table";
import { ApiError } from "@/lib/api/client";
import type { NetworkInterface, Scan, ScanRequest } from "@/lib/api/types";
import { useReadyBackend } from "@/lib/connection/BackendProvider";
import { cidrHostCount, formatDateTime, formatRelative, ipInCidr } from "@/lib/format";
import { useSelectedInterface } from "@/lib/selectedInterface";
import { usePolling } from "@/lib/usePolling";
import { useRequest } from "@/lib/useRequest";

const HISTORY_PAGE = 10;
const MAX_ACTIVE_HOSTS = 1022; // the backend's /22 limit; it re-checks, this only saves a round trip

/** Errors the backend attaches to the subnet the user typed. */
const SUBNET_CODES = new Set([
  "invalid_cidr",
  "not_ipv4",
  "host_bits_set",
  "outside_interface_network",
  "not_private",
  "too_large",
  "no_hosts",
  "no_ipv4",
  "network_not_applicable",
]);

const PHASES: Record<NonNullable<Scan["phase"]>, string> = {
  preparing: "Preparing",
  probing: "Probing the network",
  ipv6: "Looking for IPv6 neighbors",
  neighbors: "Reading the neighbor table",
  resolving: "Looking up host names",
};

const OUTCOMES: Record<Scan["status"], { label: string; tone: Tone }> = {
  running: { label: "Running", tone: "info" },
  completed: { label: "Completed", tone: "success" },
  cancelled: { label: "Cancelled", tone: "neutral" },
  timed_out: { label: "Stopped at the time limit", tone: "warning" },
  failed: { label: "Failed", tone: "critical" },
  interrupted: { label: "Interrupted", tone: "warning" },
};

function plural(count: number, one: string, many: string): string {
  return `${String(count)} ${count === 1 ? one : many}`;
}

function usable(nic: NetworkInterface): boolean {
  return nic.present && nic.discovery.passive;
}

function optionLabel(nic: NetworkInterface): string {
  const first = nic.ipv4[0];
  const ipPart = first ? `${first.address}/${String(first.prefix_length)}` : "no IPv4 address";
  const wifiPart = nic.kind === "wifi" && nic.wireless?.ssid ? ` · Wi-Fi: ${nic.wireless.ssid}` : "";
  return `${nic.name} (${ipPart}${wifiPart})`;
}

// --- the scan that is running or just finished -------------------------------------------------

function ScanPanel({
  scan,
  error,
  refreshedAt,
  onRetry,
  onCancel,
  cancelling,
}: {
  scan: Scan;
  error: Error | undefined;
  refreshedAt: number | undefined;
  onRetry: () => void;
  onCancel: () => void;
  cancelling: boolean;
}) {
  const outcome = OUTCOMES[scan.status];
  const running = scan.status === "running";
  const probing = scan.mode === "active";
  const kept = scan.status === "cancelled" || scan.status === "timed_out" || scan.status === "interrupted";
  return (
    <Panel
      title="Current scan"
      description={`${scan.mode === "active" ? "Active" : "Passive"} scan on ${scan.interface_name}${
        scan.network ? ` · ${scan.network}` : ""
      }`}
      actions={
        running && (
          <Button onClick={onCancel} loading={cancelling} disabled={scan.cancel_requested}>
            Cancel scan
          </Button>
        )
      }
    >
      <div className="space-y-3">
        {error && (
          <StaleNotice error={error} what="scan progress" asOf={refreshedAt} onRetry={onRetry} />
        )}
        <div className="flex flex-wrap items-center gap-3">
          <StatusBadge tone={outcome.tone}>{outcome.label}</StatusBadge>
          {running && (
            <span className="text-fg-muted">
              {scan.cancel_requested ? "Cancelling…" : scan.phase ? PHASES[scan.phase] : "Working"}
            </span>
          )}
        </div>

        {running && (
          <>
            <ProgressBar
              label={probing ? "Addresses probed" : "Scan progress"}
              value={scan.targets_done}
              max={scan.targets_total}
            />
            <p className="text-fg-muted">
              {probing && scan.targets_total > 0
                ? `${String(scan.targets_done)} of ${String(scan.targets_total)} addresses probed · `
                : ""}
              {plural(scan.devices_found, "device", "devices")}{" "}
              {probing ? "found so far" : "listed so far"}
            </p>
          </>
        )}

        {!running && (
          <div className="space-y-2">
            {scan.status === "completed" &&
              probing &&
              (scan.devices_found > 0 ? (
                <p className="text-fg">
                  {plural(scan.devices_found, "device", "devices")} found in{" "}
                  {String(Math.round(scan.elapsed_seconds))} s
                </p>
              ) : (
                <p className="text-fg">
                  No other devices were found in {String(Math.round(scan.elapsed_seconds))} s.
                </p>
              ))}
            {scan.status === "completed" && !probing && (
              <p className="text-fg">
                {scan.devices_found > 0
                  ? `${plural(scan.devices_found, "device", "devices")} listed in the operating system's neighbor table.`
                  : "The operating system's neighbor table lists no other devices."}
              </p>
            )}
            {!probing && scan.status !== "failed" && (
              <p className="text-xs text-fg-muted">
                Listed devices are not a check that they are present now: the operating system can
                remember the address of a device that has gone.
              </p>
            )}            {kept && (
              <p className="text-fg">
                {scan.status === "interrupted"
                  ? "TAPROX stopped while this scan was running. "
                  : ""}
                Partial results were kept.
                {probing &&
                  ` ${String(scan.targets_done)} of ${String(scan.targets_total)} addresses were probed.`}{" "}
                {plural(scan.devices_found, "device", "devices")}{" "}
                {probing ? "found" : "listed"}.
              </p>
            )}
            {scan.status === "failed" && (
              <p className="text-fg">{scan.error_message ?? "The scan could not complete."}</p>
            )}
            {probing && scan.status !== "failed" && (
              <p className="text-xs text-fg-muted">
                A device that did not answer is not necessarily offline: it may be asleep, busy or
                ignoring ARP requests.
              </p>
            )}
            {scan.devices_found > 0 && (
              <a
                href={`#/devices?scan=${scan.id}`}
                className="inline-block text-link underline underline-offset-2 hover:text-fg"
              >
                View the {plural(scan.devices_found, "device", "devices")}
              </a>
            )}
          </div>
        )}

        {scan.warnings.length > 0 && (
          <ul className="space-y-1 text-xs text-warning">
            {scan.warnings.map((warning) => (
              <li key={warning}>{warning}</li>
            ))}
          </ul>
        )}
      </div>
    </Panel>
  );
}

// --- the page ----------------------------------------------------------------------------------

export function DiscoveryPage({ pollMs = 1000 }: { pollMs?: number }) {
  const { client } = useReadyBackend();
  const { selectedId } = useSelectedInterface();

  const interfaces = useRequest((signal) => client.getInterfaces({ signal }), [client]);
  const current = useRequest((signal) => client.getCurrentScan(signal), [client]);

  const [startedScan, setStartedScan] = useState<Scan | null>(null);
  const trackedId = startedScan?.id ?? current.data?.scan?.id ?? null;
  const tracked = useRequest(
    (signal) => (trackedId ? client.getScan(trackedId, signal) : Promise.resolve(null)),
    [client, trackedId],
  );
  const loaded = tracked.data && tracked.data.id === trackedId ? tracked.data : null;
  const shown =
    loaded ?? (startedScan?.id === trackedId ? startedScan : (current.data?.scan ?? null));
  const running = shown?.status === "running";
  usePolling(() => {
    if (running && !tracked.isPending) tracked.reloadQuietly();
  }, pollMs);

  // The history reloads whenever the tracked scan changes state, so a finished scan appears.
  const [historyOffset, setHistoryOffset] = useState(0);
  const history = useRequest(
    (signal) => client.listScans({ limit: HISTORY_PAGE, offset: historyOffset }, signal),
    [client, historyOffset, `${trackedId ?? ""}:${shown?.status ?? ""}`],
  );

  // --- the form ---
  const usableInterfaces = (interfaces.data?.interfaces ?? []).filter(usable);
  const [chosenId, setChosenId] = useState<string | null>(null);
  const preselected = usableInterfaces.some((nic) => nic.id === selectedId) ? selectedId : "";
  const interfaceId = chosenId ?? preselected ?? "";
  const nic = usableInterfaces.find((candidate) => candidate.id === interfaceId);

  const [wantsActive, setWantsActive] = useState(false);
  const [authorized, setAuthorized] = useState(false);
  const [subnet, setSubnet] = useState("");
  const [resolveNames, setResolveNames] = useState(true);
  const [starting, setStarting] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const [startError, setStartError] = useState<ApiError | Error | null>(null);

  const activeAllowed = nic?.discovery.active === true;
  const active = wantsActive && activeAllowed;
  const needsSubnet = nic?.discovery.needs_subnet === true;
  const trimmed = subnet.trim();
  const target = trimmed || (needsSubnet ? "" : (nic?.discovery.network ?? ""));
  // Host addresses of the target network, minus this computer's own, which are never probed.
  const networkHosts = cidrHostCount(target);
  const ownInTarget = nic?.ipv4.filter((a) => ipInCidr(a.address, target)).length ?? 0;
  const hostCount = networkHosts === null ? null : Math.max(0, networkHosts - ownInTarget);

  let subnetError: string | undefined;
  if (active && trimmed) {
    if (cidrHostCount(trimmed) === null) {
      subnetError = "Enter the network in CIDR form, for example 192.168.1.0/24.";
    } else if ((cidrHostCount(trimmed) ?? 0) > MAX_ACTIVE_HOSTS) {
      subnetError = `Active discovery is limited to ${String(MAX_ACTIVE_HOSTS)} addresses (a /22).`;
    }
  }
  if (active && startError instanceof ApiError && SUBNET_CODES.has(startError.code)) {
    subnetError = startError.message;
  }

  const canStart =
    !running &&
    !starting &&
    nic !== undefined &&
    (!active ||
      (authorized && subnetError === undefined && hostCount !== null && hostCount > 0));

  const forget = () => {
    setStartError(null);
  };

  const start = async (event: FormEvent) => {
    event.preventDefault();
    if (!nic || !canStart) return;
    const body: ScanRequest = {
      interface_id: nic.id,
      mode: active ? "active" : "passive",
      confirm_authorized: active && authorized,
      resolve_names: resolveNames,
      ...(active && trimmed ? { network: trimmed } : {}),
    };
    setStarting(true);
    setStartError(null);
    try {
      setStartedScan(await client.startScan(body));
      setAuthorized(false); // consent covers one scan, not the next one
    } catch (cause) {
      setStartError(cause instanceof Error ? cause : new Error(String(cause)));
      if (cause instanceof ApiError && cause.code === "scan_in_progress") current.reload();
    } finally {
      setStarting(false);
    }
  };

  const cancel = async () => {
    if (!shown) return;
    setCancelling(true);
    try {
      await client.cancelScan(shown.id);
      tracked.reload();
    } catch (cause) {
      setStartError(cause instanceof Error ? cause : new Error(String(cause)));
    } finally {
      setCancelling(false);
    }
  };

  const bannerError =
    startError && !(active && startError instanceof ApiError && SUBNET_CODES.has(startError.code))
      ? startError
      : null;

  return (
    <div className="grid grid-cols-1 gap-4">
      <Panel
        title="Start a scan"
        description="Find the devices on a network this computer is connected to."
      >
        {interfaces.isLoading && <StateView variant="loading" title="Loading network interfaces" />}
        {!interfaces.data && interfaces.error && (
          <RequestError
            error={interfaces.error}
            what="network interfaces"
            onRetry={interfaces.reload}
          />
        )}
        {interfaces.data && usableInterfaces.length === 0 && (
          <p className="text-fg-muted">
            No interface can be used for discovery right now. Connect to a network, then check{" "}
            <a href="#/interfaces" className="text-link underline underline-offset-2 hover:text-fg">
              Network Interfaces
            </a>
            .
          </p>
        )}
        {interfaces.data && usableInterfaces.length > 0 && (
          <form onSubmit={(event) => void start(event)} className="grid max-w-xl gap-4" noValidate>
            <SelectField
              label="Interface"
              value={interfaceId}
              onChange={(event) => {
                setChosenId(event.target.value);
                setSubnet("");
                setAuthorized(false); // consent was for the network chosen before
                forget();
              }}
            >
              <option value="">Choose an interface</option>
              {usableInterfaces.map((candidate) => (
                <option key={candidate.id} value={candidate.id}>
                  {optionLabel(candidate)}
                </option>
              ))}
            </SelectField>

            {!nic && <p className="text-fg-muted">Choose an interface to scan.</p>}

            {nic && (
              <>
                <fieldset className="grid gap-3">
                  <legend className="mb-1 text-xs font-medium text-fg-muted">Method</legend>
                  <RadioField
                    name="mode"
                    value="passive"
                    label="Passive"
                    description="Reads the list of neighbors the operating system already knows and sends no probes. If host-name lookup is on, it still asks your DNS server about the addresses it lists."
                    checked={!active}
                    onChange={() => {
                      setWantsActive(false);
                      setAuthorized(false);
                      forget();
                    }}
                  />
                  <RadioField
                    name="mode"
                    value="active"
                    label="Active"
                    description={
                      activeAllowed
                        ? "Sends one ARP request to each address of the network and records the devices that answer. Where the interface has IPv6 it also sends one multicast ping on the local link; on Linux each request is triggered by a small UDP datagram instead."
                        : (nic.discovery.reason ?? "Not available on this interface.")
                    }
                    checked={active}
                    disabled={!activeAllowed}
                    onChange={() => {
                      setWantsActive(true);
                      setAuthorized(false);
                      forget();
                    }}
                  />
                </fieldset>

                {active && (
                  <>
                    <TextField
                      label="Subnet to scan"
                      value={subnet}
                      placeholder={needsSubnet ? "10.0.1.0/24" : (nic.discovery.network ?? "")}
                      autoComplete="off"
                      spellCheck={false}
                      hint={
                        needsSubnet
                          ? `This interface's network (${nic.discovery.network ?? ""}) is larger than the scan limit. Enter a narrower subnet inside it, for example 10.0.1.0/24.`
                          : `Leave empty to scan the whole network (${nic.discovery.network ?? ""}).`
                      }
                      error={subnetError}
                      onChange={(event) => {
                        setSubnet(event.target.value);
                        forget();
                      }}
                    />
                    {hostCount !== null && hostCount > 0 && !subnetError && (
                      <p className="text-fg">
                        This will probe {String(hostCount)} addresses in {target}.
                      </p>
                    )}
                    <CheckboxField
                      label="I am authorised to scan this network"
                      description="Confirm that you are authorised to send ARP requests (and, where used, an IPv6 multicast ping or a UDP datagram) to every address in it. Never scan a network you do not own or manage."
                      checked={authorized}
                      onChange={(event) => {
                        setAuthorized(event.target.checked);
                        forget();
                      }}
                    />
                  </>
                )}

                <CheckboxField
                  label="Look up host names"
                  description="Asks your DNS server (and the operating system's name services) for the name of each device found."
                  checked={resolveNames}
                  onChange={(event) => {
                    setResolveNames(event.target.checked);
                  }}
                />
              </>
            )}

            {bannerError &&
              (bannerError instanceof ApiError && bannerError.code.endsWith("permission_denied") ? (
                <RequestError error={bannerError} what="scan" onRetry={forget} />
              ) : (
                <StateView
                  variant="error"
                  title="Could not start the scan"
                  description={bannerError.message}
                />
              ))}

            <div className="flex flex-wrap items-center gap-3">
              <Button type="submit" variant="primary" loading={starting} disabled={!canStart}>
                Start scan
              </Button>
              {running && (
                <span className="text-xs text-fg-muted">
                  A scan is running. Cancel it or wait for it to finish before starting another.
                </span>
              )}
            </div>
          </form>
        )}
      </Panel>

      {shown && (
        <ScanPanel
          scan={shown}
          error={tracked.error}
          refreshedAt={tracked.dataUpdatedAt}
          onRetry={tracked.reload}
          onCancel={() => void cancel()}
          cancelling={cancelling}
        />
      )}

      <Panel title="Scan history" description="Earlier scans, newest first.">
        {history.isLoading && <StateView variant="loading" title="Loading scan history" />}
        {!history.data && history.error && (
          <RequestError error={history.error} what="scan history" onRetry={history.reload} />
        )}
        {history.data && history.data.total === 0 && (
          <p className="text-fg-muted">No scans have been run yet.</p>
        )}
        {history.data && history.data.scans.length > 0 && (
          <div className="grid gap-3">
            <Table label="Scan history, newest first">
              <thead>
                <tr>
                  <Th>Started</Th>
                  <Th>Interface</Th>
                  <Th>Method</Th>
                  <Th>Outcome</Th>
                  <Th>Devices</Th>
                  <Th>Duration</Th>
                </tr>
              </thead>
              <tbody>
                {history.data.scans.map((past) => (
                  <tr key={past.id}>
                    <RowTh>
                      <time dateTime={past.started_at} title={formatDateTime(past.started_at)}>
                        {formatRelative(past.started_at)}
                      </time>
                    </RowTh>
                    <Td>{past.interface_name}</Td>
                    <Td>{past.mode === "active" ? "Active" : "Passive"}</Td>
                    <Td>
                      <StatusBadge tone={OUTCOMES[past.status].tone}>
                        {OUTCOMES[past.status].label}
                      </StatusBadge>
                    </Td>
                    <Td>
                      {past.devices_found > 0 ? (
                        <a
                          href={`#/devices?scan=${past.id}`}
                          aria-label={`View devices from this scan (${String(past.devices_found)})`}
                          className="text-link underline underline-offset-2 hover:text-fg"
                        >
                          {past.devices_found}
                        </a>
                      ) : (
                        "0"
                      )}
                    </Td>
                    <Td>{past.finished_at ? `${String(Math.round(past.elapsed_seconds))} s` : "—"}</Td>
                  </tr>
                ))}
              </tbody>
            </Table>
            <Pagination
              total={history.data.total}
              limit={HISTORY_PAGE}
              offset={historyOffset}
              onChange={setHistoryOffset}
            />
          </div>
        )}
      </Panel>
    </div>
  );
}
