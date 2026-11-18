import { LoaderCircle } from "lucide-react";
import { useState, type FormEvent } from "react";
import { RequestError, StaleNotice } from "@/components/RequestError";
import { Button } from "@/components/ui/Button";
import { DetailPanel } from "@/components/ui/DetailPanel";
import { CheckboxField, SelectField, TextField } from "@/components/ui/Fields";
import { Pagination } from "@/components/ui/Pagination";
import { Panel } from "@/components/ui/Panel";
import { StateView } from "@/components/ui/StateView";
import { StatusBadge, type Tone } from "@/components/ui/StatusBadge";
import { SortTh, Table, Td, Th, type SortState } from "@/components/ui/Table";
import { ApiError } from "@/lib/api/client";
import type {
  CaptureState,
  CaptureStatus,
  PacketField,
  PacketLayer,
  PacketSort,
} from "@/lib/api/types";
import { useReadyBackend } from "@/lib/connection/BackendProvider";
import { AttachToCasePanel } from "@/features/investigations/AttachToCaseModal";
import { useDebouncedValue } from "@/lib/useDebouncedValue";
import { usePolling } from "@/lib/usePolling";
import { useRequest } from "@/lib/useRequest";
import { formatBytes, formatPacketTime, hexRows } from "./hexdump";

const PAGE_SIZE = 100;
const BUSY: readonly CaptureState[] = ["preparing", "capturing", "stopping"];

const STATES: Record<CaptureState, { label: string; tone: Tone }> = {
  idle: { label: "Idle", tone: "neutral" },
  preparing: { label: "Preparing", tone: "info" },
  capturing: { label: "Capturing", tone: "info" },
  stopping: { label: "Stopping", tone: "info" },
  completed: { label: "Completed", tone: "success" },
  failed: { label: "Failed", tone: "critical" },
};

const COLUMNS: { key: PacketSort; label: string }[] = [
  { key: "number", label: "No." },
  { key: "time", label: "Time" },
  { key: "source", label: "Source" },
  { key: "destination", label: "Destination" },
  { key: "protocol", label: "Protocol" },
  { key: "length", label: "Length" },
];

const asError = (cause: unknown): Error => (cause instanceof Error ? cause : new Error(String(cause)));

// --- decoded fields ----------------------------------------------------------------------------

function Fields({ fields }: { fields: PacketField[] }) {
  return (
    <ul className="space-y-0.5 pl-4">
      {fields.map((field, index) => (
        <li key={`${field.name}-${String(index)}`} className="break-words">
          <span className="text-fg-muted">{field.name}</span>
          {field.value && <span className="font-mono text-[13px] text-fg">: {field.value}</span>}
          {field.children.length > 0 && <Fields fields={field.children} />}
        </li>
      ))}
    </ul>
  );
}

function Layer({ layer }: { layer: PacketLayer }) {
  return (
    <details open={layer.name === "frame" ? false : undefined} className="rounded-md border border-line">
      <summary className="cursor-pointer px-3 py-1.5 text-sm font-medium text-fg">
        {layer.name}
      </summary>
      <div className="pb-2">
        <Fields fields={layer.fields} />
        {layer.truncated && (
          <p className="px-3 pt-1 text-xs text-warning">
            Some fields of this layer are not shown because it has too many.
          </p>
        )}
      </div>
    </details>
  );
}

function PacketDetails({ number, onClose }: { number: number; onClose: () => void }) {
  const { client } = useReadyBackend();
  const detail = useRequest((signal) => client.getPacket(number, signal), [client, number]);
  return (
    <DetailPanel title={`Packet ${String(number)}`} onClose={onClose}>
      {detail.isLoading && <StateView variant="loading" title="Loading packet" />}
      {!detail.data && detail.error && (
        <RequestError error={detail.error} what="the packet" onRetry={detail.reload} />
      )}
      {detail.data && (
        <div className="grid gap-4">
          <div className="grid gap-2">
            {detail.data.layers.map((layer, index) => (
              <Layer key={`${layer.name}-${String(index)}`} layer={layer} />
            ))}
          </div>
          <div>
            <h3 className="mb-1 text-xs font-medium text-fg-muted">
              Bytes ({detail.data.data_length} captured
              {detail.data.original_length !== detail.data.data_length
                ? ` of ${String(detail.data.original_length)} on the wire`
                : ""}
              )
            </h3>
            {detail.data.data_truncated && (
              <p className="mb-1 text-xs text-warning">Only the first bytes are shown.</p>
            )}
            <pre
              tabIndex={0}
              aria-label="Packet bytes in hexadecimal and ASCII"
              className="overflow-x-auto rounded-md border border-line bg-inset p-3 font-mono text-[13px] leading-5 text-fg"
            >
              {hexRows(detail.data.data_hex)
                .map((row) => `${row.offset}  ${row.hex.padEnd(47)}  ${row.ascii}`)
                .join("\n")}
            </pre>
          </div>
        </div>
      )}
    </DetailPanel>
  );
}

// --- the capture controls ----------------------------------------------------------------------

function StatusLine({ status }: { status: CaptureStatus }) {
  const state = STATES[status.state];
  const where =
    status.source === "file"
      ? `File ${status.file_name ?? ""}`
      : status.interface_name
        ? `Interface ${status.interface_name}${status.promiscuous ? " (promiscuous)" : ""}`
        : "";
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-3">
        <StatusBadge tone={state.tone}>{state.label}</StatusBadge>
        {where && <span className="text-fg-muted">{where}</span>}
        <span className="text-fg">
          {status.packets.toLocaleString()} packets · {formatBytes(status.captured_bytes)}
          {status.source === "live" ? ` · ${String(Math.round(status.elapsed_seconds))} s` : ""}
        </span>
      </div>
      {status.state === "failed" && (
        <p role="alert" className="text-critical">
          {status.error_message ?? "The capture failed."}
        </p>
      )}
      {status.list_dropped > 0 && (
        <p className="text-xs text-warning">
          The list holds {status.limits.max_listed_packets.toLocaleString()} packets.{" "}
          {status.list_dropped.toLocaleString()} more are in the capture and are included when you
          save it.
        </p>
      )}
      {status.dropped_by_capture !== null && status.dropped_by_capture > 0 && (
        <p className="text-xs text-warning">
          The operating system dropped {status.dropped_by_capture.toLocaleString()} packets before
          they could be captured.
        </p>
      )}
      {status.warnings.length > 0 && (
        <ul className="space-y-1 text-xs text-warning">
          {status.warnings.map((warning) => (
            <li key={warning}>{warning}</li>
          ))}
        </ul>
      )}
      {status.unsaved && status.state !== "capturing" && status.packets > 0 && (
        <p className="text-xs text-fg-muted">
          This capture is stored temporarily and is deleted when the next one starts or the app
          closes. Save it to keep it.
        </p>
      )}
      {status.saved_to && <p className="text-xs text-fg-muted">Saved to {status.saved_to}</p>}
    </div>
  );
}

// --- the page ----------------------------------------------------------------------------------

export function PacketsPage({ pollMs = 1000 }: { pollMs?: number }) {
  const { client } = useReadyBackend();

  const status = useRequest((signal) => client.getCaptureStatus(signal), [client]);
  const interfaces = useRequest((signal) => client.getCaptureInterfaces(signal), [client]);
  const state = status.data?.state ?? "idle";
  const busy = BUSY.includes(state);
  const live = status.data?.state === "capturing" || status.data?.state === "preparing";

  // --- the list: server-side sort, filter, search and paging ---
  const [offset, setOffset] = useState(0);
  const [sort, setSort] = useState<SortState>({ key: "number", order: "asc" });
  const [filterText, setFilterText] = useState("");
  const [appliedFilter, setAppliedFilter] = useState("");
  const [filterError, setFilterError] = useState<string | undefined>();
  const [checkingFilter, setCheckingFilter] = useState(false);
  const [searchText, setSearchText] = useState("");
  const search = useDebouncedValue(searchText.trim(), 300);
  const [selected, setSelected] = useState<number | null>(null);

  // A new capture or file starts a fresh list.
  const session = `${status.data?.source ?? ""}|${status.data?.started_at ?? ""}|${status.data?.file_name ?? ""}`;
  const [lastSession, setLastSession] = useState(session);
  if (session !== lastSession) {
    setLastSession(session);
    setOffset(0);
    setSelected(null);
  }

  const packets = useRequest(
    (signal) =>
      client.getPackets(
        {
          offset,
          limit: PAGE_SIZE,
          sort: sort.key as PacketSort,
          order: sort.order,
          display_filter: appliedFilter || undefined,
          search: search || undefined,
        },
        signal,
      ),
    [client, offset, sort.key, sort.order, appliedFilter, search, session, state],
  );

  usePolling(() => {
    if (!status.isPending) status.reloadQuietly();
    if (live && !packets.isPending) packets.reloadQuietly();
  }, busy ? pollMs : null);

  // --- start / stop ---
  const capturable = (interfaces.data?.interfaces ?? []).filter((nic) => nic.capturable);
  const [chosen, setChosen] = useState<string | null>(null);
  const interfaceId = chosen ?? capturable[0]?.interface_id ?? "";
  const [promiscuous, setPromiscuous] = useState(false);
  const [acting, setActing] = useState(false);
  const [actionError, setActionError] = useState<Error | null>(null);

  const act = async (work: () => Promise<unknown>) => {
    setActing(true);
    setActionError(null);
    try {
      await work();
    } catch (cause) {
      setActionError(asError(cause));
    } finally {
      setActing(false);
      status.reload();
      interfaces.reload();
    }
  };

  const [confirmReplace, setConfirmReplace] = useState(false);
  const hasUnsaved = status.data?.unsaved === true && status.data.packets > 0;
  const start = () => {
    if (hasUnsaved && !confirmReplace) {
      setConfirmReplace(true);
      return;
    }
    setConfirmReplace(false);
    void act(() => client.startCapture({ interface_id: interfaceId, promiscuous }));
  };

  // --- save / open ---
  const [savePath, setSavePath] = useState("");
  const [openPath, setOpenPath] = useState("");
  const [saved, setSaved] = useState<string | null>(null);
  const [savedPath, setSavedPath] = useState<string | null>(null);
  const [attachPcapOpen, setAttachPcapOpen] = useState(false);

  const applyFilter = async (event: FormEvent) => {
    event.preventDefault();
    const text = filterText.trim();
    setOffset(0);
    if (!text) {
      setAppliedFilter("");
      setFilterError(undefined);
      return;
    }
    setCheckingFilter(true);
    try {
      const check = await client.validateFilter(text);
      if (check.valid) {
        setAppliedFilter(text);
        setFilterError(undefined);
      } else {
        setFilterError(check.error ?? "That is not a valid display filter.");
      }
    } catch (cause) {
      setFilterError(asError(cause).message);
    } finally {
      setCheckingFilter(false);
    }
  };

  const onSort = (key: string) => {
    setOffset(0);
    setSort((previous) =>
      previous.key === key
        ? { key, order: previous.order === "asc" ? "desc" : "asc" }
        : { key, order: "asc" },
    );
  };

  // A filter on a large capture takes seconds: say so, and keep the previous list on screen meanwhile.
  const filtering = checkingFilter || packets.isRefreshing;
  const settled = packets.data?.display_filter === (appliedFilter || null);
  const filterHint = !appliedFilter
    ? "Wireshark syntax, e.g. dns, ip.addr == 192.168.1.1"
    : filtering
      ? `Applying: ${appliedFilter}. The list below is still the previous result.`
      : settled && packets.data
        ? `Showing packets that match: ${appliedFilter} (${packets.data.total.toLocaleString()} found)`
        : `The filter could not be applied. The list below is the previous result.`;

  const tools = interfaces.data;
  const hasData = (status.data?.packets ?? 0) > 0;
  const showToolsProblem = tools !== undefined && !tools.tools_ready;

  return (
    <div className="grid grid-cols-1 gap-4">
      <Panel
        title="Capture"
        description="Listen passively on one interface. TAPROX never sends traffic and does not decrypt anything."
      >
        {interfaces.isLoading && <StateView variant="loading" title="Loading interfaces" />}
        {!interfaces.data && interfaces.error && (
          <RequestError error={interfaces.error} what="capture interfaces" onRetry={interfaces.reload} />
        )}
        {showToolsProblem && (
          <StateView
            variant="error"
            title="Packet capture is not available"
            description={
              (tools.problem ?? "Wireshark's capture tools were not found.") +
              " Packet files can still be opened if tshark is installed. See Settings for the full check."
            }
          />
        )}
        {tools && tools.tools_ready && (
          <form
            className="grid max-w-xl gap-4"
            onSubmit={(event) => {
              event.preventDefault();
              start();
            }}
          >
            <SelectField
              label="Interface"
              value={interfaceId}
              disabled={busy}
              onChange={(event) => {
                setChosen(event.target.value);
              }}
            >
              {tools.interfaces.map((nic) => (
                <option key={nic.interface_id} value={nic.interface_id} disabled={!nic.capturable}>
                  {nic.name}
                  {nic.capturable ? "" : ` (${nic.reason ?? "not available"})`}
                </option>
              ))}
            </SelectField>
            <CheckboxField
              label="Promiscuous mode"
              description="Also listen to traffic addressed to other devices on the network. Off by default; switched networks usually deliver little of it, and some networks and policies treat it as sensitive."
              checked={promiscuous}
              disabled={busy}
              onChange={(event) => {
                setPromiscuous(event.target.checked);
              }}
            />
            <div className="flex flex-wrap items-center gap-3">
              {busy ? (
                <Button
                  variant="primary"
                  loading={acting || state === "stopping"}
                  onClick={() => void act(() => client.stopCapture())}
                >
                  {state === "stopping" ? "Stopping" : "Stop capture"}
                </Button>
              ) : (
                <Button
                  type="submit"
                  variant="primary"
                  loading={acting}
                  disabled={capturable.length === 0 || interfaceId === ""}
                >
                  {confirmReplace ? "Discard the unsaved capture and start" : "Start capture"}
                </Button>
              )}
              {confirmReplace && !busy && (
                <>
                  <span className="text-xs text-warning">
                    The current capture is not saved and will be deleted.
                  </span>
                  <Button
                    onClick={() => {
                      setConfirmReplace(false);
                    }}
                  >
                    Keep it
                  </Button>
                </>
              )}
            </div>
            {capturable.length === 0 && (
              <p className="text-fg-muted">No connected interface can be captured on right now.</p>
            )}
          </form>
        )}

        {actionError &&
          (actionError instanceof ApiError ? (
            <div className="mt-4">
              <RequestError
                error={actionError}
                what="capture"
                onRetry={() => {
                  setActionError(null);
                }}
              />
            </div>
          ) : (
            <p role="alert" className="mt-4 text-critical">
              {actionError.message}
            </p>
          ))}

        {status.data && status.data.state !== "idle" && (
          <div className="mt-4 border-t border-line pt-4">
            {status.error && (
              <StaleNotice
                error={status.error}
                what="capture status"
                asOf={status.dataUpdatedAt}
                onRetry={status.reload}
              />
            )}
            <StatusLine status={status.data} />
          </div>
        )}
      </Panel>

      <Panel
        title="Open or save"
        description="Capture files are standard PCAPNG and open in Wireshark."
        actions={
          savedPath || (status.data?.source === "file" && openPath.trim()) ? (
            <Button
              className="h-7 px-2.5 text-xs"
              onClick={() => {
                setAttachPcapOpen(true);
              }}
            >
              Attach PCAPNG to Investigation…
            </Button>
          ) : undefined
        }
      >
        {attachPcapOpen && (savedPath || openPath.trim()) && (
          <div className="mb-4">
            <AttachToCasePanel
              target={{
                kind: "pcapng_file",
                sourcePath: savedPath ?? openPath.trim(),
                label: `PCAPNG: ${savedPath ?? openPath.trim()}`,
              }}
              onClose={() => {
                setAttachPcapOpen(false);
              }}
            />
          </div>
        )}
        <div className="grid gap-4 md:grid-cols-2">
          <form
            className="grid gap-2"
            onSubmit={(event) => {
              event.preventDefault();
              setSaved(null);
              void act(async () => {
                const result = await client.saveCapture(savePath.trim());
                setSaved(`Saved ${String(result.packets)} packets to ${result.path}`);
                setSavedPath(result.path);
              });
            }}
          >
            <TextField
              label="Save as"
              value={savePath}
              placeholder="C:\Captures\my-capture.pcapng"
              autoComplete="off"
              spellCheck={false}
              hint="A full path ending in .pcapng. An existing file is never overwritten."
              onChange={(event) => {
                setSavePath(event.target.value);
              }}
            />
            <div className="flex items-center gap-3">
              <Button type="submit" disabled={!hasData || busy || savePath.trim() === ""} loading={acting}>
                Save capture
              </Button>
              {saved && <span className="text-xs text-success">{saved}</span>}
            </div>
          </form>
          <form
            className="grid gap-2"
            onSubmit={(event) => {
              event.preventDefault();
              void act(() => client.openCapture(openPath.trim()));
            }}
          >
            <TextField
              label="Open a capture file"
              value={openPath}
              placeholder="C:\Captures\my-capture.pcapng"
              autoComplete="off"
              spellCheck={false}
              hint="A full path to a .pcapng file. It replaces the capture shown here."
              onChange={(event) => {
                setOpenPath(event.target.value);
              }}
            />
            <div>
              <Button type="submit" disabled={busy || openPath.trim() === ""} loading={acting}>
                Open file
              </Button>
            </div>
          </form>
        </div>
      </Panel>

      <Panel
        title="Packets"
        description={
          status.data?.source === "file"
            ? "Packets from the opened file."
            : "Packets from the current capture."
        }
      >
        <div className="mb-4 grid gap-3 md:grid-cols-2">
          <form
            onSubmit={(event) => {
              void applyFilter(event);
            }}
            className="flex items-end gap-2"
          >
            <TextField
              className="flex-1"
              label="Display filter"
              value={filterText}
              placeholder="tcp.port == 443"
              autoComplete="off"
              spellCheck={false}
              error={filterError}
              hint={filterHint}
              onChange={(event) => {
                setFilterText(event.target.value);
              }}
            />
            <Button
              type="submit"
              loading={checkingFilter}
              disabled={(!hasData && filterText.trim() === "") || (packets.isRefreshing && filterText.trim() === appliedFilter)}
            >
              Apply
            </Button>
          </form>
          <TextField
            label="Search"
            value={searchText}
            placeholder="Text in any column"
            autoComplete="off"
            hint="Matches source, destination, protocol and info."
            onChange={(event) => {
              setOffset(0);
              setSearchText(event.target.value);
            }}
          />
        </div>

        {filtering && (
          <p role="status" className="mb-3 flex items-center gap-2 text-sm text-fg-muted">
            <LoaderCircle aria-hidden="true" className="size-4 animate-spin motion-reduce:animate-none" />
            {checkingFilter ? "Checking the filter…" : "Updating the packet list. A large capture can take a few seconds."}
          </p>
        )}
        {packets.isLoading && <StateView variant="loading" title="Loading packets" />}
        {!packets.data && packets.error && (
          <RequestError error={packets.error} what="packets" onRetry={packets.reload} />
        )}
        {packets.data && packets.error && (
          <StaleNotice
            error={packets.error}
            what="the packet list"
            asOf={packets.dataUpdatedAt}
            onRetry={packets.reload}
          />
        )}
        {packets.data && packets.data.total === 0 && (
          <StateView
            variant="empty"
            title={
              appliedFilter || search
                ? "No packets match"
                : live
                  ? "Waiting for packets"
                  : "No packets yet"
            }
            description={
              appliedFilter || search
                ? "Change or clear the filter and search to see more."
                : live
                  ? "Capturing. Packets appear here as they arrive."
                  : "Start a capture or open a capture file."
            }
          />
        )}
        {packets.data && packets.data.rows.length > 0 && (
          <div className="grid gap-3">
            {packets.data.list_capped && (
              <p className="text-xs text-warning">
                The list is full: only the first packets are shown. The capture itself keeps
                everything and saves it all.
              </p>
            )}
            <Table label="Packet list">
              <thead>
                <tr>
                  {COLUMNS.map((column) => (
                    <SortTh
                      key={column.key}
                      label={column.label}
                      sortKey={column.key}
                      sort={sort}
                      onSort={onSort}
                    />
                  ))}
                  <Th>Info</Th>
                </tr>
              </thead>
              <tbody>
                {packets.data.rows.map((row) => {
                  const time = formatPacketTime(row.time);
                  return (
                    <tr
                      key={row.number}
                      className={selected === row.number ? "bg-raised" : "hover:bg-raised/60"}
                    >
                      <Td mono>
                        <button
                          type="button"
                          aria-pressed={selected === row.number}
                          aria-label={`Packet ${String(row.number)}, show details`}
                          onClick={() => {
                            setSelected(row.number);
                          }}
                          className="cursor-pointer text-link underline underline-offset-2 hover:text-fg"
                        >
                          {row.number}
                        </button>
                      </Td>
                      <Td mono>
                        <time title={time.title}>{time.text}</time>
                      </Td>
                      <Td mono>{row.source}</Td>
                      <Td mono>{row.destination}</Td>
                      <Td>{row.protocol}</Td>
                      <Td mono>{row.length}</Td>
                      <Td className="max-w-md truncate" >
                        <span title={row.info}>{row.info}</span>
                      </Td>
                    </tr>
                  );
                })}
              </tbody>
            </Table>
            <Pagination
              total={packets.data.total}
              limit={PAGE_SIZE}
              offset={offset}
              onChange={setOffset}
              label="Packet pages"
            />
          </div>
        )}
      </Panel>

      {selected !== null && (
        <PacketDetails
          key={`${session}-${String(selected)}`}
          number={selected}
          onClose={() => {
            setSelected(null);
          }}
        />
      )}
    </div>
  );
}
