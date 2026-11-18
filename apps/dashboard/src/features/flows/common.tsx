import { useSyncExternalStore } from "react";
import { SelectField } from "@/components/ui/Fields";
import { StatusBadge, type Tone } from "@/components/ui/StatusBadge";
import type { EndpointRef, FlowSessionInfo, FlowState } from "@/lib/api/types";
import { useReadyBackend } from "@/lib/connection/BackendProvider";
import { formatDateTime } from "@/lib/format";
import { useRequest } from "@/lib/useRequest";

export const CONFIDENCE: Record<string, { label: string; tone: Tone }> = {
  confirmed: { label: "Confirmed", tone: "success" },
  probable: { label: "Probable", tone: "info" },
  unknown: { label: "Unknown", tone: "neutral" },
};

export const FLOW_STATES: Record<FlowState, { label: string; tone: Tone }> = {
  active: { label: "Active", tone: "info" },
  closed: { label: "Closed", tone: "neutral" },
  reset: { label: "Reset", tone: "warning" },
  idle_timeout: { label: "Idle", tone: "neutral" },
  capture_ended: { label: "Capture ended", tone: "neutral" },
};

export const IDENTIFICATION_METHODS: Record<string, string> = {
  decoded_protocol: "Decoded protocol",
  tls_sni: "TLS server name",
  http_host: "HTTP Host header",
  dns_answer: "Earlier DNS answer",
  none: "No identification",
};

export function ConfidenceBadge({ value }: { value: string }) {
  const entry = CONFIDENCE[value] ?? CONFIDENCE.unknown;
  return <StatusBadge tone={entry?.tone ?? "neutral"}>{entry?.label ?? value}</StatusBadge>;
}

export function FlowStateBadge({ state }: { state: FlowState }) {
  const entry = FLOW_STATES[state];
  return <StatusBadge tone={entry.tone}>{entry.label}</StatusBadge>;
}

/** Duration in the largest sensible unit; sub-second flows keep their milliseconds. */
export function formatFlowDuration(seconds: number): string {
  if (seconds < 1) return `${String(Math.round(seconds * 1000))} ms`;
  if (seconds < 60) return `${seconds.toFixed(1)} s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${String(minutes)} min ${String(Math.round(seconds % 60))} s`;
  return `${String(Math.floor(minutes / 60))} h ${String(minutes % 60)} min`;
}

export function formatTimeOfDay(iso: string): string {
  const date = new Date(iso);
  const pad = (n: number, w = 2) => String(n).padStart(w, "0");
  return `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}.${pad(date.getMilliseconds(), 3)}`;
}

/** The address, and underneath it what is known about who it is. Captured text renders as text. */
export function EndpointLabel({ endpoint, showPort = false }: { endpoint: EndpointRef; showPort?: boolean }) {
  const { device } = endpoint;
  const who = device ? (device.hostname ?? device.vendor ?? device.mac) : null;
  return (
    <div className="min-w-0">
      <span className="font-mono text-[13px]">
        {endpoint.address}
        {showPort && endpoint.port !== null ? `:${String(endpoint.port)}` : ""}
      </span>
      {endpoint.is_local_computer && <div className="text-xs text-accent">This computer</div>}
      {device && (
        <div className="text-xs">
          <a
            href={`#/devices/${String(device.id)}`}
            className="text-link underline underline-offset-2 hover:text-fg"
            title={
              device.match === "ip_only"
                ? "Matched by IP address only; the inventory may be out of date."
                : "The packets' Ethernet address matches this inventory device."
            }
          >
            {who}
          </a>
          {device.match === "ip_only" && <span className="text-fg-subtle"> (by IP only)</span>}
        </div>
      )}
      {!device && endpoint.hostname && (
        <div className="break-all text-xs text-fg-muted" title={`from ${endpoint.hostname_source ?? "the flow"}`}>
          {endpoint.hostname}
        </div>
      )}
      {endpoint.device_note && <div className="text-xs text-warning">{endpoint.device_note}</div>}
    </div>
  );
}

/** Chooses which capture session to look at; "Current" follows the Packet Explorer. */
export function SessionPicker({
  value,
  onChange,
}: {
  value: string;
  onChange: (session: string) => void;
}) {
  const { client } = useReadyBackend();
  const sessions = useRequest((signal) => client.getFlowSessions({ limit: 20 }, signal), [client]);
  const list = sessions.data?.sessions ?? [];
  return (
    <SelectField
      label="Capture session"
      value={value}
      onChange={(event) => {
        onChange(event.target.value);
      }}
    >
      <option value="current">Current capture or file</option>
      {list
        .filter((s) => !s.current)
        .map((s) => (
          <option key={s.id} value={String(s.id)}>
            {sessionLabel(s)}
          </option>
        ))}
    </SelectField>
  );
}

export function sessionLabel(s: FlowSessionInfo): string {
  const where = s.source === "file" ? `File ${s.file_name ?? ""}` : `${s.interface_name ?? "Capture"}`;
  return `${where} · ${formatDateTime(s.started_at)} · ${s.flows.toLocaleString()} flows`;
}

function subscribe(onChange: () => void): () => void {
  window.addEventListener("hashchange", onChange);
  return () => {
    window.removeEventListener("hashchange", onChange);
  };
}

/** The `?a=b` part of the URL hash, e.g. `#/flows?application=Spotify`. Never trusted. */
export function useHashQuery(): URLSearchParams {
  const hash = useSyncExternalStore(subscribe, () => window.location.hash);
  const cut = hash.indexOf("?");
  return new URLSearchParams(cut === -1 ? "" : hash.slice(cut + 1));
}

const IPV4_PATTERN = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const IPV6_PATTERN = /^[0-9a-fA-F:]{2,39}$/;

export function isValidIp(text: string): boolean {
  const trimmed = text.trim();
  if (!trimmed) return false;
  if (IPV4_PATTERN.test(trimmed)) {
    return trimmed.split(".").every((part) => {
      const n = Number(part);
      return n >= 0 && n <= 255;
    });
  }
  return trimmed.includes(":") && IPV6_PATTERN.test(trimmed);
}
