import { StatusBadge } from "@/components/ui/StatusBadge";
import type { Device, NetworkInterface } from "@/lib/api/types";

export function ConnectionBadge({
  connection,
  present,
}: {
  connection: NetworkInterface["connection"];
  present: boolean;
}) {
  if (!present) return <StatusBadge tone="neutral">Removed</StatusBadge>;
  if (connection === "connected") return <StatusBadge tone="success">Connected</StatusBadge>;
  if (connection === "disconnected") return <StatusBadge tone="neutral">Disconnected</StatusBadge>;
  return <StatusBadge tone="warning">State unknown</StatusBadge>;
}

/** Recency, not liveness: a device we have not heard from lately may be asleep, not offline. */
export function DeviceStateBadge({ state }: { state: Device["inferred"]["state"] }) {
  if (state === "active") return <StatusBadge tone="success">Active</StatusBadge>;
  if (state === "inactive") return <StatusBadge tone="neutral">Not seen recently</StatusBadge>;
  return <StatusBadge tone="neutral">Previously observed</StatusBadge>;
}

export function ConfidenceBadge({ confidence }: { confidence: Device["observed"]["confidence"] }) {
  if (confidence === "confirmed") return <StatusBadge tone="success">Confirmed</StatusBadge>;
  if (confidence === "probable") return <StatusBadge tone="info">Probable</StatusBadge>;
  return <StatusBadge tone="warning">Stale</StatusBadge>;
}

/**
 * Why the evidence has the confidence it has. The reason depends on how the device was seen:
 * "confirmed" can mean it answered our probe, or that it is this computer's own interface, and
 * the two must not be confused. The text for probable and stale evidence must also hold for a
 * passive scan, which sends no probe at all.
 */
export function confidenceExplanation(
  confidence: Device["observed"]["confidence"],
  source: string,
): string {
  if (confidence === "confirmed") {
    if (source === "arp") return "The device replied to an ARP request this computer sent.";
    if (source === "local_interface") {
      return "This is one of this computer's own interfaces, read directly from the operating system.";
    }
    return "Confirmed, but how it was seen is not described here.";
  }
  if (confidence === "probable") {
    return "The operating system lists it as recently reachable. This computer did not check it itself.";
  }
  return "The operating system still remembers this address but has not confirmed it lately. That is not evidence that it is present now.";
}

const SOURCES: Record<string, string> = {
  arp: "ARP reply to our probe",
  ndp: "IPv6 neighbor table",
  os_neighbor_table: "Operating system ARP cache",
  local_interface: "This computer's own interface",
};

export function sourceLabel(source: string): string {
  return SOURCES[source] ?? source;
}
