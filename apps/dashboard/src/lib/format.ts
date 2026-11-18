/** "1h 02m 05s", "3m 05s", "7s" - compact uptime for dense panels. */
export function formatUptime(totalSeconds: number): string {
  const seconds = Number.isFinite(totalSeconds) && totalSeconds > 0 ? Math.floor(totalSeconds) : 0;
  const days = Math.floor(seconds / 86_400);
  const hours = Math.floor((seconds % 86_400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const rest = seconds % 60;
  const two = (n: number) => String(n).padStart(2, "0");

  if (days > 0) return `${String(days)}d ${String(hours)}h ${two(minutes)}m`;
  if (hours > 0) return `${String(hours)}h ${two(minutes)}m ${two(rest)}s`;
  if (minutes > 0) return `${String(minutes)}m ${two(rest)}s`;
  return `${String(rest)}s`;
}

const dateTime = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "medium" });

/** Local, human-readable timestamp for an ISO-8601 string or epoch milliseconds. */
export function formatDateTime(value: string | number | null | undefined): string {
  if (value === null || value === undefined || value === "") return "Unknown";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : dateTime.format(date);
}

/**
 * "just now", "5 min ago", "3 h ago", "2 d ago" for how recently something was observed.
 * A time in the future (clock skew) reads as "just now" rather than inventing a negative age.
 */
export function formatRelative(value: string | number | null | undefined, now = Date.now()): string {
  if (value === null || value === undefined || value === "") return "Unknown";
  const time = new Date(value).getTime();
  if (Number.isNaN(time)) return "Unknown";
  const seconds = Math.max(0, Math.floor((now - time) / 1000));
  if (seconds < 45) return "just now";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${String(Math.max(1, minutes))} min ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${String(hours)} h ago`;
  return `${String(Math.floor(hours / 24))} d ago`;
}

/** Hardware addresses are stored lowercase; show them the way tools like Wireshark do. */
export function formatMac(mac: string | null | undefined): string {
  return mac ? mac.toUpperCase() : "—";
}

/** Link speed as the operating system reports it (Mbps), in the unit people expect. */
export function formatSpeed(mbps: number | null | undefined): string {
  if (!mbps || mbps <= 0) return "Not reported";
  if (mbps < 1000) return `${String(mbps)} Mbps`;
  const gbps = mbps / 1000;
  return `${Number.isInteger(gbps) ? String(gbps) : gbps.toFixed(1)} Gbps`;
}

/**
 * Number of host addresses in an IPv4 network written as CIDR, or null when the text is not one.
 * Only used to tell the user how much a scan will do; the backend validates the real request.
 */
export function cidrHostCount(cidr: string): number | null {
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/.exec(cidr);
  if (!match) return null;
  const octets = match.slice(1, 5).map(Number);
  const prefix = Number(match[5]);
  if (octets.some((octet) => octet > 255) || prefix > 32) return null;
  return Math.max(0, 2 ** (32 - prefix) - 2);
}

function ipv4ToNumber(text: string): number | null {
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(text);
  if (!match) return null;
  const octets = match.slice(1, 5).map(Number);
  if (octets.some((octet) => octet > 255)) return null;
  return ((octets[0] ?? 0) * 2 ** 24) + ((octets[1] ?? 0) * 2 ** 16) + ((octets[2] ?? 0) * 2 ** 8) + (octets[3] ?? 0);
}

/** Whether an IPv4 address lies inside a CIDR network. False for anything that is not IPv4/CIDR. */
export function ipInCidr(ip: string, cidr: string): boolean {
  const [base, prefixText] = cidr.split("/");
  const prefix = Number(prefixText);
  const address = ipv4ToNumber(ip);
  const network = ipv4ToNumber(base ?? "");
  if (address === null || network === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
    return false;
  }
  const size = 2 ** (32 - prefix);
  return Math.floor(address / size) === Math.floor(network / size);
}
