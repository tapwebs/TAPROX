const IPV4 = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const IPV6 = /^[0-9a-fA-F:]{2,39}$/;
const MAC = /^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$/;
const SERVICE = /^(tcp|udp):(\d{1,5})$/;

const isAddress = (text: string) => (IPV4.test(text) && text.split(".").every((p) => Number(p) <= 255)) || (text.includes(":") && IPV6.test(text));

interface AlertLike {
  category: string;
  entity_kind: string;
  entity_key: string;
  secondary_key: string;
}

/**
 * A Wireshark display filter that finds the packets an alert is about, or null.
 * It is built only from values that pass a strict pattern (an address, a hardware address, a port), never from
 * other captured text, so nothing in a hostile name can end up inside the filter.
 */
export function packetFilterFor(alert: AlertLike): string | null {
  const key = alert.entity_key;
  if (alert.entity_kind === "mac") return MAC.test(key) ? `eth.addr == ${key.toLowerCase()}` : null;
  if (alert.entity_kind !== "ip" || !isAddress(key)) return null;
  const parts = [`ip.addr == ${key}`];
  const second = alert.secondary_key;
  const service = SERVICE.exec(second);
  if (isAddress(second)) parts.push(`ip.addr == ${second}`);
  else if (service && Number(service[2]) <= 65535) parts.push(`${service[1] ?? "tcp"}.port == ${service[2] ?? ""}`);
  else if (alert.category === "dns") parts.push("dns");
  return parts.join(" && ");
}
