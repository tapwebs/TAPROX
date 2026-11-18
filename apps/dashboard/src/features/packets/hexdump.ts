export interface HexRow {
  offset: string;
  hex: string;
  ascii: string;
}

/** Classic 16-bytes-per-row dump from the backend's hexadecimal text. Unprintable bytes show as ".". */
export function hexRows(hex: string): HexRow[] {
  const rows: HexRow[] = [];
  for (let start = 0; start < hex.length; start += 32) {
    const chunk = hex.slice(start, start + 32);
    const bytes = chunk.match(/../g) ?? [];
    const values = bytes.map((pair) => Number.parseInt(pair, 16));
    rows.push({
      offset: (start / 2).toString(16).padStart(4, "0"),
      hex: bytes.join(" "),
      ascii: values.map((v) => (v >= 0x20 && v < 0x7f ? String.fromCharCode(v) : ".")).join(""),
    });
  }
  return rows;
}

/** Capture time (seconds since the epoch) as local HH:MM:SS.mmm; the date is in the tooltip. */
export function formatPacketTime(seconds: number): { text: string; title: string } {
  const date = new Date(seconds * 1000);
  const pad = (n: number, width = 2) => String(n).padStart(width, "0");
  return {
    text: `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}.${pad(date.getMilliseconds(), 3)}`,
    title: date.toLocaleString(),
  };
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${String(bytes)} B`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KiB`;
  if (bytes < 1024 ** 3) return `${(bytes / 1024 ** 2).toFixed(1)} MiB`;
  return `${(bytes / 1024 ** 3).toFixed(2)} GiB`;
}
