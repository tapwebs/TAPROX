const SAFE_HOST_RE = /^[A-Za-z0-9.-]{1,253}$/;

export interface PrefillParams {
  scheme?: "http" | "https";
  sessionId?: number;
  deviceId?: number | null;
  alertId?: number;
}

/** Build a read-only hash URL that prefills the Web Inspector form without ever auto-starting it. */
export function buildWebInspectorHref(
  rawHost: string | null | undefined,
  params: PrefillParams = {},
): string | null {
  if (!rawHost) return null;
  const host = rawHost.trim().toLowerCase();
  if (!host || host.startsWith(".") || host.endsWith(".") || host.includes("..") || !SAFE_HOST_RE.test(host)) {
    return null;
  }
  const scheme = params.scheme ?? "https";
  const query = new URLSearchParams({ url: `${scheme}://${host}/` });
  if (params.sessionId !== undefined) query.set("session_id", String(params.sessionId));
  if (params.alertId !== undefined) query.set("alert_id", String(params.alertId));
  if (params.deviceId !== undefined && params.deviceId !== null) {
    query.set("device_id", String(params.deviceId));
  }
  return `#/web-inspector?${query.toString()}`;
}

