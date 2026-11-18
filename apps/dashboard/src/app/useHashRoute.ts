import { useMemo, useSyncExternalStore } from "react";
import type { RouteId } from "./routes";

const KNOWN: readonly RouteId[] = ["overview", "interfaces", "discovery", "devices", "activity", "packets", "flows", "applications", "threats", "alerts", "history", "topology", "rules", "risk", "web-inspector", "investigations", "reports", "settings"];

/** Pages that take one parameter after their name, e.g. `#/devices/12`. */
const TAKES_PARAM: readonly RouteId[] = ["devices", "alerts", "risk", "web-inspector", "investigations"];

export interface ParsedRoute {
  route: RouteId;
  /** Raw text after the page name, or null. Never trusted: the page validates it. */
  param: string | null;
  /** `?scan=<id>` on the inventory: show only devices seen by that scan. Also unvalidated. */
  scan: string | null;
}

/** `#/<page>[/<param>][?scan=<id>]`. Unknown or empty hashes show the Overview. */
export function parseHash(hash: string): ParsedRoute {
  const text = hash.replace(/^#\/?/, "");
  const cut = text.indexOf("?");
  const path = cut === -1 ? text : text.slice(0, cut);
  const query = cut === -1 ? "" : text.slice(cut + 1);
  const [name = "", param] = path.split("/");
  const route = KNOWN.find((known) => known === name);
  if (!route) return { route: "overview", param: null, scan: null };
  return {
    route,
    param: param && TAKES_PARAM.includes(route) ? param : null,
    scan: (route === "devices" && new URLSearchParams(query).get("scan")) || null,
  };
}

function subscribe(onChange: () => void): () => void {
  window.addEventListener("hashchange", onChange);
  return () => {
    window.removeEventListener("hashchange", onChange);
  };
}

/** The current page, read from the URL hash and kept in sync as it changes. */
export function useHashRoute(): ParsedRoute {
  const hash = useSyncExternalStore(subscribe, () => window.location.hash);
  const { route, param, scan } = parseHash(hash);
  // One object per distinct route, so consumers can safely list it as a dependency.
  return useMemo(() => ({ route, param, scan }), [route, param, scan]);
}
