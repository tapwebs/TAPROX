import { useEffect, useMemo, useRef, useState, type KeyboardEvent, type MouseEvent as ReactMouseEvent } from "react";
import { RequestError, StaleNotice } from "@/components/RequestError";
import { Button } from "@/components/ui/Button";
import { DefinitionList } from "@/components/ui/DefinitionList";
import { CheckboxField, SelectField, TextField } from "@/components/ui/Fields";
import { Pagination } from "@/components/ui/Pagination";
import { Panel } from "@/components/ui/Panel";
import { StateView } from "@/components/ui/StateView";
import { Table, Td, Th } from "@/components/ui/Table";
import type { TopologyEdge, TopologyGraph, TopologyNode } from "@/lib/api/types";
import { useReadyBackend } from "@/lib/connection/BackendProvider";
import { useDebouncedValue } from "@/lib/useDebouncedValue";
import { usePolling } from "@/lib/usePolling";
import { useRequest } from "@/lib/useRequest";
import { formatBytes } from "@/features/packets/hexdump";
import { SessionPicker } from "@/features/flows/common";
import { BasisBadge, SeverityBadge } from "@/features/security/common";
import { layoutNodes, type LayoutMode, type Placed } from "./layout";
import { HOME, box as viewBox, panBy, zoomAt } from "./view";

type Basis = "observed" | "inferred" | "inventory";
const WINDOWS = [
  { value: "session", label: "Session" },
  { value: "24h", label: "24 hours" },
  { value: "7d", label: "7 days" },
  { value: "30d", label: "30 days" },
  { value: "all", label: "All history" },
] as const;
const TYPE_LABEL: Record<TopologyNode["type"], string> = {
  this_computer: "This computer",
  device: "Device",
  gateway: "Gateway",
  unresolved_host: "Unresolved host",
  remote_host: "Remote host",
  remote_group: "Remote group",
  group: "Group",
};
const KIND_LABEL: Record<TopologyEdge["kind"], string> = {
  communication: "Communication",
  via_gateway: "Via gateway",
  name_service: "Name lookups",
  on_link: "On-link presence",
};
const PAGE = 50;
const GROUPINGS = [
  { value: "auto", label: "Automatic (above 150 devices)" },
  { value: "none", label: "Not grouped" },
  { value: "role", label: "Role" },
  { value: "vendor", label: "Vendor" },
  { value: "segment", label: "Segment" },
] as const;

function NodeShape({
  p,
  selected,
  focused,
  isHovered,
  isNeighbor,
}: {
  p: Placed;
  selected: boolean;
  focused: boolean;
  isHovered: boolean;
  isNeighbor: boolean;
}) {
  const n = p.node;
  const isAlert = n.alerts > 0;
  const stroke = isAlert
    ? "stroke-critical"
    : selected || isHovered
    ? "stroke-accent"
    : isNeighbor
    ? "stroke-[#8A8A94]"
    : "stroke-[#383842]";
  const strokeWidth = isAlert ? 3 : selected || isHovered || focused ? 2.5 : 1.5;
  const common = { className: `fill-[#141418]/95 ${stroke} transition-all duration-150`, strokeWidth };

  switch (n.type) {
    case "gateway":
      return (
        <g>
          {/* Subtle outer diamond glow for gateway */}
          <polygon
            points={`${p.x},${p.y - 20} ${p.x + 20},${p.y} ${p.x},${p.y + 20} ${p.x - 20},${p.y}`}
            className={isAlert ? "stroke-critical/30 fill-critical/10" : "stroke-accent/30 fill-accent/5"}
            strokeWidth={1}
          />
          <polygon
            points={`${p.x},${p.y - 15} ${p.x + 15},${p.y} ${p.x},${p.y + 15} ${p.x - 15},${p.y}`}
            {...common}
          />
          <polygon
            points={`${p.x},${p.y - 5} ${p.x + 5},${p.y} ${p.x},${p.y + 5} ${p.x - 5},${p.y}`}
            className={isAlert ? "fill-critical" : "fill-accent"}
          />
        </g>
      );
    case "this_computer":
      return (
        <g>
          {/* Radar beacon rings */}
          <circle cx={p.x} cy={p.y} r={28} className="fill-accent/5 stroke-accent/20" strokeWidth={1} />
          <circle cx={p.x} cy={p.y} r={22} className="fill-accent/10 stroke-accent/40" strokeWidth={1} strokeDasharray="3 3" />
          <circle cx={p.x} cy={p.y} r={16} {...common} />
          <circle cx={p.x} cy={p.y} r={5} className="fill-accent" />
        </g>
      );
    case "unresolved_host":
      return (
        <g>
          <circle cx={p.x} cy={p.y} r={12} {...common} strokeDasharray="4 3" />
          <circle cx={p.x} cy={p.y} r={3} className="fill-fg-muted/60" />
        </g>
      );
    case "remote_host":
      return (
        <g>
          <circle cx={p.x} cy={p.y} r={9} {...common} />
          <circle cx={p.x} cy={p.y} r={2.5} className={isAlert ? "fill-critical" : "fill-fg-subtle"} />
        </g>
      );
    case "remote_group":
      return (
        <g>
          <rect x={p.x - 16} y={p.y - 12} width={32} height={24} rx={6} {...common} />
          <text x={p.x} y={p.y + 4} textAnchor="middle" className="fill-current font-mono text-[10px] font-semibold text-fg">
            {n.members > 99 ? "99+" : n.members}
          </text>
        </g>
      );
    case "group":
      return (
        <g>
          <rect x={p.x - 20} y={p.y - 14} width={40} height={28} rx={6} {...common} strokeDasharray="1 0" />
          <text x={p.x} y={p.y + 4} textAnchor="middle" className="fill-current font-mono text-[11px] font-semibold text-fg">
            {n.members}
          </text>
        </g>
      );
    default:
      return (
        <g>
          <circle cx={p.x} cy={p.y} r={12} {...common} strokeDasharray={n.flows === 0 && n.basis === "inventory" ? "3 2" : undefined} />
          <circle cx={p.x} cy={p.y} r={4} className={isAlert ? "fill-critical" : n.flows === 0 && n.basis === "inventory" ? "fill-accent/40" : "fill-accent/80"} />
        </g>
      );
  }
}

/** Compute quadratic Bézier curve path for aesthetic, non-overlapping routed connections */
function computeEdgePath(a: { x: number; y: number }, b: { x: number; y: number }, id: string): string {
  const dx = b.x - a.x;
  const dy = b.y - a.y;
  const dist = Math.hypot(dx, dy);
  if (dist < 2) return `M ${a.x} ${a.y} L ${b.x} ${b.y}`;

  // Perpendicular unit vector
  const nx = -dy / dist;
  const ny = dx / dist;

  // Midpoint
  const mx = (a.x + b.x) / 2;
  const my = (a.y + b.y) / 2;

  // Vector from center (450, 350) to midpoint
  const vcx = mx - 450;
  const vcy = my - 350;
  const dot = nx * vcx + ny * vcy;
  const sign = dot >= 0 ? 1 : -1;

  // Deterministic arch: subtle outward curve with slight edge hash jitter to prevent overlapping paths
  let hash = 0;
  for (let i = 0; i < id.length; i++) hash = (hash * 31 + id.charCodeAt(i)) | 0;
  const jitter = ((Math.abs(hash) % 7) - 3) * 2;

  const arch = Math.min(34, Math.max(10, dist * 0.11)) * sign + jitter;
  const cx = Math.round((mx + nx * arch) * 10) / 10;
  const cy = Math.round((my + ny * arch) * 10) / 10;

  return `M ${a.x} ${a.y} Q ${cx} ${cy} ${b.x} ${b.y}`;
}

function Graph({
  graph,
  nodes,
  edges,
  selection,
  onSelect,
}: {
  graph: TopologyGraph;
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  selection: { kind: "node" | "edge"; id: string } | null;
  onSelect: (s: { kind: "node" | "edge"; id: string } | null) => void;
}) {
  const [view, setView] = useState(HOME);
  const [layoutMode, setLayoutMode] = useState<LayoutMode>("clustered");
  const [hoveredKey, setHoveredKey] = useState<string | null>(null);
  const [focusIndex, setFocusIndex] = useState(0);
  const svgRef = useRef<SVGSVGElement>(null);
  const viewRef = useRef(view);
  const dragged = useRef(false);
  const stopDrag = useRef<(() => void) | null>(null);
  useEffect(() => {
    viewRef.current = view; // the wheel and drag handlers read the latest view without being re-created
  });

  const placed = useMemo(() => layoutNodes(nodes, layoutMode), [nodes, layoutMode]);
  const at = useMemo(() => new Map(placed.map((p) => [p.node.key, p])), [placed]);
  const shown = viewBox(view);
  const box = `${String(shown.x)} ${String(shown.y)} ${String(shown.w)} ${String(shown.h)}`;

  // Set of neighbor keys connected to the currently hovered node
  const neighborKeys = useMemo(() => {
    if (!hoveredKey) return new Set<string>();
    const neighbors = new Set<string>();
    for (const e of edges) {
      if (e.a === hoveredKey) neighbors.add(e.b);
      else if (e.b === hoveredKey) neighbors.add(e.a);
    }
    return neighbors;
  }, [hoveredKey, edges]);

  /** Pixels per canvas unit and the blank margin the browser leaves around a view that does not fill the element. */
  const screenScale = () => {
    const r = svgRef.current?.getBoundingClientRect();
    const b = viewBox(viewRef.current);
    if (!r?.width || !r.height) return { r, scale: 1, ox: 0, oy: 0 };
    const scale = Math.min(r.width / b.w, r.height / b.h);
    return { r, scale, ox: (r.width - b.w * scale) / 2, oy: (r.height - b.h * scale) / 2 };
  };

  // The wheel needs a listener that may cancel the page scroll, which React's own onWheel cannot do.
  useEffect(() => {
    const el = svgRef.current;
    if (!el) return;
    const onWheel = (event: WheelEvent) => {
      if (event.shiftKey) return; // Shift + wheel scrolls the page as usual
      event.preventDefault();
      const { r, scale, ox, oy } = screenScale();
      const b = viewBox(viewRef.current);
      const px = b.x + (event.clientX - (r?.left ?? 0) - ox) / scale;
      const py = b.y + (event.clientY - (r?.top ?? 0) - oy) / scale;
      setView((v) => zoomAt(v, event.deltaY < 0 ? 1.15 : 1 / 1.15, px, py));
    };
    el.addEventListener("wheel", onWheel, { passive: false });
    return () => { el.removeEventListener("wheel", onWheel); };
  }, []);
  useEffect(() => () => { stopDrag.current?.(); }, []);

  const startDrag = (event: ReactMouseEvent) => {
    if (event.button !== 0) return;
    dragged.current = false;
    const { scale } = screenScale();
    const origin = { x: event.clientX, y: event.clientY };
    let last = origin;
    const move = (e: MouseEvent) => {
      if (!dragged.current && Math.hypot(e.clientX - origin.x, e.clientY - origin.y) < 4) return; // a click, not a drag
      dragged.current = true;
      const dx = (e.clientX - last.x) / scale;
      const dy = (e.clientY - last.y) / scale;
      last = { x: e.clientX, y: e.clientY };
      setView((v) => panBy(v, dx, dy));
    };
    const end = () => {
      window.removeEventListener("mousemove", move);
      window.removeEventListener("mouseup", end);
      stopDrag.current = null;
    };
    window.addEventListener("mousemove", move);
    window.addEventListener("mouseup", end);
    stopDrag.current = end;
  };
  const withAlerts = nodes.filter((n) => n.alerts > 0).length;
  const summary = `Network graph: ${String(nodes.length)} nodes, ${String(edges.length)} relationships, ${String(withAlerts)} with alerts.`;

  const onKey = (event: KeyboardEvent, index: number, key: string) => {
    const move = (to: number) => {
      event.preventDefault();
      const next = (to + placed.length) % Math.max(1, placed.length);
      setFocusIndex(next);
      document.getElementById(`topology-node-${String(next)}`)?.focus();
    };
    if (event.key === "ArrowRight" || event.key === "ArrowDown") move(index + 1);
    else if (event.key === "ArrowLeft" || event.key === "ArrowUp") move(index - 1);
    else if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      onSelect({ kind: "node", id: key });
    } else if (event.key === "Escape") onSelect(null);
  };

  return (
    <div>
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2">
          {/* Layout mode switcher */}
          <div className="flex items-center gap-1 rounded-md border border-line/60 bg-inset/40 p-0.5" role="group" aria-label="Layout mode">
            {(["clustered", "hierarchical", "concentric"] as const).map((mode) => (
              <Button
                key={mode}
                className="h-7 px-2.5 text-xs"
                variant={layoutMode === mode ? "primary" : "ghost"}
                aria-pressed={layoutMode === mode}
                onClick={() => setLayoutMode(mode)}
              >
                {mode[0]?.toUpperCase() + mode.slice(1)}
              </Button>
            ))}
          </div>

          <div className="h-4 w-px bg-line/60" />

          <Button aria-label="Zoom in" onClick={() => { setView((v) => zoomAt(v, (v.zoom + 0.25) / v.zoom, v.cx, v.cy)); }}>+</Button>
          <Button aria-label="Zoom out" onClick={() => { setView((v) => zoomAt(v, (v.zoom - 0.25) / v.zoom, v.cx, v.cy)); }}>−</Button>
          <Button onClick={() => { setView(HOME); }}>Fit</Button>
        </div>
        <span className="text-xs text-fg-subtle">Drag to move, scroll to zoom (Shift + scroll scrolls the page). Arrow keys move between nodes; Enter selects; Escape clears.</span>
      </div>
      <svg
        ref={svgRef}
        role="group"
        aria-label={summary}
        viewBox={box}
        onMouseDown={startDrag}
        onClickCapture={(e) => {
          if (dragged.current) {
            e.stopPropagation(); // the mouse button was released after a drag: that is not a selection
            dragged.current = false;
          }
        }}
        className="h-[38rem] w-full cursor-grab select-none rounded-lg border border-line bg-[#0A0A0C] shadow-[inset_0_2px_12px_rgba(0,0,0,0.7)] active:cursor-grabbing"
      >
        <defs>
          <radialGradient id="topology-glow" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#E5203A" stopOpacity="0.06" />
            <stop offset="50%" stopColor="#E5203A" stopOpacity="0.015" />
            <stop offset="100%" stopColor="#0A0A0C" stopOpacity="0" />
          </radialGradient>
        </defs>
        <rect x="-10000" y="-10000" width="20000" height="20000" fill="url(#topology-glow)" pointerEvents="none" />

        {/* Ambient radar guide rings & crosshairs */}
        <g pointerEvents="none" className="opacity-30">
          <circle cx="450" cy="350" r="130" fill="none" stroke="#26262C" strokeDasharray="3 6" strokeWidth="0.8" />
          <circle cx="450" cy="350" r="240" fill="none" stroke="#26262C" strokeDasharray="4 8" strokeWidth="0.8" />
          <circle cx="450" cy="350" r="360" fill="none" stroke="#26262C" strokeDasharray="4 10" strokeWidth="0.8" />
          <line x1="450" y1="330" x2="450" y2="370" stroke="#26262C" strokeWidth="0.8" />
          <line x1="430" y1="350" x2="470" y2="350" stroke="#26262C" strokeWidth="0.8" />
        </g>

        {/* Edges rendered as smooth routed Bézier curves */}
        {edges.map((e) => {
          const a = at.get(e.a);
          const b = at.get(e.b);
          if (!a || !b) return null;
          const selected = selection?.kind === "edge" && selection.id === e.id;
          const isIncident = hoveredKey === e.a || hoveredKey === e.b;
          const isDimmed = hoveredKey !== null && !isIncident && !selected;

          const dash = e.basis === "inferred" ? "6 4" : e.kind === "name_service" ? "2 3" : e.kind === "on_link" ? "4 4" : undefined;
          const pathD = computeEdgePath(a, b, e.id);
          const strokeWidth = selected ? 3.5 : isIncident ? 3 : e.bytes > 1_000_000 ? 3 : e.bytes > 10_000 ? 2 : 1.2;

          const strokeClass = e.alerts > 0
            ? "stroke-critical"
            : selected || isIncident
            ? "stroke-accent"
            : e.kind === "via_gateway"
            ? "stroke-[#8BA9B8]/75"
            : e.kind === "on_link"
            ? "stroke-[#8A8A94]/70"
            : "stroke-[#383842]/70";

          return (
            <g key={e.id} className={`transition-opacity duration-150 ${isDimmed ? "opacity-20" : "opacity-100"}`}>
              {/* Frictionless click target overlay */}
              <path
                d={pathD}
                fill="none"
                stroke="transparent"
                strokeWidth={Math.max(14, strokeWidth + 8)}
                className="cursor-pointer"
                onClick={() => { onSelect({ kind: "edge", id: e.id }); }}
              />
              {/* Visible edge line */}
              <path
                d={pathD}
                fill="none"
                strokeDasharray={dash}
                strokeWidth={strokeWidth}
                className={`${strokeClass} pointer-events-none transition-all duration-150`}
              />
            </g>
          );
        })}

        {/* Nodes with interactive hover highlighting and pill labels */}
        {placed.map((p, i) => {
          const selected = selection?.kind === "node" && selection.id === p.node.key;
          const isHovered = hoveredKey === p.node.key;
          const isNeighbor = neighborKeys.has(p.node.key);
          const isDimmed = hoveredKey !== null && !isHovered && !isNeighbor && !selected;
          const labelText = p.node.label.length > 22 ? `${p.node.label.slice(0, 21)}…` : p.node.label;
          const pillWidth = Math.max(28, labelText.length * 6.6 + 12);

          return (
            <g
              key={p.node.key}
              id={`topology-node-${String(i)}`}
              role="button"
              tabIndex={i === focusIndex ? 0 : -1}
              aria-pressed={selected}
              aria-label={`${TYPE_LABEL[p.node.type]} ${p.node.label}${p.node.alerts ? `, ${String(p.node.alerts)} open alerts` : ""}`}
              onClick={() => { onSelect({ kind: "node", id: p.node.key }); }}
              onKeyDown={(e) => { onKey(e, i, p.node.key); }}
              onFocus={() => { setFocusIndex(i); }}
              onMouseEnter={() => { setHoveredKey(p.node.key); }}
              onMouseLeave={() => { setHoveredKey(null); }}
              className={`cursor-pointer outline-none transition-opacity duration-150 [&:focus-visible_*]:stroke-accent ${
                isDimmed ? "opacity-35" : "opacity-100"
              }`}
            >
              <NodeShape
                p={p}
                selected={selected}
                focused={i === focusIndex}
                isHovered={isHovered}
                isNeighbor={isNeighbor}
              />

              {/* Protective backdrop pill for label legibility */}
              <rect
                x={p.x - pillWidth / 2}
                y={p.y + 19}
                width={pillWidth}
                height={17}
                rx={4}
                className="fill-[#141418]/95 stroke-[#26262C]"
                strokeWidth={0.8}
                pointerEvents="none"
              />

              <text
                x={p.x}
                y={p.y + 31}
                textAnchor="middle"
                className="fill-current font-medium text-[11px] text-fg"
                pointerEvents="none"
              >
                {labelText}
              </text>

              {p.node.alerts > 0 && (() => {
                const sev = p.node.alert_severity ?? "medium";
                const isCritOrHigh = sev === "critical" || sev === "high";
                const isMed = sev === "medium";
                const circleFill = isCritOrHigh ? "fill-critical" : isMed ? "fill-amber-500" : "fill-sky-500";
                const textFill = isCritOrHigh ? "fill-critical" : isMed ? "fill-amber-400" : "fill-sky-400";
                const icon = isCritOrHigh || isMed ? "!" : "i";
                return (
                  <g pointerEvents="none">
                    <circle cx={p.x + 14} cy={p.y - 12} r={9} className={`${circleFill} stroke-[#161311]`} strokeWidth={2} />
                    <text x={p.x + 14} y={p.y - 9} textAnchor="middle" className="fill-white font-mono text-[9px] font-bold">
                      {icon}
                    </text>
                    <text x={p.x + 27} y={p.y - 9} className={`${textFill} font-mono text-[10px] font-bold`}>
                      {p.node.alerts}
                    </text>
                  </g>
                );
              })()}
            </g>
          );
        })}
      </svg>
      <p className="mt-1 text-xs text-fg-subtle">
        Line styles: solid = observed, dashed = inferred, dotted = name lookups. Shapes: square = gateway, dashed circle = unresolved on-link host,
        rounded square = group of remote hosts, ringed circle = this computer. {graph.reduced ?? ""}
      </p>
    </div>
  );
}

function Details({
  graph,
  selection,
  onClose,
}: {
  graph: TopologyGraph;
  selection: { kind: "node" | "edge"; id: string };
  onClose: () => void;
}) {
  const nodes = new Map(graph.nodes.map((n) => [n.key, n]));
  if (selection.kind === "node") {
    const n = nodes.get(selection.id);
    if (!n) return null;
    const mine = graph.edges.filter((e) => e.a === n.key || e.b === n.key).sort((a, b) => b.bytes - a.bytes).slice(0, 10);
    return (
      <Panel title={`${TYPE_LABEL[n.type]}: ${n.label}`} actions={<Button onClick={onClose}>Close</Button>}>
        <DefinitionList
          items={[
            { label: "Basis", value: <BasisBadge basis={n.basis} /> },
            ...(n.visibility_status
              ? [
                  {
                    label: "Capture visibility",
                    value: (
                      <div className="space-y-1">
                        <span className="inline-flex items-center gap-1.5 text-xs font-medium">
                          <span
                            className={`inline-block size-2 rounded-full ${
                              n.visibility_status === "traffic_observed" || n.visibility_status === "application_identified"
                                ? "bg-emerald-500"
                                : n.visibility_status === "partial_visibility"
                                ? "bg-amber-400"
                                : "bg-zinc-400"
                            }`}
                          />
                          <span className="capitalize">{n.visibility_status.replace(/_/g, " ")}</span>
                        </span>
                        {n.visibility_note && (
                          <p className="text-xs text-fg-subtle leading-relaxed">{n.visibility_note}</p>
                        )}
                      </div>
                    ),
                  },
                ]
              : n.flows === 0 && n.basis === "inventory"
              ? [{ label: "Status", value: "Discovered in inventory (No unicast traffic observed at this capture point)" }]
              : []),
            { label: "Addresses", value: n.ips.join(", ") || "none", mono: true },
            ...(n.mac ? [{ label: "Hardware address", value: n.mac, mono: true }] : []),
            ...(n.vendor ? [{ label: "Vendor", value: n.vendor }] : []),
            ...(n.members > 1 ? [{ label: n.type === "group" ? "Devices" : "Hosts", value: String(n.members) }] : []),
            { label: "Traffic", value: n.flows === 0 && n.basis === "inventory" ? "0 flows, 0 B (No unicast traffic observed)" : `${String(n.flows)} flows, ${formatBytes(n.bytes)}` },
            { label: "Applications", value: n.applications.join(", ") || (n.flows === 0 && n.basis === "inventory" ? "none (no traffic observed)" : "none identified") },
            { label: "Protocols", value: n.protocols.join(", ") || "none" },
            {
              label: "Open alerts",
              value:
                n.alerts > 0 ? (
                  <div className="space-y-1.5">
                    <div className="flex flex-wrap items-center gap-1.5">
                      <a
                        className="text-link underline underline-offset-2 font-medium"
                        href={`#/alerts?search=${encodeURIComponent(n.ips[0] ?? n.label)}`}
                      >
                        {String(n.alerts)} total
                      </a>
                      {n.alerts_by_severity &&
                        Object.entries(n.alerts_by_severity).map(([sev, count]) => (
                          <span
                            key={sev}
                            className={`inline-flex items-center gap-1 px-1.5 py-0.2 rounded text-[11px] font-medium ${
                              sev === "critical" || sev === "high"
                                ? "bg-critical-subtle text-critical border border-critical/30"
                                : sev === "medium"
                                ? "bg-amber-950/40 text-amber-400 border border-amber-500/30"
                                : "bg-sky-950/40 text-sky-400 border border-sky-500/30"
                            }`}
                          >
                            {sev}: {count}
                          </span>
                        ))}
                    </div>
                  </div>
                ) : (
                  "0"
                ),
            },
            ...(n.device_id !== null ? [{ label: "Device", value: <><a className="text-link underline underline-offset-2" href={`#/devices/${String(n.device_id)}`}>Inventory</a> · <a className="text-link underline underline-offset-2" href={`#/risk/${String(n.device_id)}`}>Risk profile</a></> }] : []),
          ]}
        />
        {n.alert_details && n.alert_details.length > 0 && (
          <div className="mt-4 space-y-2">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-fg-muted">
              Active Security Findings ({n.alert_details.length})
            </h4>
            <div className="grid gap-2">
              {n.alert_details.map((a) => (
                <div key={a.id} className="rounded border border-line bg-card/60 p-2.5 text-xs">
                  <div className="flex items-center justify-between gap-2 mb-1">
                    <span className="font-medium text-fg">
                      {a.rule_id}: {a.title}
                    </span>
                    <SeverityBadge level={a.severity} />
                  </div>
                  {a.why && <p className="text-fg-muted leading-relaxed mb-1">{a.why}</p>}
                  <div className="flex items-center justify-between text-[11px] text-fg-subtle">
                    <span>Status: {a.status}</span>
                    <a className="text-link underline underline-offset-2" href={`#/alerts?search=${encodeURIComponent(a.rule_id)}`}>
                      View alert #{a.id}
                    </a>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
        {mine.length > 0 && (
          <ul className="mt-3 grid gap-1 text-sm">
            {mine.map((e) => (
              <li key={e.id}>{KIND_LABEL[e.kind]} with {nodes.get(e.a === n.key ? e.b : e.a)?.label ?? "?"}: {formatBytes(e.bytes)}</li>
            ))}
          </ul>
        )}
      </Panel>
    );
  }
  const e = graph.edges.find((x) => x.id === selection.id);
  if (!e) return null;
  return (
    <Panel title={`${KIND_LABEL[e.kind]}: ${nodes.get(e.a)?.label ?? "?"} and ${nodes.get(e.b)?.label ?? "?"}`} actions={<Button onClick={onClose}>Close</Button>}>
      <DefinitionList
        items={[
          { label: "Basis", value: <BasisBadge basis={e.basis} /> },
          { label: "Confidence", value: `${e.confidence}: ${e.reason}` },
          { label: "Traffic", value: `${String(e.flows)} flows, ${formatBytes(e.bytes)}` },
          { label: "Protocols", value: e.protocols.join(", ") || "none" },
          { label: "Applications", value: e.applications.join(", ") || "none identified" },
          { label: "Open alerts", value: String(e.alerts) },
        ]}
      />
      <ul className="mt-2 list-disc pl-5 text-sm">{e.evidence.map((l) => (<li key={l}>{l}</li>))}</ul>
    </Panel>
  );
}

export function TopologyPage({ pollMs = 5000 }: { pollMs?: number }) {
  const { client } = useReadyBackend();
  const [session, setSession] = useState("current");
  const [range, setRange] = useState<(typeof WINDOWS)[number]["value"]>("session");
  const [view, setView] = useState<"graph" | "list">("graph");
  const [bases, setBases] = useState<Record<Basis, boolean>>({ observed: true, inferred: true, inventory: true });
  const [onlyAlerts, setOnlyAlerts] = useState(false);
  const [groupBy, setGroupBy] = useState<(typeof GROUPINGS)[number]["value"]>("auto");
  const [minBytes, setMinBytes] = useState("");
  const [text, setText] = useState("");
  const [offset, setOffset] = useState(0);
  const [selection, setSelection] = useState<{ kind: "node" | "edge"; id: string } | null>(null);
  const search = useDebouncedValue(text, 300).trim().toLowerCase();

  const topology = useRequest((signal) => client.getTopology({ session, window: range, group_by: groupBy === "auto" ? undefined : groupBy }, signal), [client, session, range, groupBy]);
  const live = topology.data?.source === "live" && range === "session" && session === "current";
  usePolling(() => { if (!topology.isPending) topology.reloadQuietly(); }, live ? pollMs : null);

  const graph = topology.data;
  const min = /^\d{1,12}$/.test(minBytes) ? Number(minBytes) : 0;
  const { nodes, edges } = useMemo(() => {
    if (!graph) return { nodes: [] as TopologyNode[], edges: [] as TopologyEdge[] };
    const label = new Map(graph.nodes.map((n) => [n.key, n]));
    const matches = (n: TopologyNode | undefined) =>
      !search || (n !== undefined && [n.label, n.mac ?? "", n.vendor ?? "", ...n.ips].some((t) => t.toLowerCase().includes(search)));
    const keptEdges = graph.edges.filter(
      (e) => bases[e.basis] && e.bytes >= min && (!onlyAlerts || e.alerts > 0 || (label.get(e.a)?.alerts ?? 0) > 0 || (label.get(e.b)?.alerts ?? 0) > 0) && (!search || matches(label.get(e.a)) || matches(label.get(e.b))),
    );
    const used = new Set(keptEdges.flatMap((e) => [e.a, e.b]));
    const isInventoryOnly = (n: TopologyNode) => n.basis === "inventory" && n.flows === 0;
    const keptNodes = graph.nodes.filter((n) => {
      if (!bases.inventory && isInventoryOnly(n)) return false;
      if (search && !matches(n) && !used.has(n.key)) return false;
      if (onlyAlerts && n.alerts === 0 && !used.has(n.key)) return false;
      return used.has(n.key) || n.type === "this_computer" || (bases.inventory && n.basis === "inventory");
    });
    return { nodes: keptNodes, edges: keptEdges };
  }, [graph, bases, min, onlyAlerts, search]);

  const byKey = new Map((graph?.nodes ?? []).map((n) => [n.key, n]));
  const rows = [...edges].sort((a, b) => b.bytes - a.bytes || (a.id < b.id ? -1 : 1));

  return (
    <div className="grid gap-4">
      <Panel
        title="Network topology"
        description="Relationships are drawn only where traffic between two ends was observed from this position."
        actions={
          <div className="flex gap-2" role="group" aria-label="View">
            <Button aria-pressed={view === "graph"} variant={view === "graph" ? "primary" : "secondary"} onClick={() => { setView("graph"); }}>Graph</Button>
            <Button aria-pressed={view === "list"} variant={view === "list" ? "primary" : "secondary"} onClick={() => { setView("list"); }}>List</Button>
          </div>
        }
      >
        <div className="mb-4 grid gap-3 md:grid-cols-5">
          <SessionPicker value={session} onChange={(s) => { setSession(s); setSelection(null); }} />
          <SelectField label="Window" value={range} onChange={(e) => { setRange(e.target.value as typeof range); setSelection(null); }}>
            {WINDOWS.map((w) => (<option key={w.value} value={w.value}>{w.label}</option>))}
          </SelectField>
          <SelectField label="Group devices by" value={groupBy} onChange={(e) => { setGroupBy(e.target.value as typeof groupBy); setSelection(null); }}>
            {GROUPINGS.map((g) => (<option key={g.value} value={g.value}>{g.label}</option>))}
          </SelectField>
          <TextField label="Search" value={text} onChange={(e) => { setText(e.target.value); setOffset(0); }} placeholder="Address, name, hardware address or vendor" />
          <TextField label="Minimum bytes" inputMode="numeric" value={minBytes} onChange={(e) => { setMinBytes(e.target.value); setOffset(0); }} error={minBytes !== "" && !/^\d{1,12}$/.test(minBytes) ? "Use a whole number." : undefined} />
        </div>
        <fieldset className="mb-4 flex flex-wrap gap-4">
          <legend className="mb-1 text-xs font-medium text-fg-muted">Show relationships that are</legend>
          {(["observed", "inferred", "inventory"] as const).map((b) => (
            <CheckboxField key={b} label={b[0]?.toUpperCase() + b.slice(1)} checked={bases[b]} onChange={(e) => { setBases((s) => ({ ...s, [b]: e.target.checked })); }} />
          ))}
          <CheckboxField label="Only with alerts" checked={onlyAlerts} onChange={(e) => { setOnlyAlerts(e.target.checked); }} />
        </fieldset>

        {topology.isLoading && <StateView variant="loading" title="Loading the network graph" />}
        {!graph && topology.error && <RequestError error={topology.error} what="the topology" onRetry={topology.reload} />}
        {graph && topology.error && <StaleNotice error={topology.error} what="the topology" asOf={topology.dataUpdatedAt} onRetry={topology.reload} />}
        {graph && (
          <div className="mb-4 rounded-md border border-line bg-inset p-3 text-sm" aria-label="Coverage">
            <h3 className="text-xs font-semibold text-fg-muted">What this picture can and cannot show</h3>
            {graph.coverage.statement && <p className="mt-1 text-fg">{graph.coverage.statement}</p>}
            <p className="mt-1 text-fg-muted">
              Capture position: {graph.coverage.interface_name ?? "unknown"}; visibility {graph.coverage.visibility.replaceAll("_", " ")}; gateways{" "}
              {graph.coverage.gateways.join(", ") || "unknown"}; this computer {graph.coverage.local_addresses.join(", ") || "unknown"}.
            </p>
            <ul className="mt-1 list-disc pl-5 text-fg-muted">{graph.coverage.cannot_see.map((t) => (<li key={t}>{t}</li>))}</ul>
            {graph.reduced && <p className="mt-1 text-warning">{graph.reduced}</p>}
            {graph.grouped_by && (
              <p className="mt-1 text-fg">
                Devices are shown as groups, merged by {graph.grouped_by}. A relationship between two groups stands for all the relationships between their members.
              </p>
            )}
          </div>
        )}
        {graph && graph.nodes.length === 0 && (
          <StateView variant="empty" title="No relationships observed yet" description="Start a capture or open a capture file in the Packet Explorer; history shows live sessions only." />
        )}
        {graph && graph.nodes.length > 0 && view === "graph" && (
          <Graph graph={graph} nodes={nodes} edges={edges} selection={selection} onSelect={setSelection} />
        )}
        {graph && graph.nodes.length > 0 && view === "list" && (
          <div className="grid gap-3">
            <Table label="Relationships">
              <thead>
                <tr><Th>From</Th><Th>To</Th><Th>Kind</Th><Th>Basis</Th><Th>Confidence</Th><Th>Flows</Th><Th>Bytes</Th><Th>Alerts</Th><Th>History</Th></tr>
              </thead>
              <tbody>
                {rows.slice(offset, offset + PAGE).map((e) => (
                  <tr key={e.id} aria-selected={selection?.id === e.id}>
                    <Td>
                      <button type="button" className="cursor-pointer text-link underline underline-offset-2" onClick={() => { setSelection({ kind: "edge", id: e.id }); }}>
                        {byKey.get(e.a)?.label ?? e.a}
                      </button>
                    </Td>
                    <Td>{byKey.get(e.b)?.label ?? e.b}</Td>
                    <Td>{KIND_LABEL[e.kind]}</Td>
                    <Td><BasisBadge basis={e.basis} /></Td>
                    <Td>{e.confidence}</Td>
                    <Td mono>{e.flows}</Td>
                    <Td mono>{formatBytes(e.bytes)}</Td>
                    <Td mono>{e.alerts}</Td>
                    <Td>{e.new ? "New" : ""}</Td>
                  </tr>
                ))}
              </tbody>
            </Table>
            <Pagination total={rows.length} limit={PAGE} offset={offset} onChange={setOffset} label="Relationship pages" />
          </div>
        )}
      </Panel>
      {graph && selection && <Details graph={graph} selection={selection} onClose={() => { setSelection(null); }} />}
    </div>
  );
}
