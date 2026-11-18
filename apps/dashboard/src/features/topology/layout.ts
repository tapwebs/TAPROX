import type { TopologyNode } from "@/lib/api/types";

export type LayoutMode = "clustered" | "hierarchical" | "concentric";

export interface Placed {
  node: TopologyNode;
  x: number;
  y: number;
  tier?: number;
  cluster?: "local" | "gateway" | "lan" | "wan";
}

export const CANVAS = { width: 900, height: 700 };
const CENTER = { x: CANVAS.width / 2, y: CANVAS.height / 2 };

const byKey = (a: TopologyNode, b: TopologyNode) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0);
const byTraffic = (a: TopologyNode, b: TopologyNode) => b.bytes - a.bytes || byKey(a, b);

/**
 * Deterministic multi-mode topology layout engine for TAPROX.
 * Guarantees identical output regardless of input ordering.
 * Supports Clustered (default), Hierarchical, and Concentric layout paradigms.
 */
export function layoutNodes(nodes: readonly TopologyNode[], mode: LayoutMode = "clustered"): Placed[] {
  if (nodes.length === 0) return [];

  // Group nodes deterministically
  let localNode: TopologyNode | null = null;
  const gateways: TopologyNode[] = [];
  const lanNodes: TopologyNode[] = [];
  const wanNodes: TopologyNode[] = [];

  for (const n of nodes) {
    if (n.type === "this_computer") {
      localNode = n;
    } else if (n.type === "gateway") {
      gateways.push(n);
    } else if (n.type === "device" || n.type === "unresolved_host" || n.type === "group") {
      lanNodes.push(n);
    } else {
      wanNodes.push(n);
    }
  }

  gateways.sort(byKey);
  lanNodes.sort(byTraffic);
  wanNodes.sort(byTraffic);

  const placed: Placed[] = [];
  const occupied = new Set<string>();

  const round = (val: number) => Math.round(val * 10) / 10;

  const pushPlaced = (node: TopologyNode, rawX: number, rawY: number, tier = 1, cluster?: Placed["cluster"]) => {
    let x = round(Math.max(40, Math.min(CANVAS.width - 40, rawX)));
    let y = round(Math.max(40, Math.min(CANVAS.height - 40, rawY)));
    let key = `${String(x)},${String(y)}`;
    let step = 1;

    // Guaranteed collision prevention: nudge deterministically if occupied
    while (occupied.has(key)) {
      x = round(x + (step % 2 === 1 ? step * 2.5 : -step * 2.5));
      y = round(y + (step % 4 < 2 ? step * 1.5 : -step * 1.5));
      key = `${String(x)},${String(y)}`;
      step++;
    }

    occupied.add(key);
    placed.push({ node, x, y, tier, cluster });
  };

  // Centerpiece: this computer is always at center (450, 350)
  if (localNode) {
    pushPlaced(localNode, CENTER.x, CENTER.y, 0, "local");
  }

  switch (mode) {
    case "hierarchical": {
      // Tier 1: Gateways (bridge layer above local computer)
      const gwCount = gateways.length;
      gateways.forEach((gw, i) => {
        const span = Math.min(400, Math.max(120, gwCount * 80));
        const startX = CENTER.x - span / 2;
        const x = gwCount === 1 ? CENTER.x : startX + (i / (gwCount - 1)) * span;
        pushPlaced(gw, x, 210, 1, "gateway");
      });

      // Tier 2: LAN Devices & Groups (lower tier below local computer)
      const lanCount = lanNodes.length;
      lanNodes.forEach((node, i) => {
        const row = i % 2;
        const col = Math.floor(i / 2);
        const colsInRow = Math.ceil(lanCount / 2);
        const span = Math.min(760, Math.max(160, colsInRow * 70));
        const startX = CENTER.x - span / 2;
        const x = colsInRow <= 1 ? CENTER.x : startX + (col / Math.max(1, colsInRow - 1)) * span;
        const y = 480 + row * 85;
        pushPlaced(node, x, y, 2, "lan");
      });

      // Tier 3: Remote Hosts & Services (WAN cloud tier across upper canvas)
      const wanCount = wanNodes.length;
      wanNodes.forEach((node, i) => {
        const row = i % 2;
        const col = Math.floor(i / 2);
        const colsInRow = Math.ceil(wanCount / 2);
        const span = Math.min(800, Math.max(180, colsInRow * 65));
        const startX = CENTER.x - span / 2;
        const x = colsInRow <= 1 ? CENTER.x : startX + (col / Math.max(1, colsInRow - 1)) * span;
        const y = 75 + row * 65;
        pushPlaced(node, x, y, 3, "wan");
      });
      break;
    }

    case "concentric": {
      // Orbit 1: Gateways (radius ~130, upper arc)
      const gwCount = gateways.length;
      gateways.forEach((gw, i) => {
        const angle = -Math.PI / 2 + (gwCount > 1 ? ((i / (gwCount - 1)) - 0.5) * 0.9 : 0);
        pushPlaced(gw, CENTER.x + 130 * Math.cos(angle), CENTER.y + 105 * Math.sin(angle), 1, "gateway");
      });

      // Orbit 2: LAN Devices (radius ~230, inner ring)
      const lanCount = lanNodes.length;
      lanNodes.forEach((node, i) => {
        const angle = -Math.PI / 2 + 0.3 + (2 * Math.PI * i) / Math.max(1, lanCount);
        pushPlaced(node, CENTER.x + 230 * Math.cos(angle), CENTER.y + 185 * Math.sin(angle), 2, "lan");
      });

      // Orbit 3 & 4: WAN Remote Hosts (staggered outer orbital rings ~330 & ~390)
      const wanCount = wanNodes.length;
      wanNodes.forEach((node, i) => {
        const orbit = i % 2 === 0 ? 330 : 395;
        const orbitY = i % 2 === 0 ? 260 : 315;
        const angle = -Math.PI / 2 + 0.15 + (2 * Math.PI * i) / Math.max(1, wanCount);
        pushPlaced(node, CENTER.x + orbit * Math.cos(angle), CENTER.y + orbitY * Math.sin(angle), 3, "wan");
      });
      break;
    }

    case "clustered":
    default: {
      // Clustered Multi-Sector Paradigm:
      // Gateways bridge the sectors above center
      const gwCount = gateways.length;
      gateways.forEach((gw, i) => {
        const angle = -Math.PI / 2 + (gwCount > 1 ? ((i / (gwCount - 1)) - 0.5) * 0.7 : 0);
        pushPlaced(gw, CENTER.x + 130 * Math.cos(angle), CENTER.y + 110 * Math.sin(angle), 1, "gateway");
      });

      const lanCount = lanNodes.length;
      const wanCount = wanNodes.length;

      // LAN cluster on the left / southwest sector (angles ~ 0.55π to 1.35π)
      if (lanCount > 0) {
        const startAngle = wanCount > 0 ? 0.6 * Math.PI : 0.1 * Math.PI;
        const spanAngle = wanCount > 0 ? 0.8 * Math.PI : 1.8 * Math.PI;

        lanNodes.forEach((node, i) => {
          const tier = lanCount > 6 ? (i % 2 === 0 ? 0 : 1) : 0;
          const rx = tier === 0 ? 190 : 255;
          const ry = tier === 0 ? 150 : 205;
          const fraction = lanCount === 1 ? 0.5 : i / (lanCount - 1);
          const angle = startAngle + fraction * spanAngle;
          pushPlaced(node, CENTER.x + rx * Math.cos(angle), CENTER.y + ry * Math.sin(angle), 2 + tier, "lan");
        });
      }

      // WAN cluster on the right / northeast sector (angles ~ -0.4π to 0.45π)
      if (wanCount > 0) {
        const startAngle = lanCount > 0 ? -0.38 * Math.PI : -0.9 * Math.PI;
        const spanAngle = lanCount > 0 ? 0.82 * Math.PI : 1.8 * Math.PI;

        wanNodes.forEach((node, i) => {
          // Stagger across 2 or 3 radial tiers for external hosts to prevent label collision
          const tier = wanCount > 12 ? i % 3 : wanCount > 5 ? i % 2 : 0;
          const rx = tier === 0 ? 290 : tier === 1 ? 355 : 410;
          const ry = tier === 0 ? 220 : tier === 1 ? 275 : 320;
          const fraction = wanCount === 1 ? 0.5 : i / (wanCount - 1);
          const angle = startAngle + fraction * spanAngle;
          pushPlaced(node, CENTER.x + rx * Math.cos(angle), CENTER.y + ry * Math.sin(angle), 3 + tier, "wan");
        });
      }
      break;
    }
  }

  return placed;
}
