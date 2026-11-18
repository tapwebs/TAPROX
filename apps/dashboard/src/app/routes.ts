import {
  Activity,
  AppWindow,
  Binary,
  Cable,
  FileText,
  FolderSearch,
  Globe,
  LayoutDashboard,
  MonitorSmartphone,
  Network,
  Radar,
  Settings,
  ShieldAlert,
  SlidersHorizontal,
  Waypoints,
  type LucideIcon,
} from "lucide-react";

export type RouteId =
  | "overview"
  | "interfaces"
  | "discovery"
  | "devices"
  | "activity"
  | "packets"
  | "flows"
  | "applications"
  | "threats"
  | "alerts"
  | "history"
  | "topology"
  | "rules"
  | "risk"
  | "web-inspector"
  | "investigations"
  | "reports"
  | "settings";

export interface NavItem {
  label: string;
  icon: LucideIcon;
  /** Roadmap phase that delivers this module (0 = available now). */
  phase: number;
  /** Present only for screens that exist in this build. Everything else is shown as planned. */
  route?: RouteId;
}

/** Primary navigation, in the order defined by the product architecture. */
export const NAV_ITEMS: readonly NavItem[] = [
  { label: "Overview", icon: LayoutDashboard, phase: 0, route: "overview" },
  { label: "Network Interfaces", icon: Cable, phase: 1, route: "interfaces" },
  { label: "Device Discovery", icon: Radar, phase: 1, route: "discovery" },
  { label: "Device Inventory", icon: MonitorSmartphone, phase: 1, route: "devices" },
  { label: "Network Topology", icon: Network, phase: 4, route: "topology" },
  { label: "Network Activity", icon: Activity, phase: 3, route: "activity" },
  { label: "Packet Explorer", icon: Binary, phase: 2, route: "packets" },
  { label: "Flow Intelligence", icon: Waypoints, phase: 3, route: "flows" },
  { label: "Application Intelligence", icon: AppWindow, phase: 3, route: "applications" },
  { label: "Threat Detection", icon: ShieldAlert, phase: 4, route: "threats" },
  { label: "Web Inspector", icon: Globe, phase: 5, route: "web-inspector" },
  { label: "Investigations", icon: FolderSearch, phase: 6, route: "investigations" },
  { label: "Reports & Evidence", icon: FileText, phase: 6, route: "reports" },
  { label: "Detection Rules", icon: SlidersHorizontal, phase: 4, route: "rules" },
  { label: "Settings", icon: Settings, phase: 0, route: "settings" },
];

export const PAGE_TITLES: Record<RouteId, string> = {
  overview: "Overview",
  interfaces: "Network Interfaces",
  discovery: "Device Discovery",
  devices: "Device Inventory",
  activity: "Network Activity",
  packets: "Packet Explorer",
  flows: "Flow Explorer",
  applications: "Application Intelligence",
  threats: "Threat Detection",
  alerts: "Security Alerts",
  history: "Detection History",
  topology: "Network Topology",
  rules: "Detection Rules",
  risk: "Device Risk Profile",
  "web-inspector": "Web Inspector",
  investigations: "Investigations",
  reports: "Reports & Evidence",
  settings: "Settings",
};

/** The sidebar entry that stays highlighted on screens that are reached from another one. */
export const NAV_PARENT: Partial<Record<RouteId, RouteId>> = { alerts: "threats", history: "threats", risk: "devices" };

/** Screens that need the full content width (the graph). */
export const WIDE_ROUTES: readonly RouteId[] = ["topology"];
