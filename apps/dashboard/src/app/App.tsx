import { useEffect, useRef } from "react";
import { Header } from "@/components/layout/Header";
import { Sidebar } from "@/components/layout/Sidebar";
import { BackendGate } from "@/components/BackendGate";
import { DevicesPage } from "@/features/devices/DevicesPage";
import { DiscoveryPage } from "@/features/discovery/DiscoveryPage";
import { InterfacesPage } from "@/features/interfaces/InterfacesPage";
import { ActivityPage } from "@/features/activity/ActivityPage";
import { ApplicationsPage } from "@/features/applications/ApplicationsPage";
import { FlowsPage } from "@/features/flows/FlowsPage";
import { PacketsPage } from "@/features/packets/PacketsPage";
import { OverviewPage } from "@/features/overview/OverviewPage";
import { AlertDetailPage } from "@/features/security/AlertDetailPage";
import { AlertsPage } from "@/features/security/AlertsPage";
import { HistoryPage } from "@/features/security/HistoryPage";
import { RiskPage } from "@/features/security/RiskPage";
import { RulesPage } from "@/features/security/RulesPage";
import { ThreatOverviewPage } from "@/features/security/ThreatOverviewPage";
import { SettingsPage } from "@/features/settings/SettingsPage";
import { TopologyPage } from "@/features/topology/TopologyPage";
import { WebInspectorPage } from "@/features/web_inspector/WebInspectorPage";
import { InvestigationsPage } from "@/features/investigations/InvestigationsPage";
import { ReportsPage } from "@/features/reports/ReportsPage";
import { BackendProvider } from "@/lib/connection/BackendProvider";
import type { ConnectionSource } from "@/lib/connection/sources";
import { SelectedInterfaceProvider } from "@/lib/selectedInterface";
import { PAGE_TITLES, WIDE_ROUTES } from "./routes";
import { useHashRoute, type ParsedRoute } from "./useHashRoute";

function Page({ route, param, scan }: ParsedRoute) {
  switch (route) {
    case "overview":
      return <OverviewPage />;
    case "interfaces":
      return <InterfacesPage />;
    case "discovery":
      return <DiscoveryPage />;
    case "devices":
      return <DevicesPage param={param} scan={scan} />;
    case "activity":
      return <ActivityPage />;
    case "packets":
      return <PacketsPage />;
    case "flows":
      return <FlowsPage />;
    case "applications":
      return <ApplicationsPage />;
    case "threats":
      return <ThreatOverviewPage />;
    case "alerts":
      return param === null ? <AlertsPage /> : <AlertDetailPage param={param} />;
    case "history":
      return <HistoryPage />;
    case "topology":
      return <TopologyPage />;
    case "rules":
      return <RulesPage />;
    case "risk":
      return <RiskPage param={param} />;
    case "web-inspector":
      return <WebInspectorPage param={param} />;
    case "investigations":
      return <InvestigationsPage param={param} />;
    case "reports":
      return <ReportsPage />;
    case "settings":
      return <SettingsPage />;
  }
}

function Screen({ current }: { current: ParsedRoute }) {
  return (
    <BackendGate>
      <Page {...current} />
    </BackendGate>
  );
}

function Shell() {
  const current = useHashRoute();
  const route = current.route;
  const mainRef = useRef<HTMLElement>(null);
  const headingRef = useRef<HTMLHeadingElement>(null);
  const firstRender = useRef(true);

  // After navigating, move focus to the new page's heading so screen readers announce the change.
  useEffect(() => {
    if (firstRender.current) {
      firstRender.current = false;
      return;
    }
    headingRef.current?.focus();
  }, [route]);

  return (
    <div className="grid min-h-dvh grid-cols-[3.5rem_minmax(0,1fr)] lg:grid-cols-[18.5rem_minmax(0,1fr)]">
      <a
        href="#main"
        onClick={(event) => {
          event.preventDefault(); // the URL hash is the router; do not navigate
          mainRef.current?.focus();
        }}
        className="sr-only focus:not-sr-only focus:fixed focus:left-2 focus:top-2 focus:z-50 focus:rounded-md focus:bg-accent-strong focus:px-3 focus:py-2 focus:font-semibold focus:text-on-accent"
      >
        Skip to content
      </a>
      <Sidebar current={route} />
      <div className="flex min-w-0 flex-col">
        <Header ref={headingRef} title={PAGE_TITLES[route]} />
        <main ref={mainRef} id="main" tabIndex={-1} className="flex-1 p-4 focus:outline-none lg:p-6">
          <div className={`mx-auto ${WIDE_ROUTES.includes(route) ? "max-w-none" : "max-w-5xl"}`}>
            <Screen current={current} />
          </div>
        </main>
      </div>
    </div>
  );
}

export function App({ source, watchMs }: { source: ConnectionSource; watchMs?: number }) {
  return (
    <BackendProvider source={source} watchMs={watchMs}>
      <SelectedInterfaceProvider>
        <Shell />
      </SelectedInterfaceProvider>
    </BackendProvider>
  );
}
