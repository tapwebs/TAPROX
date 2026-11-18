import type { ReactNode } from "react";
import { StateView } from "@/components/ui/StateView";
import { useBackend } from "@/lib/connection/BackendProvider";

/** Renders its children only once the backend connection is confirmed; otherwise says why not. */
export function BackendGate({ children }: { children: ReactNode }) {
  const backend = useBackend();
  if (backend.phase === "connecting") {
    return <StateView variant="loading" title="Starting the TAPROX backend" />;
  }
  if (backend.phase === "failed") {
    // No retry button on purpose: the desktop shell does not restart the backend, so one could
    // only repeat the same answer. Restarting the app is the real recovery.
    return (
      <StateView
        variant="error"
        title="The backend is not running"
        description={`${backend.message} Close and reopen TAPROX to start it again. Diagnostic logs are written to %LOCALAPPDATA%\\TAPNETTRACK\\logs\\backend.log.`}
      />
    );
  }
  return <>{children}</>;
}
