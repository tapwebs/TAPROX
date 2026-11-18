import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { createApiClient, type ApiClient } from "@/lib/api/client";
import type { BackendStatus, ConnectionSource } from "./sources";

export type BackendConnection =
  | { phase: "connecting" }
  | { phase: "ready"; client: ApiClient; baseUrl: string }
  | { phase: "failed"; message: string };

export const BackendContext = createContext<BackendConnection | null>(null);

interface Props {
  source: ConnectionSource;
  /** How often to ask the desktop shell while the backend is still starting. */
  pollMs?: number;
  /** How often to re-check the shell once ready, to notice a backend that died later. */
  watchMs?: number;
  children: ReactNode;
}

const sleep = (ms: number, onTimer: (timer: ReturnType<typeof setTimeout>) => void) =>
  new Promise<void>((resolve) => {
    onTimer(setTimeout(resolve, ms));
  });

/**
 * Learns how to reach the backend and keeps watching that answer.
 * Startup failures are final: the shell never restarts the backend, so there is nothing to retry.
 */
export function BackendProvider({ source, pollMs = 400, watchMs = 2000, children }: Props) {
  const [connection, setConnection] = useState<BackendConnection>({ phase: "connecting" });

  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let current: { baseUrl: string; token: string } | undefined;

    const read = async (): Promise<BackendStatus> => {
      try {
        return await source();
      } catch (cause) {
        const message = cause instanceof Error ? cause.message : "Could not reach the desktop shell.";
        return { state: "failed", message };
      }
    };

    const run = async () => {
      while (!cancelled) {
        const status = await read();
        if (cancelled) return;
        if (status.state === "failed") {
          setConnection({ phase: "failed", message: status.message });
          return;
        }
        if (status.state === "ready") {
          // Keep the same client while nothing changed, so pages do not re-fetch needlessly.
          if (current?.baseUrl !== status.baseUrl || current.token !== status.token) {
            current = { baseUrl: status.baseUrl, token: status.token };
            setConnection({
              phase: "ready",
              baseUrl: status.baseUrl,
              client: createApiClient({ baseUrl: status.baseUrl, token: status.token }),
            });
          }
        }
        // 'starting' while already ready is ignored; otherwise keep waiting.
        await sleep(current ? watchMs : pollMs, (t) => {
          timer = t;
        });
      }
    };
    void run();

    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [source, pollMs, watchMs]);

  return <BackendContext.Provider value={connection}>{children}</BackendContext.Provider>;
}

export function useBackend(): BackendConnection {
  const value = useContext(BackendContext);
  if (!value) throw new Error("useBackend must be used inside <BackendProvider>.");
  return value;
}

/** For screens that are only rendered once the shell has confirmed the connection. */
export function useReadyBackend(): { client: ApiClient; baseUrl: string } {
  const backend = useBackend();
  if (backend.phase !== "ready") throw new Error("useReadyBackend called before the backend was ready.");
  return { client: backend.client, baseUrl: backend.baseUrl };
}
