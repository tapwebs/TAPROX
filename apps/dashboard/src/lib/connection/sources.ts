/** Where the dashboard learns how to reach the backend. */

export type BackendStatus =
  | { state: "starting" }
  | { state: "ready"; baseUrl: string; token: string }
  | { state: "failed"; message: string };

export type ConnectionSource = () => Promise<BackendStatus>;
export type Invoke = (command: string) => Promise<unknown>;

export interface DevEnv {
  DEV: boolean;
  VITE_TAPNETTRACK_API_URL?: string;
  VITE_TAPNETTRACK_API_TOKEN?: string;
}

// The backend only ever listens on loopback; refuse anything else even if the shell says otherwise.
const LOOPBACK_HTTP = /^http:\/\/(127\.0\.0\.1|localhost):\d{1,5}\/?$/;

const failed = (message: string): BackendStatus => ({ state: "failed", message });

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function parseStatus(value: unknown): BackendStatus {
  if (!isRecord(value)) return failed("The desktop shell returned an unreadable answer.");
  if (value.state === "starting") return { state: "starting" };
  if (value.state === "failed") {
    return failed(typeof value.message === "string" ? value.message : "The backend failed to start.");
  }
  if (value.state === "ready" && typeof value.baseUrl === "string" && typeof value.token === "string") {
    if (!LOOPBACK_HTTP.test(value.baseUrl)) {
      return failed("The desktop shell returned a non-loopback backend address; refusing to use it.");
    }
    return { state: "ready", baseUrl: value.baseUrl, token: value.token };
  }
  return failed("The desktop shell returned an unexpected answer.");
}

/** Inside TAPROX Desktop: ask the Rust shell, which supervises the backend process. */
export function tauriSource(invoke: Invoke): ConnectionSource {
  return async () => {
    try {
      return parseStatus(await invoke("backend_connection"));
    } catch (cause) {
      const detail = cause instanceof Error ? cause.message : String(cause);
      return failed(`Could not ask the desktop shell for the backend connection: ${detail}`);
    }
  };
}

/**
 * Plain browser during development only. In a production build `DEV` is false, so the
 * environment variables are ignored and no token can be baked into shipped code.
 */
export function devSource(env: DevEnv): ConnectionSource {
  return () => {
    if (!env.DEV) {
      return Promise.resolve(failed("TAPROX must be run inside TAPROX Desktop."));
    }
    const baseUrl = env.VITE_TAPNETTRACK_API_URL;
    const token = env.VITE_TAPNETTRACK_API_TOKEN;
    if (!baseUrl || !token) {
      return Promise.resolve(
        failed("No development backend is configured. Start the stack with `npm run dev`."),
      );
    }
    if (!LOOPBACK_HTTP.test(baseUrl)) {
      return Promise.resolve(failed("The development backend address must be loopback http."));
    }
    return Promise.resolve<BackendStatus>({ state: "ready", baseUrl, token });
  };
}

export function selectSource(options: { isTauri: boolean; invoke: Invoke; env: DevEnv }): ConnectionSource {
  return options.isTauri ? tauriSource(options.invoke) : devSource(options.env);
}
