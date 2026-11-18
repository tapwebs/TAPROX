import { useCallback, useEffect, useReducer, useRef, useState, type DependencyList } from "react";

interface State<T> {
  data: T | undefined;
  error: Error | undefined;
  pending: boolean;
  /** The pending load was started by automatic polling, so it must not look like user activity. */
  quiet: boolean;
  /** Epoch milliseconds of the last successful load. */
  updatedAt: number | undefined;
}

type Action<T> =
  | { type: "start"; quiet: boolean }
  | { type: "success"; data: T }
  | { type: "failure"; error: Error };

function reducer<T>(state: State<T>, action: Action<T>): State<T> {
  switch (action.type) {
    case "start":
      return state.pending && state.quiet === action.quiet
        ? state
        : { ...state, pending: true, quiet: action.quiet };
    case "success":
      return { data: action.data, error: undefined, pending: false, quiet: false, updatedAt: Date.now() };
    case "failure":
      return { ...state, error: action.error, pending: false, quiet: false };
  }
}

export interface RequestResult<T> {
  data: T | undefined;
  error: Error | undefined;
  /** When `data` was last loaded successfully; kept through failed reloads so stale data is labelled. */
  dataUpdatedAt: number | undefined;
  /** First load: nothing to show yet, so show a skeleton. */
  isLoading: boolean;
  /** Reload the user asked for: keep showing the current data and indicate activity elsewhere. */
  isRefreshing: boolean;
  /** Any load in flight, including quiet ones. Polling uses this to avoid overlapping requests. */
  isPending: boolean;
  reload: () => void;
  /** For automatic polling: reloads without ever setting `isRefreshing` (no spinner, no flicker). */
  reloadQuietly: () => void;
}

/**
 * Run an async load on mount (and whenever `deps` change or `reload` is called).
 * A loading skeleton is only ever shown when there is no data yet. Superseded and unmounted
 * requests are aborted and their results are ignored.
 */
export function useRequest<T>(
  load: (signal: AbortSignal) => Promise<T>,
  deps: DependencyList,
): RequestResult<T> {
  const [state, dispatch] = useReducer(reducer<T>, {
    data: undefined,
    error: undefined,
    pending: true,
    quiet: false,
    updatedAt: undefined,
  });
  const [nonce, setNonce] = useState(0);
  const loadRef = useRef(load);
  const quietRef = useRef(false);

  useEffect(() => {
    loadRef.current = load;
  });

  useEffect(() => {
    const controller = new AbortController();
    dispatch({ type: "start", quiet: quietRef.current });
    quietRef.current = false;
    loadRef.current(controller.signal).then(
      (data) => {
        if (!controller.signal.aborted) dispatch({ type: "success", data });
      },
      (cause: unknown) => {
        if (controller.signal.aborted) return;
        dispatch({
          type: "failure",
          error: cause instanceof Error ? cause : new Error(String(cause)),
        });
      },
    );
    return () => {
      controller.abort();
    };
    // `deps` is the caller's explicit trigger list; `nonce` drives reload().
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, nonce]);

  const reload = useCallback(() => {
    quietRef.current = false;
    setNonce((n) => n + 1);
  }, []);

  const reloadQuietly = useCallback(() => {
    quietRef.current = true;
    setNonce((n) => n + 1);
  }, []);

  return {
    data: state.data,
    error: state.error,
    dataUpdatedAt: state.updatedAt,
    isLoading: state.pending && state.data === undefined,
    isRefreshing: state.pending && state.data !== undefined && !state.quiet,
    isPending: state.pending,
    reload,
    reloadQuietly,
  };
}
