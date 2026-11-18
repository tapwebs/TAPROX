import { useEffect, useRef } from "react";

/**
 * Call `tick` every `ms` milliseconds while the window is visible, and once as soon as it becomes
 * visible again; `null` turns polling off.
 * The latest `tick` is always used, so callers can close over fresh state without restarting
 * the timer.
 */
export function usePolling(tick: () => void, ms: number | null): void {
  const latest = useRef(tick);
  useEffect(() => {
    latest.current = tick;
  });

  useEffect(() => {
    if (ms === null) return;
    const timer = setInterval(() => {
      if (!document.hidden) latest.current();
    }, ms);
    // Ticks are skipped while the window is hidden, so on return the data may be stale: refresh
    // now instead of showing old data until the next tick.
    const onVisibility = () => {
      if (!document.hidden) latest.current();
    };
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      clearInterval(timer);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [ms]);
}
