"""Small bounded helpers shared by rules. Pure: no clock, no I/O, no threads."""

from collections import deque
from collections.abc import Iterable


def port_ranges(ports: Iterable[int], limit: int = 50) -> tuple[list[tuple[int, int]], int]:
    """Sorted contiguous ranges of `ports`, at most `limit` of them, and how many ranges there were in all."""
    ordered = sorted(set(ports))
    ranges: list[tuple[int, int]] = []
    for port in ordered:
        if ranges and port == ranges[-1][1] + 1:
            ranges[-1] = (ranges[-1][0], port)
        else:
            ranges.append((port, port))
    return ranges[:limit], len(ranges)


def format_ranges(ranges: list[tuple[int, int]]) -> str:
    return ", ".join(str(a) if a == b else f"{a}-{b}" for a, b in ranges)


class CoverageTracker:
    """Tells whether the telemetry queue refused too many events lately (the "reduced coverage" condition).

    It is fed the queue's cumulative drop count and the engine's cumulative processed count once per
    second of packet time and keeps a bounded history.
    """

    def __init__(self, max_points: int = 3600, minimum_events: int = 100) -> None:
        self._points: deque[tuple[float, int, int]] = deque(maxlen=max_points)
        self._minimum = minimum_events

    def record(self, t: float, dropped_cumulative: int, processed_cumulative: int) -> None:
        self._points.append((t, dropped_cumulative, processed_cumulative))

    def drop_ratio(self, since: float) -> float:
        """Share of events refused since packet time `since` (0.0 when too few events to say)."""
        if not self._points:
            return 0.0
        first = next((p for p in self._points if p[0] >= since), self._points[0])
        last = self._points[-1]
        dropped = last[1] - first[1]
        offered = dropped + (last[2] - first[2])
        return dropped / offered if offered >= self._minimum else 0.0

    def reduced(self, since: float, threshold: float = 0.01) -> bool:
        return self.drop_ratio(since) > threshold
