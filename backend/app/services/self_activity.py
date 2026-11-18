"""When TAPNETTRACK's own discovery scan was sending probes (Phase 4 / M3).

Discovery sends an ARP probe to every address of a network and one multicast ping. A detection rule
that watches for sweeps would otherwise raise an alert on every scan the user starts. The discovery
service records the span of each scan here; the detection engine asks `contains(packet_time)` and
excludes this computer's own ARP and ICMP activity inside those spans (and counts what it excluded).

In memory only, bounded, no database. It uses the wall clock only to stamp the scans, never inside a
rule. A live capture's packet time is the wall clock, so the two can be compared; an opened file's
cannot, which is why the engine ignores this record for files.
"""

import math
import threading
import time
from collections.abc import Callable

KEEP = 64  # scans remembered
MAX_AGE = 3600.0  # seconds after which a finished scan is forgotten
GRACE = 2.0  # seconds either side: packets are stamped before the call and replies come after


class SelfActivity:
    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.time,
        grace: float = GRACE,
        keep: int = KEEP,
        max_age: float = MAX_AGE,
    ) -> None:
        self._clock = clock
        self._grace = grace
        self._keep = max(1, keep)
        self._max_age = max_age
        self._lock = threading.Lock()
        self._windows: dict[int, list[float | None]] = {}  # token -> [start, end or None]
        self._next = 1

    def __len__(self) -> int:
        with self._lock:
            return len(self._windows)

    def begin(self) -> int:
        """A scan is starting. Returns the token to pass to `end`."""
        now = self._clock()
        with self._lock:
            for token in [
                t
                for t, (_, end) in self._windows.items()
                if end is not None and now - end > self._max_age
            ]:
                del self._windows[token]
            token = self._next
            self._next += 1
            self._windows[token] = [now, None]
            while len(self._windows) > self._keep:
                del self._windows[next(iter(self._windows))]
            return token

    def end(self, token: int) -> None:
        with self._lock:
            window = self._windows.get(token)
            if window is not None:
                window[1] = self._clock()

    def contains(self, t: float) -> bool:
        """Was a scan running at `t` (epoch seconds), give or take the grace?"""
        if not isinstance(t, (int, float)) or not math.isfinite(t) or t < 0:
            return False
        with self._lock:
            for start, end in self._windows.values():
                if (
                    start is not None
                    and t >= start - self._grace
                    and (end is None or t <= end + self._grace)
                ):
                    return True
        return False
