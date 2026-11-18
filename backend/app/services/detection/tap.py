"""The hand-off between the flow engine and a consumer of telemetry: a counter set and a bounded queue.

Rules this module keeps (each has a test):

* It never blocks the thread that decodes packets. A full queue refuses the event and counts it.
  The one exception is the end of a capture (`put_all`): every flow still open retires at once, and that burst
  is handed over in order, waiting for the consumer to make room. It waits only while the consumer makes progress; if
  none is made for `FINISH_STALL_SECONDS`, or the queue is closed, the rest is dropped and counted.
* It does no I/O: no database, no socket, no clock, no thread of its own.
* Events leave in the order they were produced; what is dropped is the newest overflow, so the
  sequence a consumer sees is never reordered or holey in the middle of a batch.
* After `close()` a consumer still receives everything already queued, then `None`.
"""

import threading
from collections import deque
from collections.abc import Sequence
from dataclasses import dataclass

from app.services.detection.events import (
    OTHER_HOSTS,
    Event,
    FlowOpened,
    FlowRetired,
    HostCounters,
    TickSummary,
)
from app.services.flows.packet import FlowPacket

DEFAULT_QUEUE_SIZE = 10_000
FINISH_STALL_SECONDS = (
    15.0  # how long the end-of-capture burst waits for a consumer that makes no progress
)
MAX_TICK_HOSTS = 2_000


class EventQueue:
    """A bounded FIFO with one lock. Producers never wait; consumers wait with a timeout."""

    def __init__(self, maxsize: int = DEFAULT_QUEUE_SIZE) -> None:
        if maxsize < 1:
            raise ValueError("The queue must hold at least one event.")
        self.maxsize = maxsize
        self._items: deque[Event] = deque()
        self._cond = threading.Condition()
        self._closed = False
        self._offered = 0
        self._accepted = 0
        self._dropped = 0
        self._dropped_closed = 0
        self._high_water = 0
        self._producers = 0  # callers of put_all that are waiting for room

    def offer(self, event: Event) -> bool:
        return self.offer_many((event,)) == 1

    def offer_many(self, events: Sequence[Event]) -> int:
        """Queue as many as fit, in order. Returns how many were accepted; the rest are counted as dropped."""
        if not events:
            return 0
        with self._cond:
            self._offered += len(events)
            if self._closed:
                self._dropped_closed += len(events)
                return 0
            room = self.maxsize - len(self._items)
            take = events if len(events) <= room else events[: max(room, 0)]
            self._items.extend(take)
            accepted = len(take)
            self._accepted += accepted
            self._dropped += len(events) - accepted
            if len(self._items) > self._high_water:
                self._high_water = len(self._items)
            if accepted:
                self._cond.notify()
            return accepted

    def put_all(self, events: Sequence[Event], stall_seconds: float) -> int:
        """Queue every event, in order, waiting for the consumer to make room. For the end of a capture only.

        The queue never holds more than `maxsize`. If the consumer makes no room for `stall_seconds`, or the queue is closed,
        what is left is dropped and counted (`dropped`, `dropped_after_close`), so a stopped consumer cannot hold up a
        shutdown and nothing is lost without a trace. Returns how many were accepted.
        """
        if not events:
            return 0
        done = 0
        with self._cond:
            self._offered += len(events)
            while done < len(events):
                if self._closed:
                    self._dropped_closed += len(events) - done
                    return done
                room = self.maxsize - len(self._items)
                if room <= 0:
                    self._producers += 1
                    try:
                        woke = self._cond.wait_for(
                            lambda: self._closed or len(self._items) < self.maxsize,
                            timeout=stall_seconds,
                        )
                    finally:
                        self._producers -= 1
                    if not woke:
                        self._dropped += len(events) - done
                        return done
                    continue
                chunk = events[done : done + room]
                self._items.extend(chunk)
                done += len(chunk)
                self._accepted += len(chunk)
                self._high_water = max(self._high_water, len(self._items))
                self._cond.notify_all()
        return done

    def get_batch(self, max_items: int = 256, timeout: float | None = None) -> list[Event] | None:
        """Up to `max_items` events. `[]` after `timeout` with nothing queued; `None` once closed and empty."""
        with self._cond:
            if not self._items and not self._closed:
                self._cond.wait(timeout)
            if not self._items:
                return None if self._closed else []
            count = min(max_items, len(self._items))
            batch = [self._items.popleft() for _ in range(count)]
            if self._producers:
                self._cond.notify_all()  # room was made for a waiting end-of-capture burst
            return batch

    def close(self) -> None:
        with self._cond:
            self._closed = True
            self._cond.notify_all()

    @property
    def dropped(self) -> int:
        with self._cond:
            return self._dropped

    def stats(self) -> dict[str, int | bool]:
        with self._cond:
            return {
                "maxsize": self.maxsize,
                "depth": len(self._items),
                "high_water": self._high_water,
                "offered": self._offered,
                "accepted": self._accepted,
                "dropped": self._dropped,
                "dropped_after_close": self._dropped_closed,
                "closed": self._closed,
            }


@dataclass(frozen=True, slots=True)
class TapContext:
    """What a consumer needs to know about the session it is about to analyse (kept in memory in M1)."""

    session_id: int
    source: str  # live | file
    interface_id: str | None = None
    interface_name: str | None = None
    local_addresses: frozenset[str] = frozenset()
    local_networks: tuple[str, ...] = ()
    gateways: tuple[str, ...] = ()
    dns_servers: tuple[str, ...] = ()
    interface_mac: str | None = None
    promiscuous: bool | None = None


class TelemetryTap:
    """Called by the flow engine on its reader thread, after the engine's lock has been released.

    Keeps O(1) per-address counters for the current second of packet time and turns them into a
    `TickSummary` when the second ends. Everything else the engine produced for the packet is queued as is.
    """

    def __init__(
        self,
        queue: EventQueue,
        *,
        max_hosts: int = MAX_TICK_HOSTS,
        finish_stall_seconds: float = FINISH_STALL_SECONDS,
    ) -> None:
        self.queue = queue
        self.max_hosts = max_hosts
        self.finish_stall_seconds = finish_stall_seconds
        self._second: int | None = None
        self._hosts: dict[str, HostCounters] = {}

    def after_packet(self, packet: FlowPacket, events: Sequence[Event]) -> None:
        out: list[Event] = []
        second = int(packet.time // 1)
        if self._second is None:
            self._second = second
        elif (
            second > self._second
        ):  # packet time only moves the tick forward; a stray old packet joins the current one
            self._flush(out, float(self._second + 1))
            self._second = second
        if packet.src_ip is not None and packet.dst_ip is not None:
            src = self._counters(packet.src_ip)
            src.packets_out += 1
            src.bytes_out += packet.length
            dst = self._counters(packet.dst_ip)
            dst.packets_in += 1
            dst.bytes_in += packet.length
        self._account(events)
        out.extend(events)
        if out:
            self.queue.offer_many(out)

    def after_finish(self, events: Sequence[Event]) -> None:
        """The capture ended: queue the final events and the last, partial second."""
        out: list[Event] = list(events)
        self._account(events)  # the flows that just ended belong to the last second
        if self._second is not None:
            self._flush(out, float(self._second + 1))
            self._second = None
        if out:
            self.queue.put_all(
                out, self.finish_stall_seconds
            )  # the whole burst, in order; see the module notes

    def close(self) -> None:
        self.queue.close()

    def _account(self, events: Sequence[Event]) -> None:
        for event in events:
            if isinstance(event, FlowOpened):
                self._counters(event.src_ip).new_flows_out += 1
            elif (
                isinstance(event, FlowRetired)
                and event.transport == "tcp"
                and event.syn
                and not event.synack
            ):
                self._counters(event.src_ip).failed_flows_out += 1

    def _counters(self, address: str) -> HostCounters:
        counters = self._hosts.get(address)
        if counters is None:
            counters = self._hosts[address] = HostCounters()
        return counters

    def _flush(self, out: list[Event], t: float) -> None:
        hosts, self._hosts = self._hosts, {}
        omitted = 0
        if len(hosts) > self.max_hosts:
            ranked = sorted(
                hosts.items(), key=lambda kv: kv[1].bytes_out + kv[1].bytes_in, reverse=True
            )
            kept = dict(ranked[: self.max_hosts])
            rest = HostCounters()
            for _, c in ranked[self.max_hosts :]:
                rest.packets_out += c.packets_out
                rest.bytes_out += c.bytes_out
                rest.packets_in += c.packets_in
                rest.bytes_in += c.bytes_in
                rest.new_flows_out += c.new_flows_out
                rest.failed_flows_out += c.failed_flows_out
            kept[OTHER_HOSTS] = rest
            omitted = len(hosts) - self.max_hosts
            hosts = kept
        if hosts:
            out.append(
                TickSummary(
                    t=t, hosts=hosts, hosts_omitted=omitted, dropped_events=self.queue.dropped
                )
            )
