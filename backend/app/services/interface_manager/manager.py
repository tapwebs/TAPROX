"""Keeps the current view of the machine's network interfaces and notices changes.

No background task: the manager refreshes on demand (with a short cache) and compares each
snapshot with the previous one. Changes are therefore detected whenever interfaces are read, for
example by a screen that polls. Adapters that vanish stay listed as `present: false` for the rest of
the session, so a removal and a later reconnection are both visible.
"""

import logging
import threading
import time
from collections import deque
from collections.abc import Callable
from datetime import UTC, datetime

from app.schemas.interfaces import InterfaceEvent, InterfaceList, NetworkInterface
from app.services.interface_manager.build import build_interface
from app.services.interface_manager.raw import (
    InterfaceProvider,
    InterfaceProviderError,
    RawInterface,
)

log = logging.getLogger(__name__)

_KIND_ORDER = {"ethernet": 0, "wifi": 1}
_MAX_ABSENT = 64


class InterfaceNotFoundError(LookupError):
    """No interface with that id has been seen in this session."""


def _describe(addresses: list[tuple[str, int]]) -> str:
    return ", ".join(f"{a}/{p}" for a, p in addresses) or "no IPv4 address"


def _sort_key(nic: NetworkInterface) -> tuple[bool, bool, int, bool, int, str]:
    hardware_rank = 0 if nic.hardware in ("physical", "usb") else 1
    return (
        not nic.present,
        nic.support != "supported",
        hardware_rank,
        nic.connection != "connected",
        _KIND_ORDER.get(nic.kind, 2),
        nic.name.lower(),
    )


class InterfaceManager:
    def __init__(
        self,
        provider: InterfaceProvider,
        *,
        ttl_seconds: float = 2.0,
        max_events: int = 200,
        monotonic: Callable[[], float] = time.monotonic,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._provider = provider
        self._ttl = ttl_seconds
        self._monotonic = monotonic
        self._now = now
        self._lock = threading.RLock()
        self._events: deque[InterfaceEvent] = deque(maxlen=max_events)
        self._sequence = 0
        self._present: dict[str, RawInterface] = {}
        self._absent: dict[str, tuple[RawInterface, datetime]] = {}
        self._last_seen: dict[str, datetime] = {}
        self._baselined = False
        self._cached: InterfaceList | None = None
        self._refreshed_at: float | None = None

    # --- public ------------------------------------------------------------------------------

    def snapshot(self, *, force: bool = False) -> InterfaceList:
        with self._lock:
            fresh = (
                self._cached is not None
                and self._refreshed_at is not None
                and self._monotonic() - self._refreshed_at < self._ttl
            )
            if fresh and not force and self._cached is not None:
                return self._cached.model_copy(update={"new_events": []})
            return self._refresh()

    def get(self, interface_id: str) -> NetworkInterface:
        for nic in self.snapshot().interfaces:
            if nic.id == interface_id:
                return nic
        raise InterfaceNotFoundError(interface_id)

    def events(self, limit: int = 50) -> list[InterfaceEvent]:
        with self._lock:
            return list(reversed(self._events))[:limit]

    # --- internals ---------------------------------------------------------------------------

    def _refresh(self) -> InterfaceList:
        now = self._now()
        try:
            raws, warnings = self._provider.list_interfaces()
        except InterfaceProviderError as exc:
            if self._cached is None:
                raise
            self._refreshed_at = self._monotonic()  # do not hammer a failing provider
            log.warning("Interface refresh failed: %s", exc)
            self._cached = self._cached.model_copy(
                update={
                    "stale": True,
                    "new_events": [],
                    "warnings": [
                        *self._cached.warnings,
                        f"{exc} Showing the last known interface information.",
                    ],
                }
            )
            return self._cached

        events = self._diff(raws, now) if self._baselined else []
        self._baselined = True
        current = {r.id: r for r in raws}
        for gone_id, gone in self._present.items():
            if gone_id not in current:
                self._absent[gone_id] = (gone, self._last_seen.get(gone_id, now))
        for returned in current:
            self._absent.pop(returned, None)
        self._present = current
        self._last_seen.update(dict.fromkeys(current, now))
        self._trim_absent()

        interfaces: list[NetworkInterface] = []
        for raw in raws:
            try:
                interfaces.append(build_interface(raw, last_seen_at=now))
            except Exception:  # one malformed adapter must not hide the others
                log.exception("Could not interpret interface %r", raw.name)
                warnings = [
                    *warnings,
                    f"Interface '{raw.name}' could not be interpreted and is hidden.",
                ]
        for raw, seen in self._absent.values():
            interfaces.append(build_interface(raw, present=False, last_seen_at=seen))
        interfaces.sort(key=_sort_key)

        self._cached = InterfaceList(
            interfaces=interfaces,
            collected_at=now,
            provider=self._provider.name,
            stale=False,
            warnings=warnings,
            new_events=events,
        )
        self._refreshed_at = self._monotonic()
        return self._cached

    def _trim_absent(self) -> None:
        overflow = len(self._absent) - _MAX_ABSENT
        if overflow > 0:
            for key, _ in sorted(self._absent.items(), key=lambda kv: kv[1][1])[:overflow]:
                del self._absent[key]

    def _event(
        self, kind: str, raw: RawInterface, at: datetime, detail: str | None = None
    ) -> InterfaceEvent:
        self._sequence += 1
        event = InterfaceEvent(
            sequence=self._sequence,
            at=at,
            kind=kind,  # type: ignore[arg-type]
            interface_id=raw.id,
            interface_name=raw.name,
            detail=detail,
        )
        self._events.append(event)
        return event

    def _diff(self, raws: list[RawInterface], now: datetime) -> list[InterfaceEvent]:
        current = {r.id: r for r in raws}
        events: list[InterfaceEvent] = []
        for ident in sorted(self._present, key=lambda i: self._present[i].name.lower()):
            if ident not in current:
                events.append(self._event("removed", self._present[ident], now))
        for raw in sorted(raws, key=lambda r: r.name.lower()):
            before = self._present.get(raw.id)
            if before is None:
                events.append(self._event("appeared", raw, now))
                continue
            was, is_ = build_interface(before).connection, build_interface(raw).connection
            if was != is_ and "unknown" not in (was, is_):
                events.append(
                    self._event("connected" if is_ == "connected" else "disconnected", raw, now)
                )
            if before.ipv4 != raw.ipv4:
                events.append(
                    self._event(
                        "address_changed",
                        raw,
                        now,
                        f"{_describe(before.ipv4)} → {_describe(raw.ipv4)}",
                    )
                )
        return events
