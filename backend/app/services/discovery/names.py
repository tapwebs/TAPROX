"""Reverse DNS for discovered addresses.

A name is what a DNS server (or the operating system's own name services) says about an address. It
is recorded as such, never treated as proof of what the device is. Lookups are slow and can hang, so
they run through the bounded pool and are abandoned at the deadline.
"""

import socket
import threading
from collections.abc import Callable, Sequence

from app.services.discovery.pool import run_parallel


def reverse_lookup(ip: str) -> str | None:
    """The operating system's answer for this address, or None when there is none."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):  # herror and gaierror are OSError subclasses
        return None


def resolve_names(
    ips: Sequence[str],
    *,
    stop: threading.Event,
    deadline: float,
    lookup: Callable[[str], str | None] = reverse_lookup,
    workers: int = 8,
    grace: float = 1.0,
) -> dict[str, str]:
    names: dict[str, str] = {}
    for outcome in run_parallel(
        ips, lookup, workers=workers, stop=stop, deadline=deadline, grace=grace
    ):
        name = outcome.value
        if outcome.error is None and name and name != outcome.item:
            names[outcome.item] = name
    return names
