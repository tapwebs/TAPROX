"""Runs discovery scans: one at a time, on one tracked thread, with limits that always hold.

Safety properties (each has a test):

* Active probing only ever targets hosts of a private network the chosen interface is itself
  connected to, capped at /22, and only after the user explicitly confirmed authorisation.
* One scan at a time. Every scan has a hard time limit and can be cancelled; cancelling or timing
  out keeps what was already found.
* The scan thread is tracked and joined at shutdown, probes run on a bounded pool of daemon
  threads, and nothing blocks the web server's event loop.
* Not answering is not evidence of absence: unanswered addresses are never recorded and known
  devices are never marked offline. Observed facts and inferred ones stay separate in storage.
"""

import json
import logging
import threading
import time
import uuid
from collections.abc import Callable
from contextlib import closing
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv4Network
from typing import Any, Protocol

from sqlalchemy import Engine, func, select, update
from sqlalchemy.orm import Session

from app.models.discovery_scan import DiscoveryScan
from app.repositories.devices import (
    DEFAULT_OBSERVATION_CAP,
    Observation,
    record_observation,
    set_hostname,
)
from app.schemas.discovery import Scan, ScanRequest
from app.schemas.interfaces import NetworkInterface
from app.services.discovery.backend import DiscoveryBackend, DiscoveryError, NeighborEntry
from app.services.discovery.names import resolve_names, reverse_lookup
from app.services.discovery.oui import OuiDatabase, default_database
from app.services.discovery.pool import run_parallel
from app.services.discovery.subnet import SubnetError, scan_targets, validate_scan_target
from app.services.interface_manager.manager import InterfaceManager, InterfaceNotFoundError
from app.services.interface_manager.raw import InterfaceProviderError
from app.services.netutil import is_unicast_ip, is_unicast_mac, normalize_mac

log = logging.getLogger(__name__)

ABORT_AFTER_ERRORS = (
    16  # this many probe errors with not one clean result: stop, don't repeat it 1000 times
)
MAX_WARNINGS = 20
_BATCH = 25


class ScanRefused(Exception):
    """The request cannot start a scan. status/code are what the API reports."""

    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code


class _Job:
    """The live state of the running scan. Read by API threads, written by the scan thread."""

    def __init__(
        self,
        scan_id: str,
        request: ScanRequest,
        nic: NetworkInterface,
        network: IPv4Network | None,
        started_at: datetime,
        deadline: float,
    ) -> None:
        self.id = scan_id
        self.request = request
        self.nic = nic
        self.network = network
        self.started_at = started_at
        self.started_monotonic = time.monotonic()
        self.deadline = deadline
        self.cancel = threading.Event()
        self.timed_out = False
        self._lock = threading.Lock()
        self._phase: str | None = "preparing"
        self._targets_total = 0
        self._targets_done = 0
        self._devices_found = 0
        self._warnings: list[str] = []

    def progress(self, **values: Any) -> None:
        with self._lock:
            for key, value in values.items():
                setattr(self, f"_{key}", value)

    def warn(self, message: str) -> None:
        with self._lock:
            if len(self._warnings) < MAX_WARNINGS and message not in self._warnings:
                self._warnings.append(message)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "phase": self._phase,
                "targets_total": self._targets_total,
                "targets_done": self._targets_done,
                "devices_found": self._devices_found,
                "warnings": list(self._warnings),
            }

    def expired(self) -> bool:
        return time.monotonic() >= self.deadline

    def should_stop(self) -> bool:
        if self.cancel.is_set():
            return True
        if self.expired():
            self.timed_out = True
            return True
        return False

    def view(self) -> Scan:
        state = self.snapshot()
        return Scan(
            id=self.id,
            interface_id=self.nic.id,
            interface_name=self.nic.name,
            mode=self.request.mode,
            network=str(self.network) if self.network else None,
            status="running",
            phase=state["phase"],
            cancel_requested=self.cancel.is_set(),
            targets_total=state["targets_total"],
            targets_done=state["targets_done"],
            devices_found=state["devices_found"],
            started_at=self.started_at,
            finished_at=None,
            elapsed_seconds=round(time.monotonic() - self.started_monotonic, 1),
            resolve_names=self.request.resolve_names,
            error_code=None,
            error_message=None,
            warnings=state["warnings"],
        )


class _Recorder:
    """Writes observations for one scan in small batches, so partial results survive any ending."""

    def __init__(
        self,
        session: Session,
        oui: OuiDatabase,
        job: _Job,
        clock: Callable[[], datetime],
    ) -> None:
        self._session = session
        self._oui = oui
        self._job = job
        self._clock = clock
        self._pending = 0
        self.found: dict[str, str | None] = {}  # MAC -> address to look a name up for
        self.confirmed: set[tuple[str, str]] = set()  # (MAC, IP) that answered our own ARP

    def commit(self) -> None:
        self._session.commit()
        self._pending = 0

    def _write(
        self,
        mac: str,
        ip: str | None,
        source: str,
        confidence: str,
        *,
        state: str | None = None,
        count: bool = True,
    ) -> None:
        try:
            record_observation(
                self._session,
                Observation(
                    mac=mac,
                    ip=ip,
                    interface_id=self._job.nic.id,
                    source=source,
                    confidence=confidence,
                    observed_at=self._clock(),
                    neighbor_state=state,
                    scan_id=self._job.id,
                ),
                oui=self._oui,
                observation_cap=DEFAULT_OBSERVATION_CAP,
            )
        except ValueError:
            log.warning("Ignored an unusable observation for %r", mac)
            return
        if count:
            known = self.found.get(mac)
            if mac not in self.found or (ip and ":" not in ip and (known is None or ":" in known)):
                self.found[mac] = ip
            self._job.progress(devices_found=len(self.found))
        self._pending += 1
        if self._pending >= _BATCH:
            self.commit()

    def local(self, nic: NetworkInterface) -> None:
        """This computer's own interface: certain, because we read it from the operating system."""
        mac = normalize_mac(nic.mac)
        if mac and is_unicast_mac(mac):
            first = nic.ipv4[0].address if nic.ipv4 else None
            self._write(mac, first, "local_interface", "confirmed", count=False)

    def arp_reply(self, ip: str, raw_mac: str) -> None:
        mac = normalize_mac(raw_mac)
        if mac is None or not is_unicast_mac(mac):
            return
        self.confirmed.add((mac, ip))
        self._write(mac, ip, "arp", "confirmed")

    def neighbors(self, entries: list[NeighborEntry]) -> None:
        nic = self._job.nic
        own_macs = {normalize_mac(nic.mac)} if nic.mac else set()
        own_ips = {a.address for a in (*nic.ipv4, *nic.ipv6)}
        for entry in entries:
            on_interface = (entry.if_index is not None and entry.if_index == nic.os_index) or (
                entry.if_name is not None and entry.if_name == nic.name
            )
            mac = normalize_mac(entry.mac)
            ip = entry.ip.partition("%")[0]
            state = entry.state.lower()
            if (
                not on_interface
                or mac is None
                or not is_unicast_mac(mac)
                or mac in own_macs
                or not is_unicast_ip(ip)
                or ip in own_ips
                or state in ("incomplete", "unreachable")
                or (mac, ip) in self.confirmed
            ):
                continue
            confidence = "stale" if state in ("stale", "unknown") else "probable"
            self._write(
                mac, ip, "ndp" if ":" in ip else "os_neighbor_table", confidence, state=state
            )

    def name_targets(self) -> list[tuple[str, str]]:
        return [(mac, ip) for mac, ip in self.found.items() if ip]

    def attach_names(self, names: dict[str, str]) -> None:
        for mac, ip in self.name_targets():
            if ip in names:
                set_hostname(self._session, mac, names[ip], source="reverse_dns")


class ScanActivityRecord(Protocol):
    """Where a scan's start and end are noted, so detection ignores this computer's own probes."""

    def begin(self) -> int: ...

    def end(self, token: int) -> None: ...


class DiscoveryService:
    def __init__(
        self,
        engine: Engine,
        interfaces: InterfaceManager,
        backend: DiscoveryBackend,
        *,
        oui: OuiDatabase | None = None,
        lookup: Callable[[str], str | None] = reverse_lookup,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        probe_workers: int = 48,
        probe_timeout: float = 2.0,
        max_duration: float = 120.0,
        grace: float = 3.0,
        name_workers: int = 8,
        name_timeout: float = 10.0,
        ipv6_settle: float = 1.5,
        activity: ScanActivityRecord | None = None,
    ) -> None:
        self._activity = activity
        self._engine = engine
        self._interfaces = interfaces
        self._backend = backend
        self._oui = oui or default_database()
        self._lookup = lookup
        self._clock = clock
        # Called with the scan id when a scan ends (the application feeds rule TT-DEV-001).
        self.on_scan_finished: Callable[[str], None] | None = None
        self._probe_workers = probe_workers
        self._probe_timeout = probe_timeout
        self._max_duration = max_duration
        self._grace = grace
        self._name_workers = name_workers
        self._name_timeout = name_timeout
        self._ipv6_settle = ipv6_settle
        self._lock = threading.Lock()
        self._job: _Job | None = None
        self._thread: threading.Thread | None = None
        self._closed = False

    # --- public ----------------------------------------------------------------------------

    def start(self, request: ScanRequest) -> Scan:
        nic = self._usable_interface(request.interface_id)
        network: IPv4Network | None = None
        if request.mode == "active":
            if not request.confirm_authorized:
                raise ScanRefused(
                    400,
                    "authorization_required",
                    "Active discovery sends ARP requests to every address of the network. "
                    "Confirm that you are authorised to scan this network.",
                )
            try:
                network = validate_scan_target(
                    [IPv4Network(a.network) for a in nic.ipv4], request.network
                )
            except SubnetError as exc:
                raise ScanRefused(422, exc.code, str(exc)) from exc
        elif request.network:
            raise ScanRefused(
                422, "network_not_applicable", "A subnet only applies to active scans."
            )
        try:
            self._backend.preflight()
        except DiscoveryError as exc:
            raise ScanRefused(503, f"discovery_{exc.code}", str(exc)) from exc

        with self._lock:
            if self._closed:
                raise ScanRefused(503, "shutting_down", "TAPROX is shutting down.")
            if self._job is not None:
                raise ScanRefused(
                    409,
                    "scan_in_progress",
                    "A scan is already running. Wait for it to finish or cancel it first.",
                )
            job = _Job(
                str(uuid.uuid4()),
                request,
                nic,
                network,
                self._clock(),
                time.monotonic() + self._max_duration,
            )
            with Session(self._engine) as session:
                session.add(
                    DiscoveryScan(
                        id=job.id,
                        interface_id=nic.id,
                        interface_name=nic.name,
                        mode=request.mode,
                        network=str(network) if network else None,
                        status="running",
                        phase="preparing",
                        started_at=job.started_at,
                        resolve_names=request.resolve_names,
                    )
                )
                session.commit()
            thread = threading.Thread(
                target=self._run, args=(job,), name="tapnettrack-scan", daemon=True
            )
            self._job, self._thread = job, thread
            try:
                thread.start()
            except Exception as exc:  # e.g. the operating system has no thread to give
                self._job = self._thread = None
                self._finish(
                    job, "failed", ("scan_not_started", "The scan thread could not start.")
                )
                log.exception("Could not start the scan thread")
                raise ScanRefused(
                    503, "scan_not_started", "The scan could not be started. Try again."
                ) from exc
        return job.view()

    def current(self) -> Scan | None:
        with self._lock:
            return self._job.view() if self._job else None

    def get(self, scan_id: str) -> Scan | None:
        with self._lock:
            if self._job is not None and self._job.id == scan_id:
                return self._job.view()
        with Session(self._engine) as session:
            row = session.get(DiscoveryScan, scan_id)
            return self._from_row(row) if row else None

    def list(self, *, limit: int, offset: int) -> tuple[list[Scan], int]:
        with Session(self._engine) as session:
            total = session.scalar(select(func.count()).select_from(DiscoveryScan)) or 0
            rows = session.scalars(
                select(DiscoveryScan)
                .order_by(DiscoveryScan.started_at.desc(), DiscoveryScan.id.desc())
                .limit(limit)
                .offset(offset)
            ).all()
            return [self._from_row(r) for r in rows], total

    def cancel(self, scan_id: str) -> Scan | None:
        """Ask a running scan to stop. A finished scan is returned as is; an unknown id is None."""
        with self._lock:
            if self._job is not None and self._job.id == scan_id:
                self._job.cancel.set()
                return self._job.view()
        return self.get(scan_id)

    def recover(self) -> int:
        """At startup: no scan can be running, so any 'running' row is left over from a crash."""
        with Session(self._engine) as session:
            stale = session.scalars(
                select(DiscoveryScan.id).where(DiscoveryScan.status == "running")
            ).all()
            if stale:
                session.execute(
                    update(DiscoveryScan)
                    .where(DiscoveryScan.id.in_(stale))
                    .values(
                        status="interrupted",
                        phase=None,
                        finished_at=self._clock(),
                        error_code="interrupted",
                        error_message="TAPROX stopped while this scan was running.",
                    )
                )
                session.commit()
            return len(stale)

    def wait_idle(self, timeout: float) -> bool:
        thread = self._thread
        if thread is not None:
            thread.join(timeout)
            return not thread.is_alive()
        return True

    def shutdown(self, timeout: float = 5.0) -> None:
        with self._lock:
            self._closed = True
            job = self._job
        if job is not None:
            job.cancel.set()
        self.wait_idle(timeout)

    # --- validation ------------------------------------------------------------------------

    def _usable_interface(self, interface_id: str) -> NetworkInterface:
        try:
            nic = self._interfaces.get(interface_id)
        except InterfaceNotFoundError as exc:
            raise ScanRefused(
                404, "interface_not_found", f"No interface '{interface_id}' has been seen."
            ) from exc
        except InterfaceProviderError as exc:
            raise ScanRefused(503, f"interfaces_{exc.code}", str(exc)) from exc
        if not nic.discovery.passive:
            code = nic.discovery.reason_code or "unavailable"
            raise ScanRefused(
                409,
                f"interface_{code}",
                nic.discovery.reason or "Discovery is not available on this interface.",
            )
        return nic

    # --- the scan --------------------------------------------------------------------------

    def _run(self, job: _Job) -> None:
        token = self._note_start()
        try:
            self._run_scan(job)
        finally:
            self._note_end(token)

    def _note_start(self) -> int | None:
        if self._activity is None:
            return None
        try:
            return self._activity.begin()
        except Exception:  # a failing record must never break a scan
            log.exception("Could not record the scan's start")
            return None

    def _note_end(self, token: int | None) -> None:
        if self._activity is None or token is None:
            return
        try:
            self._activity.end(token)
        except Exception:
            log.exception("Could not record the scan's end")

    def _run_scan(self, job: _Job) -> None:
        status: str = "failed"
        error: tuple[str, str] | None = (
            "internal_error",
            "The scan stopped because of an internal error.",
        )
        try:
            with Session(self._engine) as session:
                recorder = _Recorder(session, self._oui, job, self._clock)
                try:
                    status, error = self._execute(job, recorder)
                except Exception:
                    log.exception("Discovery scan %s failed", job.id)
                finally:
                    recorder.commit()  # whatever was found is kept, however the scan ended
        except Exception:
            log.exception("Discovery scan %s could not store its results", job.id)
            status, error = "failed", ("storage_error", "The scan results could not be saved.")
        finally:
            try:
                self._finish(job, status, error)
            finally:
                with self._lock:
                    self._job = None

    def _execute(self, job: _Job, rec: _Recorder) -> tuple[str, tuple[str, str] | None]:
        nic = job.nic
        rec.local(nic)

        if job.request.mode == "active":
            failure = self._probe_phase(job, rec)
            if failure:
                return "failed", failure
            if not job.should_stop():
                self._ipv6_phase(job)

        if not job.should_stop():
            job.progress(phase="neighbors")
            try:
                rec.neighbors(self._backend.read_neighbors())
            except DiscoveryError as exc:
                if job.request.mode == "passive":
                    return "failed", (exc.code, str(exc))
                job.warn(f"The operating system's neighbor table could not be read: {exc}")

        if job.request.resolve_names and not job.should_stop() and rec.name_targets():
            job.progress(phase="resolving")
            rec.commit()
            name_deadline = min(job.deadline, time.monotonic() + self._name_timeout)
            names = resolve_names(
                [ip for _, ip in rec.name_targets()],
                stop=job.cancel,
                deadline=name_deadline,
                lookup=self._lookup,
                workers=self._name_workers,
                grace=1.0,
            )
            rec.attach_names(names)
            if time.monotonic() >= name_deadline and not job.cancel.is_set():
                # Lookups that ran out of time look the same as "no name" unless we say so.
                job.warn("Name lookup stopped at its time limit; some host names may be missing.")

        self._warn_if_interface_dropped(job)
        if job.cancel.is_set():
            return "cancelled", None
        return ("timed_out" if job.timed_out else "completed"), None

    def _probe_phase(self, job: _Job, rec: _Recorder) -> tuple[str, str] | None:
        assert job.network is not None  # noqa: S101 - set for every active scan by start()
        nic = job.nic
        own = {IPv4Address(a.address) for a in nic.ipv4}
        source = next(a.address for a in nic.ipv4 if job.network.subnet_of(IPv4Network(a.network)))
        targets = [str(t) for t in scan_targets(job.network, own)]
        total = len(targets)
        job.progress(phase="probing", targets_total=total)

        done = errors = 0
        first_error: Exception | None = None
        with closing(
            run_parallel(
                targets,
                lambda target: self._backend.arp_probe(
                    source, target, timeout=self._probe_timeout, interface=nic.name
                ),
                workers=self._probe_workers,
                stop=job.cancel,
                deadline=job.deadline,
                grace=self._grace,
                abort_after_errors=ABORT_AFTER_ERRORS,
            )
        ) as outcomes:
            for outcome in outcomes:
                done += 1
                if outcome.error is not None:
                    errors += 1
                    first_error = first_error or outcome.error
                else:
                    if outcome.value:
                        rec.arp_reply(outcome.item, outcome.value)
                job.progress(targets_done=done)

        # Fewer outcomes than targets without a cancel or the time limit means the pool gave up
        # because every call it had made failed.
        gave_up = done < total and not job.cancel.is_set() and not job.expired()
        if gave_up and first_error is not None:
            if isinstance(first_error, DiscoveryError):
                return first_error.code, str(first_error)
            log.error("ARP probing failed", exc_info=first_error)
            return "probe_failed", "ARP probing failed on this computer."
        if errors:
            job.warn(f"{errors} of {total} ARP probes failed and were skipped.")
        if done < total:
            if job.cancel.is_set():
                job.warn(f"Cancelled after probing {done} of {total} addresses.")
            else:
                job.timed_out = True
                job.warn(
                    f"Stopped at the {self._max_duration:g} s time limit after probing "
                    f"{done} of {total} addresses."
                )
        return None

    def _ipv6_phase(self, job: _Job) -> None:
        nic = job.nic
        if not nic.ipv6:
            return
        job.progress(phase="ipv6")
        try:
            self._backend.nudge_ipv6(
                if_index=nic.os_index, if_name=nic.name, timeout=min(4.0, self._probe_timeout * 2)
            )
        except Exception as exc:  # best effort by design: IPv6 is a bonus, never a reason to fail
            message = str(exc) if isinstance(exc, DiscoveryError) else "an unexpected error"
            job.warn(f"IPv6 neighbors could not be probed: {message}")
            return
        job.cancel.wait(self._ipv6_settle)  # a moment for answers to reach the neighbor cache

    def _warn_if_interface_dropped(self, job: _Job) -> None:
        try:
            current = {n.id: n for n in self._interfaces.snapshot(force=True).interfaces}
        except InterfaceProviderError:
            return  # cannot tell, so say nothing rather than guess
        nic = current.get(job.nic.id)
        if nic is None or not nic.present or nic.connection != "connected":
            job.warn("The interface disconnected during the scan; the results may be incomplete.")

    # --- persistence -----------------------------------------------------------------------

    def _finish(self, job: _Job, status: str, error: tuple[str, str] | None) -> None:
        state = job.snapshot()
        try:
            with Session(self._engine) as session:
                session.execute(
                    update(DiscoveryScan)
                    .where(DiscoveryScan.id == job.id)
                    .values(
                        status=status,
                        phase=None,
                        targets_total=state["targets_total"],
                        targets_done=state["targets_done"],
                        devices_found=state["devices_found"],
                        finished_at=self._clock(),
                        error_code=error[0] if error else None,
                        error_message=error[1][:500] if error else None,
                        warnings_json=json.dumps([w[:300] for w in state["warnings"]])
                        if state["warnings"]
                        else None,
                    )
                )
                session.commit()
        except Exception:
            log.exception("Could not record the end of scan %s", job.id)
        hook = self.on_scan_finished
        if hook is not None and status == "completed":
            try:
                hook(job.id)
            except Exception:
                log.exception("The inventory check after scan %s failed", job.id)

    def _from_row(self, row: DiscoveryScan) -> Scan:
        warnings: list[str] = json.loads(row.warnings_json) if row.warnings_json else []
        elapsed = (
            (row.finished_at - row.started_at).total_seconds()
            if row.finished_at is not None
            else 0.0
        )
        return Scan(
            id=row.id,
            interface_id=row.interface_id,
            interface_name=row.interface_name,
            mode=row.mode,  # type: ignore[arg-type]
            network=row.network,
            status=row.status,  # type: ignore[arg-type]
            phase=row.phase,  # type: ignore[arg-type]
            cancel_requested=False,
            targets_total=row.targets_total,
            targets_done=row.targets_done,
            devices_found=row.devices_found,
            started_at=row.started_at,
            finished_at=row.finished_at,
            elapsed_seconds=round(elapsed, 1),
            resolve_names=row.resolve_names,
            error_code=row.error_code,
            error_message=row.error_message,
            warnings=warnings,
        )
