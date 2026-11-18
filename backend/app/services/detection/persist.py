"""Asynchronous, bounded, honest alert persistence.

The detection worker calls `offer` for every alert it creates or updates. `offer` only touches memory: it merges
the alert into a bounded pending set (one entry per dedup key) and returns. One writer thread writes the pending
set in a single short transaction, at most once per interval (or sooner when many are waiting). So the database
can be slow, locked or gone without the detection worker, the flow engine or the capture threads ever waiting.

Honesty rules:
* an alert is counted as stored only after its transaction committed;
* when the database refuses a batch (locked, busy, unavailable) the batch is kept and retried;
* when a pending set is full, or the database rejects one particular alert, or the application closes with alerts
  still waiting, the alert is counted (`alerts_not_stored`), shown in the run's warnings, and logged.
"""

import logging
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.exc import OperationalError

from app.services.detection.alerts import Alert
from app.services.detection.store import AlertStore, PendingAlert, RunFinish, RunRecord

log = logging.getLogger(__name__)

MAX_PENDING = 2_000
MAX_CONTROL = 1_000  # run starts and finishes waiting
FLUSH_INTERVAL = 1.0
FLUSH_TRIGGER = 50
WRITE_CHUNK = 10  # alerts per transaction: about 30 ms, so the database lock is never held for long
RETRIES = 5
BACKOFF = 0.1

DELAYED = "Alert writes were delayed: the database was busy or unavailable."
NOT_STORED_FULL = "Some alerts could not be stored: the write queue was full."
REJECTED = "An alert was rejected by the database and was not stored."


def _now() -> datetime:
    return datetime.now(UTC)


class WriterBusy(RuntimeError):
    """The writer is in the middle of a long write and did not become free in time."""


def _describe(exc: BaseException) -> str:
    """An error for the status: its kind and the database's own message, never the SQL or its parameters."""
    inner = getattr(exc, "orig", None)
    detail = str(inner if inner is not None else "")[:120]
    return f"{type(exc).__name__}: {detail}" if detail else type(exc).__name__


@dataclass(slots=True)
class _Entry:
    run: int
    alert: Alert
    occurrences: int


@dataclass(slots=True)
class _Counters:
    flushes: int = 0
    writes: int = 0
    failed_flushes: int = 0
    consecutive_failures: int = 0
    alerts_inserted: int = 0
    alerts_updated: int = 0
    dropped_alerts: int = 0
    rejected_alerts: int = 0
    rejected_runs: int = 0
    lost_at_shutdown: int = 0
    pruned_alerts: int = 0
    pruned_open_alerts: int = 0
    pruned_runs: int = 0
    prune_failures: int = 0
    longest_write_ms: float = 0.0
    last_error: str | None = None
    last_error_at: datetime | None = None
    last_flush_at: datetime | None = None
    retention_days: int | None = None
    retention_rows: int | None = None
    retention_problems: tuple[str, ...] = ()


class AlertWriter:
    def __init__(
        self,
        store: AlertStore,
        *,
        interval: float = FLUSH_INTERVAL,
        trigger: int = FLUSH_TRIGGER,
        max_pending: int = MAX_PENDING,
        retries: int = RETRIES,
        backoff: float = BACKOFF,
        chunk: int = WRITE_CHUNK,
        clock: Callable[[], datetime] = _now,
    ) -> None:
        # Nothing here does I/O or starts a thread (the contract export builds the application with no database).
        self._store = store
        self._interval = interval
        self._trigger = trigger
        self._max_pending = max_pending
        self._retries = max(1, retries)
        self._backoff = backoff
        self._chunk = max(1, chunk)
        self._clock = clock
        self._cond = threading.Condition()
        self._flush_lock = threading.RLock()
        self._pending: dict[str, _Entry] = {}
        self._starts: list[RunRecord] = []
        self._finishes: list[RunFinish] = []
        self._active: set[int] = set()
        self._warnings: dict[int, list[str]] = {}
        self._d = _Counters()
        self._stored_ids: dict[
            int, int
        ] = {}  # run key -> stored run id, kept for the status after the run ends
        self._thread: threading.Thread | None = None
        self._stopping = False
        self._closed = False
        self._prune_requested = False
        self._wake = threading.Event()

    # --- called from the detection worker (memory only) ------------------------------------------------------

    def run_started(self, record: RunRecord) -> None:
        with self._cond:
            if self._closed or len(self._starts) >= MAX_CONTROL:
                self._d.rejected_runs += 1
                return
            self._starts.append(record)
            self._active.add(record.key)
            self._cond.notify()

    def run_finished(self, finish: RunFinish) -> None:
        with self._cond:
            if self._closed or len(self._finishes) >= MAX_CONTROL:
                self._d.rejected_runs += 1
                return
            self._finishes.append(finish)
            self._active.discard(finish.key)
            self._cond.notify()

    def offer(self, run: int, alert: Alert, outcome: str) -> None:
        """Queue (or merge) one alert snapshot. `outcome` is what the alert book did: created, updated or unchanged."""
        occurrences = 1 if outcome in ("created", "updated") else 0
        with self._cond:
            if self._closed:
                self._d.dropped_alerts += 1
                return
            entry = self._pending.get(alert.dedup_key)
            if entry is None:
                if len(self._pending) >= self._max_pending:
                    self._d.dropped_alerts += 1
                    self._warn_locked(run, NOT_STORED_FULL)
                    return
                self._pending[alert.dedup_key] = _Entry(run, alert, occurrences)
            else:
                entry.run, entry.alert = run, alert
                entry.occurrences += occurrences
            if len(self._pending) >= self._trigger:
                self._cond.notify()

    # --- reading state ----------------------------------------------------------------------------------------

    def warnings(self, run: int) -> list[str]:
        with self._cond:
            return list(self._warnings.get(run, ()))

    def stored_run_id(self, run: int) -> int | None:
        with self._cond:
            known = self._stored_ids.get(run)
        return known if known is not None else self._store.run_db_id(run)

    def _remember_runs(self, ids: dict[int, int]) -> None:
        with self._cond:
            self._stored_ids.update(ids)
            while len(self._stored_ids) > 100:
                del self._stored_ids[next(iter(self._stored_ids))]

    def diagnostics(self) -> dict[str, Any]:
        with self._cond:
            d = self._d
            return {
                "running": self._thread is not None and self._thread.is_alive(),
                "healthy": d.consecutive_failures == 0,
                "pending_alerts": len(self._pending),
                "max_pending": self._max_pending,
                "alerts_inserted": d.alerts_inserted,
                "alerts_updated": d.alerts_updated,
                "flushes": d.flushes,
                "writes": d.writes,
                "failed_flushes": d.failed_flushes,
                "consecutive_failures": d.consecutive_failures,
                "dropped_alerts": d.dropped_alerts,
                "rejected_alerts": d.rejected_alerts,
                "lost_at_shutdown": d.lost_at_shutdown,
                "alerts_not_stored": d.dropped_alerts + d.rejected_alerts + d.lost_at_shutdown,
                "last_error": d.last_error,
                "last_error_at": d.last_error_at,
                "last_flush_at": d.last_flush_at,
                "longest_write_ms": round(d.longest_write_ms, 1),
                "pruned_alerts": d.pruned_alerts,
                "pruned_open_alerts": d.pruned_open_alerts,
                "pruned_runs": d.pruned_runs,
                "prune_failures": d.prune_failures,
                "retention_days": d.retention_days,
                "retention_rows": d.retention_rows,
                "retention_problems": list(d.retention_problems),
            }

    # --- thread -----------------------------------------------------------------------------------------------

    def start(self) -> None:
        with self._cond:
            if self._thread is not None or self._closed:
                return
            self._thread = threading.Thread(target=self._loop, daemon=True, name="alert-writer")
            self._thread.start()

    def _loop(self) -> None:
        while True:
            with self._cond:
                if not self._stopping and not self._due():
                    self._cond.wait(self._interval)
                stopping = self._stopping
            ok = True
            try:
                ok = self.flush()
                self._prune_if_requested()
            except Exception:  # the writer thread must survive anything
                log.exception("The alert writer failed")
                self._record_error("unexpected error")
                ok = False
            if stopping:
                return
            if not ok:
                self._wake.wait(self._interval)  # do not spin against a database that is down

    def _due(self) -> bool:
        return bool(
            self._starts
            or self._finishes
            or self._prune_requested
            or len(self._pending) >= self._trigger
        )

    def request_prune(self) -> None:
        """Apply the retention limits soon, on the writer thread (used at start-up: it can take a while)."""
        with self._cond:
            self._prune_requested = True
            self._cond.notify()

    def _prune_if_requested(self) -> None:
        with self._cond:
            requested, self._prune_requested = self._prune_requested, False
        if requested:
            with self._flush_lock:
                self.prune()

    def stop(self, timeout: float = 5.0) -> None:
        """Write what is pending (final flush), end the thread, and count anything that could not be stored."""
        with self._cond:
            if self._closed:
                return
            self._stopping = True
            thread = self._thread
            self._cond.notify_all()
        self._wake.set()
        if thread is not None:
            thread.join(timeout)
        else:
            self.flush()
        with self._cond:
            self._closed = True
            leftover = len(self._pending)
            self._d.lost_at_shutdown += leftover
            self._pending.clear()
            self._starts.clear()
            self._finishes.clear()
        if leftover:
            log.error(
                "%d alert(s) were not stored: the database was unavailable at shutdown", leftover
            )

    @contextmanager
    def exclusive(self, timeout: float | None = None) -> Iterator[None]:
        """No flush runs while this is held (used by delete-all so a flush cannot bring deleted alerts back).

        Raises WriterBusy if a flush is still running after `timeout` seconds.
        """
        if not self._flush_lock.acquire(timeout=-1 if timeout is None else timeout):
            raise WriterBusy("The alert writer is busy.")
        try:
            yield
        finally:
            self._flush_lock.release()

    def discard_pending(self) -> int:
        with self._cond:
            n = len(self._pending)
            self._pending.clear()
            return n

    # --- flushing ---------------------------------------------------------------------------------------------

    def flush(self) -> bool:
        """Write everything pending now. True when nothing is left waiting because of a failure."""
        with self._flush_lock:
            with self._cond:
                starts, items = self._starts, self._pending
                # a run's warnings travel with its record, including ones added after it finished
                finishes = [
                    replace(
                        f,
                        warnings=list(dict.fromkeys([*f.warnings, *self._warnings.pop(f.key, [])])),
                    )
                    for f in self._finishes
                ]
                self._starts, self._finishes, self._pending = [], [], {}
            if not (starts or finishes or items):
                return True
            return self._write(starts, items, finishes)

    def _write(
        self, starts: list[RunRecord], items: dict[str, _Entry], finishes: list[RunFinish]
    ) -> bool:
        """Write a backlog as a series of small transactions: runs first, then alerts, then run ends."""
        entries = list(items.items())
        pieces: list[tuple[list[RunRecord], dict[str, _Entry], list[RunFinish]]] = [
            ([], dict(entries[n : n + self._chunk]), [])
            for n in range(0, len(entries), self._chunk)
        ] or [([], {}, [])]
        pieces[0] = (starts, pieces[0][1], [])
        pieces[-1] = (pieces[-1][0], pieces[-1][1], pieces[-1][2] + finishes)
        inserted = 0
        for position, (p_starts, p_items, p_finishes) in enumerate(pieces):
            result = self._write_piece(p_starts, p_items, p_finishes)
            if (
                result is None
            ):  # the database refused it; this piece is back in the queue, so is the rest
                for later in pieces[position + 1 :]:
                    self._restore(*later)
                return False
            inserted += result
        with self._cond:
            self._d.flushes += 1
            self._d.consecutive_failures = 0
            self._d.last_flush_at = self._clock()
        self._after_write(inserted=inserted, finished=bool(finishes))
        return True

    def _write_piece(
        self, starts: list[RunRecord], items: dict[str, _Entry], finishes: list[RunFinish]
    ) -> int | None:
        """One transaction, retried while the database is busy. Returns the alerts inserted, or None if it failed."""
        batch = [PendingAlert(e.run, e.alert, e.occurrences) for e in items.values()]
        error: Exception = OperationalError("write", {}, Exception("not attempted"))
        for attempt in range(self._retries):
            began = time.perf_counter()
            try:
                result = self._store.write(starts, batch, finishes)
            except OperationalError as exc:  # locked, busy, I/O: worth trying again
                error = exc
                if attempt + 1 < self._retries and self._backoff:
                    time.sleep(self._backoff)
                continue
            except Exception as exc:  # the data itself is the problem: find which part
                log.warning(
                    "The alert writer could not store a batch (%s); trying each item",
                    type(exc).__name__,
                )
                return self._write_each(starts, items, finishes)
            self._remember_runs(result.run_ids)
            self._succeeded(result.inserted, result.updated, (time.perf_counter() - began) * 1000)
            return result.inserted
        self._restore(starts, items, finishes)
        with self._cond:
            self._d.failed_flushes += 1
            self._d.consecutive_failures += 1
            self._d.last_error = _describe(error)
            self._d.last_error_at = self._clock()
            for run in self._active | {e.run for e in items.values()} | {f.key for f in finishes}:
                self._warn_locked(run, DELAYED)
        log.warning(
            "Alert writes delayed (%s); %d alert(s) are waiting", type(error).__name__, len(items)
        )
        return None

    def _write_each(
        self, starts: list[RunRecord], items: dict[str, _Entry], finishes: list[RunFinish]
    ) -> int | None:
        """After a non-lock failure: one transaction per piece, so one bad alert cannot hold back the rest."""
        inserted = updated = 0
        pieces: list[tuple[str, Any]] = (
            [("start", s) for s in starts]
            + [("alert", (k, e)) for k, e in items.items()]
            + [("finish", f) for f in finishes]
        )
        for position, (kind, piece) in enumerate(pieces):
            try:
                if kind == "start":
                    self._remember_runs(self._store.write([piece], [], []).run_ids)
                elif kind == "alert":
                    entry = piece[1]
                    r = self._store.write(
                        [], [PendingAlert(entry.run, entry.alert, entry.occurrences)], []
                    )
                    inserted, updated = inserted + r.inserted, updated + r.updated
                else:
                    self._store.write([], [], [piece])
            except (
                OperationalError
            ) as exc:  # the database went away part-way: keep this piece and the rest
                rest = pieces[position:]
                self._restore(
                    [p for k, p in rest if k == "start"],
                    {p[0]: p[1] for k, p in rest if k == "alert"},
                    [p for k, p in rest if k == "finish"],
                )
                self._record_error(_describe(exc), failure=True)
                return None
            except Exception as exc:
                with self._cond:
                    if kind == "alert":
                        self._d.rejected_alerts += 1
                        self._warn_locked(piece[1].run, REJECTED)
                    else:
                        self._d.rejected_runs += 1
                self._record_error(_describe(exc))
                log.warning("The database rejected a %s (%s)", kind, type(exc).__name__)
        self._succeeded(inserted, updated, 0.0)
        return inserted

    def _succeeded(self, inserted: int, updated: int, ms: float) -> None:
        with self._cond:
            d = self._d
            d.writes += 1
            d.alerts_inserted += inserted
            d.alerts_updated += updated
            d.longest_write_ms = max(d.longest_write_ms, ms)

    def note_error(self, message: str) -> None:
        """Show an error that happened around persistence (for example while recovering at start-up)."""
        self._record_error(message)

    def _record_error(self, message: str, *, failure: bool = False) -> None:
        with self._cond:
            self._d.last_error = message
            self._d.last_error_at = self._clock()
            if failure:
                self._d.failed_flushes += 1
                self._d.consecutive_failures += 1

    def _restore(
        self, starts: list[RunRecord], items: dict[str, _Entry], finishes: list[RunFinish]
    ) -> None:
        """Put an unwritten batch back in front of whatever arrived meanwhile, merging counts for the same alert."""
        with self._cond:
            self._starts = starts + self._starts
            self._finishes = finishes + self._finishes
            merged = dict(items)
            for key, newer in self._pending.items():
                older = merged.get(key)
                merged[key] = (
                    newer
                    if older is None
                    else _Entry(newer.run, newer.alert, older.occurrences + newer.occurrences)
                )
            self._pending = merged

    def _warn_locked(self, run: int, message: str) -> None:
        warnings = self._warnings.setdefault(run, [])
        if message not in warnings:
            warnings.append(message)

    # --- retention --------------------------------------------------------------------------------------------

    def _after_write(self, *, inserted: int, finished: bool) -> None:
        if inserted or finished:
            self.prune()

    def prune(self) -> None:
        """Apply the retention limits now. A failure here never undoes a write; it is counted and shown."""
        try:
            limits = self._store.retention()
            result = self._store.prune(days=limits.days, rows=limits.rows)
        except Exception as exc:
            log.warning("Alert retention failed (%s)", type(exc).__name__)
            with self._cond:
                self._d.prune_failures += 1
            self._record_error(_describe(exc))
            return
        with self._cond:
            d = self._d
            d.retention_days, d.retention_rows = limits.days, limits.rows
            d.retention_problems = tuple(limits.problems)
            d.pruned_alerts += result.alerts_deleted
            d.pruned_open_alerts += result.open_deleted
            d.pruned_runs += result.runs_deleted
            if result.open_deleted:
                for run in self._active:
                    self._warn_locked(
                        run,
                        f"{result.open_deleted} open alerts were deleted to stay within the retention limit.",
                    )
