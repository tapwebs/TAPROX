"""Runs the detection engine for each analysed session, off the capture threads.

For every capture or opened file the capture service asks `tap_factory` for a tap. The tap feeds M1's bounded
queue; one worker thread per run reads the queue and drives a `DetectionEngine`. The worker can fall behind
(the queue then refuses events and counts them) but it can never slow the decoder, and an error inside it is
caught and counted.

Alerts are also handed, as private snapshots, to an `AlertWriter` (persist.py), which stores them in SQLite on its
own thread. Nothing on the capture, flow or detection threads ever waits for the database. Without a store (unit
tests, the contract export) alerts stay in memory only, and the status says so.
"""

import logging
import threading
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.schemas.alerts import DeleteHistoryResult
from app.services.detection import inventory_hook
from app.services.detection.alerts import MAX_ALERTS_PER_RUN, Alert
from app.services.detection.baseline import BaselineLearner, BaselineView
from app.services.detection.config_store import ConfigStore, network_key
from app.services.detection.engine import DetectionEngine, RunInfo, utcnow
from app.services.detection.persist import AlertWriter
from app.services.detection.registry import (
    Registry,
    RuleConfigError,
    RuleSettings,
    default_registry,
)
from app.services.detection.rules.base import LocalScope
from app.services.detection.store import AlertStore, RunFinish, RunRecord
from app.services.detection.tap import DEFAULT_QUEUE_SIZE, EventQueue, TapContext, TelemetryTap

log = logging.getLogger(__name__)

RUNS_KEPT = 3  # finished runs whose alerts and counters stay readable in memory
BATCH = 256
MAX_VANTAGE_ITEMS = 64


class DetectionUnavailable(RuntimeError):
    """Alert storage is not configured in this service."""


@dataclass(slots=True)
class _Run:
    id: int
    ctx: TapContext
    queue: EventQueue
    engine: DetectionEngine
    started_at: datetime
    thread: threading.Thread | None = None
    ended_at: datetime | None = None
    status: str = "running"  # running | completed | failed
    error: str | None = None
    baseline_ready: bool = False
    settings: RuleSettings = field(default_factory=RuleSettings)
    learner: BaselineLearner | None = None
    key: str | None = None
    notes: list[str] = field(default_factory=list)
    baseline_updated: bool = False


@dataclass(slots=True)
class _State:
    runs: deque[_Run] = field(default_factory=deque)
    next_id: int = 1
    closed: bool = False


class DetectionService:
    def __init__(
        self,
        *,
        enabled: bool = True,
        registry: Registry | None = None,
        settings: RuleSettings | None = None,
        queue_size: int = DEFAULT_QUEUE_SIZE,
        runs_kept: int = RUNS_KEPT,
        max_alerts_per_run: int = MAX_ALERTS_PER_RUN,
        clock: Callable[[], datetime] = utcnow,
        own_activity: Callable[[float], bool] | None = None,
        store: AlertStore | None = None,
        writer: AlertWriter | None = None,
        config: ConfigStore | None = None,
        vantage_sink: Callable[[int, TapContext], None] | None = None,
    ) -> None:
        # The constructor does no I/O and starts no thread (the contract export builds the app on an empty database).
        self.enabled = enabled
        self.registry = registry or default_registry()
        self.settings = settings or RuleSettings()
        self._queue_size = queue_size
        self._runs_kept = runs_kept
        self._max_alerts = max_alerts_per_run
        self._clock = clock
        self._own_activity = own_activity
        self._config = config
        self._vantage_sink = vantage_sink
        self._lock = threading.Lock()
        self._state = _State()
        self.store = store
        self.delete_wait = 10.0  # seconds delete-all waits for a flush in progress before giving up
        self._writer: AlertWriter | None = None
        if store is not None:
            self._writer = writer or AlertWriter(store, clock=clock)

    @property
    def config(self) -> ConfigStore | None:
        return self._config

    # --- the hook the capture service calls --------------------------------------------------------------------

    def tap_factory(self, ctx: TapContext) -> TelemetryTap | None:
        if not self.enabled:
            return None
        with self._lock:
            if self._state.closed:
                return None
            run_id = self._state.next_id
            self._state.next_id += 1
        settings, known, suppressed, inv_macs, view, gw_mac, learner, notes, ip_macs = (
            self._run_inputs(ctx)
        )
        local = LocalScope(
            addresses=ctx.local_addresses,
            networks=ctx.local_networks,
            gateways=ctx.gateways,
            dns_servers=ctx.dns_servers,
            interface_mac=ctx.interface_mac,
            gateway_mac=gw_mac,
            direction_known=ctx.source == "live" and bool(ctx.local_addresses),
        )
        writer = self._writer
        engine = DetectionEngine(
            self.registry,
            settings,
            RunInfo(run_id, ctx.session_id, ctx.source, local),
            clock=self._clock,
            own_activity=self._own_activity,
            known_entities=known,
            baseline=view,
            learner=learner,
            suppressed=suppressed,
            inventory_macs=inv_macs,
            inventory_ip_macs=ip_macs,
            max_alerts=self._max_alerts,
            on_alert=(lambda alert, outcome: writer.offer(run_id, alert, outcome))
            if writer
            else None,
        )
        queue = EventQueue(self._queue_size)
        run = _Run(run_id, ctx, queue, engine, self._clock())
        run.settings, run.learner, run.notes = settings, learner, notes
        run.key = network_key(ctx.local_networks, ctx.gateways)
        run.baseline_ready = view.ready
        if writer is not None:
            writer.start()
            writer.run_started(self._run_record(run))
        run.thread = threading.Thread(
            target=self._work, args=(run,), daemon=True, name="detection-worker"
        )
        with self._lock:
            self._state.runs.append(run)
            while len(self._state.runs) > self._runs_kept:
                old = self._state.runs[0]
                if old.status == "running":
                    break  # never drop a run that is still working
                self._state.runs.popleft()
        self._save_vantage(run_id, ctx)
        run.thread.start()
        return TelemetryTap(queue)

    def _work(self, run: _Run) -> None:
        try:
            while (batch := run.queue.get_batch(BATCH, timeout=0.25)) is not None:
                if batch:
                    run.engine.process_batch(batch)
            run.engine.finish()
            run.status = "completed"
        except BaseException as exc:  # a failure here must never reach the capture threads
            log.exception("The detection worker for run %s failed", run.id)
            run.status = "failed"
            run.error = type(exc).__name__
        finally:
            run.ended_at = self._clock()
            self._remember(run)
            if self._writer is not None:
                self._writer.run_finished(self._run_finish(run))

    def _current_settings(self) -> RuleSettings:
        """The saved settings (what the next run will use); the constructor's when nothing is stored or readable."""
        if self._config is None:
            return self.settings
        try:
            return self._config.load_settings(self.registry)
        except Exception:
            log.exception("Could not read the saved rule settings")
            return self.settings

    def _run_inputs(
        self, ctx: TapContext
    ) -> tuple[
        RuleSettings,
        frozenset[str],
        frozenset[tuple[str, str, str]],
        frozenset[str],
        BaselineView,
        str | None,
        BaselineLearner | None,
        list[str],
        dict[str, str],
    ]:
        """What this run reads once at its start: saved settings, user knowledge and the stored baseline."""
        settings, view, gw_mac, learner = self.settings, BaselineView(), None, None
        known: frozenset[str] = frozenset()
        suppressed: frozenset[tuple[str, str, str]] = frozenset()
        macs: frozenset[str] = frozenset()
        ip_macs: dict[str, str] = {}
        notes: list[str] = []
        if self._config is not None:
            try:
                settings = self._config.load_settings(self.registry)
                known = self._config.known_entities()
                suppressed = self._config.active_suppressions()
                macs = self._config.inventory_macs()
                ip_macs = self._config.inventory_ip_macs()
                key = network_key(ctx.local_networks, ctx.gateways)
                view, gw_mac = self._config.run_inputs(key)
                if ctx.source == "live" and key is not None:
                    learner = BaselineLearner(ctx.local_networks, self._config.ip_keys())
            except Exception as exc:  # the run still starts, with defaults, and says so
                log.exception("Could not read the saved detection configuration")
                notes.append(
                    f"Saved rule settings, baselines or suppressions could not be read ({type(exc).__name__}); defaults were used for this run."
                )
                settings, view, gw_mac, learner = self.settings, BaselineView(), None, None
        return settings, known, suppressed, macs, view, gw_mac, learner, notes, ip_macs

    def _save_vantage(self, run_id: int, ctx: TapContext) -> None:
        if self._vantage_sink is None:
            return
        try:
            self._vantage_sink(run_id, ctx)
        except Exception:
            log.exception("Could not store the vantage of run %s", run_id)

    def _remember(self, run: _Run) -> None:
        """A finished live run adds its time and what it learned to the network's baseline. Files never do."""
        if (
            self._config is None
            or run.key is None
            or run.ctx.source != "live"
            or run.learner is None
        ):
            return
        try:
            cidr = run.ctx.local_networks[0] if run.ctx.local_networks else ""
            gateway_ip = run.ctx.gateways[0] if run.ctx.gateways else None
            out = self._config.record_run(
                run.key, cidr, gateway_ip, run.engine.gateway_mac_seen, True,
                run.learner.seconds, run.learner.devices(),
            )  # fmt: skip
            run.baseline_updated = bool(out.get("baseline_updated"))
        except Exception as exc:
            log.exception("Could not store the baseline of run %s", run.id)
            run.notes.append(f"The baseline could not be stored ({type(exc).__name__}).")

    def inventory_scan_finished(self, scan_id: str) -> None:
        """Called after a discovery scan ends (TT-DEV-001). It never raises and never blocks the scan for long."""
        if not self.enabled or self._config is None or self._writer is None or self._state.closed:
            return
        try:
            settings = self._config.load_settings(self.registry)
            spec = self.registry.get("TT-DEV-001")
            if not settings.is_enabled(spec.meta):
                return
            params = self.registry.validate("TT-DEV-001", settings.overrides.get("TT-DEV-001", {}))
            event = inventory_hook.new_devices(self._config.engine, scan_id, params)
            if event is None:
                return
            with self._lock:
                run_id = self._state.next_id
                self._state.next_id += 1
            local = LocalScope()
            engine = DetectionEngine(
                self.registry, settings, RunInfo(run_id, 0, "live", local), clock=self._clock,
                known_entities=self._config.known_entities(), suppressed=self._config.active_suppressions(),
                max_alerts=self._max_alerts, on_alert=lambda alert, outcome: self._writer.offer(run_id, alert, outcome),  # type: ignore[union-attr]
            )  # fmt: skip
            started = self._clock()
            self._writer.start()
            self._writer.run_started(
                RunRecord(run_id, None, "live", started, [], {"inventory_scan": scan_id})
            )
            engine.process(event)
            engine.finish()
            snap = engine.snapshot()
            self._writer.run_finished(
                RunFinish(run_id, "completed", self._clock(), snap["processed"], 0, snap["alerts_created"],
                          snap["alerts_updated"], [], snap["findings_suppressed"], False)
            )  # fmt: skip
        except Exception:
            log.exception("The inventory check after scan %s failed", scan_id)

    def _run_record(self, run: _Run) -> RunRecord:
        ctx = run.ctx
        rules: list[dict[str, Any]] = []
        for spec in self.registry.specs():
            meta = spec.meta
            state, reason = run.engine.rule_states.get(meta.id, ("disabled", "switched off"))
            try:
                params: dict[str, int | float] = self.registry.validate(
                    meta.id, run.settings.overrides.get(meta.id, {})
                )
            except RuleConfigError:
                params = {}
            rules.append(
                {
                    "id": meta.id,
                    "version": meta.version,
                    "state": state,
                    "reason": reason,
                    "params": params,
                }
            )
        vantage = {
            "interface_id": ctx.interface_id,
            "interface_name": ctx.interface_name,
            "interface_mac": ctx.interface_mac,
            "promiscuous": ctx.promiscuous,
            "local_addresses": sorted(ctx.local_addresses)[:MAX_VANTAGE_ITEMS],
            "local_networks": list(ctx.local_networks[:MAX_VANTAGE_ITEMS]),
            "gateways": list(ctx.gateways[:MAX_VANTAGE_ITEMS]),
            "dns_servers": list(ctx.dns_servers[:MAX_VANTAGE_ITEMS]),
        }  # fmt: skip
        return RunRecord(run.id, ctx.session_id or None, ctx.source, run.started_at, rules, vantage)

    def _run_warnings(self, run: _Run) -> list[str]:
        """What a reader of this run should know about the quality of its analysis."""
        snap = run.engine.snapshot()
        dropped = run.queue.stats()["dropped"]
        out: list[str] = []
        if dropped:
            out.append(
                f"Coverage reduced: {dropped} telemetry events were dropped because the detection queue was full."
            )
        out.extend(run.notes)
        if run.status == "failed":
            out.append(
                f"The detection worker stopped early ({run.error}); alerts after that point are missing."
            )
        if snap["rule_errors"]:
            out.append(
                "A rule failed during this run: "
                + ", ".join(f"{k} x{v}" for k, v in snap["rule_errors"].items())
                + "."
            )
        if sum(snap["malformed"].values()):
            out.append(f"{sum(snap['malformed'].values())} malformed events were discarded.")
        if snap["sink_errors"]:
            out.append(f"{snap['sink_errors']} alert updates could not be handed to storage.")
        return out

    def _run_finish(self, run: _Run) -> RunFinish:
        snap = run.engine.snapshot()
        return RunFinish(
            key=run.id,
            status=run.status,
            ended_at=run.ended_at or self._clock(),
            events_processed=snap["processed"],
            events_dropped=run.queue.stats()["dropped"],
            alerts_created=snap["alerts_created"],
            alerts_updated=snap["alerts_updated"],
            warnings=self._run_warnings(run),
            findings_suppressed=snap["findings_suppressed"],
            baseline_updated=run.baseline_updated,
        )

    # --- start-up and delete-all -------------------------------------------------------------------------------

    def recover(self) -> None:
        """At start-up: runs left 'running' by a crash become 'aborted'; retention is applied; the writer starts."""
        if self.store is None or self._writer is None:
            return
        try:
            aborted = self.store.recover()
            if aborted:
                log.info("%d detection run(s) did not finish and were marked aborted", aborted)
            self._writer.request_prune()  # on the writer thread: a long catch-up must not delay start-up
        except (
            Exception
        ) as exc:  # the application starts anyway; the failure is shown in the status
            log.exception("Detection recovery failed")
            self._writer.note_error(f"recovery: {type(exc).__name__}")
        finally:
            self._writer.start()

    def delete_history(self) -> DeleteHistoryResult:
        """Delete stored alerts and finished runs. Waiting alerts are discarded first so a flush cannot bring them back."""
        if self.store is None or self._writer is None:
            raise DetectionUnavailable("Alert storage is not available.")
        with self._writer.exclusive(timeout=self.delete_wait):
            self._writer.discard_pending()
            result = self.store.delete_history()
            if self._config is not None:
                self._config.delete_all()  # learned baselines go with the history they belong to
            return result

    # --- reading ----------------------------------------------------------------------------------------------------

    def alerts(self, run_id: int | None = None) -> list[Alert]:
        """Alerts of one run (default: the newest run), newest first. Held in memory only in M2."""
        with self._lock:
            runs = list(self._state.runs)
        if not runs:
            return []
        chosen = runs[-1] if run_id is None else next((r for r in runs if r.id == run_id), None)
        return list(reversed(chosen.engine.alerts())) if chosen else []

    def status(self) -> dict[str, Any]:
        with self._lock:
            runs = list(self._state.runs)
        rules = []
        newest = runs[-1].engine.rule_states if runs else {}
        current = self._current_settings()
        for spec in self.registry.specs():
            meta = spec.meta
            enabled = current.is_enabled(meta)
            state, reason = newest.get(
                meta.id,
                ("evaluating" if enabled else "disabled", "" if enabled else "switched off"),
            )
            rules.append(
                {
                    "id": meta.id, "name": meta.name, "category": meta.category, "version": meta.version,
                    "severity": meta.severity, "enabled": enabled, "state": state, "reason": reason,
                    "default_enabled": meta.default_enabled,
                    "requires_baseline": meta.requires_baseline,
                    "params": [
                        {"name": p.name, "value": self.registry.validate(meta.id, current.overrides.get(meta.id, {}))[p.name],
                         "default": p.default, "minimum": p.minimum, "maximum": p.maximum, "unit": p.unit}
                        for p in meta.params
                    ],
                }
            )  # fmt: skip
        persistence: dict[str, Any] = (
            {"enabled": True, **self._writer.diagnostics()}
            if self._writer is not None
            else {"enabled": False}
        )
        return {
            "enabled": self.enabled,
            "persistence": persistence,
            "queue_size": self._queue_size,
            "runs_kept": self._runs_kept,
            "max_alerts_per_run": self._max_alerts,
            "rules": rules,
            "runs": [self._run_info(r) for r in reversed(runs)],
        }

    def _run_info(self, run: _Run) -> dict[str, Any]:
        queue = run.queue.stats()
        warnings = self._run_warnings(run)
        if self._writer is not None:
            warnings += [w for w in self._writer.warnings(run.id) if w not in warnings]
        return {
            "run_id": run.id,
            "stored_run_id": self._writer.stored_run_id(run.id)
            if self._writer is not None
            else None,
            "warnings": warnings,
            "session_id": run.ctx.session_id,
            "source": run.ctx.source,
            "status": run.status,
            "error": run.error,
            "started_at": run.started_at,
            "ended_at": run.ended_at,
            "queue": queue,
            "engine": run.engine.snapshot(),
        }

    def wait_idle(self, timeout: float = 5.0) -> bool:
        """Block until every run's worker has finished (tests and shutdown)."""
        with self._lock:
            threads = [r.thread for r in self._state.runs if r.thread is not None]
        for thread in threads:
            thread.join(timeout)
        return all(not t.is_alive() for t in threads)

    def shutdown(self, timeout: float = 5.0) -> None:
        with self._lock:
            self._state.closed = True
            runs = list(self._state.runs)
        for run in runs:
            run.queue.close()  # the worker drains what is queued, finishes the engine, and ends
        for run in runs:
            if run.thread is not None:
                run.thread.join(timeout)
        if self._writer is not None:
            self._writer.stop(
                timeout
            )  # after the workers: every run has reported its alerts and its end
