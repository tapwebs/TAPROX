"""Phase 4 / M1 performance gate: Phase 3 columns versus the current columns, on one capture.

Windows only (process CPU time and peak memory come from the Win32 API). Run with the backend's python:

  backend\\.venv\\Scripts\\python.exe scripts\\perf\\telemetry_bench.py all <capture.pcapng> --runs 3 --out result.json

Stages
  tshark  tshark alone (output read through a pipe and discarded), Phase 3 column set against the current set, runs interleaved.
  ingest  tshark -> parse -> row store -> flow engine, tap off and tap on, each run in a fresh process.
  queue   the event queue by itself: throughput, and what happens when it is full.
  dns     the M4 DNS rule pack: a 100,000-packet DNS capture built at run time, ingested with detection off, TT-REC-001
          alone, the product defaults and all rules; and engine-only DNS floods (unique names, NXDOMAIN, many clients).
  m3      the M3 rule pack on synthetic telemetry (TT-REC-001 alone, the product defaults, all rules), in separate
          processes: throughput, CPU, peak memory, high-cardinality floods, state sizes and alerts per rule.
  persist alert storage (M2 completion): the cost of handing alerts to the writer, write times per transaction, read
          times at 5,000 / 10,000 / 100,000 stored alerts, retention, and database size per alert.
  all     the stages; also prints the gate verdict (tshark time must not grow by more than 12%).
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import statistics
import subprocess
import sys
import threading
import time
from ctypes import wintypes
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
# TT_BENCH_BACKEND points at another copy of backend/app (for example the Phase 3 code) to compare against.
sys.path.insert(0, os.environ.get("TT_BENCH_BACKEND") or str(ROOT / "backend"))

TSHARK = Path(r"C:\Program Files\Wireshark\tshark.exe")
GATE = 0.12
LOCAL = frozenset({"192.168.1.7"})  # the reference capture was taken on this address
DISPLAY = (
    "frame.number", "frame.time_epoch", "_ws.col.Source", "_ws.col.Destination",
    "_ws.col.Protocol", "frame.len",
)  # fmt: skip
# The 21 decoded fields Phase 3 shipped with, written out so the baseline never moves with the code.
PHASE3_FIELDS = (
    "frame.protocols", "eth.src", "eth.dst", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "ip.proto",
    "ipv6.nxt", "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport", "tcp.flags",
    "dns.qry.name", "dns.flags.response", "dns.a", "dns.aaaa",
    "tls.handshake.extensions_server_name", "http.host", "tls.handshake.extension.type",
)  # fmt: skip


def argv_for(capture: Path, fields: tuple[str, ...]) -> list[str]:
    cols: list[str] = []
    for name in (*DISPLAY, *fields, "_ws.col.Info"):
        cols += ["-e", name]
    return [str(TSHARK), "-r", str(capture), "-n", "-T", "fields", "-E", "separator=/t",
            "-E", "occurrence=a", *cols]  # fmt: skip


# --- Win32 process statistics -------------------------------------------------------------------------


class _Counters(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
        ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t),
    ]  # fmt: skip


def _ft(value: wintypes.FILETIME) -> float:
    return ((value.dwHighDateTime << 32) | value.dwLowDateTime) / 1e7


def process_stats(handle: int) -> dict[str, float]:
    """CPU seconds (user + kernel) and peak working set (MiB) of a process, from its handle."""
    k32, psapi = ctypes.windll.kernel32, ctypes.windll.psapi
    c, e, kern, user = (wintypes.FILETIME() for _ in range(4))
    k32.GetProcessTimes(wintypes.HANDLE(handle), ctypes.byref(c), ctypes.byref(e),
                        ctypes.byref(kern), ctypes.byref(user))  # fmt: skip
    mem = _Counters()
    mem.cb = ctypes.sizeof(mem)
    psapi.GetProcessMemoryInfo(wintypes.HANDLE(handle), ctypes.byref(mem), mem.cb)
    return {"cpu_s": _ft(kern) + _ft(user), "peak_mib": mem.PeakWorkingSetSize / 1048576}


def own_stats() -> dict[str, float]:
    return process_stats(ctypes.windll.kernel32.GetCurrentProcess())


# --- stage 1: tshark alone ------------------------------------------------------------------------------


def run_tshark(capture: Path, fields: tuple[str, ...]) -> dict[str, float]:
    start = time.perf_counter()
    # stdout is a pipe that is read and thrown away: that is how the backend runs tshark, and it is
    # faster than writing to NUL, which would make the measurement unlike production.
    proc = subprocess.Popen(argv_for(capture, fields), stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, creationflags=0x08000000)  # fmt: skip
    assert proc.stdout is not None
    while proc.stdout.read(1 << 20):
        pass
    proc.wait()
    wall = time.perf_counter() - start
    return {"wall_s": wall, **process_stats(int(proc._handle))}  # type: ignore[attr-defined]


def stage_tshark(capture: Path, runs: int, current: tuple[str, ...]) -> dict:
    a, b = [], []
    run_tshark(capture, PHASE3_FIELDS)  # warm the file cache; not counted
    for _ in range(runs):  # interleaved, so drift hits both sides equally
        a.append(run_tshark(capture, PHASE3_FIELDS))
        b.append(run_tshark(capture, current))
    med = lambda rows, key: statistics.median(r[key] for r in rows)  # noqa: E731
    result = {
        "runs": runs,
        "phase3_fields": len(PHASE3_FIELDS),
        "current_fields": len(current),
        "phase3": a,
        "current": b,
        "median_wall_phase3_s": med(a, "wall_s"),
        "median_wall_current_s": med(b, "wall_s"),
        "median_cpu_phase3_s": med(a, "cpu_s"),
        "median_cpu_current_s": med(b, "cpu_s"),
        "median_peak_phase3_mib": med(a, "peak_mib"),
        "median_peak_current_mib": med(b, "peak_mib"),
    }
    result["wall_increase"] = result["median_wall_current_s"] / result["median_wall_phase3_s"] - 1
    result["cpu_increase"] = result["median_cpu_current_s"] / result["median_cpu_phase3_s"] - 1
    return result


# --- stage 2: the whole ingest path ---------------------------------------------------------------------


def ingest_once(capture: Path, tap_mode: str) -> dict:
    from app.services.capture.rows import RowStore, row_from_parts
    from app.services.capture.tools import CaptureTools
    from app.services.flows.engine import FlowEngine
    from app.services.flows.packet import parse_packet, split_line

    tools = CaptureTools(Path("dumpcap"), TSHARK)
    argv = tools.tshark_file_argv(capture, 2_000_000)
    kwargs = {}
    consumer = None
    drained = [0]
    queue = None
    service = None
    if tap_mode in ("detect", "detect-m3", "detect-all", "persist"):
        # The real thing: a tap feeding the bounded queue, and the detection worker thread consuming it.
        # "persist" adds the SQLite alert store and writer thread.
        import tempfile

        from app.services.detection.service import DetectionService
        from app.services.detection.tap import TapContext

        if tap_mode == "persist":
            from app.database import init_database
            from app.services.detection.store import AlertStore

            tmp = tempfile.mkdtemp(prefix="tt-bench-")
            service = DetectionService(store=AlertStore(init_database(Path(tmp))))
            service.recover()
        else:
            from app.services.detection.registry import RuleSettings, default_registry
            specs = default_registry().specs()
            if tap_mode == "detect":  # the M2-equivalent: TT-REC-001 alone
                settings = RuleSettings(enabled={sp.meta.id: sp.meta.id == "TT-REC-001" for sp in specs})
            elif tap_mode == "detect-all":  # every rule, the default-off ones included
                settings = RuleSettings(enabled={sp.meta.id: True for sp in specs})
            else:  # "detect-m3": what the product runs
                settings = RuleSettings()
            service = DetectionService(settings=settings)
        tap = service.tap_factory(
            TapContext(session_id=1, source="live", local_addresses=LOCAL, gateways=("192.168.1.1",),
                       interface_mac="30:56:0f:1e:2e:c7")  # fmt: skip
        )
        assert tap is not None
        queue = tap.queue
        kwargs["tap"] = tap
    if tap_mode == "on":
        from app.services.detection.tap import EventQueue, TelemetryTap

        queue = EventQueue(10_000)
        kwargs["tap"] = TelemetryTap(queue)

        def drain() -> None:
            while True:
                batch = queue.get_batch(512, timeout=0.2)
                if batch is None:
                    return
                drained[0] += len(batch)

        consumer = threading.Thread(target=drain, daemon=True)
        consumer.start()
    engine = FlowEngine(1, local_addresses=LOCAL, **kwargs)
    rows = RowStore(100_000)
    packets = 0
    cpu0, wall0 = time.process_time(), time.perf_counter()
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            creationflags=0x08000000)  # fmt: skip
    assert proc.stdout is not None
    for raw in proc.stdout:
        parts = split_line(raw.decode("utf-8", errors="replace"))
        if parts is None:
            continue
        row = row_from_parts(parts)
        if row is not None:
            rows.append(row)
        packet = parse_packet(parts)
        if packet is not None:
            engine.add(packet)
            packets += 1
    proc.wait()
    engine.finish()
    wall, cpu = time.perf_counter() - wall0, time.process_time() - cpu0
    tshark = process_stats(int(proc._handle))  # type: ignore[attr-defined]
    out: dict = {"tap": tap_mode}
    if service is not None:
        assert queue is not None
        queue.close()
        service.wait_idle(30)
        if tap_mode == "persist":
            service.shutdown()
        run = service.status()["runs"][0]
        out["queue"] = run["queue"]
        out["detection"] = {k: run["engine"][k] for k in ("processed", "findings", "alerts_created", "malformed", "rule_errors", "events")}
        out["detection"]["status"] = run["status"]
        out["detection"]["alerts"] = [(a.rule_id, a.severity, a.confidence, a.risk.value) for a in service.alerts()]
        by_rule: dict[str, int] = {}
        for a in service.alerts():
            by_rule[a.rule_id] = by_rule.get(a.rule_id, 0) + 1
        out["detection"]["alerts_by_rule"] = by_rule
        out["detection"]["alerts_detail"] = [(a.rule_id, a.summary, a.observed) for a in service.alerts()]
        out["detection"]["rule_diagnostics"] = run["engine"].get("rule_diagnostics")
        if tap_mode == "persist":
            out["persistence"] = service.status()["persistence"]
    elif queue is not None:
        queue.close()
        consumer.join(5)  # type: ignore[union-attr]
        out["queue"] = {**queue.stats(), "consumed": drained[0]}
    flows = engine.snapshot()
    digest = hashlib.sha256()
    for f in sorted(flows, key=lambda f: f.seq):
        digest.update(repr((f.transport, f.src_ip, f.dst_ip, f.src_port, f.dst_port, f.packets_fwd,
                            f.packets_rev, f.bytes_fwd, f.bytes_rev, f.state, f.protocol,
                            f.application, f.confidence, f.method)).encode())  # fmt: skip
    apps: dict[str, int] = {}
    for f in flows:
        apps[f.application or "-"] = apps.get(f.application or "-", 0) + 1
    t = engine.totals
    out.update(
        packets=packets,
        rows=len(rows),
        flows=len(flows),
        flows_created=t.flows_created,
        totals={k: getattr(t, k) for k in t.__dataclass_fields__},
        flow_digest=digest.hexdigest(),
        applications=dict(sorted(apps.items())),
        wall_s=wall,
        python_cpu_s=cpu,
        packets_per_s=packets / wall,
        python_peak_mib=own_stats()["peak_mib"],
        tshark_cpu_s=tshark["cpu_s"],
        tshark_peak_mib=tshark["peak_mib"],
    )
    return out


def stage_ingest(capture: Path, runs: int, modes: list[str], baseline: str | None) -> dict:
    """Interleaved rounds: [phase3 code], tap off, tap on - so machine noise lands on every side."""
    configs = ([("phase3_code", baseline, "off")] if baseline else []) + [(m, None, m) for m in modes]
    collected: dict[str, list[dict]] = {label: [] for label, _, _ in configs}
    for _ in range(runs):
        for label, backend, mode in configs:
            env = {**os.environ, **({"TT_BENCH_BACKEND": backend} if backend else {})}
            if backend is None:
                env.pop("TT_BENCH_BACKEND", None)
            done = subprocess.run([sys.executable, __file__, "ingest-one", str(capture), mode],
                                  capture_output=True, text=True, check=True, env=env)  # fmt: skip
            collected[label].append(json.loads(done.stdout.strip().splitlines()[-1]))
    result: dict = {}
    for label, rows in collected.items():
        key = lambda k: statistics.median(r[k] for r in rows)  # noqa: E731
        result[label] = {
            "runs": rows,
            "median_wall_s": key("wall_s"),
            "median_packets_per_s": key("packets_per_s"),
            "median_python_cpu_s": key("python_cpu_s"),
            "median_python_peak_mib": key("python_peak_mib"),
            "same_result_every_run": len({r["flow_digest"] for r in rows}) == 1,
        }
    return result


# --- stage 3: the event queue -----------------------------------------------------------------------------


def stage_queue() -> dict:
    from app.services.detection.events import FlowOpened
    from app.services.detection.tap import EventQueue

    def event(i: int) -> FlowOpened:
        return FlowOpened(float(i), 1, i, "tcp", "10.0.0.1", "10.0.0.2", 1000, 443, "syn", None, None, True)

    n = 500_000
    events = [event(i) for i in range(n)]
    # 1. producer and consumer together, batches as the engine hands them over
    q = EventQueue(10_000)
    got = [0]
    last = [-1.0]
    ordered = [True]

    def consume() -> None:
        while (batch := q.get_batch(512, timeout=0.2)) is not None:
            got[0] += len(batch)
            for ev in batch:
                if ev.t < last[0]:
                    ordered[0] = False
                last[0] = ev.t

    t = threading.Thread(target=consume)
    t.start()
    start = time.perf_counter()
    for i in range(0, n, 16):
        q.offer_many(events[i : i + 16])
    produced = time.perf_counter() - start
    q.close()
    t.join()
    live = {"events": n, "producer_s": produced, "offered_per_s": n / produced, **q.stats(),
            "consumed": got[0], "in_order": ordered[0]}  # fmt: skip
    # 2. saturation: nobody consumes, the queue is small
    q2 = EventQueue(1_000)
    start = time.perf_counter()
    for i in range(0, n, 16):
        q2.offer_many(events[i : i + 16])
    full = time.perf_counter() - start
    saturated = {"events": n, "producer_s": full, "offered_per_s": n / full, **q2.stats()}
    # 3. how fast a consumer can empty a full queue (nothing is being produced meanwhile)
    q3 = EventQueue(n)
    for i in range(0, n, 1000):
        q3.offer_many(events[i : i + 1000])
    q3.close()
    start = time.perf_counter()
    taken = 0
    while (batch := q3.get_batch(512, timeout=0.2)) is not None:
        taken += len(batch)
    drain = time.perf_counter() - start
    consumer = {"events": taken, "seconds": drain, "consumed_per_s": taken / drain}
    # 4. a steady producer far above what the pipeline makes (a few hundred events/s): batches of 500
    #    every 10 ms is about 50,000 events/s, for 5 s, with a consumer. Nothing may be dropped.
    q4 = EventQueue(10_000)
    seen = [0]

    def eat() -> None:
        while (batch := q4.get_batch(512, timeout=0.2)) is not None:
            seen[0] += len(batch)

    worker = threading.Thread(target=eat)
    worker.start()
    start = time.perf_counter()
    sent = 0
    while time.perf_counter() - start < 5.0:
        at = sent % (n - 500)
        q4.offer_many(events[at : at + 500])
        sent += 500
        time.sleep(0.01)
    steady_s = time.perf_counter() - start
    q4.close()
    worker.join()
    steady = {"sent": sent, "seconds": steady_s, "actual_events_per_s": sent / steady_s,
              "consumed": seen[0], **q4.stats()}  # fmt: skip
    return {"live": live, "saturated": saturated, "consumer_drain": consumer, "steady": steady}


def stage_detect_synth() -> dict:
    """The detection engine by itself on synthetic telemetry: events per second and memory growth."""
    from app.services.detection.engine import DetectionEngine, RunInfo
    from app.services.detection.events import FlowOpened, FlowRetired, TickSummary
    from app.services.detection.registry import RuleSettings, default_registry
    from app.services.detection.rules.base import LocalScope

    def build() -> DetectionEngine:
        return DetectionEngine(default_registry(), RuleSettings(),
                               RunInfo(1, 1, "live", LocalScope(addresses=LOCAL, direction_known=True)))  # fmt: skip

    def opened(seq: int, t: float, src: str, dst: str, port: int) -> FlowOpened:
        return FlowOpened(t, 1, seq, "tcp", src, dst, 40000 + seq % 20000, port, "syn", None, None, True)

    def retired(seq: int, t: float, src: str, dst: str, port: int, ok: bool) -> FlowRetired:
        return FlowRetired(t, 1, seq, "closed", "tcp", src, dst, 40000 + seq % 20000, port, 5, 5 if ok else 0, 500,
                           500 if ok else 0, True, ok, False, t, t, "TCP", None, "unknown", None, None,
                           frozenset({"tcp"}))  # fmt: skip

    out: dict = {}
    # 1. ordinary mix: many sources, a few connections each, all answered. Events are made on the fly in
    #    batches, so the memory figure is the detection state, not a million prebuilt events.
    eng = build()
    before = own_stats()["peak_mib"]
    total = 0
    seq = 0
    start = time.perf_counter()
    cpu0 = time.process_time()
    for base in range(0, 500_000, 128):
        batch = []
        for i in range(base, min(base + 128, 500_000)):
            seq += 1
            t = 1_700_000_000.0 + i * 0.002
            src, dst = f"10.{(i // 250) % 80}.{i % 250}.{(i // 3) % 200 + 1}", f"203.0.113.{i % 50 + 1}"
            port = 443 if i % 7 else 8443
            batch.append(opened(seq, t, src, dst, port))
            batch.append(retired(seq, t + 0.5, src, dst, port, True))
            if i % 500 == 0:
                batch.append(TickSummary(t, {}, 0, 0))
        total += len(batch)
        eng.process_batch(batch)
    secs, cpu = time.perf_counter() - start, time.process_time() - cpu0
    snap = eng.snapshot()
    out["ordinary_mix"] = {"events": total, "seconds": secs, "cpu_s": cpu, "events_per_s": total / secs,
                           "alerts": snap["alerts_in_memory"], "findings": snap["findings"],
                           "rule_diagnostics": snap["rule_diagnostics"], "rule_errors": snap["rule_errors"],
                           "peak_mib_before": before, "peak_mib_after": own_stats()["peak_mib"]}  # fmt: skip
    # 2. a 65,535-port scan, one source and one target: state must stay bounded and one alert results
    eng = build()
    events = []
    for p in range(1, 65_536):
        t = 1_700_100_000.0 + p * 0.0005
        events.append(opened(p, t, "198.51.100.9", "192.168.1.7", p))
    events.append(TickSummary(1_700_100_040.0, {}, 0, 0))
    start = time.perf_counter()
    eng.process_batch(events)
    secs = time.perf_counter() - start
    snap = eng.snapshot()
    diag = snap["rule_diagnostics"]["TT-REC-001"]
    out["port_flood"] = {"events": len(events), "seconds": secs, "events_per_s": len(events) / secs,
                         "alerts": snap["alerts_in_memory"], "entries_tracked": diag["entries_tracked"],
                         "port_cap_hits": diag["port_cap_hits"]}  # fmt: skip
    # 3. 300,000 different sources, one connection each: the pair table and the entry budget must hold
    eng = build()
    events = []
    for i in range(300_000):
        events.append(opened(i + 1, 1_700_200_000.0 + i * 0.0001, f"{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}.9", "192.168.1.7", 80))
    events.append(TickSummary(1_700_200_100.0, {}, 0, 0))
    start = time.perf_counter()
    eng.process_batch(events)
    secs = time.perf_counter() - start
    diag = eng.snapshot()["rule_diagnostics"]["TT-REC-001"]
    out["source_flood"] = {"events": len(events), "seconds": secs, "events_per_s": len(events) / secs,
                           "pairs_tracked": diag["pairs_tracked"], "entries_tracked": diag["entries_tracked"],
                           "state_evictions": diag["state_evictions"], "peak_mib": own_stats()["peak_mib"]}  # fmt: skip
    return out


# --- stage 5: alert storage ------------------------------------------------------------------------------


def _pct(values: list[float], q: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(q * len(ordered)))] if ordered else 0.0


def stage_persist() -> dict:
    """Alert persistence: hand-off cost, write transactions, read latency at size, retention, bytes per alert."""
    import shutil
    import tempfile
    from dataclasses import replace
    from datetime import UTC, datetime, timedelta

    from sqlalchemy import text
    from sqlalchemy.orm import Session

    from app.database import init_database
    from app.models.alert import AlertRow
    from app.services.detection.engine import DetectionEngine, RunInfo
    from app.services.detection.events import FlowOpened, FlowRetired, TickSummary
    from app.services.detection.persist import AlertWriter
    from app.services.detection.registry import RuleSettings, default_registry
    from app.services.detection.rules.base import LocalScope
    from app.services.detection.store import AlertFilter, AlertStore, PendingAlert, RunFinish, RunRecord

    scope = LocalScope(addresses=LOCAL, direction_known=True)

    def scanners(count: int, ports: int = 25) -> list:
        events: list = []
        seq = 0
        for i in range(count):
            src = f"10.{i // 250 % 250}.{i % 250}.9"
            t0 = 1_700_000_000.0 + i * 0.05
            for p in range(ports):
                seq += 1
                events.append(FlowOpened(t0 + p * 0.01, 1, seq, "tcp", src, "192.168.1.50", 40000 + p, 1000 + p, "syn", None, None, True))
            for p in range(ports):
                events.append(FlowRetired(t0 + 1, 1, seq - ports + p + 1, "closed", "tcp", src, "192.168.1.50", 40000 + p, 1000 + p, 1, 0, 60, 0,
                                          True, False, False, t0, t0, "TCP", None, "unknown", None, None, frozenset({"tcp"})))
            events.append(TickSummary(t0 + 3, {}, 0, 0))
        return events

    def engine_run(events: list, hook) -> float:  # type: ignore[no-untyped-def]
        eng = DetectionEngine(default_registry(), RuleSettings(), RunInfo(1, 1, "live", scope), on_alert=hook)
        started = time.perf_counter()
        for base in range(0, len(events), 256):
            eng.process_batch(events[base:base + 256])
        eng.finish()
        return time.perf_counter() - started

    out: dict = {}
    work = Path(tempfile.mkdtemp(prefix="tt-persist-"))
    try:
        events = scanners(2000)
        engine_run(events[:5000], None)  # warm up
        plain = [engine_run(events, None) for _ in range(3)]
        # 1. the hand-off: the engine calls a hook that offers each alert to a writer whose thread is not running
        offers: list[float] = []
        idle_writer = AlertWriter(AlertStore(init_database(work / "idle")))

        def timed(alert, outcome):  # type: ignore[no-untyped-def]
            t = time.perf_counter()
            idle_writer.offer(1, alert, outcome)
            offers.append(time.perf_counter() - t)

        hooked = [engine_run(events, timed) for _ in range(3)]
        out["engine"] = {
            "events": len(events), "alerts": idle_writer.diagnostics()["pending_alerts"],
            "median_s_without_storage": statistics.median(plain), "median_s_with_hook": statistics.median(hooked),
            "hook_overhead": statistics.median(hooked) / statistics.median(plain) - 1,
            "offer_calls": len(offers), "offer_us_median": statistics.median(offers) * 1e6,
            "offer_us_p99": _pct(offers, 0.99) * 1e6, "offer_us_max": max(offers) * 1e6,
        }  # fmt: skip
        # 2. the whole thing: engine -> writer thread -> SQLite, with every write transaction timed
        engine = init_database(work / "live")
        store = AlertStore(engine)
        durations: list[float] = []
        sizes: list[int] = []
        real_write = store.write

        def timed_write(starts, items, finishes):  # type: ignore[no-untyped-def]
            t = time.perf_counter()
            result = real_write(starts, items, finishes)
            durations.append(time.perf_counter() - t)
            sizes.append(len(items))
            return result

        store.write = timed_write  # type: ignore[method-assign]
        writer = AlertWriter(store)
        writer.start()
        writer.run_started(RunRecord(1, None, "live", datetime.now(UTC), [], {}))
        seconds = engine_run(events, lambda a, o: writer.offer(1, a, o))
        engine_done = time.perf_counter()
        writer.run_finished(RunFinish(1, "completed", datetime.now(UTC), len(events), 0, 2000, 0, []))
        writer.stop(60)
        drain = time.perf_counter() - engine_done
        diag = writer.diagnostics()
        out["pipeline"] = {
            "engine_seconds_with_live_writer": seconds, "seconds_to_store_the_rest_after_the_engine_finished": drain,
            "stored_alerts": store.count_alerts(), "writes": len(durations), "alerts_per_write_max": max(sizes),
            "write_ms_median": statistics.median(durations) * 1e3, "write_ms_p95": _pct(durations, 0.95) * 1e3,
            "write_ms_max": max(durations) * 1e3, "alerts_not_stored": diag["alerts_not_stored"],
            "failed_flushes": diag["failed_flushes"], "pruned_alerts": diag["pruned_alerts"],
        }  # fmt: skip
        # 3. size on disk, per alert (23 evidence items each, as the real rule produces)
        engine.dispose()
        size_dir = work / "size"
        engine = init_database(size_dir)
        store = AlertStore(engine)
        eng2 = DetectionEngine(default_registry(), RuleSettings(), RunInfo(1, 1, "live", scope), max_alerts=10_000)
        eng2.process_batch(scanners(5000))
        eng2.finish()
        alerts = eng2.alerts()
        with engine.connect() as c:
            c.exec_driver_sql("PRAGMA wal_checkpoint(TRUNCATE)")
        base_size = (size_dir / "tapnettrack.db").stat().st_size
        for base in range(0, len(alerts), 50):
            store.write([], [PendingAlert(1, a, 1) for a in alerts[base:base + 50]], [])
        with engine.connect() as c:
            c.exec_driver_sql("PRAGMA wal_checkpoint(TRUNCATE)")
        grown = (size_dir / "tapnettrack.db").stat().st_size - base_size
        out["size"] = {"alerts": len(alerts), "evidence_items_each": len(alerts[0].evidence), "bytes_total": grown, "bytes_per_alert": grown / len(alerts),
                       "projected_mib_at_5000_alerts": grown / len(alerts) * 5000 / 2**20}  # fmt: skip
        engine.dispose()

        # 4. reading at size: bulk-load alert rows by SQL (the write path is measured above), then time the queries
        template = alerts[0]
        reads: dict = {}
        for rows_total in (5_000, 10_000, 100_000):
            engine = init_database(work / f"read-{rows_total}")
            store = AlertStore(engine)
            store.write([], [PendingAlert(1, template, 1)], [])
            with Session(engine) as db:
                row = db.query(AlertRow).one()
                cols = [c.name for c in AlertRow.__table__.columns if c.name != "id"]  # type: ignore[attr-defined]
                base_values = {c: getattr(row, c) for c in cols}
                db.execute(text("DELETE FROM alerts"))
                statuses = ["open", "open", "acknowledged", "resolved"]
                severities = ["low", "medium", "high", "critical"]
                rules = ["TT-REC-001", "TT-REC-002", "TT-TRF-003", "TT-DNS-001", "TT-DEV-001"]
                batch = []
                now = datetime(2026, 11, 5, tzinfo=UTC)
                for i in range(rows_total):
                    v = dict(base_values)
                    v.update(dedup_key=f"k{i}", status=statuses[i % 4], severity=severities[i % 4], rule_id=rules[i % 5],
                             risk_score=(i * 7) % 101, entity_key=f"10.{i // 62500}.{i // 250 % 250}.{i % 250}",
                             updated_at=now - timedelta(minutes=i), created_at=now - timedelta(minutes=i),
                             status_changed_at=now - timedelta(minutes=i))  # fmt: skip
                    batch.append(v)
                    if len(batch) == 5000:
                        db.execute(AlertRow.__table__.insert(), batch)  # type: ignore[attr-defined]
                        batch = []
                if batch:
                    db.execute(AlertRow.__table__.insert(), batch)  # type: ignore[attr-defined]
                db.commit()
            with engine.connect() as c:
                c.exec_driver_sql("ANALYZE")
                plan = " | ".join(str(r[3]) for r in c.exec_driver_sql(
                    "EXPLAIN QUERY PLAN SELECT id FROM alerts WHERE status='open' ORDER BY updated_at DESC, id DESC LIMIT 50"))  # fmt: skip

            def measure(name, call, n=60):  # type: ignore[no-untyped-def]
                call()
                samples = []
                for _ in range(n):
                    t = time.perf_counter()
                    call()
                    samples.append((time.perf_counter() - t) * 1e3)
                reads.setdefault(rows_total, {})[name] = {"p50_ms": statistics.median(samples), "p95_ms": _pct(samples, 0.95), "max_ms": max(samples)}

            measure("list_open_newest_50", lambda: store.list_alerts(AlertFilter(status="open"), "updated", "desc", 50, 0))
            measure("list_all_newest_50", lambda: store.list_alerts(AlertFilter(), "updated", "desc", 50, 0))
            measure("list_by_risk_50", lambda: store.list_alerts(AlertFilter(), "risk", "desc", 50, 0))
            measure("list_rule_and_severity", lambda: store.list_alerts(AlertFilter(rule_id="TT-REC-001", severity="low"), "updated", "desc", 50, 0))
            measure("list_deep_page_offset_5000", lambda: store.list_alerts(AlertFilter(), "updated", "desc", 50, min(5000, rows_total - 50)))
            measure("list_by_ip", lambda: store.list_alerts(AlertFilter(ip="10.0.1.7"), "updated", "desc", 50, 0))
            measure("list_text_search", lambda: store.list_alerts(AlertFilter(search="10.0.2"), "updated", "desc", 50, 0), n=15)
            measure("summary", lambda: store.summary(AlertFilter()), n=15)
            reads[rows_total]["default_list_plan"] = plan
            if rows_total == 100_000:
                t = time.perf_counter()
                result = store.prune(days=180, rows=5_000)
                reads[rows_total]["prune_to_5000_seconds"] = time.perf_counter() - t
                reads[rows_total]["prune_deleted"] = result.alerts_deleted
            engine.dispose()
        out["reads"] = reads
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return out


# --- stage 6: the M3 rule pack ---------------------------------------------------------------------------
def _m3_settings(config: str):  # type: ignore[no-untyped-def]
    from app.services.detection.registry import RuleSettings, default_registry
    specs = default_registry().specs()
    if config == "rec001":  # the M2-equivalent: the one rule that existed then
        return RuleSettings(enabled={s.meta.id: s.meta.id == "TT-REC-001" for s in specs})
    if config == "all":  # all rules, the four default-off ones included
        return RuleSettings(enabled={s.meta.id: True for s in specs})
    return RuleSettings()  # "default": what the product runs
def m3_one(config: str) -> dict:
    """One configuration, in this process, so peak memory belongs to it alone."""
    from app.services.detection.engine import DetectionEngine, RunInfo
    from app.services.detection.events import ArpObserved, FlowOpened, FlowRetired, IcmpObserved, TickSummary
    from app.services.detection.rules.base import LocalScope
    def build() -> DetectionEngine:
        return DetectionEngine(_m3_settings_registry(), _m3_settings(config),
                               RunInfo(1, 1, "live", LocalScope(addresses=LOCAL, direction_known=True)))  # fmt: skip
    def opened(seq: int, t: float, src: str, dst: str, port: int) -> FlowOpened:
        return FlowOpened(t, 1, seq, "tcp", src, dst, 40000 + seq % 20000, port, "syn", None, None, True)
    def retired(seq: int, t: float, src: str, dst: str, port: int, ok: bool) -> FlowRetired:
        return FlowRetired(t, 1, seq, "closed", "tcp", src, dst, 40000 + seq % 20000, port, 5, 5 if ok else 0, 500,
                           500 if ok else 0, True, ok, False, t, t, "TCP", None, "unknown", None, None,
                           frozenset({"tcp"}))  # fmt: skip
    out: dict = {"config": config}
    def run(label: str, make_events) -> None:  # type: ignore[no-untyped-def]
        eng = build()
        total = 0
        start, cpu0 = time.perf_counter(), time.process_time()
        for batch in make_events():
            total += len(batch)
            eng.process_batch(batch)
        secs, cpu = time.perf_counter() - start, time.process_time() - cpu0
        snap = eng.snapshot()  # before finish(): that call releases every rule's state
        peak_hold = snap["held_findings"]
        eng.finish()
        by_rule: dict[str, int] = {}
        for a in eng.alerts():
            by_rule[a.rule_id] = by_rule.get(a.rule_id, 0) + 1
        out[label] = {
            "events": total, "seconds": secs, "cpu_s": cpu, "events_per_s": total / secs, "alerts_by_rule": by_rule,
            "findings": snap["findings"], "rule_errors": snap["rule_errors"], "held_findings": peak_hold,
            "state": {rid: {k: v for k, v in d.items() if k.endswith("_tracked")} for rid, d in snap["rule_diagnostics"].items()},
            "evictions": {rid: d.get("state_evictions", 0) for rid, d in snap["rule_diagnostics"].items()},
            "process_peak_mib_so_far": own_stats()["peak_mib"],
        }  # fmt: skip
    T = 1_700_000_000.0
    def ordinary():  # type: ignore[no-untyped-def]
        seq = 0
        for base in range(0, 500_000, 128):
            batch = []
            for i in range(base, min(base + 128, 500_000)):
                seq += 1
                t = T + i * 0.002
                src, dst = f"10.{(i // 250) % 80}.{i % 250}.{(i // 3) % 200 + 1}", f"203.0.113.{i % 50 + 1}"
                port = 443 if i % 7 else 8443
                batch.append(opened(seq, t, src, dst, port))
                batch.append(retired(seq, t + 0.5, src, dst, port, True))
                if i % 500 == 0:
                    batch.append(TickSummary(t, {}, 0, 0))
            yield batch
    def many_sources():  # type: ignore[no-untyped-def]
        events = [opened(i + 1, T + i * 0.0005, f"10.{(i >> 8) & 255}.{i & 255}.9", "192.168.1.50", 80) for i in range(10_000)]
        events += [retired(i + 1, T + 5 + i * 0.0001, f"10.{(i >> 8) & 255}.{i & 255}.9", "192.168.1.50", 80, False) for i in range(10_000)]
        events.append(TickSummary(T + 30, {}, 0, 0))
        yield events
    def many_destinations():  # type: ignore[no-untyped-def]
        dsts = [f"172.{16 + (i >> 16)}.{(i >> 8) & 255}.{i & 255}" for i in range(10_000)]
        events = [opened(i + 1, T + i * 0.001, "198.51.100.9", d, 445) for i, d in enumerate(dsts)]
        events += [retired(i + 1, T + 11 + i * 0.0001, "198.51.100.9", d, 445, False) for i, d in enumerate(dsts)]
        events.append(TickSummary(T + 40, {}, 0, 0))
        yield events
    def sequential_ports():  # type: ignore[no-untyped-def]
        events = [opened(i + 1, T + i * 0.01, "198.51.100.9", "192.168.1.50", 1000 + i) for i in range(20_000)]
        events.append(TickSummary(T + 300, {}, 0, 0))
        yield events
    def icmp_flood():  # type: ignore[no-untyped-def]
        events = [IcmpObserved(T + i * 0.0005, "198.51.100.9", f"192.168.{(i // 250) % 40}.{i % 250 + 1}", 8, 0, 1000) for i in range(200_000)]
        events.append(TickSummary(T + 200, {}, 0, 0))
        yield events
    def arp_flood():  # type: ignore[no-untyped-def]
        events = [ArpObserved(T + i * 0.001, 1, "a8:bb:cc:00:00:01", "192.168.1.99", f"10.{(i >> 8) & 255}.{i & 255}.1") for i in range(10_000)]
        events.append(TickSummary(T + 11, {}, 0, 0))  # the one-to-many sender is judged by the next tick
        events += [ArpObserved(T + 12 + i * 0.001, 1, f"a8:bb:{(i >> 16) & 255:02x}:{(i >> 8) & 255:02x}:{i & 255:02x}:01", f"192.168.{(i >> 8) & 255}.{i & 255}", "192.168.1.1") for i in range(10_000)]
        events.append(TickSummary(T + 60, {}, 0, 0))
        yield events
    for label, make in (("ordinary_mix", ordinary), ("flood_10000_sources", many_sources),
                        ("flood_10000_destinations", many_destinations), ("flood_sequential_ports", sequential_ports),
                        ("flood_icmp_200000", icmp_flood), ("flood_arp_20000", arp_flood)):
        run(label, make)
    return out
def _m3_settings_registry():  # type: ignore[no-untyped-def]
    from app.services.detection.registry import default_registry
    return default_registry()
def stage_m3(runs: int) -> dict:
    """The M3 rule pack on synthetic telemetry: rec001 (M2-equivalent), default and all rules, interleaved rounds."""
    configs = ["rec001", "default", "all"]
    collected: dict[str, list[dict]] = {c: [] for c in configs}
    for _ in range(runs):
        for config in configs:
            done = subprocess.run([sys.executable, __file__, "m3-one", config], capture_output=True, text=True,
                                  check=True)  # fmt: skip
            collected[config].append(json.loads(done.stdout.strip().splitlines()[-1]))
    result: dict = {"runs": runs}
    for config, rows in collected.items():
        summary: dict = {}
        for label in rows[0]:
            if label == "config":
                continue
            summary[label] = {
                "median_events_per_s": statistics.median(r[label]["events_per_s"] for r in rows),
                "median_seconds": statistics.median(r[label]["seconds"] for r in rows),
                "median_cpu_s": statistics.median(r[label]["cpu_s"] for r in rows),
                "max_process_peak_mib": max(r[label]["process_peak_mib_so_far"] for r in rows),
                "alerts_by_rule": rows[0][label]["alerts_by_rule"],
                "same_alerts_every_run": len({json.dumps(r[label]["alerts_by_rule"], sort_keys=True) for r in rows}) == 1,
                "rule_errors": rows[0][label]["rule_errors"],
                "held_findings_at_end": rows[0][label]["held_findings"],
                "state_tracked": rows[0][label]["state"],
                "evictions": {k: v for k, v in rows[0][label]["evictions"].items() if v},
            }
        result[config] = summary
    return result
# --- stage 7: the M4 DNS rule pack ------------------------------------------------------------------------
DNS_PACKETS = 100_000


def build_dns_capture(path: Path, packets: int = DNS_PACKETS) -> dict:
    """A DNS-heavy capture, built here (nothing binary is committed): ordinary lookups from 400 clients over 100 s, one
    client whose names mostly do not exist, one that asks for many unique names with TXT queries."""
    from tests.flow_fixtures import dns_query, dns_response, udp  # noqa: PLC0415
    from tests.pcapng_fixtures import pcapng  # noqa: PLC0415

    frames: list = []
    server = "192.168.1.1"
    span = 100.0
    pairs = packets // 2
    for i in range(pairs):
        t = span * i / pairs
        client = f"192.168.{1 + (i % 400) // 200}.{10 + (i % 400) % 200}"
        sport = 40_000 + (i % 20_000)
        if i % 10 == 0:  # a client whose names mostly do not exist
            client, name, rcode, qtype = "192.168.9.9", f"gone{i}.example.net", 3, 1
        elif i % 25 == 0:  # a client that asks for many unique names under one domain, with TXT queries
            client, name, rcode, qtype = "192.168.9.10", f"d{i}.t.example.org", 0, 16
        else:
            name, rcode, qtype = f"w{i % 2_000}.site{i % 500}.example.com", 0, 1
        frames.append((udp(client, server, sport, 53, dns_query(name, i & 0xFFFF, qtype), mac_src=2, mac_dst=1), t))
        answers = [] if rcode else ["203.0.113.5"]
        frames.append(
            (udp(server, client, 53, sport, dns_response(name, answers, i & 0xFFFF, rcode=rcode, qtype=qtype), mac_src=1, mac_dst=2), t + 0.004)
        )
    data = pcapng(frames)
    path.write_bytes(data)
    return {"packets": len(frames), "bytes": len(data), "span_s": span}


def dns_one(config: str) -> dict:
    """Engine-only DNS workloads for one configuration, in this process (so peak memory is its own)."""
    from app.services.detection.engine import DetectionEngine, RunInfo
    from app.services.detection.events import DnsObserved, TickSummary
    from app.services.detection.rules.base import LocalScope

    def build() -> DetectionEngine:
        return DetectionEngine(_m3_settings_registry(), _m3_settings(config),
                               RunInfo(1, 1, "live", LocalScope(addresses=LOCAL, dns_servers=("192.168.1.1",), direction_known=True)))  # fmt: skip

    T = 1_700_000_000.0
    out: dict = {"config": config}

    def q(t: float, client: str, name: str, qtype: int = 1) -> DnsObserved:
        return DnsObserved(t, client, "192.168.1.1", None, False, name, qtype, None, 53, "udp")

    def r(t: float, client: str, name: str, rcode: int = 0) -> DnsObserved:
        return DnsObserved(t, client, "192.168.1.1", None, True, name, 1, rcode, 53, "udp")

    def run(label: str, make) -> None:  # type: ignore[no-untyped-def]
        eng = build()
        total = 0
        start, cpu0 = time.perf_counter(), time.process_time()
        for batch in make():
            total += len(batch)
            eng.process_batch(batch)
        secs, cpu = time.perf_counter() - start, time.process_time() - cpu0
        snap = eng.snapshot()
        eng.finish()
        by_rule: dict[str, int] = {}
        for a in eng.alerts():
            by_rule[a.rule_id] = by_rule.get(a.rule_id, 0) + 1
        dns_state = {rid: d for rid, d in snap["rule_diagnostics"].items() if rid.startswith("TT-DNS")}
        out[label] = {
            "events": total, "seconds": secs, "cpu_s": cpu, "events_per_s": total / secs, "alerts_by_rule": by_rule,
            "rule_errors": snap["rule_errors"], "malformed": snap["malformed"],
            "dns_entries_tracked": sum(d.get("entries_tracked", 0) for d in dns_state.values()),
            "dns_state": {rid: {k: v for k, v in d.items() if k in ("clients_tracked", "keys_tracked", "entries_tracked", "state_evictions", "cap_hits")} for rid, d in dns_state.items()},
            "process_peak_mib_so_far": own_stats()["peak_mib"],
        }  # fmt: skip

    def ordinary():  # type: ignore[no-untyped-def]
        for base in range(0, 100_000, 256):
            batch = []
            for i in range(base, min(base + 256, 100_000)):
                t = T + i * 0.001
                client = f"10.0.{(i % 400) // 200}.{(i % 400) % 200 + 1}"
                name = f"w{i % 2_000}.site{i % 500}.example.com"
                batch.append(q(t, client, name))
                batch.append(r(t + 0.002, client, name))
                if i % 1000 == 0:
                    batch.append(TickSummary(t, {}, 0, 0))
            yield batch

    def unique_names():  # type: ignore[no-untyped-def]
        events = [q(T + i * 0.0005, "10.0.0.5", f"n{i}.flood.example.org", (1, 16, 10, 255)[i % 4]) for i in range(100_000)]
        events.append(TickSummary(T + 100, {}, 0, 0))
        yield events

    def nxdomain():  # type: ignore[no-untyped-def]
        events = [r(T + i * 0.0005, "10.0.0.6", f"x{i}.nx.example.net", 3) for i in range(100_000)]
        events.append(TickSummary(T + 100, {}, 0, 0))
        yield events

    def many_clients():  # type: ignore[no-untyped-def]
        events = [q(T + i * 0.0001, f"{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}.7", f"a{i}.example.com") for i in range(100_000)]
        events.append(TickSummary(T + 100, {}, 0, 0))
        yield events

    for label, make in (("dns_ordinary_200000_events", ordinary), ("flood_100000_unique_names", unique_names),
                        ("flood_100000_nxdomain", nxdomain), ("flood_100000_clients", many_clients)):
        run(label, make)
    return out


def stage_dns(runs: int, work: Path) -> dict:
    work.mkdir(parents=True, exist_ok=True)
    capture = work / "dns100k.pcapng"
    built = build_dns_capture(capture)
    result: dict = {"capture": built, "runs": runs}
    # The real pipeline: tshark -> flow engine -> tap -> queue -> detection worker. `detect` is TT-REC-001 alone.
    result["ingest"] = stage_ingest(capture, runs, ["off", "detect", "detect-m3", "detect-all"], None)
    configs = ["rec001", "default", "all"]
    collected: dict[str, list[dict]] = {c: [] for c in configs}
    for _ in range(runs):
        for config in configs:
            done = subprocess.run([sys.executable, __file__, "dns-one", config], capture_output=True, text=True, check=True)
            collected[config].append(json.loads(done.stdout.strip().splitlines()[-1]))
    engine: dict = {}
    for config, rows in collected.items():
        summary: dict = {}
        for label in rows[0]:
            if label == "config":
                continue
            summary[label] = {
                "median_events_per_s": statistics.median(r[label]["events_per_s"] for r in rows),
                "median_seconds": statistics.median(r[label]["seconds"] for r in rows),
                "max_process_peak_mib": max(r[label]["process_peak_mib_so_far"] for r in rows),
                "alerts_by_rule": rows[0][label]["alerts_by_rule"],
                "same_alerts_every_run": len({json.dumps(r[label]["alerts_by_rule"], sort_keys=True) for r in rows}) == 1,
                "rule_errors": rows[0][label]["rule_errors"], "malformed": rows[0][label]["malformed"],
                "dns_entries_tracked": rows[0][label]["dns_entries_tracked"],
                "dns_state": rows[0][label]["dns_state"],
            }
        engine[config] = summary
    result["engine"] = engine
    return result


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("stage", choices=["tshark", "ingest", "ingest-one", "queue", "detect-synth", "persist", "m3", "m3-one", "dns", "dns-one", "all"])
    ap.add_argument("capture", nargs="?")
    ap.add_argument("tap", nargs="?", default="off")
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--out")
    ap.add_argument("--baseline-backend", help="directory holding the Phase 3 `app` package")
    ap.add_argument("--modes", help="comma-separated ingest modes (default: off,on,detect,detect-m3,detect-all,persist)")
    args = ap.parse_args()
    capture = Path(args.capture) if args.capture else None
    if args.stage == "dns-one":
        print(json.dumps(dns_one(args.capture or "default"), default=str))
        return
    if args.stage == "m3-one":
        print(json.dumps(m3_one(args.capture or "default"), default=str))
        return
    if args.stage == "ingest-one":
        assert capture is not None
        print(json.dumps(ingest_once(capture, args.tap), default=str))
        return
    from app.services.flows.packet import FLOW_FIELDS

    result: dict = {"machine": sys.platform, "tshark": subprocess.run([str(TSHARK), "--version"],
                    capture_output=True, text=True).stdout.splitlines()[0]}  # fmt: skip
    if args.stage in ("tshark", "all"):
        assert capture is not None
        result["tshark_stage"] = stage_tshark(capture, args.runs, tuple(FLOW_FIELDS))
    if args.stage in ("ingest", "all"):
        assert capture is not None
        try:
            import app.services.detection.tap  # noqa: F401

            modes = ["off", "on"]
            import app.services.detection.service  # noqa: F401
            modes += ["detect", "detect-m3", "detect-all"]
            import app.services.detection.persist  # noqa: F401
            modes.append("persist")
        except ImportError:
            modes = modes if "modes" in dir() else ["off"]
        if args.modes:
            modes = args.modes.split(",")
        result["ingest_stage"] = stage_ingest(capture, args.runs, modes, args.baseline_backend)
    if args.stage in ("queue", "all"):
        try:
            result["queue_stage"] = stage_queue()
        except ImportError:
            result["queue_stage"] = "not available in this build"
    if args.stage in ("detect-synth", "all"):
        try:
            result["detect_synth_stage"] = stage_detect_synth()
        except ImportError:
            result["detect_synth_stage"] = "not available in this build"
    if args.stage == "dns":
        result["dns_stage"] = stage_dns(args.runs, Path(os.environ.get("TEMP", ".")) / "tt-m4")
    if args.stage in ("m3", "all"):
        result["m3_stage"] = stage_m3(args.runs)
    if args.stage in ("persist", "all"):
        try:
            result["persist_stage"] = stage_persist()
        except ImportError:
            result["persist_stage"] = "not available in this build"
    if "tshark_stage" in result:
        inc = result["tshark_stage"]["wall_increase"]
        result["gate"] = {"limit": GATE, "wall_increase": inc, "passed": inc <= GATE}
    text = json.dumps(result, indent=2, default=str)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
