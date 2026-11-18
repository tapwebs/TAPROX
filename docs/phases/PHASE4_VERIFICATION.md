# Phase 4 verification record

Branch `phase-4/threat-detection`, created from the Phase 3 commit `a42ac1c`. Milestones M1 and M2 are implemented;
M3 onward has not started. One section per milestone, with measured numbers only; the last section lists every known
limitation in one place.

## M1. Telemetry foundation and performance gate

### What was built

* Nine tshark fields appended to `FLOW_FIELDS` (so every earlier column keeps its position): `dns.flags.rcode`,
  `dns.qry.type`, `icmp.type`, `icmp.code`, `icmpv6.type`, `arp.opcode`, `arp.src.hw_mac`, `arp.src.proto_ipv4`,
  `arp.dst.proto_ipv4`. All exist in the installed tshark 4.6.9 (`tshark -G fields`). Same single tshark process.
* `FlowPacket` gained eight optional attributes (all default `None`): `dns_rcode`, `dns_qtype`, `icmp_type`,
  `icmp_code`, `arp_op`, `arp_sender_mac`, `arp_sender_ip`, `arp_target_ip`. Values are range-checked and must be ASCII
  digits (Python's `int()` would accept other scripts' digits). ARP frames are still not flow packets, but their address
  announcements are parsed.
* `services/detection/events.py`: typed immutable events (`FlowOpened`, `FlowRetired`, `DnsObserved`, `IcmpObserved`,
  `ArpObserved`, `TickSummary`).
* `services/detection/tap.py`: `EventQueue` (bounded, non-blocking producers, drops counted, FIFO, close-then-drain),
  `TelemetryTap` (O(1) per-address counters, one `TickSummary` per second of packet time) and `TapContext` (the
  session's vantage: local addresses and networks, gateways, DNS servers, interface MAC, promiscuous flag).
* `FlowEngine(tap=None)`: events are collected while the lock is held and handed to the tap **after** it is released.
  With no tap the engine does nothing extra.
* `CaptureService(tap_factory=None)`: one tap per session (live and opened file), closed when the session ends or
  fails to start. A factory that raises is logged and the capture continues without a tap. **Production passes no
  factory in M1, so no tap runs in the shipped application yet**; the new columns do.
* Not done in M1 (belongs later): rules, scoring, alert storage, migrations, UI, topology.

### Files

New: `backend/app/services/detection/{__init__,events,tap}.py`, `backend/tests/test_telemetry_fields.py`,
`backend/tests/test_telemetry_tap.py`, `scripts/perf/telemetry_bench.py`, this document.
Changed: `backend/app/services/flows/packet.py`, `flows/engine.py`, `capture/service.py`, `backend/pyproject.toml`
(one lint rule for the new package), `backend/tests/fake_tools/fake_tshark.py` (30 empty flow columns instead of 21),
`backend/tests/flow_fixtures.py` (DNS query type and response code, ICMP messages, ICMPv6, ARP builders),
`backend/tests/test_capture_service.py` (four tap integration tests).

### The performance gate (limit: +12% tshark time)

Method: `scripts/perf/telemetry_bench.py`, run with the backend's Python on the 168,349-packet, 165 MiB reference
capture (the Ethernet capture from the Phase 3 soak). Stage 1 runs tshark alone with the Phase 3 column set (21 decoded
fields, written out in the script so the baseline cannot move) and the current set (30), **interleaved**, output read
through a pipe and discarded. Stage 2 runs the whole ingest path (tshark → parse → row store → flow engine) in a fresh
process per run, with the Phase 3 code (extracted with `git archive a42ac1c`), the new code with no tap, and the new
code with a tap and a consumer thread, also interleaved. Memory is peak working set; CPU is user plus kernel time.

**Before (Phase 3 code, quiet machine, 3 runs):** tshark 5.66 s (runs 5.48, 6.12, 5.66), CPU 5.66 s, peak 327 MiB;
whole ingest 5.7 s, 29,668 packets/s, Python CPU 3.8 s, Python peak 76 MiB. The same bench comparing identical columns
against themselves read -3.8%, which is the noise floor of this method.

**After, tshark alone (limit +12%), three independent runs of the final column set:**

| Run | Phase 3 columns | Current columns | Wall time increase | CPU time increase | Runs per side |
|---|---|---|---|---|---|
| 1 | 8.21 s | 8.57 s | +4.4% | +2.7% | 5 |
| 2 | 8.98 s | 9.06 s | +0.9% | +2.4% | 5 |
| 3 (final code) | 9.06 s | 9.76 s | **+7.8%** | +4.0% | 5 |

Peak tshark memory is 327 MiB in both. **The gate passes in all three runs** (+0.9% to +7.8%). Caution when reading
the table: the absolute times are about 50% higher than the quiet-machine baseline because another project's test
suite was running on this computer during the "after" runs (found in the process list; not touched). Interleaving puts
that noise on both sides, but the run-to-run spread (8.55 to 10.14 s inside one side of run 3) is larger than the
differences being measured. The honest statement is "between +1% and +8%, always under 12%", not a single figure. If the
margin matters, repeat on a quiet machine.

**After, whole ingest path (final code, 5 interleaved rounds):**

| Configuration | Median wall | Packets/s | Python CPU | Python peak |
|---|---|---|---|---|
| Phase 3 code | 10.70 s | 15,728 | 7.19 s | 76 MiB |
| New code, tap off | 11.13 s (+4.0%) | 15,128 | 7.73 s | 76 MiB |
| New code, tap on, consumer draining | 11.85 s (+6.5% over tap off, +10.7% over Phase 3) | 14,208 | 8.17 s | 76 MiB |

Tap overhead: +6.5% wall and +5.7% Python CPU over the same code without a tap (target ≤ +10%). Memory did not change.
These were measured on the same loaded machine as above, so compare the rows with each other, not with the
quiet-machine baseline. A first, less careful run of the same stage showed the tap-on row at 13.1 s against 10.3 s for
tap-off while the machine load changed mid-run; the interleaved rerun above replaced it.

**Result identical to Phase 3** (compared against the pre-change baseline file): 168,349 packets analysed, 100,000
packet-list rows, 713 flows created, 0 evicted, every total (packets, bytes, non-IP, sent/received/other bytes) equal,
the per-application flow counts equal, and a SHA-256 over every flow's tuple, counters, state, protocol, application,
confidence and method equal for Phase 3 code, new code with no tap, and new code with a tap
(`b3d06d4f13cdd5cf58cfe7a8814ec04090e70720985b72ca8b530986a36e5cbe`).

### Event queue and dropped events

* On the real capture the tap produced **3,212 events** for 168,349 packets (about 19 per 1,000 packets, a few hundred
  per second at the measured pipeline speed). Queue depth never exceeded 104 of 10,000. **Dropped: 0.** All 3,212
  were consumed.
* Synthetic floods (500,000 events, batches of 16): the producer offered about 10 to 12 million events/s and never
  blocked. With a small queue and no consumer: 1,000 accepted, **499,000 dropped, counted exactly**. With a consumer
  that cannot keep up: 44,848 accepted, 455,152 dropped, accepted = consumed, order preserved. A consumer emptied a full
  queue at about 16 million events/s. A steady 46,000 events/s for 5 s with a consumer: 232,000 sent, 232,000
  consumed, **0 dropped**, depth never above 500.

### Tests

* New: `test_telemetry_fields.py` (42 tests) and `test_telemetry_tap.py` (28), plus 4 in `test_capture_service.py`:
  74 new tests. They cover missing DNS fields; malformed, out-of-range, non-ASCII and over-long field values; ICMP
  types and codes; an ICMP error that quotes another ICMP; ICMPv6; ARP request, reply, conflict probe and malformed
  ARP; the real tshark decoding NXDOMAIN, TXT queries, echo, destination unreachable, ICMPv6 echo and ARP from
  byte-built frames; queue order, saturation (producer never blocks), timeout versus end marker, close wakes a
  waiting consumer, drain after close, offers after close, four concurrent producers with a consumer; tick counters,
  failed-handshake accounting, time going backwards, top-N folding; the engine producing the same flows with and
  without a tap; the tap running after the lock is released (a tap that reads the engine from inside its callback does
  not deadlock; a slow tap does not stop another thread from reading the engine); a consumer reading while 2,000 flows
  are created sees every event in order; feeding after finish; the capture service giving the tap its vantage, closing
  it on completion and on stop, surviving a failing factory, and tapping an opened file.
* One genuine defect was found by these tests and fixed: the last second's failed-connection count was taken before
  the flows that ended with the capture were counted.
* Real tshark finding recorded in the tests: a DNS **query** has no response code (tshark prints it on responses only),
  so a query's `rcode` is `None`, never 0.
* Whole backend suite: 961 passed, 3 skipped (the same 3 platform skips as before); it was 887 + 3 before M1.
  `ruff check`, `ruff format --check` and `mypy` are clean. The contract check is up to date (no API change).

### Live checks as a normal user (Windows)

`run-live-check.ps1 -Mode Soak` (real dumpcap, real Npcap, Ethernet, normal user, no prompt), three runs on the final
code. The 2-minute run captured for the whole 137 s (6,626 packets). The last 3-minute run captured for the whole 200 s
(19,153 packets, 14.0 MiB, 307 flows after save and reopen). Every run showed `problems: none`, flows and applications
updating, a display filter returning in 1.1 s, save and reopen working, 20 processes sampled and none elevated, and
no backend, dumpcap, tshark or temporary capture file left afterwards.

The first of the three runs ended its capture by itself after 56 s while the window stayed open. It is investigated in
the follow-up section below; the cause is **not established**.

### Not run in M1

Dashboard and Rust suites were not re-run: no frontend, Rust or API file changed. A 10-minute soak was not repeated: no
capture-lifecycle code changed beyond closing an optional tap.

### Remaining risks

* The tshark gate margin is wide on average but the measurements are noisy; M2 should re-check it on a quiet machine
  before more fields are added.
* The 7.8% worst case is in the same order as the 12% limit; any further field must be measured the same way.
* `TickSummary` counters only reflect sources and destinations that are IP addresses; non-IP traffic appears only as
  ARP events.
* The unexplained early "Completed" (see the follow-up section).

## M1 follow-up: the 56-second capture completion, and final verification

### What happened in the 56-second run (retained artifacts)

The run's report, its resource samples (every 15 s), its process-token list and the saved capture were kept; the backend's
own output was not (the desktop shell drains the backend's stdout and keeps only the last stderr lines when the backend
fails). Findings, in order of how much they settle:

1. **The app and the backend did not stop.** Desktop (pid 16656), backend Python (25848) and the web view stayed alive
   for the rest of the run; working set stayed flat at about 575 MiB. Between the 04:35:02 and 04:35:18 samples
   (local time) the process count fell from 15 to 11, which is exactly dumpcap, the live tshark and their two console
   hosts leaving. So the capture tools ended while everything else carried on.
2. **"Completed" with no error has only two possible causes in the code.** After dumpcap ends, `_finish` marks the
   session failed unless the exit code is 0 **or** a stop was requested. A dumpcap that is killed or crashes would show
   "Failed" with a message. The shipped code requests a stop only from the Stop button (`POST /capture/stop`), when a new
   capture or file replaces the session, at the 1 GiB size limit (this run had 18.4 MiB), or at shutdown.
3. **A requested stop makes Windows dumpcap exit with code 1, yet the session reads "Completed".** Measured in the
   instrumented runs below (dumpcap return code 1 after every explicit stop). So the exit code alone cannot tell the
   two causes apart afterwards.
4. **Nothing in the test driver stops a capture.** `cdp-soak.mjs` only changes the page and reads text during the
   capture; its single Stop click is at the end, and in this run it found no button because the session was already
   Completed.
5. **Windows recorded nothing in the window** (04:33 to 04:38 local): the System, NetworkProfile, NDIS, DHCP client, WLAN
   and Defender logs had no events; the Application log had two events from a Microsoft-Windows-Sec... provider (not about networking or capture); the Wow64 entries seen
   elsewhere that morning are the test suite's fake executables. Nothing about the adapter, Npcap or an antivirus.
6. **M1's own code is not implicated by what is known.** The tap was `None` in the desktop application (no factory is passed
   in production), and a parsing error in the reader thread can only produce a "live packet list stopped" warning, never
   "Completed". What M1 did change in that run is the tshark column count and the parsing of the new columns.

Not determinable from the evidence: whether a stop was requested, or dumpcap exited 0 by itself. The 15-second sampling of
the soak driver cannot show the 2 to 4 second "Stopping" state that precedes every requested stop.

### Reproduction (normal user, no Npcap, UAC or antivirus setting touched)

Six two-minute live captures on the Ethernet adapter, with web, DNS and ping traffic like the soak driver's.

*Three in-process runs of the real capture service* (real dumpcap, tap attached with a consumer, every stop and
termination call logged with its caller):

| Run | Packets / bytes at 120 s | State changes | Stop calls before the planned end | Telemetry queue before stop → after stop | Result |
|---|---|---|---|---|---|
| h1 | 16,186 / 14.6 MB | preparing → capturing at 1.1 s | none | accepted 566 → 662, consumed 566 → 662, dropped 0 | ran the full time |
| h2 | 11,625 / 9.5 MB | same | none | 550 → 649, dropped 0 | ran the full time |
| h3 | 12,728 / 10.9 MB | same | none | 582 → 700, dropped 0 | ran the full time |

In each run dumpcap and tshark were still running at 120 s (no return code), no error, no warning. The harness then stopped
explicitly: state completed after about 3.2 s, dumpcap return code 1, queue closed, every accepted event consumed.

*Three runs through the desktop window* (`run-live-check.ps1 -Mode Soak -Minutes 2`, plus a read-only observer
`scripts/live-check/cdp-peek.mjs` that logs the Capture panel every 2 s, and a 1 Hz process sampler):

| Run | Packets / size / seconds at the end | Capture state seen | dumpcap and tshark | Backend and desktop | Ended |
|---|---|---|---|---|---|
| d1 | 8,456 / 5.6 MiB / 137 s | Preparing → Capturing → **Stopping** → Completed | alive until the driver's Stop click | healthy, no console errors | explicitly stopped by the driver at about 135 s |
| d2 | 13,324 / 9.0 MiB / 140 s | same | same | same | same |
| d3 | 52,282 / 44.8 MiB / 140 s | same | same | same | same |

In all three, 19 to 22 processes were sampled and none was elevated, the display filter, save and reopen worked, and no
backend, dumpcap, tshark or temporary capture file was left. A requested stop is always visible as "Stopping" for 2 to 4
seconds in the 2-second observer log; that is the signature to look for if the early completion returns.

**Result: not reproduced in 6 of 6 runs.** Counting the three soak runs made earlier with the M1 code (one of which
ended early), the early completion happened once in nine M1-era captures; none of the many captures made earlier in Phase
3 or in the two earlier soaks that day ended early. It is **unexplained and intermittent**. No defect is confirmed, so
no application code was changed.

### Questions the task asked, answered with what is known

| Possible cause | Verdict |
|---|---|
| A genuine dumpcap exit (code 0) | Possible; cannot be confirmed or excluded |
| Backend cancellation (a stop request, or a replaced session) | Possible; nothing in the retained evidence shows a caller, and the driver did not click Stop |
| Frontend request or session termination | Not shown; the driver does not stop captures, and no stop call appears in six later runs |
| Process cleanup | Not shown; no shutdown happened (desktop and backend stayed up and the later steps worked) |
| A test-driver action | Not shown (see point 4) |
| An external Windows or Npcap event | Not shown; no event is logged for the period |
| The M1 tap | Not implicated: the tap was not attached in that run, and it behaves correctly in the six later runs |

### Final M1 verification (quiet machine: the other project's tests that loaded the machine earlier were idle)

| Check | Result |
|---|---|
| tshark overhead (limit +12%) | Phase 3 columns 5.70 s, current columns 5.74 s: **+0.7% wall, +0.3% CPU** (5 interleaved runs per side); peak memory 327 MiB both |
| Whole ingest | Phase 3 code 5.61 s (30,016 packets/s); new code, no tap 5.80 s (+3.4%); tap on 6.16 s (+6.2% over no tap, +9.8% over Phase 3). Python CPU 4.06 / 4.45 / 5.11 s; Python peak 76 MiB in all |
| Phase 3 results unchanged | 168,349 packets, 100,000 list rows, 713 flows; every total equal; the flow digest (`b3d06d4f13cdd5cf58cfe7a8814ec04090e70720985b72ca8b530986a36e5cbe`) equal to the pre-change baseline for all three configurations; identical in every run |
| Real-capture events | 3,212 events, queue depth at most 104 of 10,000, 0 dropped, 3,212 consumed |
| Ordering | Preserved: queue flood test `in_order` true, four-producer test keeps each producer's order, 2,000 flows seen as 1..2,000 in order |
| Producers never block | 500,000 events offered in 0.025 s at about 19 to 20 million events/s with a full queue and no consumer |
| Overflow is counted | 499,000 refused of 500,000 with 1,000 accepted; 480,000 refused with a slow consumer, accepted = consumed |
| Shutdown drains | After close the consumer receives everything queued, then the end marker; in the live runs the queue closed after stop with every accepted event consumed (h1 to h3) |
| Steady rate | About 47,700 events/s for 5 s: 238,500 sent, 238,500 consumed, 0 dropped, depth at most 500 |
| Backend tests | 961 passed, 3 skipped (unchanged since the last code change); `ruff`, `ruff format --check`, `mypy` clean |

### Changes in this follow-up

No application code changed. One new investigation tool: `scripts/live-check/cdp-peek.mjs` (a read-only observer that logs
the Capture panel whenever it changes), and this section.

### Recommended, not done (needs approval)

The investigation was hard because the application does not record **why** a capture ended. A small change would keep that:
store the dumpcap exit code and whether a stop was requested as a status warning, or in a log file with a size cap. That is a
behaviour and API-visible change (it adds text to the status), so it was not made here.


## M2: detection engine core

Branch `phase-4/threat-detection`, uncommitted. Windows, normal user, tshark 4.6.9.

### Scope and deviations from the roadmap

* One rule only, as the roadmap's M2 says: **TT-REC-001 Vertical port scan pattern**. No other rule exists.
  Rules that need a baseline are handled by the engine (`requires_baseline` gives
  "not_evaluated: baseline not ready"), proven with stub rules only.
* **Alerts are in memory only** (1,000 per run, three runs kept). The roadmap listed migration `0004` and
  the `/alerts` APIs in M2; the M2 brief did not, so they are deferred and need a decision.
  **Superseded: migration `0004`, persistent alerts and the alert APIs were added afterwards; see "M2 completion" below.**
* API additions: `GET /api/v1/detection/status` (counters, no alert content) and the additive
  `CaptureStatus.termination`. Contract regenerated, `contracts:check` passes.

### Rule TT-REC-001 as implemented

* Pattern: one source starts TCP connections to `distinct_ports` (default 20, 5..1000) different ports on one
  destination within `window_s` (default 60, 10..3600), measured in packet time, window inclusive.
* Severity medium; high at 10 times the threshold. Confidence high when the share of attempts without an
  answer is at least `high_confidence_failed_ratio` (default 0.8, 0.5..1.0).
* Bounds: 1,024 ports per pair, 10,000 pairs, 200,000 entries; oldest state evicted and counted.
* Wording: findings describe a "pattern", never an intent or a verdict.

### Modules (`backend/app/services/detection/`)

`rules/base.py` (rule contract), `rules/recon.py` (TT-REC-001), `risk.py` (scoring), `windows.py`,
`correlate.py`, `normalize.py`, `alerts.py` (dedup, grouping, bounded book), `registry.py`, `engine.py`,
`service.py` (consumer task on the M1 queue, `tap_factory`, status). The consumer reads the bounded queue
from M1; it never blocks the tshark reader or the flow engine and does not see raw packets.

### Scoring (integer percent, half-up)

Base 50 (medium/high). Gateway target +5 = 55; recurrence +0.05 = 53; known entity -0.20 = 40; worked
example 60. The score ranks alerts; it is not a verdict.

### Capture termination diagnostics

`termination` = `{ stop_requested, stop_source, dumpcap_exit_code, tshark_exit_code, reason, final_state }`,
one log line per capture, null while running and for files. Real dumpcap probes (normal user, 3 x 120 s
explicit stop, 1 x external kill), run through the real `CaptureService` + `DetectionService`:

| Run | Action | dumpcap exit | reason | final state | Detection events | Queue dropped |
|---|---|---|---|---|---|---|
| s1 | stop at 120.7 s | 1 | `stopped_by_request` | completed | 711 | 0 |
| s2 | stop at 120.7 s | 1 | `stopped_by_request` | completed | 500 | 0 |
| s3 | stop at 120.7 s | 1 | `stopped_by_request` | completed | 517 | 0 |
| k1 | dumpcap killed at 25.5 s | 1 | `tool_failed` | failed (`capture_failed`) | 156 | 0 |

Finding: an explicit stop makes Windows dumpcap exit with code 1 while the state is `completed`. The record
makes that visible. Normal completion at a limit, size limit, session replaced, shutdown and a tool that dies
midway are covered by `test_capture_service.py` with fake tools. The 56-second early completion was not
reproduced in these three runs (all ran to the stop) and remains unexplained.

### Tests

* Backend: **1141 passed, 3 skipped** (961 after M1, +180). ruff check, ruff format and mypy (145 files) clean.
* Dashboard: 400 passed, `tsc --noEmit` and `eslint .` clean.
* Detection tests: `test_detect_rec001.py` (threshold and window boundaries, duplicates, missing and malformed
  fields, answered/unanswered, session boundary, benign traffic), `test_detect_engine.py`,
  `test_detect_support.py`, `test_detect_service.py` (queue overflow, malformed events, baseline not ready),
  `test_detect_integration.py` (real tshark, API).

### Performance (quiet machine, 168,349-packet / 165 MiB capture, median of 5)

| Measure | Result |
|---|---|
| tshark wall, Phase 3 fields vs current | 5.59 s vs 5.62 s, **+0.56 %** (gate <= +12 %: passed); CPU +0.28 % |
| Ingest wall: Phase 3 code / tap off / tap on / tap + detection | 5.66 / 5.78 / 5.92 / 5.93 s |
| Ingest result | identical flows and totals in every run; 3,212 events; queue high water 104; 0 dropped |
| Alerts on this benign capture | 0 findings, 0 malformed, 0 rule errors |
| Queue, steady 47.6k events/s for 5 s | 0 dropped, high water 500 |
| Queue, 500k burst with no consumer | bounded, excess counted as dropped (465,232 / 499,000), producer never blocked |
| Engine alone (synthetic) | ~110k events/s on 1.0M ordinary events; 148-184k on floods |
| Engine state | 10,000 pairs tracked, 490,000 evictions counted; 65,535-port flood gives 1 alert with 1,024 entries; 300k-source flood ends with 0 tracked |

Real pipeline rate is a few hundred events per second, so the engine has roughly 300 times headroom.

### Live desktop soak (2 minutes, normal user)

Detection wired in production. Capture tools running afterwards: 0; backend processes left: 0; temporary
capture files left: 0; no elevated processes. Resident memory stayed flat after startup (Python backend
100 -> 104 MiB, tshark 99 -> 105 MiB).

### Limitations

* ~~Alerts are lost at exit; no alert APIs or lifecycle yet.~~ Superseded by "M2 completion" below.
* Only TT-REC-001 exists. The self-activity exclusion is a hook with no producer wired.
* Corroboration, known-entity and baseline paths are exercised by stub rules, not by a real rule.
* Coverage reduction is approximated from `TickSummary` drop counts.
* The REC-001 positive case is proven on synthetic events, and no live scan was run against the network.
* Benchmarks ran while another project occasionally loaded the machine; the numbers above are from a quiet run.

## M2 completion: persistent alert storage and API

Branch `phase-4/threat-detection`, uncommitted. Windows, normal user, tshark 4.6.9. Scope: only what the brief
named (migration `0004`, SQLite-backed alerts, alert endpoints, retention). No new rule, no new scoring, no UI.

### What was built

* **Migration `0004_alerts`**: `detection_runs`, `alerts`, `alert_evidence`, `alert_events`, `detection_rules`,
  `detection_rule_changes`, `suppressions`, with every index of the database design. Additive only; the existing
  backup-before-migrate runs first. Differences from the plan are in `PHASE4_DATABASE_DESIGN.md` section 9.
* **`AlertStore`** (`services/detection/store.py`): one atomic write path. A write takes the SQLite write lock up
  front (`BEGIN IMMEDIATE`), so a read-then-write cannot lose an update to the API or to flow saving.
* **`AlertWriter`** (`services/detection/persist.py`): the detection worker only calls `offer`, which merges the
  alert snapshot into a bounded in-memory set (2,000 alerts, one entry per dedup key). One thread writes it, in
  transactions of at most 10 alerts, at least once a second. Capture, flow and detection threads never touch the
  database.
* **Lifecycle** (`lifecycle.py`): six states; an active alert can go to any other state, a closed one can only
  return to `open` (that is "unsuppress"). The one automatic path: a `resolved` alert whose key fires again
  reopens with `recurrence_count + 1`. A `false_positive` stays closed and the repeat is logged once.
* **API**: `GET /alerts`, `/alerts/summary`, `/alerts/{id}`, `/alerts/{id}/events`, `PATCH /alerts/{id}`,
  `GET /detection/runs`, `DELETE /detection/history`. All additive; the OpenAPI contract was regenerated with the
  repository tooling. A check against the Phase 3 contract shows no existing path changed and no existing schema
  changed except `CaptureStatus` (the M2 `termination` field).
* **Retention**: 180 days and 5,000 alerts by default, read from `app_meta` (bounds 7 to 3,650 days, 100 to 100,000
  alerts; a value outside its bounds is ignored and reported). Applied at start-up (on the writer thread, so
  start-up never waits) and after any write that adds alerts or ends a run. Over a limit, closed alerts go first, then
  acknowledged, then open and investigating ones; deleting an open one is recorded as a warning on the current run.
  Finished runs: newest 1,000 kept. Pruning works in batches of 500 rows per transaction.
* **Delete-all** needs `{"confirm": true}` as the JSON value `true`. A first version accepted the string `"yes"`
  and deleted three alerts in a test; the field is now strict and the test lists the loose values it refuses.
  It removes alerts (with evidence and events) and finished runs only. Inventory, flows, captures, rule settings
  and suppressions are untouched (asserted by test). A run that is still running keeps its row.

### How a failure shows

`GET /detection/status` carries `persistence`: `healthy`, `pending_alerts`, `alerts_inserted`, `failed_flushes`,
`last_error` (the exception kind and SQLite's own message, never SQL or alert text), and `alerts_not_stored`
(`dropped_alerts` because the waiting set was full, `rejected_alerts` refused by the database, `lost_at_shutdown`).
An alert counts as stored only after its transaction committed. Each run also lists `warnings`
("Alert writes were delayed", "Some alerts could not be stored", "Coverage reduced", and so on), and they are saved
with the stored run. A locked database keeps every alert and retries; a database that stays unavailable until the
application closes is logged and counted, not hidden.

### Tests (all first written to fail; the mutation checks below show they can)

* Backend: **1402 passed, 3 skipped** (1141 before this step, +261). ruff check, ruff format and mypy (160 files)
  clean. Dashboard: 400 passed, `tsc --noEmit` and `eslint .` clean. `contracts:check` passes.
* New files and counts: `test_migration_0004` (13), `test_alert_lifecycle` (41), `test_alert_store` (71),
  `test_alert_writer` (21), `test_detect_persistence` (18), `test_alerts_api` (92), `test_alerts_pipeline` (5).
  Three existing tests were updated because the schema head moved to `0004` and alerts are now stored
  (`test_flow_store` twice, `test_detect_integration` once).
* Covered: migration from a Phase 3 database (rows kept, one backup, no backup on reopen, newer database refused),
  fresh database, exact index set, descending risk index, ids never reused, foreign keys (SET NULL and CASCADE),
  evidence stored whole, in order and by value, the 30-item cap and `evidence_dropped`, clipping of long text,
  impossible packet times, deduplication across a restart, occurrence updates, reopen and false-positive handling,
  every status pair, filters, sorting, paging, summary, retention order and batches, delete-all scope, locked
  database, a start/finish surviving an outage, one poison alert not stopping the rest, a stuck database never
  blocking `offer`, the detection worker or loading a capture, four threads hammering the writer without losing an
  occurrence, concurrent flow saving plus API reads plus detection, authentication and Host/Origin refusals on every
  route, SQL and pattern characters in `search`, malformed ids and bodies, markup in notes returned as plain text.
* **Mutation checks** (16 deliberate breaks of the production code, each run against the tests that should catch
  it, on the final code): all 16 were caught. Examples: removing the reopen branch, appending evidence instead of replacing it, not
  restoring a failed batch, dropping the pending-set bound, not counting alerts lost at shutdown, not copying the
  snapshot, not discarding pending alerts on delete-all, dropping the `since > until` check, dropping the confirm check or making it accept strings, removing
  `BEGIN IMMEDIATE`, pruning at start-up on the caller's thread.
* Stability: the timing-sensitive files were run six times in a row and four at once in parallel; no failure.

### Real-data migration

A Phase 3 database was built with the extracted Phase 3 code from the 168,349-packet reference capture (2 sessions,
1,426 flows, schema `0003`). `init_database` with the new code: schema `0004`, flows unchanged (same SHA-256 over
all rows), `PRAGMA integrity_check` ok, `foreign_key_check` empty, one backup of the `0003` database with all 1,426
flows. No real user database exists on this machine, so none was touched.

### Performance (this machine, other applications running; two runs are given where they differ)

| Measure | Result |
|---|---|
| tshark time, Phase 3 fields vs current (gate: not more than +12 %) | 5.654 s vs 5.686 s, **+0.57 %** (CPU +1.11 %). Passed. No tshark field changed in this step |
| Ingest wall time (168k packets, median of 5): Phase 3 code / tap off / tap on / detection / detection + storage | 5.83 / 6.10 / 6.13 / 6.19 / 6.22 s. Storage adds 0.03 s (+0.5 %) over detection; the capture has no scan pattern so no alert is written |
| Same flows in every mode | yes (identical digests); queue: 3,212 events, high water 104, 0 dropped in all 10 detection runs |
| Python peak memory in that benchmark process | 77 MiB (off), 113 MiB (detection), 127 MiB (detection + storage). The extra 14 MiB is mostly importing SQLAlchemy and the schema in a process that otherwise has none |
| Hand-off of an alert to the writer (`offer`) | 5.4 us median, 13.7 us p99, 2,000 alerts / 6,000 calls. The engine ran 102,000 events in 1.357 s without storage and 1.349 s with the hook (the difference is inside run-to-run noise) |
| Alert burst: 2,000 alerts in 1.5 s, written by the live writer | all 2,000 stored, 0 not stored, 201 transactions of at most 10 alerts: median 12 ms, p95 19 ms, **one outlier of 1.2 s** (see below). The rest drained 2.5 s after the engine finished |
| Delay from an alert appearing to being stored (default 1 s interval, 30 alerts at random moments) | median 0.72 s, p95 0.98 s, max 0.99 s |
| Database size | 8.5 KB per alert with 23 evidence items; 40.5 MiB projected at the 5,000-alert default (the design estimated about 60 MiB worst case) |
| Reads at 5,000 / 10,000 / 100,000 stored alerts, p95 | newest 50 open: 2.0 / 2.0 / 9.5 ms; by risk: 2.0 / 2.3 / 10.3 ms; newest 50 of all: 9.8 / 18.6 / 155 ms; one rule + severity: 5.5 / 8.1 / 71 ms; by address: 16 / 42 / 287 ms; text search: 33 / 53 / 505 ms; summary: 22 / 35 / 335 ms |
| Retention catch-up, 100,000 rows to 5,000 | 23 s in 190 transactions of 500 rows each (on the writer thread) |
| Desktop soak, 2 minutes, normal user, detection and storage wired | no capture tool, backend process or temporary file left; Python backend 102 to 109 MiB, tshark 100 to 111 MiB; nothing elevated |

The default list (open alerts, newest first) is served by `ix_alerts_status_updated` (`EXPLAIN QUERY PLAN`: covering
index search, no table scan; also asserted by test). The design's targets (p95 under 100 ms at 10,000 rows and under
300 ms at 100,000 for the alert list) hold for that list and for sorting by risk. They do not hold at 100,000 rows for
the unfiltered list ordered by time (155 ms is inside the target; the by-address filter at 287 ms is close, text search
and summary are not) because those queries have no index in the designed schema. At the default 5,000 rows every
read is under 35 ms.

**The 1.2 s write outlier.** In the burst benchmark one 10-alert transaction took about 1.2 s. It appears once, early
in the burst (with 25 alerts per transaction it was the second write), while the engine thread is using the CPU flat
out: the writer thread waits for Python's interpreter lock between statements. I did not measure the lock itself, but a
transaction that long holds the database write lock for as long. Smaller transactions shrank it (25 alerts per
transaction: 1.45 to 1.66 s; 10: 0.8 to 1.0 s; 5: 0.5 s), which is why the default is 10. It needs a saturated Python
process; the real pipeline produces alerts at a few per minute. The roadmap's "no transaction over 100 ms in the soak"
could not be shown with alerts in the soak (benign traffic raises none); in the synthetic burst the p95 is 19 ms.

### Limitations and things not done

* Alerts have no live push; a client must poll. A new alert is visible within about 1 s of being raised.
* Reads by address or by text, and the summary, grow with the number of rows (table scan) because the designed
  schema has no index for them. Fine at the 5,000 default; slow near 100,000.
* The two retention limits are read from `app_meta` but there is no API to change them yet (M9).
* `GET /detection/rules*`, rule editing, the `suppressions` API and "top devices" in the summary are not built; the
  tables for rules and suppressions exist and nothing writes them.
* Evidence on a repeated finding is replaced, not appended (the rule's evidence is cumulative). If a second run
  produces the same alert key with less evidence, the stored evidence becomes that run's.
* Delete-all while a capture is running leaves the live run's row; the running run can recreate alerts that were
  just deleted when it next reports them.
* An alert's device link is resolved once, when the alert is first stored, from the inventory's last known address.
* Counters on a stored run are written when the run ends; a run that crashes keeps zero counters and the status
  `aborted`.
* A single burst of thousands of alerts at once is bounded (2,000 waiting; the rest are counted as not stored), by design.
* Benchmarks ran with other applications using the machine; numbers are medians of 5 runs but absolute values will differ.

## M3: reconnaissance and failure rule pack

Branch `phase-4/threat-detection`, on top of `eb8427d`, **uncommitted**. Windows, normal user, tshark 4.6.9. Backend only:
no migration, no API endpoint, no schema, no frontend or Rust change (`npm run contracts:check`: `schema.d.ts` is up to
date, no contract file changed). The exact behaviour of every rule, and the owner's approved resolutions, are in
[PHASE4_DETECTION_RULES.md](PHASE4_DETECTION_RULES.md) section 9; this section is the evidence.

### What was built

Nine rules: TT-REC-002, TT-REC-003, TT-REC-004, TT-REC-005, TT-TRF-003, TT-TRF-006, TT-APP-002, TT-APP-003, TT-APP-004.
On by default (with TT-REC-001): REC-002, REC-003, TRF-003, APP-003, APP-004. **Off by default: REC-004, REC-005, TRF-006,
APP-002. They cannot be switched on from the product until the rule-settings UI and API of M9 exist**; they are exercised by
tests through `RuleSettings`. `detection_rules` is not read at start-up (rejected as scope).

Shared changes:

* Corroboration now counts distinct rule IDs on the same entity, not categories (`CorrelationIndex.observe(entity, rule_id,
  t)`). The M2 tests that assumed categories were updated.
* `SelfActivity` (new, `services/self_activity.py`): the discovery service records when its scan runs; live captures only.
  `main.py` wires it into both services. `self_activity_excluded` is counted once per event.
* `RuleMeta.supports` and hold-and-merge in the engine (`engine.py`, `alerts.py`): TT-REC-005 findings become evidence in
  the TT-REC-001 alert of the same pair (no second alert, no corroboration factor), wait up to the rule's window, or stand
  alone. At most 1,000 findings are held.
* `rules/common.py` holds the helpers shared by the rules (IP parsing, sequential share, multicast test, MAC handling, the
  attempt-failed test). `rules/traffic.py` and `rules/app.py` are new; REC rules were added to `rules/recon.py`.
* The M2 test helper `make_engine` now defaults to TT-REC-001 alone, and four M2 service-level test modules run the
  service with that one rule (`tests/conftest.py`), because a 30-port scan with 30 refused connections is now also a
  TT-TRF-003 finding. M3 tests use the product defaults through `m3_fixtures.make_engine`.

### Tests

Written test-first, one rule at a time (red, then green). Final run of the whole backend suite after the outcome correction below: **2,014 passed, 3 skipped**
(the three skips are Linux-only or POSIX-only, as before). `ruff check` and `ruff format --check` (180 files) and `mypy`
(177 files, strict) are clean; `git diff --check` is clean.

| File | Covers |
|---|---|
| `test_m3_common.py`, `test_self_activity.py` | shared helpers; the scan-activity record, grace, expiry, bounds |
| `test_m3_rec002.py` ... `test_m3_trf006.py` (9 files) | per rule: positive, control, threshold -1/0/+1, window +-1 s, near-miss, malformed telemetry, text and wording policy, dedup and evidence, bounded state |
| `test_m3_pipeline.py` | all nine through one scenario set: explanation, storage round trip, live/file replay equivalence, quiet-time dedup, default-off rules do nothing until enabled, all nine in one interleaved stream (and three replays), sweep + scan correlation (+0.10), queue overflow with all rules on, failing database with the new alerts, 20,000-event floods within every bound, real tshark decoding of the cleartext protocols, payload privacy |
| `test_discovery_service.py` (+4) | the discovery service records its scans |

The required cases map as follows: 10,000-source state (REC-002, -003, -004, -005, TRF-003, TRF-006, APP-004 files and the
pipeline flood test); 10,000 destinations and "at least" reporting (`test_m3_rec002.py`); IPv6 destinations (`test_m3_rec002.py`,
`test_m3_common.py`, `test_m3_app003.py`); ARP conflict and gateway exclusions (`test_m3_rec003.py`); discovery exclusion and expiry
(`test_self_activity.py`, REC files); REC-005 hold, merge, timeout, standalone (`test_m3_rec005.py`, 40 tests); a sweep and a
scan from one source share a group and the later alert gains +0.10 (`test_m3_pipeline.py`); TRF-003 dual-stack
(`test_m3_trf003.py`); TRF-006 out-of-order retirement (`test_m3_trf006.py`); SNMP v1/v2c/v3 produce no finding.

**Real tshark decoding (APP-004), byte-built packets, no captured traffic.** tshark 4.6.9 decoded all eight cleartext
protocols from the built packets: telnet (23), ftp (21), tftp (UDP 69), rlogin (513), rsh (514), pop (110), imap (143) and
ldap (389, a BER simple bind). Each was then run through the real capture pipeline with the real tshark, and APP-004 reported
exactly that protocol. SNMP v1, v2c and v3 (UDP 161) were also decoded as `snmp` and produce no APP-004 finding. Nothing
could not be decoded. These are hand-built fixtures; they show that the decoder names the layers, not how real servers
behave.

**Privacy of APP-004 evidence.** Every protocol's packets carried the marker `hunter2` (the test first confirms the marker
is in the input capture). After the alerts were stored, the SQLite file and its WAL were read as bytes: the marker is absent.
Evidence holds the protocol name, endpoints, byte counters and flow tuples only.

**Mutation checks** (a small change to the real source, the relevant tests must fail, then the file is restored): nine were
caught: held findings never claimed; held findings not released at run end; corroboration step changed; TRF-006 keeping
retirement order; REC-005 run share exactly at the setting; TRF-003 fallback window; merged evidence not shrinking the rule's
own items; APP-004 TLS skip; the IPv6 dilution of the sequential share. The merged-evidence mutation was missed at first
(no scenario reaches the 30-item cap), so `test_merged_evidence_is_kept_whole_and_the_rules_own_items_give_way_at_the_cap`
was added and then caught it. Two attempts proved nothing: one changed `>=` to an equivalent comparison, and one (a TRF-003
`ratio <` boundary) matched no source text and was not run. Nothing else was mutated.

### Performance

Tool: `scripts/perf/telemetry_bench.py`, new stage `m3` (separate processes per configuration, so peak memory is each
one's own; three interleaved rounds, medians) and new ingest modes `detect` (TT-REC-001 alone, the M2 equivalent),
`detect-m3` (product defaults) and `detect-all` (all ten rules). The machine had other applications running; the repeat
runs below show how much that moved the numbers. **The ratios inside one run are the evidence.**

Engine alone on 1,001,000 synthetic ordinary events (500,000 answered connections from 10,000+ sources), quiet run:

| Configuration | Events/s | Wall | Peak memory |
|---|---|---|---|
| M2 code (`eb8427d`), TT-REC-001 alone, median of 3 (100.6k, 107.6k, 106.3k) | 106,267 | 9.3 s CPU | 36.4 MiB |
| M3 code, TT-REC-001 alone | 101,051 | 9.9 s | 36.8 MiB |
| M3 code, product defaults (6 rules) | 50,142 | 20.0 s | 52.6 MiB |
| M3 code, all 10 rules | 28,008 | 35.7 s | 70.5 MiB |

TT-REC-001 alone is within the spread of the M2 measurements (-4.9 %, the M2 runs themselves differ by 7 %). The defaults
cost about half the throughput of the single rule, and all rules about 72 % of it. A second complete run while the machine
was loaded gave 57,302 / 26,440 / 15,400 events/s: the same ratios (0.46 and 0.27 of the single-rule figure against 0.50
and 0.28 in the quiet run). A one-off measurement of each rule alone on 200,000 events (not part of the script) gave: engine
with no rule 217k events/s; REC-001 140k; REC-002 108k; REC-003 225k; REC-004 148k; REC-005 119k; TRF-003 138k; TRF-006
175k; APP-002 204k; APP-003 201k; APP-004 206k. REC-002 and REC-005 cost the most.

High-cardinality floods (quiet run, events/s; REC-001 alone / defaults / all rules):

| Flood | REC-001 alone | Defaults | All rules | Alerts (all rules) |
|---|---|---|---|---|
| 10,000 sources, one refused connection each | 106,868 | 57,907 | 41,393 | none |
| 1 source to 10,000 destinations on one port | 110,237 | 68,898 | 48,301 | REC-002 x1 ("at least"), TRF-003 x1 |
| 20,000 ascending ports to one host | 133,504 | 55,477 | 45,075 | REC-001 x1 (REC-005 merged into it) |
| 200,000 echo requests to 10,000 hosts | 195,173 | 71,597 | 72,770 | REC-002 x1 |
| 20,000 ARP requests (10,000 targets from one sender; 10,000 senders) | 505,543 | 107,740 | 104,047 | REC-003 x1 |

Every configuration gave the same alerts in all three rounds, with no rule errors and no held findings left at the end.
State stayed at its caps (ordinary mix with all rules: 10,000 keys in each of REC-001, -002, -004, -005, TRF-003 and TRF-006,
490,000 evictions counted in each; ICMP flood: 10,000 pairs and 200,000 buckets). Peak memory of the whole process after all
floods: 109.5 MiB with the defaults or all rules, against 61 MiB for the single rule.

Ingest of the 168,349-packet reference capture through tshark, flow engine, tap, queue and detection worker (5 interleaved
rounds; the machine was loaded, individual walls ranged from 6.5 s to 17.9 s, so medians are shown):

| Configuration | Median wall | Median Python CPU | Events accepted | Queue high water | Dropped | Alerts |
|---|---|---|---|---|---|---|
| M2 code, TT-REC-001 alone | 8.52 s | 6.70 s | 3,212 | 104 | 0 | 0 |
| M3 code, tap and detection off | 8.33 s | 6.11 s | - | - | - | - |
| M3 code, TT-REC-001 alone | 8.53 s | 7.02 s | 3,212 | 104 | 0 | 0 |
| M3 code, product defaults | 8.55 s | 6.84 s | 3,212 | 104 | 0 | **3** |
| M3 code, all 10 rules | 8.16 s | 6.69 s | 3,212 | 104 | 0 | **3** |

The Alerts column (3 for the defaults and for all rules) is from before the outcome correction described below; it is now 2.
The flow digest (SHA-256 over every flow's fields) is identical in all 25 runs: detection does not change the flows. No
rule error, no malformed event. The wall times of the five configurations lie within the noise of the machine's load; no
difference between them is claimed. The reference capture produces about 3,200 events in 8 s, roughly 400 per second, against
a measured 28,000 to 100,000 events per second for the engine, so the engine has at least 70 times the headroom with every
rule on.

### Alerts on the benign reference capture: found, traced and corrected

The first M3 run raised three alerts on this capture that M2 had not: two TT-REC-002 (risk 43 and 41) and one TT-TRF-003
(risk 21). They were reproduced from a recording of the capture's telemetry (3,212 events) and traced.

**Root cause.** The flow engine knows the moment a connection's SYN-ACK arrives, but it published nothing about it. The
rules learned an attempt's outcome only from `FlowRetired`, which for an open connection arrives when it closes or idles
out. The M2 rule then counted any attempt with no outcome 5 s after its SYN as unanswered. All 510 bare-SYN attempts in the
capture were examined: 469 had a SYN-ACK, one had replies but no captured SYN-ACK, 40 had no reply at all (all to one
address on port 80, retransmitting for 7 s). The REC-002 flows were all established; their retirement records arrived 129
to 229 s (median) after the SYN, so every one was "pending" when judged, and 21 to 22 of 25 were counted unanswered. The
TRF-003 finding was 35 such established connections plus 4 real failures. The diagnosis in the first report was right and
incomplete: besides the missing event, a silent SYN was treated as a failure without asking whether the capture can see
replies at all, and a flow with replies but no captured SYN-ACK (an asymmetric capture) was treated as failed.

**Correction.**

* The flow engine publishes `FlowResponded(kind)` once per connection, on the first reply to a seen bare SYN:
  `established` (SYN-ACK), `refused` (a reset) or `answered` (any other reply). A SYN nobody answers publishes nothing.
  It is an additive telemetry event: no API, schema or migration change; 3,682 events instead of 3,212 on this capture.
* TT-REC-001, -002 and TT-TRF-003 resolve an attempt from that event at once, without waiting for retirement.
* An attempt is *answered*, *failed*, *pending* (no reply yet, under 5 s) or *unknown*. **A silent SYN counts as failed only
  when the capture has shown at least one reply to a TCP attempt or an echo reply** (`responses_visible`). Without that,
  silence may be the capture's, so the verdict is unknown. Pending and unknown attempts are in neither the failed count nor
  the attempt count. A flow with replies but no captured SYN-ACK is answered. A reset with at most two responder packets
  stays a failure, as in M2, including a reset straight after the handshake.
* TT-REC-004 uses the same judgement of finished flows (it never counted pending attempts).
* Capture ends within 5 s of a SYN with no reply: pending, not failed.

**Result on the same capture, same events:**

| | M2 (TT-REC-001 only) | M3 first run | M3 corrected |
|---|---|---|---|
| Alerts, product defaults | 0 | 3 (REC-002 x2, TRF-003 x1) | **2** (REC-002 x2, low confidence, risk 25 and 26) |
| Alerts, all ten rules on | 0 | 3 | 2 |
| REC-002 counts per alert | - | 21-22 of 25 "unanswered" | 25 of 25 answered, 0 unanswered, 0 unknown, 0 pending |
| TRF-003 | - | 39 of 77 failed | no finding, even with the settings at their lowest (10 attempts, 20 %): the 40 genuinely unanswered SYNs are spread over the capture |
| Attempts, whole capture | - | all 510 judged by the 5-second rule | 469 answered by SYN-ACK, 1 answered without a SYN-ACK, 40 unanswered |

**Remaining on this capture.** The two TT-REC-002 alerts are still raised, now low confidence and low risk, because 25
different hosts were each connected to on port 443 within the 60-second window, which is the approved host-sweep pattern.
Every probe was answered, so they are no longer failure findings. Nothing was suppressed by address, port or name. Whether a
sweep whose probes all complete deserves an alert at all is a rule-design decision (for example requiring some unanswered
or reset probes), not a classification error, and is left for approval and for M11 calibration.

**Detection kept.** The genuine unanswered cases still alert: a port scan or host sweep of unanswered SYNs in a capture that
shows replies keeps high confidence (real-tshark file tests, `test_m3_outcomes.py`, the REC-001 suite). The coverage that
changes is deliberate: a capture that never shows a reply (a one-sided capture, or a file of SYNs only) can no longer call
silence a failure, so TT-TRF-003 and TT-REC-004 raise nothing there and TT-REC-001/-002 keep their count-based finding at
low confidence. A very short capture that ends within 5 s of the SYNs is pending.

**Tests.** `test_flow_responded.py` (flow engine publishes the reply), `test_m3_outcomes.py` (37: long-lived HTTPS, no
retirement after 5 s, handshake before the timeout, explicit reset, genuine unanswered SYN, unknown, asymmetric, one-sided,
pending excluded from the TRF-003 numerator, REC-002 with successful and with unanswered probes, REC-001 regressions, REC-004,
replay equivalence). Seven mutations of the new logic were all caught. The shared fixtures changed in one way: the standard
test engine starts with one answered connection ("a normal two-way capture"), and the real-tshark scan files gained one
answered connection six seconds after the scan, because a SYN-only capture is now correctly an unknown outcome. The
M2 expectation that `SYN-ACK + reset with no data` is a failure was kept; the expectation that replies without a captured
SYN-ACK are a failure was changed, with the reason recorded in `test_m3_common.py`.

**Performance.** Engine alone (separate processes, 1,001,000 events, quiet run): TT-REC-001 alone 94,411 events/s,
defaults 47,578, all rules 27,773, against 101,051 / 50,142 / 28,008 before: the same ratios, inside the 7 % spread. Ingest of
the 168,349-packet capture, median of 5, the machine less loaded than for the earlier table: tap and detection off 6.12 s,
TT-REC-001 alone 6.25 s, defaults 6.23 s, all rules 6.51 s. Queue high water 104, 0 dropped, identical flow digest in every
run. The extra `FlowResponded` events add 14.6 % to the event volume of this capture. These ingest times are not comparable
with the 8.2-8.6 s of the earlier table, which was measured while other applications were busy.

### Limitations and deferred work

* **Open decision: a sweep whose probes all complete.** TT-REC-002 still alerts, at low confidence, on 25 successful
  connections to different hosts on one port within 60 s (ordinary browsing does this). Options, none done: require some
  unanswered or reset probes; raise the host threshold; or calibrate in M11 on more captures.
* A capture that shows no replies (one-sided, or SYNs only) yields unknown outcomes: TT-TRF-003 and TT-REC-004 are silent
  there, and TT-REC-001 and -002 keep their count-based finding at low confidence. This is deliberate and is the price of
  never calling silence a failure without evidence that replies can be seen.
* Replies are judged visible from any TCP reply or echo reply in the run, not per source or per network.
* `TickSummary.failed_flows_out` (an M1 counter) still counts "SYN with no SYN-ACK" at retirement; no rule uses it.
* The four default-off rules cannot be enabled from the product until M9. REC-002 and TRF-003 thresholds are untuned.
* UDP is invisible to REC-002, REC-004 and TRF-003. TRF-003 sees only TCP handshake bits; its dual-stack handling is an
  approximation of 0.3 s and 1 s, not hostname correlation. REC-003 evidence has no vendor lookup.
* APP-002 guards chosen by the implementer (TCP flows need a SYN; UDP counts only when destination port < source port; per-run
  count with 1 h expiry and 10,000 keys) are untested against real traffic. APP-002 needs a decoded layer; port alone never
  classifies. SNMP is not detected at all.
* The ARP and cleartext fixtures prove the decoder and the rules on built packets. They are not proof of behaviour on a real
  network, and no live scan was run against a network in M3.
* TRF-006 keeps the last 100 openings per key; a longer series is reported as "at least". It is experimental and off.
* REC-005 findings can only appear inside a TT-REC-001 alert or after the hold; a pair that never reaches the REC-001
  threshold produces its alert up to `window_s` of packet time later than the pattern.
* Detection runs on one worker thread; the per-rule cost table above is an ad hoc measurement and is not in the script.
* Not run in M3: the dashboard, the Rust shell and the frontend tests (no change was made there); a live soak.

### M3 final audit and acceptance status

**Status: accepted for commit, subject to the open decisions below.** An independent review of the whole uncommitted diff
(a separate reviewer, then re-checked by running the code) found two defects, both reproduced first with a failing test and
then fixed:

* TT-APP-004: the "endpoints" evidence listed up to 20 client addresses in one text; from about 16 IPv4 clients (fewer with
  IPv6) it exceeded the 300-character limit, raised an error on every later flow to that server, and after 50 errors the
  engine switched the rule off for the run. The text now names the count and the first three clients; the full list (at most
  20) stays in the item's data.
* TT-REC-005: `_runs` counted a flow twice when one run ended and the next began on it (`1,2,3,2,1` covered 6 of 5 flows),
  inflating the run share. Covered flows are now a set and can never exceed the flows seen.

**Judgements recorded, not changed** (each is documented behaviour or an approved decision):

* TT-REC-003 does not count ARP requests for the gateway or from the gateway address. This was approved as a rule exclusion
  and is listed as a blind spot; it means a misbehaving gateway sweeping the LAN is not seen by this rule.
* A reset with at most two responder packets is a failed attempt even after a SYN-ACK (the M2 meaning, kept). A half-open
  scan of an open port (SYN, SYN-ACK, RST) therefore counts as failed at retirement, although the handshake event first
  records it as answered.
* TT-APP-004 treats the destination of a flow as the server and does not require a seen SYN (TT-APP-002 does).
* "Replies are visible" is capture-wide and sticky: after any reply, silent SYNs to other hosts count as failed.
* TT-REC-004 and TT-TRF-003 do not apply the own-scan exclusion (discovery sends no TCP). TT-TRF-006 bounds keys (10,000)
  and openings per key (100) but has no global entry cap (at most 1,000,000 small tuples).
* A held TT-REC-005 finding can join a later TT-REC-001 alert of the same pair within its hold; each merge raises
  `occurrence_count`.

**Calibration noise, not an attack.** The two TT-REC-002 alerts on the benign reference capture (25 answered connections to 25
hosts on `tcp:443` inside 60 s, low confidence, risk 25 and 26) are calibration noise from ordinary browsing. They are not
findings of hostile activity and nothing in the evidence suggests any. The 25-host / 60-second defaults and the rule that an
answered sweep stays low confidence are unchanged. **Calibration of the TT-REC-002 and TT-TRF-003 thresholds, and the choice
of whether an all-answered sweep should alert at all, is deferred to M11** (rule calibration on more captures); until then
these defaults are untuned.
## M4: DNS rule pack

Working tree on branch `phase-4/threat-detection` on top of the M3 commit; I did not use Git in this task, so nothing here was
committed by me. Windows, normal user, tshark 4.6.9. Backend only: no migration, no API endpoint, no schema, no frontend or
Rust change (`npm run contracts:check`: `schema.d.ts` is up to date). Rule behaviour is in
[PHASE4_DETECTION_RULES.md](PHASE4_DETECTION_RULES.md) section 10; this section is the evidence.

### What was built

* Six rules, `backend/app/services/detection/rules/dns.py`: TT-DNS-001 high query rate, -002 high NXDOMAIN rate, -003 many unique
  names under one parent domain (on by default); -004 long or high-entropy names, -005 unusual query types, -006 resolver not
  configured on this interface (off by default, and not enable-able from the product until M9).
* `services/detection/names.py`: name normalisation, parent domain from the Public Suffix List, entropy, service-name test.
* `app/data/public_suffix_list.dat` (full list, 338,546 bytes, list version 2026-11-06, retrieved 2026-11-07, MPL-2.0,
  SHA-256 `027FE126...2310`) and `app/data/README.md` recording source, licence and hash. The application never fetches it.
* `DnsObserved` gained `server_port` and `transport` (from existing packet metadata, no new tshark field); `normalize.py`
  validates the DNS event fields and now caches address validation.
* `registry.py` registers the six rules. The M3 support test lists all 16.

Decisions applied: all ten approved in the M4 pre-flight (see the rules document, section 10).

**A correction to the pre-flight.** I wrote that `clean_hostname` silently drops DNS names with unusual characters. That is wrong
for DNS: the packet parser keeps DNS names through `clean_text` (control characters removed, 255 characters), and only SNI and
HTTP host go through `clean_hostname`. No parser change was needed for hostile names.

### Tests

Written test-first. Final run of the whole backend suite on 2026-11-07: **2,294 passed, 3 skipped** (2,018 at the M3 commit, so
276 new). `ruff check`, `ruff format --check` (194 files) and strict `mypy` (190 files) clean; `contracts:check` unchanged.

| File | Tests | Covers |
|---|---|---|
| `test_names.py` | 44 | normalisation and hostile input; `co.uk`, wildcard, exception and private suffixes, IDN in punycode; fallback; the README hash; entropy |
| `test_dns_events.py` | 24 | port and transport on queries, answers, TCP and multicast DNS; validation of the DNS event |
| `test_m4_dns001.py` | 34 | threshold -1/0/+1, window +-1 s, mDNS/LLMNR exclusion, baseline parameter inert, hostile names, bounds, 12,000 clients, at-least reporting |
| `test_m4_dns002.py` | 26 | response and ratio boundaries, severity and confidence rules, missing codes, 100,000 distinct failing names |
| `test_m4_dns003.py` | 35 | 49/50, parent grouping, `co.uk` and private suffixes, fallback wording, per client and parent findings, 100,000 names |
| `test_m4_dns004.py` | 38 | DNS-004 and DNS-005 boundaries, entropy, exclusions, the three query types, DNS-003/005 correlation (+0.10, same parent) |
| `test_m4_dns006.py` | 22 | only configured resolvers, gateway not trusted, unknown configuration, files, bounds |
| `test_m4_pipeline.py` | 53 | all six through one scenario set (explanation, DoH/DoT text, storage round trip, live/file replay, quiet-time dedup, default-off), all M1 to M4 rules interleaved, floods, queue overflow, failing database, real tshark |

**Real tshark.** tshark decoded response code 3 and query types 16, 10 and 255 from byte-built packets, and the full pipeline
raised the matching alerts (NXDOMAIN with the resolver named; TXT, NULL and ANY counted by type; `example.co.uk` as the parent of
60 names under `shop.example.co.uk`). Hostile names went through the real pipeline: upper case, 63-character labels, markup,
quote-and-SQL-looking text, spaces and control characters (tshark shows the latter escaped as text). **Finding:** tshark gives no
name for a query whose labels contain bytes above 0x7f, so a query with a non-ASCII label is not an observation. Every name it does
decode was counted. **Privacy:** a capture with 30 answers carrying the address 198.51.100.77 was stored; the SQLite and WAL
bytes do not contain it (the control confirms it is in the input). Names, which are the evidence, are stored as inert text.

**Mutation checks** (a small change to the real source; the relevant tests must fail; the file is restored): ten were caught,
among them the threshold comparison, the exception rule of the suffix list, the multicast port check, the NXDOMAIN ratio
boundary, address validation, the "list was available" flag, missing response codes, trusting the gateway as a configured resolver,
and parent domain by last two labels. One was missed at first (fitting names into the 4 KiB evidence limit), because no test used
names of the worst size; `test_names_of_the_worst_size_still_fit_in_the_evidence` was added and then caught it.

### Performance

Tool: `scripts/perf/telemetry_bench.py`, new stage `dns`. It builds a 100,000-packet DNS capture at run time (12.4 MB, 100 s of
packet time, 400 ordinary clients, one client whose names mostly do not exist, one asking unique names with TXT queries; nothing
binary is committed), ingests it through the real pipeline in four modes, and runs engine-only DNS floods in separate processes.
Median of 3; the machine was lightly loaded (7 % at the start).

Real pipeline (tshark, flow engine, tap, queue, detection worker), 100,000 DNS packets:

| Mode | Wall | Packets/s | Python CPU | Peak memory | Queue | Alerts |
|---|---|---|---|---|---|---|
| Tap and detection off | 5.57 s | 17,951 | 4.30 s | 110.5 MiB | - | - |
| TT-REC-001 alone (the M3 equivalent) | 8.69 s | 11,507 | 7.44 s | 161.3 MiB | high water 10,000, 10,001 dropped | 0 |
| Product defaults (DNS-001/2/3 on) | 11.32 s | 8,836 | 10.11 s | 186.1 MiB | same | DNS-001 x2, DNS-003 x2, DNS-002 x1 |
| All rules | 12.06 s | 8,293 | 10.89 s | 186.5 MiB | same | the above and DNS-005 x1 |

The flow digest is identical in every mode. **Targets from the architecture document that were missed, stated plainly:** the
pipeline did not keep its detection-off rate (17,951 packets/s) with detection on, and the queue dropped events. Causes found:
the capture produces 140,101 events for 100,000 packets (every DNS packet is an event, plus 20,000 flows); TT-REC-001 alone
already costs +3.1 s on it, and the DNS rules add +2.6 s (defaults) or +3.4 s (all rules) on top. The 10,001 dropped events are
the 20,000 `capture_ended` flow retirements that the flow engine emits in one burst at the end of the capture into a 10,000-slot
queue; they occur identically with TT-REC-001 alone, so they are the existing M1 queue behaviour under a capture with many
flows and not a DNS-rule cost. They carry no DNS observation. Worker CPU was not measured per thread, so the "under 25 % of one
core" target is not claimed either way.

Engine only (events per second, median of 3, separate processes), with a rule-less comparison from the same run:

| Workload | TT-REC-001 alone | Product defaults | All rules |
|---|---|---|---|
| Ordinary DNS, 200,000 events, 400 clients | 455,086 | 140,611 | 115,619 |
| 100,000 unique names from one client | 445,780 | 100,543 | 37,880 |
| 100,000 NXDOMAIN answers from one client | 429,508 | 207,308 | 80,609 |
| 100,000 different clients | 236,209 | 21,601 | 18,519 |

Peak process memory after all four workloads: 54.6 MiB (REC-001 alone), 86.8 MiB (defaults), 90.6 MiB (all rules). The DNS state
therefore adds about 32 to 36 MiB, under the 64 MiB budget, and holds at most 105,000 tracked entries. The worst case, 100,000
different clients, is the slowest (about 20,000 events/s) because every event creates and evicts a key; it stays within its
bounds (10,000 clients, evictions counted, no rule error). One change outside the rules was made for speed: address validation in
`normalize.py` was 3.9 of 10.8 s in a profile of one DNS rule alone, and is now cached. No before-and-after rate is claimed,
because the synthetic workload was also changed in the same step.

### Benign reference capture (168,349 packets, 538 DNS events)

All six DNS rules were enabled, with this computer's configured DNS server set to the gateway for DNS-006.

| Rule | Alerts |
|---|---|
| TT-DNS-001 | 0 |
| TT-DNS-002 | 0 |
| TT-DNS-003 | 0 |
| TT-DNS-004 | 0 |
| TT-DNS-005 | 0 |
| TT-DNS-006 | 0 |

The M3 result is unchanged: two low-confidence TT-REC-002 alerts and nothing else; the flow digest is identical to the M3 run
(`b3d06d4f13...`); 3,682 events accepted, none dropped, queue high water 104. Closest approaches, so that the zeros are
read correctly: 331 queries and 207 responses over 613 s from three clients; the busiest client sent 47 queries in a minute (the
rule needs 300); 51 different names under one parent over the whole ten minutes by one client (DNS-003 needs 50 inside 300 s, so it
was a near miss only across the whole capture); no NXDOMAIN; six ANY queries (DNS-005 needs 20); the longest first label was 43
characters (DNS-004 needs ten qualifying queries); 26 mDNS events excluded and counted. Zero alerts on one three-device capture
is not evidence of a low false-positive rate; calibration on more captures is M11 work.

### Limitations and deferred work

* Thresholds are untuned (M11). DNS-001's baseline comparison waits for M6. Suppression waits for M9, and the three default-off
  rules cannot be enabled before M9.
* Pipeline throughput and queue targets were missed on a DNS-heavy capture (above). Reducing per-event cost, batching in the
  queue, and a larger or draining end-of-capture burst are existing-architecture changes and are not part of M4.
* tshark's missing names for non-ASCII labels; entropy over short labels is biased low; the Public Suffix List is a snapshot.
* DNS-002 does not match responses to queries; DNS-005 reads the first question only; a forwarder hides the real client.
* Encrypted DNS is invisible, stated in every DNS finding.
* No live DNS capture was run in M4, and no soak. The DNS fixtures are byte-built, not captured traffic.
* Not run: the dashboard, Rust shell and their suites (no change was made there).

## M5 to M11: fast-track completion

Done in one pass at the owner's request (no per-milestone approval, one consolidated regression pass at the end). Nothing
here was committed.

### What was built
* **M5** device rules TT-DEV-001 to -004, device annotations, network profiles, suppressions, device risk, the inventory hook
  after a completed discovery scan, migration `0005`.
* **M6** baseline learner and readiness, the seven baseline rules (TT-TRF-001, -002, -004, -005, TT-DEV-005, -006, TT-APP-001),
  `DELETE /detection/baselines/{network_id}`, `GET /detection/networks`.
* **M7** topology builder (pure, deterministic), history tables (migration `0006`), session vantage columns, three API routes.
* **M8 to M10** screens: Threat Overview, Security Alerts, Alert Details, Detection History, Detection Rules (with settings,
  suppressions and baselines), Device Risk Profile, Network Topology (SVG graph, adjacency table, coverage panel).
* **M11** labelled synthetic corpus (`backend/tests/detection_corpus.py`) and runner (`python -m scripts.detect_eval`, run from
  `backend/`).

### Results (this machine, 2026-11-07)
| Check | Result |
|---|---|
| Backend `pytest` | 2,374 passed, 3 skipped (the same three skips as before) |
| `ruff check`, `ruff format --check`, `mypy` (strict, 209 files) | clean |
| `npm run contracts:check` | schema unchanged after export and generate |
| Dashboard `tsc`, `eslint`, `vitest` | clean, 422 tests passed |
| Desktop (Rust) tests and clippy/fmt | passed |
| Corpus | 27 labelled cases over 12 rules, all correct; ordinary traffic raises nothing (`python -m scripts.detect_eval`) |
| Owner reference capture (168,349 packets) through the real app | the same two low-confidence TT-REC-002 alerts as in M4; no alert from any new default rule; topology 22 nodes, 21 edges, 100 remote hosts grouped |
| `telemetry_bench m3-one` (synthetic, product defaults incl. new rules) | about 26,000 events/s, no alerts on the ordinary mix, state caps held |

An integration test drives the real `DetectionService` with a live and a file session: the live one stores the network
profile, the gateway hardware address and the vantage; the file one stores the vantage only and no baseline.

### Changes to existing tests and why
* `test_alerts_pipeline`: the 45-port scan also passes TT-TRF-003's threshold (30 attempts), so the test now expects both alerts.
  The old assertion `total == 1` only held while the second alert was not yet stored (a timing window of about 10 ms).
* Rule-catalogue, migration-head (`0006`), contract path, navigation and `useHashRoute` tests were updated for the new rules,
  revision and screens. `test_m3_pipeline` and `test_m4_pipeline` check "every rule evaluating" for the rules that existed then.
* Dashboard test setup now waits up to 4 s for asynchronous queries and each test may take 20 s. Under the full parallel suite
  three unrelated tests (Applications, Flows, mine) failed at the old 1 s / 5 s limits and passed when run alone.

### Not done, or only partly done (stated plainly)
* **Group by role/vendor/segment** in the topology (UI spec 6.5) is not implemented; remote hosts are grouped by name evidence,
  then application, then "Other remote hosts", only when there are more than 40 of them. Application nodes are not drawn;
  applications are listed on nodes and edges.
* **No pan by drag or mouse wheel zoom** on the graph: zoom buttons and arrow-key node navigation only.
* Alerts over time shows the **last 24 hours** (the summary endpoint's range), not the 7-day range with a selector.
* The Threat Overview range control, the Alerts "Device" and "Range" filters (device only via a link) and a Packet Explorer
  filter shown on the alert are not built.
* TT-DEV-003 does not yet read flow/inventory contradictions; TT-DEV-006 case (b) is not separate; TT-TRF-001 and -004 have no
  destination list in evidence.
* Real-window checks over the DevTools protocol (900, 1024, 1440 px), long-task observers for the topology and a
  seeded 5,000-device topology run were **not performed**. The builder is tested to stay inside the caps with 3,000 remote hosts.
* Baseline rules have only been exercised on synthetic data. No live multi-hour session was run, so baseline readiness,
  gateway-hardware-address memory and TT-DEV-001 have not been seen on a real network.
* The security review is limited to what the tests assert: user text (notes, reasons) is plain text, captured names appear
  only in text nodes and in evidence `data`, new routes need the token, every setting is validated server-side against published
  bounds, and the new UI uses no `dangerouslySetInnerHTML`. No separate review document was written.

### Outstanding technical debt carried from M4 (deferred, as instructed)
* **DNS throughput and queue.** On a DNS-heavy capture the pipeline missed its throughput target, and an end-of-capture burst of
  10,001 `FlowRetired` events exceeds the 10,000-slot queue so some are dropped. Per-event overhead in the DNS rules is the
  larger cost. Nothing was changed for this in M5 to M11; the new rules add about the same per-event cost as the M3 rules.
  **Update:** the queue part was fixed in "Phase 4 last four items" below; the throughput part is still open.

## Phase 4 final gap closure

Closes the gaps listed at the end of "M5 to M11: fast-track completion". Nothing was committed. No Git command was used.

### Status of each gap

| Gap | Status | Evidence |
|---|---|---|
| Topology grouping by role, vendor, segment, automatic above 150 devices | **Fixed, verified** | `test_gap_closure.py` (6 tests), dashboard test for the "Group devices by" control; `group_by` query parameter, `grouped_by` in the answer |
| 5,000-device topology | **Verified** | Builder: inside 400 nodes / 1,200 edges, deterministic, under 5 s. Through the API with 5,000 devices and flows in the database: 0.73 s, 21 nodes, 20 edges. With grouping off the graph is reduced to 400 nodes and says so |
| Alerts Range control and Device filter | **Fixed, verified** | Range 24 hours / 7 days (default) / 30 days / All time sends `since`; Device is filled from devices with alerts and keeps a device given in the link; 3 dashboard tests; checked in the real window |
| TT-DEV-003 flow/inventory contradiction | **Fixed, verified** on synthetic traffic | 2 tests. Not seen on a real network: the live run had no contradicting frame |
| TT-DEV-006 case (b), this computer | **Fixed, verified** on synthetic traffic | 4 tests. Case (b) shares case (a)'s handshake test; what is new is the label, the empty-set rule for this computer and the escalation. Not seen on a real network |
| TT-TRF-001 / -004 destination evidence | **Fixed, verified** on synthetic traffic | 3 tests, including the bound. Limit stated in the evidence: flows still open at the end of the window are not counted |
| Overview, Alerts, Rules, Device Risk, Topology in a real window at 900, 1024, 1440 px | **Verified** | See below |
| 5,000-device topology test | **Verified** | See above |
| Live-session validation: baseline readiness, gateway-MAC memory, DEV-001 | **Verified** on this machine, with two stated alterations | See below |
| Security-review document | **Done** | `docs/security/PHASE4_SECURITY_REVIEW.md`, backed by 37 tests in `test_phase4_security.py` |
| Overview range control; 7-day chart | **Still outstanding** | The chart still shows the last 24 hours and the Overview has no range control; not in the list for this pass |
| Graph pan by drag and wheel zoom | **Still outstanding** | Zoom buttons and arrow-key navigation only |
| Packet Explorer filter text on the alert page | **Still outstanding** | |
| M4 DNS throughput and queue drops | **Queue fixed; DNS throughput still outstanding (deferred technical debt)** | End-of-capture queue drops fixed in "Phase 4 last four items" below; per-event overhead in the DNS rules still misses the throughput target |

### Real desktop window (debug build, WebView2 over the DevTools protocol)

`scripts/live-check/run-phase4-check.ps1` resizes the real window with the operating system (the page reports `innerWidth`
900, 1024 and 1440 at device pixel ratio 1 on a 1920-wide screen), opens the 168,349-packet reference capture through the
Packet Explorer, then visits Threat Overview, Alerts, Alert Details, Rules, Device Risk, Topology (graph) and Topology (list) at each width,
and tries the graph by keyboard. The database is a seeded throw-away folder reached through a junction, because a debug build
otherwise uses `<repo>/data`.

Result: 21 screen visits and 3 keyboard checks, **0 failures**: the page heading is right, no page-level or main-area horizontal
overflow, no console error or warning, the graph's 22 nodes take focus with the arrow keys and Enter selects one. Screens
became ready in about 0.2 s (the poll step is 0.2 s). Screenshots were looked at for the Alerts, Topology, Overview and Risk screens;
the Alerts table scrolls sideways inside its own labelled region at 900 and 1024 px (by design), the page does not. Not done:
DevTools long-task and timer-stall observers, other DPI scalings, and an axe run in the real window (axe runs in the unit tests).

### Live session on this machine

`scripts/live-check/phase4_live.py` runs the real backend with real dumpcap/tshark on the Ethernet adapter as a normal user,
ordinary traffic (web requests, DNS, pings of the gateway) and passive discovery only. Baseline minimums were lowered to 18 s and
2 sessions for the test. **10 of 10 checks passed:**

* After session 1 (28 s live): one network profile, 1 session, baseline **not** ready. After session 2 (55 s total): 2 sessions,
  baseline **ready**, rows stored for 4 devices.
* **Gateway-MAC memory:** the stored MAC `30:4f:75:ea:00:ef` equals the operating system's own entry for 192.168.1.1.
* A baseline rule (TT-TRF-005, switched on) was **evaluating** in session 3, and an unchanged gateway raised no TT-DEV-004 alert.
* **Alteration 1:** the stored gateway MAC was changed in the database to `02:00:00:aa:bb:cc` to stand in for a replaced router.
  Session 4 then raised **TT-DEV-004** from real frames, and the true MAC replaced the stored one afterwards.
* **Alteration 2:** one inventory device (`c4:3a:35:8e:42:d8`) was deleted between two passive scans (with `network_age_h` 0 and
  `min_inventory_size` 1). Scan 2 recorded it again and **TT-DEV-001** raised one alert for that MAC. The rule's own conditions
  (an earlier completed scan, an established inventory, not marked known) were real; only the appearance of a new device was staged.
* Not done: a baseline of several hours, a real replaced router, a real new device on the network, and TT-DEV-003 / TT-DEV-006 /
  TT-TRF-001 / -004 on real traffic.

### Regression pass (once, at the end)

| Check | Result |
|---|---|
| Backend `pytest` | 2,426 passed, 3 skipped (the same three) |
| `ruff check`, `ruff format --check`, `mypy` (211 files) | clean |
| `npm run contracts:check` | unchanged after export and generate |
| `npm run lint`, `npm run typecheck` | clean |
| Dashboard `vitest` | 30 files, 427 tests passed |
| Desktop (Rust) tests, clippy/fmt | passed |
| Corpus `python -m scripts.detect_eval` | exit 0: 27 labelled cases correct, ordinary traffic raises nothing |

Test-first note: the detection and grouping tests and the Alerts/Topology dashboard tests were written first and seen failing
for the expected reason before the code. The security tests in `test_phase4_security.py` check behaviour that already existed,
so they passed at once; they were not seen failing.

## Phase 4 last four items

Nothing was committed. No Git command was used.

### 1. Threat Overview chart range: fixed, verified
`GET /alerts/summary` takes `range` (24h default, 7d, 30d, all) and returns `timeline_step` and `timeline`; the Overview has a
Range control (24 hours, 7 days, 30 days, All time). 7d and 30d are daily in UTC; all time is daily up to 120 days and weekly beyond
(at most 520 weeks). The tiles and counts do not depend on the range. Tests: `test_summary_range.py` (8), dashboard test for
the control; seen in the real window.

### 2. Mouse drag-pan and wheel zoom on the topology: fixed, verified
Wheel zooms around the pointer (0.5x to 4x); Shift + wheel scrolls the page as before; dragging pans, and the view cannot leave the
canvas; a drag that ends on a node does not select it; Fit returns; the zoom buttons and the keyboard model are unchanged.
Tests: `view.test.ts` (4), 3 in `TopologyPage.test.tsx`. In the real window (WebView2, real mouse events through the DevTools protocol
at 900, 1024 and 1440 px) the wheel changed the view width from 900 to 783 and a drag moved the view without selecting a node.
Not done: touch gestures, pinch zoom, a minimap.

### 3. Packet Explorer filter on Alert Details: fixed, verified
A "Find these packets" panel shows a read-only display filter, a Copy filter button (clipboard; if the browser refuses, the text stays
selectable) and a link to the Packet Explorer. The filter is built only from validated values: the alert's address, MAC, and target
address or `tcp`/`udp` port (and `dns` for DNS alerts); anything else gives no filter. Tests: `packetFilter.test.ts` (6),
2 in `security.test.tsx`; the real window showed `ip.addr == 192.168.1.7 && tcp.port == 443` for a real alert. The link opens the Packet
Explorer but does not fill its filter box: the filter applies to the capture or file that is open then (the packets are not stored with an alert).

### 4. M4 end-of-capture queue overflow: fixed, verified
*Root cause.* When a capture ends, `FlowEngine.finish()` retires every open flow at once, and `TelemetryTap.after_finish` offered the
whole burst to the 10,000-slot queue in one call. `offer_many` takes what fits and drops the rest, so a burst of 20,000
`FlowRetired` events lost 10,000 (the newest). *Reproduced* before the fix with `test_the_original_burst_loses_nothing_and_keeps_its_order`
(`dropped` was 10,000, and the detection-service test saw half the flows).
*Fix (smallest safe change).* `EventQueue.put_all` hands the burst over in order, in chunks that fit, waiting on the queue's condition until the
consumer makes room; `after_finish` uses it. Packets are no longer decoded at that moment, so the wait does not slow capture. The queue size
is unchanged (high-water stayed at or below 10,000), memory stays bounded, the order is the production order, and each wait is bounded:
if the consumer makes no progress for 15 s (`FINISH_STALL_SECONDS`) the rest is dropped and counted in `dropped`, and if the queue is
closed meanwhile the rest is counted in `dropped_after_close`. The live-decoder path (`offer_many`) is untouched and still never waits.
*Tests* (`test_finish_burst.py`): 20,000 events through a slow consumer arrive complete and in order with `dropped` 0; a stopped consumer
cannot hang the shutdown and the loss is counted; closing the queue ends the wait; live packets still never wait; the detection service
processes all 20,000 and the run has no warning.

### Regression pass (once, at the end)
| Check | Result |
|---|---|
| Backend `pytest` (full) | 2,439 passed, 3 skipped (the same three) |
| After that run only test type hints and import order in `test_finish_burst.py` changed; re-run | that file 5 passed; `ruff check`, `ruff format --check`, `mypy` (213 files) clean |
| `npm run contracts:check`, `npm run lint`, `npm run typecheck` | clean |
| Dashboard `vitest` | 32 files, 443 tests passed |
| Desktop (Rust) tests, clippy/fmt | passed (25 tests) |
| Corpus `python -m scripts.detect_eval` | 27 labelled cases correct, ordinary traffic raises nothing |
| Real window, 900 / 1024 / 1440 px (`run-phase4-check.ps1`) | 21 screen visits, 3 keyboard checks, 3 mouse checks, 3 chart-range checks, 3 packet-filter checks: 0 failures |

A first run of the real-window check failed the mouse step at 900 px because the graph was below the visible area and the check had
not deselected a node chosen by the keyboard step. Both were mistakes in the check, not in the product, and the script now scrolls
the graph into view and clears the selection first.

### Still outstanding
* **M4 DNS throughput** (per-event cost of the DNS rules on a DNS-heavy capture): not touched, deferred technical debt.
* The queue still refuses events while packets are being decoded if the consumer falls behind; that is by design and is reported.
* A multi-hour live baseline, a real replaced router, a real new device, and TT-DEV-003 / TT-DEV-006 / TT-TRF-001 / -004 on real traffic.
* Long-task and timer-stall observers, other DPI scalings, and axe in the real window.

## Known limitations of M1 and M2 (consolidated for the commit)

Nothing below is a hidden defect; each item is stated where it was measured. Items marked **open** have no fix in this
commit.

**Capture and telemetry**

* **Open: unexplained, intermittent early capture completion.** One live capture in the first M1 soak ended itself
  after 56 s while the desktop window stayed open. Six reproduction runs, and the three real-dumpcap runs in M2, all ran
  to the requested stop. No defect was found and no cause is claimed. The new termination record
  (`CaptureStatus.termination`) is there to diagnose it if it recurs.
* An explicit stop makes Windows dumpcap exit with code 1 while the state is `completed`; the exit code alone does not
  mean failure.
* The telemetry queue refuses events when full and counts them (`dropped`); detection then runs with reduced coverage.
  Coverage reduction is approximated from the per-second drop counts in `TickSummary`.
* M1 adds 9 tshark fields. The gate measured +0.56 % to +0.57 % tshark wall time (limit +12 %) on a quiet machine and
  +0.9 % to +7.8 % while another project loaded the machine. Ingest through the flow engine is about 4.6 % slower than the
  Phase 3 code with the tap off (5.83 s vs 6.10 s, 168k packets).

**Detection**

* **Only TT-REC-001 existed at the M2 commit; M3 adds nine rules (see "M3" above).** The other default-on rules, baselines and device risk are not built. Baseline-dependent
  rules are handled by the engine ("not_evaluated: baseline not ready") and proven with stub rules only.
* The positive case of TT-REC-001 is proven on synthetic traffic and on a synthetic capture file through the real tshark;
  no live scan was run against a network.
* The self-activity exclusion is a hook with no producer wired. Corroboration, known-entity and baseline score factors are
  exercised by stub rules, not by a real rule.
* A scan spread over longer than the window, split across several sources, or over UDP is not seen (the rule's listed
  blind spots).

**Alert storage and API**

* **Open: a 1.2 s write transaction.** In a synthetic burst of 2,000 alerts in 1.5 s, one 10-alert transaction took about
  1.2 s (about 0.8 to 1.0 s in earlier runs, 1.45 to 1.66 s with 25 alerts per transaction). It occurs while the engine
  thread is using the CPU flat out and the writer waits for Python's interpreter lock. Such a transaction holds the SQLite
  write lock for as long. The rest of the burst: median 12 ms, p95 19 ms.
* **Open: a transaction time of 100 ms or less has not been demonstrated.** The roadmap's "no write transaction over
  100 ms in the soak" could not be shown, because benign soak traffic raises no alerts; the only evidence is the synthetic
  burst above (p95 19 ms, with the outlier).
* **Open: unindexed reads.** Reads by address, text search and the summary have no index in the designed schema and scan
  the table. At the default 5,000 alerts every read measured under 35 ms (p95). At 100,000 alerts, by address 287 ms,
  text search 505 ms, summary 335 ms; the unfiltered list ordered by time is 155 ms. The open-alert list and the list by
  risk are index-served (10 ms at 100,000).
* **Open: delete-all during an active detection session.** It waits for any flush in progress (up to 10 s, then answers
  503) and discards the alerts waiting to be written, but it keeps the row of a running run. The running session keeps
  its in-memory alerts and will store them again the next time it reports them, so alerts can reappear after a delete-all
  made while a capture is analysing.
* **Open: missing APIs.** There is no API to edit the retention limits (they are read from `app_meta`, bounds enforced),
  no `GET /detection/rules*`, no rule editing, no suppressions endpoint, and no "top devices" in the alert summary. The
  tables for rule settings, rule changes and suppressions exist and nothing writes them. Suppressing one alert is a status
  change.
* Alerts are polled, not pushed; a new alert is visible about 0.7 s (p95 1 s) after it is raised.
* The stored evidence is the rule's latest complete snapshot, at most 30 items; on a repeated finding it is replaced, not
  appended. A device link is resolved once, when the alert is first stored.
* Counters on a stored run are written when the run ends; a run that crashes keeps zero counters and the status `aborted`.
* More than 2,000 distinct alerts waiting at once: the excess is counted in `alerts_not_stored` and shown as a run
  warning, by design.
* Benchmarks ran with other applications using the machine. Absolute numbers will differ; the ratios are the evidence.
