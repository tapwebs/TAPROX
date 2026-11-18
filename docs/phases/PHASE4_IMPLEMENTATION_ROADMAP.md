# Phase 4 implementation roadmap

Status: **M1 and M2 are implemented** (see [PHASE4_VERIFICATION.md](PHASE4_VERIFICATION.md) for what was built, what
differs from this plan, and the known limitations). M3 onward has not started. Read
[architecture](PHASE4_ARCHITECTURE.md), [rules](PHASE4_DETECTION_RULES.md),
[database](PHASE4_DATABASE_DESIGN.md) and [UI/UX](PHASE4_UI_UX_SPECIFICATION.md) first.

## 1. How this roadmap is used

* Eleven milestones, ordered by dependency. Each ends with software that runs, passes its tests and can be
  reviewed on its own. A milestone can be cut or reordered later without breaking earlier ones, except where a
  dependency is stated.
* This is an outline, not a task-level plan. After approval, each milestone gets its own task-level plan
  (`docs/superpowers/plans/…`, bite-sized TDD steps with exact signatures), written just before that milestone
  starts, so it reflects what the previous milestone actually produced.
* Size is relative: S (about a day), M (a few days), L (a week or more). These are rough guides, not commitments.
* Rules for every milestone: failing test first for each behaviour; only the files listed (plus tests); no change to
  Phase 0 to 3 behaviour unless the milestone says so and measures it; contracts regenerated and checked
  (`contracts:export`, `contracts:generate`, `contracts:check`); `ruff`, `mypy`, `tsc`, `eslint`, `cargo`
  checks clean; the debug exe rebuilt before any real-window test (running `cargo test` or `clippy` replaces it with a dev-server build); a short
  entry added to a `PHASE4_VERIFICATION.md` with measured numbers.

## 2. Dependency map

```
M1 telemetry ──> M2 core+alerts ──> M3 recon pack ──┬──> M5 behaviour+0005 ──> M6 baselines ─┐
                       │                  └> M4 DNS pack                                    │
                       ├──────────────> M7 topology backend (0006) ───────────────────────┐  │
                       └──────────────> M8 UI foundation + alerts screens ──> M9 rest ─┐  │  │
                                                                                      v  v  v
                                                                          M10 topology UI ──> M11 calibration + hardening
```

M7 needs only M2 for the alert overlay and can run in parallel with M3 to M6. M8 needs M2. M10 needs M7 and M8.

## 3. Milestones

### M1. Telemetry foundation (size M)

* **Scope.** Add the 9 tshark fields, parse them, and add the `TelemetryTap` seam in the flow engine. No rules yet.
* **Features.** New `FlowPacket` fields (`dns_rcode`, `dns_qtype`, `icmp_type`, `icmp_code`, `arp_*`); ARP path for non-IP frames; `TelemetryTap` that records counters inline and emits typed events (`FlowOpened`, `FlowRetired`, `DnsObserved`, `IcmpObserved`, `ArpObserved`, `TickSummary`) **after** the engine lock is released; bounded queue with a drop counter; vantage captured at capture start (kept in memory in this milestone).
* **Files.** `services/capture/tools.py`; `services/flows/packet.py`, `engine.py`; `services/capture/service.py` (two construction sites and `_finalize_flows`); new `services/detection/events.py`, `tap.py`; `tests/fake_tools/fake_tshark.py` (its hard-coded 21 empty columns become 30); `tests/flow_fixtures.py` (DNS rcode and qtype parameters, ARP, ICMP types, many-port SYN builder); `tests/test_flow_real_tshark.py`.
* **Database.** None.
* **API.** None.
* **UI.** None.
* **Dependencies.** None (Phase 3).
* **Tests.** Real-tshark decode of each new field from byte-built frames (the same method that proved the Phase 3 field formats); parser tests for malformed values; tap unit tests (events emitted once per flow, none while a lock is held: assert by running a slow subscriber and checking `engine.add` latency); queue overflow counts drops and never blocks; engine behaviour unchanged with the tap absent (existing 887 backend tests pass untouched).
* **Acceptance.** (1) Added tshark time ≤ +12% on the 168,349-packet reference capture, three runs each, A/B recorded. If not met: drop optional fields (`icmp.code`, `arp.dst.proto_ipv4` first) and re-measure; if still not met, stop and bring the dynamic-column option for approval. (2) Tap overhead ≤ +10% ingest time on the same capture. (3) Replay of the reference capture through the production pump produces the same flow counts as before (87 flows on the 10,783-packet capture; 713 on the soak capture), same totals. (4) No new warning or process left running.
* **Risks.** tshark cost; ARP frames carry no IP so they bypass `_update` (tested); hidden coupling to column count in the stand-in tools.

### M2. Detection core and alert storage, with one vertical slice (size L)

* **Scope.** The framework, scoring, correlation, alert persistence and a read API, proven end to end with one rule (TT-REC-001).
* **Features.** `Rule` protocol, `RuleMeta`/`ParamSpec`, registry; `windows.py` helpers; `risk.py`; `correlate.py`; `DetectionWorker` and `AlertWriter` threads; `AlertService` (dedup, lifecycle, reopen); `DetectionService.start_run/end_run/recover/shutdown`; self-activity exclusion (discovery scan windows and local MAC); wording-policy validation in the alert builder (banned words, required benign explanations and blind spots, evidence cap 30); run records; `detection.enabled` switch; retention prune.
* **Files.** New `services/detection/*` (`rules/base.py`, `rules/recon.py` with REC-001 only, `registry.py`, `risk.py`, `correlate.py`, `windows.py`, `worker.py`, `alerts.py`, `store.py`, `service.py`); `models/alert.py`, `models/detection.py`; migration `0004_alerts.py`; `migrations/env.py`; `schemas/alerts.py`, `schemas/detection.py`; `api/v1/alerts.py`, `api/v1/detection.py`, `api/v1/__init__.py`; `main.py` (create, recover, shutdown in the right order); `services/capture/service.py` (call `start_run`/`end_run`); `tests/test_contract.py`.
* **Database.** Revision `0004` (all seven tables, indexes as in the database design).
* **API.** `GET /alerts`, `GET /alerts/{id}`, `PATCH /alerts/{id}`, `GET /alerts/{id}/events`, `GET /alerts/summary`, `GET /detection/status`, `GET /detection/rules`, `GET /detection/rules/{id}`, `GET /detection/runs`. (Rule editing and suppressions arrive in M9 with their UI; the tables exist now.)
* **UI.** None.
* **Dependencies.** M1.
* **Tests.** Scoring properties (determinism, monotonicity, bounds, worked example from the rules document reproduces 60); dedup and bucket boundaries; lifecycle transition table (every allowed and every refused transition); reopen behaviour; evidence cap and `evidence_dropped`; banned-words and required-fields enforcement; REC-001 boundary tests and replay equivalence; queue overflow reporting; writer retry on a forced `database is locked`; crash mid-run (kill after N alerts, restart, alerts present, run marked `aborted`); no `socket` opened during a run (patched `socket`); import-lint test (detection and topology packages import no socket/subprocess/discovery-probe modules); migration test for `0004` (fresh, upgrade from `0003` with flows preserved and one backup); API tests with the standard envelope; contract regeneration; shutdown order (worker joined before `engine.dispose()`).
* **Acceptance.** (1) A synthetic port scan fixture replayed through the real pump with the real tshark yields exactly one alert with the evidence, score breakdown and wording required. (2) Alert latency p95 ≤ 2 s from the triggering packet in a live-style replay at real-time speed. (3) 10-minute replay loop: detection state flat, memory ≤ 64 MiB, no queue drops, no `database is locked` while a flow save runs concurrently. (4) All Phase 0 to 3 tests unchanged and passing. (5) Alert write path: no transaction over 100 ms in the soak.
* **Risks.** Thread lifecycle and ordering at shutdown; SQLite contention with `finish_session`; scope creep into more rules (blocked: one rule only).

### M3. Reconnaissance and failure rule pack (size M)

* **Scope.** REC-002, REC-003, REC-004, REC-005, TRF-003, TRF-006, APP-002, APP-003, APP-004 (the rules that need no baseline and no inventory).
* **Features.** The rules as specified, with their parameters, ICMP and ARP use, dual-stack fallback exclusion for TRF-003, merging of REC-005 into REC-001 alerts via correlation, the interval statistics for TRF-006, the usual-port sets for APP-002, and the protocol list for APP-004.
* **Files.** `services/detection/rules/recon.py`, `traffic.py` (TRF-003, TRF-006), `app.py` (APP-002, APP-003, APP-004); fixtures; tests.
* **Database / API / UI.** None (rules are discovered through the existing registry and `GET /detection/rules`).
* **Dependencies.** M2.
* **Tests.** Per rule: the standard set in the rules document section 8, with the near-miss fixtures listed per rule; APP-004 content-never-stored test (the builder's payload bytes must not appear in stored evidence); correlation test (sweep + scan on the same source gives one correlation group and the +0.10 factor); IPv6 destinations; sources with 10,000 distinct destinations stay under the state cap and report "at least".
* **Acceptance.** Each rule passes its boundary, near-miss and replay-equivalence tests; throughput and memory targets re-measured with all M3 rules enabled and recorded.
* **Risks.** ARP visibility depends on vantage; fixtures for ARP must not be mistaken for proof of real-network behaviour.

### M4. DNS rule pack (size M)

* **Scope.** DNS-001 to DNS-006 and the bundled public suffix list.
* **Features.** Per-client DNS windows, NXDOMAIN ratio, unique-subdomain counting under a parent domain, entropy, qtype counts, resolver comparison; mDNS/LLMNR exclusion counters; the suffix list loader with its source and licence recorded in `app/data/README` and `docs`.
* **Files.** `services/detection/rules/dns.py`, `services/detection/names.py` (suffix logic, entropy), `app/data/public_suffix_list.dat` (pending approval of decision 5), tests and fixtures (NXDOMAIN builder).
* **Database / API / UI.** None.
* **Dependencies.** M2 (and M1 for rcode/qtype).
* **Tests.** Real-tshark decode of rcode 3 and qtype 16/10/255 responses; hostile names (punycode, 63-character labels, 253-character names, control characters, uppercase, trailing dots) never break parsing or storage and are stored as text; parent-domain grouping tests including `co.uk`-style suffixes; DoH/DoT noted as a documented blind spot (a test asserts the blind-spot text is in the alert).
* **Acceptance.** Rule tests pass; DNS-heavy replay (a capture with 100,000 DNS packets) stays within the throughput and memory targets.
* **Risks.** Licence and freshness of the suffix list; high false-positive rate for DNS-003/004 (hence default off for 004).

### M5. Device behaviour and annotations (size M)

* **Scope.** DEV-001 to DEV-004 (no baseline needed except the stored gateway MAC), device annotations, network profiles, suppression storage.
* **Features.** Inventory hook after a discovery scan finishes; on-link MAC trust reuse from `DeviceResolver`; ARP claim tracking; gateway MAC memory per network; role/trust annotations; per-entity rule suppressions.
* **Files.** `services/detection/rules/device.py`; `services/detection/inventory_hook.py`; `models/detection.py` (annotations, network profiles); migration `0005_behaviour.py` (annotations and network profiles; baselines table is created here empty so M6 needs no new revision); `services/discovery/service.py` (one call after a scan completes, nothing else); `schemas`, `api/v1/detection.py` (suppressions `GET/PUT/DELETE`), `api/v1/risk.py` (annotation `PUT`); `main.py`.
* **Database.** Revision `0005`.
* **API.** `GET/PUT/DELETE /detection/suppressions`, `PUT /devices/{id}/annotation`, `GET /risk/devices`, `GET /risk/devices/{device_id}` (profile formula from the rules document).
* **UI.** None.
* **Dependencies.** M2 and M3 (ARP events).
* **Tests.** First scan on a network raises nothing; second scan with a new MAC raises one alert; randomised MAC labelled; IP claimed by two MACs with and without alternation; gateway MAC change, first session not evaluated; suppression expiry; annotation effects on the context factor; device risk formula test against hand-computed values; migration test for `0005`; discovery service tests unchanged.
* **Acceptance.** Rules behave as specified on fixtures; the discovery service's own tests and behaviour are unchanged; a real discovery scan on the owner's network followed by a second scan raises no alert unless the inventory actually changed.
* **Risks.** Touching the discovery service (kept to one call, guarded so a failure there cannot fail a scan); virtual/teamed MACs causing DEV-003 noise (documented, medium confidence).

### M6. Baselines and baseline-dependent rules (size L)

* **Scope.** Baseline learning and readiness, then the baseline-dependent rules: TRF-001, TRF-002, TRF-004, TRF-005, DEV-005, DEV-006, APP-001.
* **Features.** Baseline accumulation from live sessions on the same network only; windows series with median/MAD; bounded sets; readiness rule; poisoning guard; reset; "not evaluated" reasons exposed through the rules API; file replays read but never update baselines.
* **Files.** `services/detection/baseline.py`, `rules/traffic.py`, `device.py`, `app.py`; `store.py` (baseline store); `api/v1/detection.py` (readiness in status and rules).
* **Database.** Uses the `0005` tables.
* **API.** Readiness fields on existing detection endpoints; `DELETE /detection/baselines/{network_id}`.
* **UI.** None.
* **Dependencies.** M5.
* **Tests.** Baseline update excluded for file sessions and for windows with open baseline-rule alerts; readiness thresholds exactly at the boundary; MAD edge cases (zero MAD, tiny samples); set caps and eviction; per-rule standard tests; replay equivalence with a prebuilt baseline; baseline rows rewritten once per run end (counted).
* **Acceptance.** Rules that need a baseline never fire when it is not ready (tested); memory and write targets hold with 500 simulated devices; the owner's real captures replayed with a built baseline give an alert volume that is recorded (not yet judged; M11 judges).
* **Risks.** Baselines learned from unrepresentative sessions (documented, resettable); seven rules in one milestone (cut order if needed: DEV-005, then TRF-005).

### M7. Topology backend (size M)

* **Scope.** Graph model, builder, history, API, session vantage persistence.
* **Features.** Node and edge catalogue from the UI/UX specification section 6; coverage object; deterministic aggregation tiers with caps; `topology_edges`/`_days` written at run end (live sessions only); vantage columns on `flow_sessions`; alert overlay counts.
* **Files.** New `services/topology/*`; `models/topology.py`; migration `0006_topology.py`; `services/flows/store.py` (write vantage columns; read them back), `services/capture/service.py` (pass vantage at session open); `schemas/topology.py`; `api/v1/topology.py`; `main.py`; `tests/test_topology_*.py`.
* **Database.** Revision `0006` (two tables, five nullable columns).
* **API.** `GET /topology`, `GET /topology/nodes/{key}`, `GET /topology/edges/{id}`.
* **UI.** None.
* **Dependencies.** M2 (overlay). Can run in parallel with M3 to M6.
* **Tests.** Builder is pure, tested with hand-built flows and inventories: Wi-Fi-style capture yields no third-party unicast edge; promiscuous capture of a switched network is labelled accordingly; IP-only matches are probable and labelled; MAC contradiction produces an unresolved node and a note, not an edge to the inventory device; opened files carry the no-vantage statement and write no history; cap enforcement (5,000 devices, 50,000 flows → ≤ 400 nodes and ≤ 1,200 edges, deterministic output order); history upsert idempotent across two runs; migration test for `0006` (old sessions keep NULL vantage); API tests.
* **Acceptance.** Build time p95 ≤ 300 ms for 50,000 flows (seeded); same input twice gives byte-identical output; memory flat across repeated builds; all Phase 3 flow tests still pass (vantage columns are additive).
* **Risks.** Misleading maps from an over-eager inference rule (each inference has a named rule and a test that it is labelled `inferred`).

### M8. UI foundation and the alert screens (size L)

* **Scope.** Routes, layout flag, shared components, Security Alerts, Alert Investigation Details.
* **Features.** Everything in UI/UX specification sections 2, 3.2, 3.3; `StatTile` extraction; client methods and builders; Overview "Threat detection" panel stub (full Overview in M9).
* **Files.** `app/routes.ts`, `useHashRoute.ts`, `App.tsx`; `components/ui` (new components); `features/alerts/*`; `lib/api/client.ts`, `types.ts`; `features/activity/ActivityPage.tsx` (extraction only); `test/backend.ts`; tests.
* **Database.** None. **API.** None new.
* **Dependencies.** M2.
* **Tests.** Per the frontend plan: states, axe, banned words, route parsing; `SeverityBadge` distinctness; transition control shows only server-allowed transitions; confirm flow for false positive; evidence cap message; file-source banner. Real-window run: open an alert from a replayed synthetic scan fixture, change its status, confirm the audit trail.
* **Acceptance.** Every state of both screens reachable and tested; no console errors; no horizontal overflow at 900, 1024 and 1440 px; `ActivityPage` tests unchanged and passing after the extraction.
* **Risks.** Churn in shared files (`routes.ts`, `App.tsx`) — keep to mechanical edits; the severity/tone mapping must not collide with existing tones (tested).

### M9. Overview, History, Rules and Device Risk screens (size L)

* **Scope.** Threat Overview, Detection History, Detection Rules and Configuration, Device Risk Profile, Devices "Security" panel, rule editing and suppression endpoints.
* **Features.** UI/UX specification 3.1, 3.5, 3.6, 3.7; `PUT /detection/rules/{id}`, `POST /detection/rules/{id}/reset`, retention and baseline settings in `app_meta`, `DELETE /detection/history`.
* **Files.** `features/threats/*`, `features/rules/*`, `features/risk/*`, `features/history/*`; `features/devices/DevicesPage.tsx` (one panel); `features/overview/OverviewPage.tsx` (panel and stale sentence fix); `api/v1/detection.py`, `services/detection/registry.py` (parameter validation), `store.py`; docs updates (`DESIGN_SYSTEM.md` screen list).
* **Database.** None (tables exist). **API.** The endpoints above.
* **Dependencies.** M5 for annotations and risk; M6 for readiness text; M8 for components.
* **Tests.** Parameter validation: every `ParamSpec` bound enforced server-side (below min, above max, wrong type, NaN, infinity, huge numbers); a rule change affects the next run, not the running one; reset restores defaults; change history written; delete-all removes all four stores and requires `confirm`; Overview "not evaluated" lists match the registry; empty/never-run/no-alert wording distinct (the "no alerts" text never contains "safe"); chart text alternative equals the data table totals.
* **Acceptance.** Real-window walk-through of all four screens with synthetic data and then with a real replay; retention and baseline settings round-trip; no wording-policy violations in the rendered text (automated).
* **Risks.** Parameter form generation from metadata must not allow a threshold of zero that makes a rule fire constantly (bounds in `ParamSpec` are part of review).

### M10. Network Topology screen (size L)

* **Scope.** UI/UX specification 3.4 and 6.
* **Features.** `TopologyCanvas` (SVG, deterministic layout, aggregation display, pan/zoom, keyboard model), `AdjacencyTable`, filters, coverage panel, details panel, time window, alert overlay, links from alerts and risk pages.
* **Files.** `features/topology/*` (`TopologyPage.tsx`, `layout.ts`, `TopologyCanvas.tsx`, `AdjacencyTable.tsx`), `lib/api` additions, tests.
* **Database / API.** None new.
* **Dependencies.** M7, M8.
* **Tests.** Layout is a pure function: determinism, no overlap of node boxes at the caps, stability when one node is added; keyboard traversal and selection; list and graph selection sync; encodings (every basis has a distinct line style and a text label); coverage text always rendered; Wi-Fi-style fixture shows no third-party unicast edge in the UI; axe; banned words. Real-window measurement: first paint, pan/zoom long tasks and timer stalls with 400 nodes / 1,200 edges seeded.
* **Acceptance.** First paint ≤ 500 ms and no long task over 50 ms during pan/zoom at the caps; 5,000-device seeded network renders through groups within the caps; list view pages correctly; the graph is operable by keyboard alone.
* **Risks.** SVG performance near the cap (fallback decision: lower the cap, not add a library, unless measurement shows otherwise and the owner approves).

### M11. Calibration, evaluation and hardening (size L)

* **Scope.** Decide default-on rules from measured noise, run the full evaluation and performance verification, security review, documentation.
* **Features.** Labelled synthetic corpus and its runner; noise measurement on the owner's private captures; final threshold adjustments (recorded as rule version bumps); `PHASE4_VERIFICATION.md`; updates to `SECURITY_MODEL.md`, `FLOWS.md` (cross-reference to alerts), `OVERVIEW.md`, `DESIGN_SYSTEM.md`, `API.md`, `SKILL_USAGE.md`.
* **Files.** `scripts/detect-eval/*` (corpus runner, report), `backend/tests/detection_corpus.py`, docs; `scripts/live-check` additions for detection soak.
* **Database / API / UI.** Only fixes found by the evaluation.
* **Dependencies.** All earlier milestones.
* **Tests and measurements.** See section 5.
* **Acceptance.** Section 6 (definition of done).
* **Risks.** Real captures can reveal rules that cannot be made quiet enough: the rule stays off by default and is documented, rather than being tuned until it hides real behaviour.

## 4. Review focus: inputs and conditions the specification implies but the milestones do not test by themselves

Each line has a test assigned in the milestone that owns the code.

1. **Out-of-order, duplicate or zero timestamps in a PCAPNG** (clock steps backwards, all packets at the same time, year 1970 or 2106). Expected: windows never go negative or hang; rules report "time not reliable" and do not alert on rate. Test in M2 (`windows.py`) and M3.
2. **High-cardinality floods** (a 65,535-port scan, 100,000 distinct DNS names, 50,000 sources). Expected: state caps hold, "at least N" is reported, memory stays under the limit, the run warning says coverage was reduced. Test in M2/M3/M4.
3. **IPv6 and dual-stack** (link-local with zone IDs, mapped IPv4, `fe80::` scans, Happy Eyeballs). Expected: no crash, correct entity keys, dual-stack fallback not counted as failure. Test in M3.
4. **Hostile names and text** (control characters, very long labels, unicode lookalikes, SQL-looking strings, HTML in hostnames). Expected: stored and shown as inert text; summaries come only from templates. Test in M4 and M8.
5. **Crash, restart and write contention** (app killed mid-run; flow-save transaction overlapping alert writes; disk full on the data folder). Expected: alerts so far are kept, run marked `aborted`, no `database is locked` surfaced to the user, clear error on disk full. Test in M2.
6. **Detection toggled or rules edited during a live run.** Expected: the running run keeps its rule set; the UI says changes apply next run. Test in M9.
7. **Capture stopped while the queue is non-empty.** Expected: queue drained within a bounded time, remaining alerts written, no orphaned thread. Test in M2.

## 5. Verification and evaluation plan

### 5.1 Test layers

| Layer | Content |
|---|---|
| Unit (pure) | Rules, scoring, correlation, windows, baseline maths, topology builder, layout. Hand-built events, boundary values, property tests (monotonic, bounded, deterministic). |
| Controlled PCAPNG fixtures | Built byte by byte with the existing builders (`pcapng_fixtures`, `flow_fixtures`), extended with ARP, ICMP types, NXDOMAIN/qtype DNS and many-port scans. Built at test time (nothing binary is committed). Decoded by the real tshark where installed (skipped otherwise, as `test_flow_real_tshark.py`). |
| Replay | Fixtures through the production pump with the stand-in dumpcap and the real tshark: live and file paths give identical alerts. |
| API and migrations | Standard envelope, pagination, contract tests; one migration test file per revision. |
| UI | Component tests with `stubBackend`, axe, banned-words, route parsing; real-window checks over DevTools. |
| Soak | The existing `run-live-check.ps1` approach extended with a detection mode: 10-minute live capture with detection on, resource sampling every 15 s, alert and queue counters, no orphan processes. |

### 5.2 Accuracy and false positives (no invented percentages)

1. **Synthetic labelled corpus.** For every rule: positive fixtures (should alert), boundary fixtures (one below the threshold), benign near-misses (from each rule's false-positive list). Ground truth is by construction. The report lists, per rule, counts of true positives, false positives and false negatives with the corpus size, and states "synthetic; not representative of real traffic". No accuracy percentage is published from it.
2. **Noise on real benign traffic.** The owner's own captures (kept private, not committed; the Phase 2 and soak captures are examples already on the machine) are replayed with all rules enabled. The owner labels each alert "expected benign", "unexpected benign" or "worth investigating". The report gives alerts per hour per rule and the label counts. Proposed gate for default-on: at most one unexplained alert per device per day on those captures. This gate is a proposal for approval, not a measured fact.
3. **Regression.** Golden alert JSON per fixture, compared exactly; a rule version bump regenerates its goldens in the same commit with the reason.
4. **Mutation checks.** Jitter packet times, shuffle same-timestamp packets, split a scan across two sources, add benign background traffic: expected behaviour documented per rule (some must still alert, some must stop alerting, and the blind spots in the rules document must match what the tests show).

### 5.3 Performance measurement methods (targets in the architecture document, section 11)

| Metric | Method |
|---|---|
| tshark field cost | `tshark -r` A/B on the 168,349-packet capture, three runs each, median reported |
| Tap and detection overhead | Replay through the real pipeline with detection off and on; per-thread CPU time; ingest packets/s |
| Memory | RSS of the backend process and the detection state-size counter every 15 s over a 10-minute replay loop |
| Alert latency | Timestamp at the tap (arrival) and at first API visibility; synthetic scan injected at real-time speed; p95 over 50 injections |
| Database | `EXPLAIN QUERY PLAN` for each list query; timing with 10,000 and 100,000 seeded alerts; no `SCAN alerts` on the default list |
| Topology | Build timing with seeded 50,000 flows; determinism by hashing output twice |
| Rendering | Real desktop window over the DevTools protocol: first paint, long-task observer, 50 ms timer-gap observer (the method used for the filter work) |
| Responsiveness | Same observers during a live capture with detection running |

Results are recorded with the machine, tool versions and run counts. A target that is missed is reported as missed.

## 6. Definition of done for Phase 4

1. All milestone acceptance criteria met, with measured numbers in `PHASE4_VERIFICATION.md`.
2. All suites green: backend (`pytest`, `ruff`, `mypy`), dashboard (`vitest`, `tsc`, `eslint`, build), Rust (`fmt`, `clippy -D warnings`, `test`), contract check, debug and release builds with the desktop smoke tests.
3. Normal-user run verified (no elevation of any process, as in Phase 3), live capture with detection on for at least 10 minutes, clean stop, no orphan `python`, `dumpcap` or `tshark`.
4. Every default-on rule has a measured noise result on the owner's captures; any rule that failed the gate is off by default and documented.
5. Wording-policy and "no external traffic" tests pass.
6. Known limitations listed explicitly (see below) and not presented as features.

## 7. Known limitations to state in the final documentation

* Detection covers only sessions that were captured or opened; there is no always-on monitoring.
* From an ordinary Wi-Fi client, most third-party unicast conversations are invisible; topology reflects the vantage and says so.
* Encrypted DNS (DoH/DoT) and encrypted payloads are invisible; classification and rules use metadata only.
* Baselines need hours of live capture and are per network; opened files never update them.
* Thresholds are uncalibrated defaults until M11; scores order alerts and are not probabilities.
* No threat-intelligence feeds, geolocation or reputation; behaviour rules only.
* IPv6 neighbour discovery (NDP) is not analysed.
* The Linux suite and any physical Linux capture are verified to the same (limited) level as Phases 1 to 3 unless re-run.

## 8. Decisions needed from the owner before M1

The seven items in [PHASE4_ARCHITECTURE.md](PHASE4_ARCHITECTURE.md) section 14, plus:

* Approve the proposed default-on gate in 5.2 (or set a different one).
* Approve cutting order if the plan must shrink: TRF-006, DEV-005, APP-002, then DNS-004, then the topology `application_use` edge.
