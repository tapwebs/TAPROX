# Phase 4 architecture: threat detection and network topology

Status: **design. Milestones M1 and M2 are implemented** (telemetry tap and bounded queue, detection engine with
rule TT-REC-001, persistent alerts, alert API; verified results are in [PHASE4_VERIFICATION.md](PHASE4_VERIFICATION.md)).
Everything else here (the other rules, baselines, device risk, topology, the dashboard screens) is planning only and
not implemented. Written against branch
`phase-3/flow-intelligence`, commit `a42ac1c` (Phase 3 complete). Where this document says "exists",
it was read in the repository at that commit; where it says "new", it does not exist yet.

Related documents: [detection rules](PHASE4_DETECTION_RULES.md),
[database design](PHASE4_DATABASE_DESIGN.md), [UI/UX specification](PHASE4_UI_UX_SPECIFICATION.md),
[implementation roadmap](PHASE4_IMPLEMENTATION_ROADMAP.md). Existing background is not repeated here:
see `architecture/FLOWS.md`, `architecture/CAPTURE.md`, `architecture/DISCOVERY.md`,
`security/SECURITY_MODEL.md`, `development/DESIGN_SYSTEM.md`.

## 1. Understanding of the request

Stated by the project owner:

* Phase 4 is an explainable threat-detection engine plus an interactive network topology, built on the
  device inventory, packets, flows, applications and capture intelligence that already exist.
* Passive by default, local-first, offline-capable. No blocking, exploitation, injection, interception,
  credential harvesting, unrestricted scanning, external uploads, cloud dependency, fabricated threat
  intelligence or unnecessary privileges.
* Severity, confidence and risk score are separate. Scores are transparent, not "AI-generated".
* Topology must separate observed, inferred, inventory and unknown relationships and must never invent a
  device-to-device link that the capture could not have seen.
* Deliverable now: specification and milestones. No implementation.

Assumptions made here (each is listed again in section 14 for confirmation):

1. Detection analyses what a **capture session** produces (live, or an opened PCAPNG). TAPNETTRACK does
   not capture on its own, so there is no always-on monitoring in Phase 4. Between sessions only
   inventory-based rules can run.
2. One user, one machine, one bearer token (the existing model). Alerts have no owner field.
3. Windows is the primary platform. Linux code paths are kept but only unit-level evidence exists for them,
   as in Phases 1 to 3.
4. Numbers in this document that are thresholds are **initial defaults to be calibrated**. They are not
   validated against any dataset. Numbers that are performance targets are goals to be measured, not
   results.

## 2. What the repository provides (source of truth)

### 2.1 Reusable

| Capability | Where | Use in Phase 4 |
|---|---|---|
| One tshark pass per session feeds the packet list and the flow engine | `services/capture/service.py` `_ingest`, `_read_rows`, `_load_file` | The only telemetry source. No second pipeline. |
| `FlowPacket` (per packet) and `FlowRecord` (per flow) | `services/flows/packet.py`, `engine.py` | Event source. Flow keys, TCP handshake bits (`syn`, `synack`, `fin_*`, `rst`), counters, first and last MAC, DNS names, SNI, HTTP host, protocol, application, confidence, evidence. |
| Flow classification with evidence and limitations | `services/flows/classify.py` | Application rules and alert evidence. |
| Device inventory: `devices`, `device_addresses`, `device_observations` | `models/device.py`, `repositories/devices.py` | Device identity, first/last seen, IP history, randomized-MAC flag. |
| Flow-to-device linking (`ip_and_mac` or `ip_only`, with notes on MAC contradictions) | `services/flows/devices.py` `DeviceResolver` | Alert and topology entity resolution. The existing "MAC contradicts inventory" note is a ready-made impersonation signal. |
| Interface facts: gateways, DNS servers, DHCP flag, addresses, networks | `services/interface_manager` (`NetworkInterface.gateways`, `dns_servers`) | Gateway and resolver identity, "local" versus "off-link". |
| Discovery scan records (start, end, interface) | `models/discovery_scan.py` | Suppress self-inflicted ARP and ping activity. |
| SQLite, WAL, foreign keys on, one shared engine, forward-only Alembic migrations with backup-before-migrate | `database/` | Storage. Next revision is `0004`. |
| Error envelope, bearer token, pagination, `Literal` sort types, observed-versus-inferred schema convention | `core/`, `schemas/` | New routers follow it unchanged. |
| OpenAPI export and generated TypeScript types | `scripts/export_contract.py`, `shared/api-contracts` | Contract for new endpoints. |
| Hash router, UI kit (`Panel`, `Table`, `StateView`, `StatusBadge`, `DetailPanel`, `DefinitionList`, `Pagination`), `useRequest`, `usePolling`, hand-written SVG chart with data-table alternative | `apps/dashboard/src` | All Phase 4 screens. |
| Placeholders in the sidebar for "Network Topology", "Threat Detection", "Policies & Rules" (phase 4, no route) | `app/routes.ts` | Activate these rather than adding new top-level entries. |

### 2.2 Missing (verified absent, so Phase 4 must add them)

| Gap | Consequence |
|---|---|
| No DNS response code, query type or answer count is extracted (`FLOW_FIELDS` has only `dns.qry.name`, `dns.flags.response`, `dns.a`, `dns.aaaa`). The test builder `dns_response` hard-codes NOERROR. | NXDOMAIN, query-type and tunnelling rules need new tshark fields. |
| No ICMP type or code. ICMP between two hosts is one portless flow. | Sweeps and ICMP-error handling need `icmp.type`, `icmp.code`, `icmpv6.type`. |
| ARP and other non-IP frames are counted and dropped (`FlowEngine.add` returns when `src_ip` is `None`). No `arp.*` fields. | ARP sweep, duplicate-IP and gateway-MAC-change rules need `arp.*` fields and a non-IP path. |
| No failed-connection state. `rst` has no direction. | "Failed" must be derived: SYN without SYN-ACK, or RST with no data. Who sent the RST is unknown. |
| No hook, callback or listener on `FlowEngine`. The engine lock is a plain `threading.Lock`. | A tap must be added and must be invoked outside the lock. |
| Flow state is in memory until the session ends. Only the 5 newest sessions are kept. Evicted flows (50,000 cap) are gone. | Detectors keep their own bounded state. Alerts copy their evidence instead of pointing at flows. |
| Gateways, DNS servers and the capturing interface MAC are not saved with a session. Opened files have no local addresses. | Add additive columns on `flow_sessions`. For files, direction is "unknown" and local scope is inferred only from private ranges, labelled as inferred. |
| Devices are created only by discovery scans. A passive capture never adds a device. | "New device" has two distinct signals: inventory-new and seen-in-traffic-but-not-in-inventory. |
| No device role, trust, label or allowlist. | New `device_annotations` table. |
| No alert, rule, baseline or topology code. No configurable thresholds (`Settings` has none). | New tables. Thresholds live in the database, not in `Settings`. |
| No graph library, `Tabs`, `Dialog`, `Tooltip`, severity scale, `Stat` component (private to `ActivityPage`). The page container is `max-w-5xl`. | See the UI/UX specification. |
| `docs/development/DESIGN_SYSTEM.md` is stale (says 5 live screens; 9 exist). `architecture/OVERVIEW.md` is labelled Phase 0. | Corrected as part of implementation, not now. |

### 2.3 Documented limits that shape the design

* Packet list: first 100,000 packets. Flow engine: 50,000 flows, 2,000,000 analysed packets, 4,096 DNS
  answers, 600 timeline buckets. Only the flow engine sees past the 100,000th packet.
* Measured pipeline throughput: about 19,000 packets/s, limited by tshark. Extra decoded columns already
  cost about +44% tshark time (21 columns). This is the main performance risk of Phase 4.
* SQLite has one writer. `FlowStore.finish_session` writes all flows in a single transaction. Anything
  that writes during a capture must use short transactions and tolerate `busy_timeout` of 5 s.
* The Phase 3 text "classification is not a security verdict" is true today. Phase 4 is the first feature
  that renders findings, so its wording rules (section 9.4) must be explicit, and `FLOWS.md` gets a
  cross-reference when Phase 4 ships.

## 3. Design principles

1. **Observation before inference.** Every stored fact is tagged `observed`, `inferred`, `inventory` or
   `unknown`. The UI never shows an inferred item with the weight of an observed one.
2. **A finding is not a verdict.** Alerts say "pattern consistent with X" and list benign explanations and
   blind spots. Nothing is called "malicious", "attack" or "compromised".
3. **Deterministic and reproducible.** Same packets and same configuration give the same alerts and scores,
   for a live session and for a replayed file. Time comes from packet timestamps, not the wall clock.
4. **Bounded everything.** Every per-source structure, queue, evidence list and retention has a cap, and a
   cap reached is reported (never silent).
5. **Never back-pressure the decoder.** (One exception, added in the final closure: the burst of flows that retire when a capture
   ends is handed over in order with a bounded wait, because by then no packets are being decoded; see PHASE4_VERIFICATION.md.) Detection runs on its own thread behind a bounded queue. Dropping
   events is allowed and visible. Slowing tshark is not allowed.
6. **Reuse the Phase 3 pipeline.** One tshark process, one parse per packet.
7. **Explain by construction.** A rule cannot raise an alert without supplying evidence items and a score
   breakdown. The alert schema enforces this.
8. **Offline.** No lookups of any kind (no DNS, no reputation, no geolocation) are made by detection.

## 4. Approaches considered for tapping telemetry

| Option | Description | Why / why not |
|---|---|---|
| A. Post-session batch | Run rules over `engine.snapshot()` and saved flows after a capture ends | Simple, but no live alerts, loses evidence for evicted flows, and misses packet-level signals (DNS names, ARP). Rejected as the only path; kept as the file-replay behaviour of option C. |
| B. Second tshark | A dedicated tshark for detection | Duplicates decoding (the main cost), doubles process lifecycle risk. Rejected (also forbidden by the reuse principle). |
| **C. In-process tap on the existing reader thread, with a bounded queue to a detection worker** | The flow engine gets an optional `TelemetryTap`. It records cheap counters inline and emits typed events after releasing the engine lock. A worker thread consumes them. | **Chosen.** Live and file sessions behave identically, no new decoder, no back-pressure, evidence captured at the moment it exists. |

Fixed superset versus dynamic tshark columns: start with a **fixed superset** of new fields (about 8 to 10).
Add a measured gate (section 11). Only if the gate fails, make optional columns depend on which rules are
enabled. Dynamic columns need per-session column maps, which is more machinery than Phase 4 should add
before it is shown to be necessary.

## 5. Architecture

### 5.1 Data flow

```
dumpcap / opened .pcapng
        |
   one tshark process  ---------------------------------------------- (unchanged, plus ~9 new fields)
        |
   _ingest(line)  [capture-rows / capture-load thread]
        |-- RowStore.append(row)                                    Packet Explorer (unchanged)
        '-- FlowEngine.add(packet)                                  Flow Intelligence (unchanged)
                 |   (engine lock released)
                 v
        TelemetryTap  --- O(1) counters, builds typed events ---+
                 |                                              |
   bounded queue (drop + count when full)          1 s packet-time TickSummary
                 v
        DetectionWorker thread  (one per running session)
           1 Normalize     event -> keyed feature windows (per source, per destination, per device)
           2 Features      sliding windows, distinct sets (capped), rates, ratios, baselines (read-only)
           3 Rules         each enabled rule evaluates and may return a Finding
           4 Correlate     findings sharing an entity within a window get one correlation group
           5 Risk          deterministic score with a written breakdown
           6 Alerts        dedup, create or update, lifecycle state
                 |
         AlertWriter thread (batches, short transactions, retry on busy)
                 v
              SQLite: alerts, alert_evidence, alert_events, detection_runs, baselines, topology_edges
                 v
   FastAPI routers  /alerts  /detection  /risk  /topology    (new, read mostly)
                 v
   Dashboard: Threat Overview, Alerts, Alert detail, Topology, Rules, Device risk, History
```

Inventory-only rules (new device, IP/MAC conflict from the inventory) run from a small scheduler hook
invoked when a discovery scan finishes. They use the same alert pipeline. No new long-lived thread.

### 5.2 Module boundaries

New code lives in new packages. Existing modules change only at the three seams listed in 5.5.

```
backend/app/services/detection/
  events.py        frozen dataclasses for telemetry events (section 6)
  tap.py           TelemetryTap: counters + event emission + bounded queue (no I/O, no DB)
  windows.py       SlidingCounter, CappedSet, RateWindow, Ewma/robust baseline helpers (pure)
  rules/           one module per category; each rule is a small class with metadata + evaluate()
    base.py        Rule protocol, RuleMeta, ParamSpec, Finding, EvidenceItem
    recon.py  traffic.py  dns.py  device.py  app.py
  registry.py      rule registry, defaults, parameter validation against ParamSpec
  risk.py          severity/confidence/context -> risk score and breakdown (pure)
  correlate.py     correlation groups (pure)
  worker.py        DetectionWorker thread: consume, evaluate, hand findings to AlertService
  alerts.py        AlertService: dedup, lifecycle, writes via AlertStore
  store.py         AlertStore, RuleStore, BaselineStore (SQLAlchemy, per-operation Session)
  baseline.py      baseline learning and readiness
  service.py       DetectionService: owns runs, worker, writer; start_run(session) / end_run()
backend/app/services/topology/
  model.py         NodeType, EdgeType, Basis, Confidence, Node, Edge, Coverage (pure)
  builder.py       builds a graph from flows + inventory + session vantage (pure given inputs)
  history.py       upsert and query of topology_edges
  service.py       TopologyService (read side, memoised like FlowService)
backend/app/models/   alert.py  detection.py  topology.py   (+ env.py import list)
backend/app/schemas/  alerts.py  detection.py  topology.py  risk.py
backend/app/api/v1/   alerts.py  detection.py  topology.py  risk.py
backend/tests/        test_detect_*.py  test_topology_*.py  test_api_alerts.py  test_migration_0004.py ...
```

Dependency rules: `rules/*` and `risk.py`, `correlate.py`, `windows.py`, `topology/builder.py` are **pure**
(no database, no clock, no threads) so they are unit-testable with hand-built events. Only `store.py`,
`history.py`, `service.py` and `worker.py` touch threads or the database.

### 5.3 Service interfaces (signatures are the contract between milestones)

```python
# events.py (all frozen, slots)
class FlowOpened:    t: float; session_id: int; flow_seq: int; transport: str
                     src_ip: str; dst_ip: str; src_port: int | None; dst_port: int | None
                     basis: str; src_mac: str | None; dst_mac_hint: str | None; tcp_syn_only: bool
class FlowRetired:   t: float; session_id: int; flow_seq: int; state: str; transport: str
                     src_ip: str; dst_ip: str; src_port: int | None; dst_port: int | None
                     packets_fwd: int; packets_rev: int; bytes_fwd: int; bytes_rev: int
                     syn: bool; synack: bool; rst: bool; first_seen: float; last_seen: float
                     protocol: str; application: str | None; confidence: str
                     sni: str | None; http_host: str | None; layers: frozenset[str]
class DnsObserved:   t: float; client_ip: str; server_ip: str; client_mac: str | None
                     is_response: bool; qname: str; qtype: int | None; rcode: int | None
class ArpObserved:   t: float; op: int; sender_mac: str; sender_ip: str | None; target_ip: str | None
class IcmpObserved:  t: float; src_ip: str; dst_ip: str; icmp_type: int | None; icmp_code: int | None; length: int
class TickSummary:   t: float; hosts: Mapping[str, HostCounters]; dropped_events: int   # 1 s packet time
class HostCounters:  packets_out; bytes_out; packets_in; bytes_in; new_flows_out; failed_flows_out

# rules/base.py
class Rule(Protocol):
    meta: RuleMeta                       # id, name, category, version, default_enabled, params: tuple[ParamSpec, ...]
    needs: frozenset[str]                # event kinds consumed
    def on_event(self, ev: Event, ctx: RuleContext) -> list[Finding]: ...
    def on_tick(self, tick: TickSummary, ctx: RuleContext) -> list[Finding]: ...
class RuleContext:                       # read-only view given to rules
    params: Mapping[str, float | int | str | bool]
    local: LocalScope                    # local addresses/networks, gateways, resolvers, "direction known"
    baseline: BaselineView | None        # None when not ready (rule must then not alert on baseline logic)
    resolve: Callable[[str], EntityRef]  # ip/mac -> device reference, cached, never does network I/O
class Finding:
    rule_id: str; entity: EntityRef; secondary: str     # dedup key parts
    window: tuple[float, float]; severity: Severity; confidence: Confidence
    summary: str; why: str; benign_explanations: tuple[str, ...]; blind_spots: tuple[str, ...]
    evidence: tuple[EvidenceItem, ...]                  # at least one; cannot be empty
    factors: tuple[ScoreFactor, ...]

# risk.py
def score(finding: Finding, context: ScoreContext) -> RiskResult        # RiskResult.value 0..100 + breakdown

# service.py
class DetectionService:
    def start_run(self, ctx: SessionContext) -> TelemetryTap
    def end_run(self, session_id: int, *, completed: bool) -> None
    def status(self) -> DetectionStatus
    def on_discovery_finished(self, scan_id: str) -> None
    def recover(self) -> int ; def shutdown(self, timeout: float = 5.0) -> None
```

### 5.4 Event schemas and normalization

* All times are **packet time** (epoch seconds, float). Wall-clock `created_at` is stored separately on alerts.
* Addresses are normalized by the existing helpers (`netutil`, `normalize_mac`). Domain names go through
  the existing `clean_hostname` rule (printable, length-capped, trailing dot removed).
* `local`, `on-link`, `off-link` classification uses `LocalScope`. For an opened file there is no
  local address: direction is `unknown`, and RFC 1918 / link-local ranges are treated as "private
  (inferred)" only. Rules that need direction declare it and do not run on files (or run in a reduced
  mode that says so in the alert).
* Event volume control: `FlowOpened` and `FlowRetired` are per-flow, `DnsObserved` per DNS packet,
  `ArpObserved` per ARP packet. Per-packet traffic volume never becomes per-packet events; it becomes
  `TickSummary` counters (top 2,000 hosts per second by bytes, remainder aggregated).

### 5.5 Seams in existing code (the only changes outside new packages)

| File | Change | Risk |
|---|---|---|
| `services/capture/tools.py`, `services/flows/packet.py` | Append about 9 fields to `FLOW_FIELDS`; add matching `FlowPacket` attributes; keep order (appending keeps positions valid). | tshark time. Gated by measurement (section 11). The fake tshark emits a hard-coded 21 extra columns and must be updated. |
| `services/flows/engine.py` | Optional `tap` constructor argument. `add()` collects events while holding the lock and emits after releasing it. A non-IP path for ARP. | Hot path. Measured: tap overhead must stay under the budget in section 11. |
| `services/capture/service.py` | Construct the tap at the two places a `FlowEngine` is built (`start`, `open_file`); persist the session vantage (gateways, interface MAC, DNS servers, promiscuous) when the flow session is opened; call `end_run` from `_finalize_flows`. | Low. |
| `main.py` | Create `DetectionService`, `TopologyService`; `recover()` at startup; `shutdown()` before `engine.dispose()`. Constructors must do no I/O (contract export builds the app on `sqlite://`). | Low. |
| `database/migrations/env.py`, `api/v1/__init__.py`, `tests/test_contract.py` | Register new models and routers; extend the explicit endpoint list. | Mechanical. |
| `apps/dashboard/src/app/*` | New routes, a wide-page layout flag, section navigation. | Low. |

No Phase 0 to 3 behaviour changes. All new API is additive.

## 6. Explainable risk scoring (summary; formulas in the detection-rules document)

Three separate values on every alert:

* **Severity** (`info`, `low`, `medium`, `high`, `critical`): how serious the *pattern* would be if the
  rule's interpretation is right. Fixed per rule, with documented escalation conditions.
* **Confidence** (`low`, `medium`, `high`): how complete the evidence is for the rule's interpretation.
  Set by explicit conditions in the rule (for example "at least 80% of probes unanswered"), never by guess.
* **Risk score** (0 to 100): `round(100 × W_severity × W_confidence × M_context)`, capped. `W` tables and the
  bounded context multiplier are fixed constants. The score orders alerts and devices. It is **not a
  probability**, and the UI says so.

Each alert stores the rule version, thresholds in force, the observed values, every score factor with its
value, and the resulting number. Replaying the same capture with the same configuration reproduces the
same score (tested).

## 7. Network topology intelligence (summary; screen design in the UI/UX specification)

A topology is a **view over stored evidence**, built per request from the session's flows, the inventory
and the saved session vantage, plus an aggregated history table for relationships over time.

* **Vantage first.** Every graph carries a `coverage` object: capture interface, whether it was
  promiscuous, the local addresses, the gateway(s), and a plain statement of what that vantage can and
  cannot see. On an ordinary Wi-Fi client, the only unicast LAN conversations visible are those that involve
  this computer. Broadcast and multicast from others are visible and are kept as such.
* **Basis** on every node attribute and every edge: `observed` (packets seen), `inferred` (derived by a
  stated rule), `inventory` (stored discovery data, not traffic), `unknown`.
* **Edges are drawn only from evidence.** Device-to-device communication edges exist only when flows
  between the two were observed. Inventory membership is shown as containment (a device inside a
  segment), not as an edge. "Unknown" is never drawn as a line: unresolved endpoints are nodes badged
  "unresolved", and the coverage panel lists what cannot be determined.
* **History.** `topology_edges` keeps first seen, last seen, days seen, bytes and flow counts per
  relationship, so the screen can answer "what is new in the last 24 hours" without keeping flows.
* **Rendering.** Deterministic layered layout (no physics), SVG up to a hard cap with aggregation
  beyond it, and an adjacency table as the accessible equivalent. No graph library in Phase 4.

Node and edge catalogues are in the database design (stored shapes) and the UI/UX specification (rendering).

## 8. Alert lifecycle, deduplication, retention

* States: `open`, `acknowledged`, `investigating`, `resolved`, `false_positive`, `suppressed`.
  Transitions are user actions plus one automatic path: a resolved alert whose dedup key fires again is
  reopened with `recurrence_count` incremented (and the event is logged).
* **Dedup key:** `(rule_id, primary entity key, secondary key, time bucket)` where the bucket is the rule's
  window rounded in packet time. One alert row per key. Repeats update `last_seen_at`, `occurrence_count`,
  bounded evidence (30 items kept, extra items counted) and re-score.
* **Correlation:** findings that share an entity and overlap in a 10-minute window get one
  `correlation_group_id`. Corroboration raises the context multiplier within a bound (and shows why).
* **Suppression:** a user can suppress a rule for one entity (stored with a reason and optional expiry).
  Suppressed findings are still counted (visible in History) but raise no open alert.
* **Self-activity:** TAPNETTRACK's own discovery scans (ARP probes, pings) are excluded from recon rules
  by matching the local MAC/IP and the scan's time window. Excluded events are counted, not hidden.
* **Retention (defaults, editable):** alerts 180 days or 5,000 rows (oldest closed first), evidence and
  events cascade with the alert, `detection_runs` 1,000 rows, topology edge history 180 days. A "Delete
  all security history" action exists and requires confirmation. Retention is enforced by a prune at
  run end and at startup, not by a background timer.

## 9. Security and operational boundaries

### 9.1 What Phase 4 will not do (testable)

| Boundary | How it is kept |
|---|---|
| Passive | Detection reads events only. It has no import of socket, subprocess or discovery-probe code (an import-lint test enforces this for `services/detection` and `services/topology`). |
| No blocking or response actions | No firewall, route, process or adapter API is called. Alert actions are labelled "mark as", not "respond". |
| No injection, interception, TLS decryption, credential collection | Only the fields already listed in `FLOW_FIELDS` plus the new header-level fields are read. Payload bytes and HTTP bodies are never requested from tshark. Cleartext-protocol rules report the **protocol name only**. |
| No unbounded scanning | Phase 4 adds no probing at all. Existing discovery keeps its `confirm_authorized` and private-range rules unchanged. |
| No external traffic | No lookups (DNS, reverse DNS, reputation, geolocation, WHOIS, update feeds). A test patches `socket` and asserts none are opened during a full detection run. |
| No fabricated intelligence | There are no built-in indicator lists of bad domains or IPs. Rules use behaviour only. (A user-imported local list is a possible later feature, off by default, and not part of Phase 4.) |
| Least privilege | Same unelevated processes. Nothing in Phase 4 needs administrator rights. |
| Bounded background work | One detection worker and one writer per running session, both joined on stop and on shutdown. Memory and queue caps in section 11. |

### 9.2 Untrusted input

Domain names, hostnames, SNI and HTTP hosts come from the network and are attacker-controlled. They are
validated by the existing cleaners, length-capped, stored as text, never used in a shell, SQL string or
file path, and rendered as text. Alert text templates take values as parameters; the summary string of an
alert is generated from fixed templates, never from captured text. API search parameters are typed and use
substring matching, as in Phase 3.

### 9.3 Data sensitivity

Alerts contain IP addresses, MACs, domain names and times. They are stored unencrypted in the same
SQLite file as the inventory (an accepted risk already listed for inventory data). Phase 4 adds: retention
limits, a delete-all action, and an audit trail for rule changes and alert state changes (`alert_events`,
`detection_rule_changes`), which narrows the existing "no audit log" gap for the new data. The threat
model entry for the new data is added to `SECURITY_MODEL.md` when implemented.

### 9.4 Wording policy (applies to API text and UI)

* Use: "pattern consistent with", "possible", "indicator", "observed", "not observed".
* Never use: "attack", "malicious", "compromised", "infected", "hacked", "safe", "clean".
* Every alert has `why`, `benign_explanations` (at least one) and `blind_spots` (at least one). A rule
  that cannot supply them is not allowed to ship. "No alert" is never shown as "the network is safe": the
  Overview states what was analysed and what was not.
* Rule categories describe behaviour ("Reconnaissance-like activity"), not intent.

## 10. Configuration

* Each rule has a `RuleMeta` with typed `ParamSpec` (name, type, default, minimum, maximum, unit,
  description). The server validates every change against it. The Rules screen is generated from this metadata.
* Values live in `detection_rules` (not in `Settings`, which has no tunables). Resetting to default is one
  call. Every change writes `detection_rule_changes` (old, new, time).
* A global switch "analyse sessions for threats" (default on) and per-category switches exist. Disabled
  rules cost nothing: the tap does not build events nobody consumes.
* Presets are **not** shipped in Phase 4 (no invented "paranoid/relaxed" profiles). The defaults are the
  one documented baseline.

## 11. Performance, resource limits and how each is measured

Targets are engineering goals. Each becomes a pass/fail gate only after the M1 measurement fixes the
baseline. The reference is the Phase 3 measurement set in `PHASE3_VERIFICATION.md` and
`PERFORMANCE_BASELINE.md`, on the project's Windows machine.

| Metric | Target | How measured |
|---|---|---|
| Added tshark time from new fields | At most +12% over the current column set on the 168,349-packet reference capture; if more, drop optional fields or go dynamic | `tshark -r` timing A/B, three runs each, as done for the filter work |
| Tap overhead on the reader thread | At most +10% of the current ingest time on the same capture | Replay through the real pipeline with and without the tap |
| Detection throughput | Sustains at least the pipeline rate (about 19,000 packets/s) with no queue drops | Replay a file at full speed; read `events_dropped` |
| Detection CPU | Worker thread under 25% of one core at 19,000 packets/s | Per-thread CPU time during replay |
| Detection memory | At most 64 MiB of detection state (hard cap with eviction), flat after warm-up | Process RSS and state-size counters over a 10-minute replay loop |
| Alert latency | p95 under 2 s from the triggering packet's arrival to the alert being readable from the API (live) | Synthetic scan injected into a live-style stream; timestamps at tap and at API read |
| Alert write path | Writer never holds a transaction longer than 100 ms; no `database is locked` errors in a 10-minute soak | Soak with concurrent flow-finish write |
| API: alert list | p95 under 100 ms with 10,000 alerts, under 300 ms with 100,000 (page of 50, filtered, sorted) | Seeded database, `EXPLAIN QUERY PLAN` plus timing |
| API: topology build | p95 under 300 ms for 50,000 flows (same order as the Phase 3 aggregate queries, 268 ms) | Seeded session |
| Topology rendering | First paint under 500 ms and pan/zoom without long tasks over 50 ms for up to 400 rendered nodes and 1,200 edges | Real desktop window over DevTools, long-task observer (the method used in the filter work) |
| Large networks | 5,000 inventory devices and 50,000 flows stay responsive through aggregation (group nodes), with the node cap never exceeded | Seeded inventory plus synthetic flows |
| Responsiveness | No UI stall over 100 ms during a live capture with detection on | Timer-gap measurement in the real window |

**Accuracy and false positives** are not given as percentages. They are measured as counts on a labelled
corpus (section 12 of the roadmap) and reported with the corpus size and its limits. Percentages from a
synthetic corpus are labelled "synthetic, not representative of any real network".

## 12. Testing approach (details in the roadmap)

Unit tests with hand-built events for every rule (boundary: threshold minus one, at threshold, above);
property tests for scoring (monotonic in severity and confidence, bounded, deterministic); controlled
PCAPNG fixtures built byte by byte with the existing builders (extended with ARP, ICMP types, NXDOMAIN and
many-port scans) and decoded by the **real tshark** where available (as `test_flow_real_tshark.py` does);
replay tests through the production pump with the stand-in dumpcap; migration tests (fresh, upgrade, backup);
API tests; dashboard tests with the existing stub pattern plus axe checks; a real-window run for every
screen; a soak run. A private corpus of the owner's own captures may be used locally to measure alert
volume; it is never committed.

## 13. Risks

| Risk | Likelihood | Effect | Mitigation |
|---|---|---|---|
| New tshark fields slow decoding too much | Medium | Capture falls behind on busy links | Measured gate; drop optional fields; dynamic columns as the fallback |
| Noisy rules make alerts ignorable | High | Feature loses value | Conservative defaults, experimental rules off by default, per-entity suppression, noise measurement on real captures before enabling a rule by default |
| Wrong vantage assumptions create false topology | Medium | Misleading map | Coverage object, basis tags, containment instead of edges, tests that a Wi-Fi-style capture produces no third-party unicast edges |
| SQLite write contention with the flow save | Medium | Lost or delayed alerts, UI errors | Short writer transactions, retry, batch per second; soak test |
| Baselines contaminated by unrelated captures | Medium | Bad "unusual" alerts | Learn only from live sessions on the same network; never from opened files; readiness gate |
| Public suffix data for DNS grouping | Low | Wrong "parent domain" grouping | Small bundled list with its source and licence recorded; documented limitation |
| Scope growth | High | Phase never finishes | Milestones in the roadmap each ship usable software; experimental rules can be cut without breaking others |
| Users read scores as probabilities | Medium | Over-trust | Fixed wording, tooltip-free explicit text beside every score |

## 14. Decisions needed before implementation

1. Confirm that detection is **session-bound** (no always-on capture in Phase 4).
2. Confirm adding about 9 tshark fields (cost gate in section 11) rather than starting with fewer.
3. Confirm default retention (180 days, 5,000 alerts) and the "delete all" action.
4. Confirm baseline readiness rule: at least 4 hours of cumulative live capture across at least 2 sessions on
   the same network before baseline rules evaluate. (Number is a starting point.)
5. Confirm bundling a small public suffix list (source and licence to be recorded) for DNS parent-domain logic.
6. Confirm the three existing sidebar placeholders are activated (`Network Topology`, `Threat Detection`,
   `Policies & Rules`) and that "Policies & Rules" is renamed "Detection Rules" for Phase 4.
7. Confirm the topology page may use the full window width (a layout exception to `max-w-5xl`).

## Appendix A: skills applied to this specification

| Skill | Use | Evidence |
|---|---|---|
| `brainstorming` | Classified as architectural; wrote back the understanding (section 1), compared approaches (section 4), listed decisions for approval (section 14). Its gate (spec approved before plan) is respected: the plan is an outline of milestones, with task-level plans to be written per milestone after approval. | Sections 1, 4, 14 |
| `writing-plans` | Milestone structure: files, interfaces consumed/produced, tests, acceptance, a Review Focus list. | Roadmap |
| `ui-ux-pro-max` | Ran its search tool for UX guidance on colour-only status, virtualisation and chart type. The tool's generated "design system" was a light, landing-page, Google-Fonts recommendation; it contradicts the existing dark tokens, the offline CSP and the project's documented decisions, so it was **not** adopted. Adopted: colour never the only signal, keyboard handlers, virtualise long lists, and "network graph accessibility is very poor, provide an adjacency list". | UI/UX specification sections 1 and 6 |
| `ui-ux-designer` (read earlier in this conversation; re-activation is not possible) | Information hierarchy, states, responsive rules. | UI/UX specification |
| `karpathy-guidelines`, `verification-before-completion` | No library, preset or feature added without a stated need; every claim about the repository was read in code. | Sections 2 and 4 |
