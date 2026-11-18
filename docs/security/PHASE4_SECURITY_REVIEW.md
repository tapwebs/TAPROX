# Phase 4 security review

Scope: the threat-detection additions of Phase 4 (rules, alerts, baselines, suppressions, annotations, device risk, topology
and their screens). The Phase 0 to 3 model is in [SECURITY_MODEL.md](SECURITY_MODEL.md) and is not repeated here. This is a
review by the author against the code and tests, not an independent audit. Claims marked **test** are proved by
`backend/tests/test_phase4_security.py` or by the named test; claims marked **by design** rest on code reading only.

## 1. Authentication

* Every Phase 4 route sits on the `/api/v1` router that requires the bearer token. **Test:** all 19 route and method
  combinations (read, write, delete) return 401 without it; a wrong token is refused.
* The backend listens on 127.0.0.1 only, receives the token on stdin (not on the command line), and refuses foreign `Host` and
  `Origin` headers before routing, which blocks DNS rebinding and cross-site requests. No cookies exist, so there is no ambient
  credential. **Test:** a request with a foreign `Origin` gets 403 and changes nothing. The process-level checks are in
  `scripts/smoke-desktop.ps1` (Phase 0).
* The topology and alert screens add no new credential, storage or network destination. The dashboard uses no `innerHTML`,
  `dangerouslySetInnerHTML` or `eval` (searched in `apps/dashboard/src`).

## 2. Authorization

The application has one local user and one token; there are no roles. What Phase 4 adds is **protection of the user's own
decisions**:

| Action | Protection |
|---|---|
| Change a rule or setting | Server validates every value against the bounds the rule publishes (type, finite number, minimum, maximum); unknown names, extra fields and out-of-range values are 422. **Test.** |
| Suppress a rule for an entity | Rule must exist (404), entity kind is a closed list, key at most 80 and reason at most 300 characters (422). A suppression is counted (`findings_suppressed` on the run), never silent, and affects only that rule and entity. **Test.** |
| Delete security history | Body must contain the JSON value `true`; a string, number, empty body or `false` is 422. It also resets baselines. **Test.** |
| Mark a device `known` | Closed lists for role and trust, note at most 300 characters. It lowers the weight of alerts about that device; it never switches a rule off. |
| Change an alert's status | Existing lifecycle rules refuse illegal transitions (M2). Notes are plain text, no control characters. |

## 3. Data isolation

* All Phase 4 data lives in the same per-user SQLite database as the inventory. Nothing is sent anywhere; the web searches and
  fetches of this project's rules exclude source code.
* **Opened files cannot teach the system.** A file session never creates a network profile, never updates a baseline, never
  records a gateway MAC and never writes topology history. **Test:** `test_a_live_run_stores_its_vantage_baseline_and_gateway_address_and_a_file_run_does_not`,
  `test_history_records_live_sessions_per_day_and_never_files`.
* **Baselines are per network** (interface network plus gateway). A device on another network is judged against nothing, not
  against a stranger's behaviour.
* No packet payload is stored. Alerts keep short templated text and bounded structured data; flows keep summaries only (Phase 3).
* A debug build of the desktop shell keeps its database in `<repo>/data`. The window checks in `scripts/live-check` therefore run
  against a junction inside a temporary folder so that the development database is never opened (see section 7).

## 4. Evidence handling

* Alert titles, summaries and explanations come from fixed templates in the rules; captured text (DNS names, SNI, host names)
  appears only in the structured `data` of evidence items, never in a title or summary. **By design**, enforced by the evidence
  length limits below.
* Limits: evidence text at most 300 characters, evidence data at most 4,096 bytes of JSON, at most 30 items per alert; a finding
  that breaks them is rejected and the failure is counted against the rule. **Test:** `test_hostile_text_in_evidence_is_kept_as_inert_text_inside_the_size_limits`.
* Wording policy (no verdict words such as attack, malicious, safe) is checked in the type that creates a finding, in every
  rule's metadata, and over the rendered text of each screen. **Test:** banned-word assertions in the dashboard tests.
* Hostile strings such as `<script>` or SQL fragments are stored as data and rendered by React as text. All database access uses
  the ORM or bound parameters. **Test:** the hostile-string test above; the dashboard has no HTML injection sink.
* Topology node keys and edge ids are validated by pattern in the path (`^[A-Za-z0-9_:.\-]+$`, at most 70 characters; edge ids
  `e` plus 14 hex digits). Odd keys return 404 or 422, never an error. **Test.** Group keys are sanitised from captured names.
* The topology draws a relationship only where a flow between the two ends was observed; it never draws a line between two
  other devices because they share a network. **Test.** `via_gateway` without frame evidence is drawn dashed and labelled inferred.

## 5. Resource limits

| Resource | Limit |
|---|---|
| Telemetry queue between capture and detection | 10,000 events. While packets are decoded, excess is dropped and counted (`dropped`) and the run says "coverage reduced". The end-of-capture burst waits for the consumer instead (up to 15 s without progress), so it is not lost; after that wait, or if the queue is closed, the rest is dropped and counted |
| Alerts held per run | 1,000; evidence 30 items |
| Rule state | Bounded maps (typically 2,000 to 10,000 keys) with oldest-first eviction, counted in diagnostics |
| Destination evidence for TT-TRF-001 and -004 | 64 destinations per device and window, 2,000 device-windows |
| TT-DEV-003 flow contradictions | 2,000 addresses tracked; reported when they reach the minimum and then every 10th time |
| Baselines | Sets capped (protocols 64, applications 128, local peers 512, listening ports 128, external peers 1,024), 1,440 windows per device, 2,000 devices per run; devices unseen for 90 days removed |
| Suppressions | 5,000 |
| Topology | 400 nodes and 1,200 edges rendered; 150 devices trigger grouping; history 50,000 edges, 180 days |
| Alert retention | Days and count limits from settings (bounds 7 to 3,650 days, 100 to 100,000 alerts) |

**Measured.** 5,000 inventory devices: the builder grouped them into 21 nodes and 20 edges in under 1 second through the API
(0.73 s on the review machine); without grouping the graph is cut to 400 nodes and says so. **Test.** The end-of-capture queue overflow of M4 is fixed ("Phase 4 last four items" in PHASE4_VERIFICATION.md). The M4 DNS **throughput** issue is
**not fixed**: a DNS-heavy capture can still outrun the pipeline and drop events while it runs; the loss is visible in the run's
warnings, but a flood could still reduce what is analysed. It stays recorded as technical debt.

## 6. Attack scenarios

| Scenario | Outcome |
|---|---|
| A web page in the user's browser calls the API | Refused by the `Origin` and `Host` guard; no ambient credential to ride on. **Test.** |
| Other software on the machine calls the API | Needs the token, which is passed on stdin and kept out of command lines. Any local process that can read the shell's memory or the user's session can use the API: **residual risk**, the same as Phase 0. |
| A hostile device sends names or banners with markup or SQL | Stored as inert data, rendered as text, parameterised queries. **Test.** |
| A flood of unique hosts, names or ports to exhaust memory | Bounded rule state with eviction, queue limit, alert cap; the run reports dropped events. The flood can still reduce detection coverage (see the M4 debt). |
| A device slowly changes its behaviour so that it becomes "normal" | **Residual risk.** Minutes in which a baseline rule raised an alert are left out of what is learned, but slow drift below the thresholds is learned. Baseline rules are off by default and say so. |
| An attacker (or the user) suppresses a rule to hide an alert | Suppressions are listed on the Rules screen, scoped to one rule and entity, and the count of suppressed findings is on every run. Nothing is removed from the history. |
| A spoofed gateway or a duplicated address | TT-DEV-003 and TT-DEV-004 report the observation. They rely on the hardware address in frames, which a device on the same link can forge: the alert states what was seen, not who sent it. |
| A user opens a crafted capture file | Parsed by tshark as before; Phase 4 adds no new parser. The file cannot create baselines, gateway memory or history. |
| Path or key injection through topology keys, rule ids, ids | Pattern-validated; odd values are rejected. **Test.** |
| Accidental deletion of the security history | Needs `confirm: true` and an inline confirmation in the screen. |

## 7. Residual risks and not covered

* No independent penetration test; no fuzzing of the new routes beyond the cases above.
* A single local token means no separation between users of the same Windows account.
* Rule thresholds are unvalidated on labelled real traffic; a rule may miss a real pattern or flag ordinary use. Alerts say
  "pattern consistent with" and list ordinary explanations and blind spots.
* The window checks used a debug build, a seeded throw-away inventory and one 168,349-packet capture from the author's network.
