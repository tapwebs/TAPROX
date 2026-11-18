# Phase 4 UI/UX specification

Status: **planning only**. No screen has been built. Facts about the current dashboard were read at commit
`a42ac1c` (React 19, Tailwind 4 with a closed token palette, `lucide-react`, hash router, hand-written SVG
chart, no graph or chart library). See [PHASE4_ARCHITECTURE.md](PHASE4_ARCHITECTURE.md) for the data these
screens show and [PHASE4_DETECTION_RULES.md](PHASE4_DETECTION_RULES.md) for rule wording.

## 1. Design position and evidence from the design skills

### 1.1 Position

Phase 4 screens extend the existing workstation look: dark graphite surfaces, one cyan accent, dense 14 px
text, `Panel` containers, status always shown by **icon plus text**, no gradients, glass, decorative charts,
animation or 3D (`DESIGN_SYSTEM.md` records these as decisions). Findings are shown with the same honesty
conventions as Phases 1 to 3: observed and inferred are separate, guesses are labelled as guesses, "not
evaluated" is shown as such, and nothing says "safe".

### 1.2 What the skills contributed (and what was rejected)

| Source | Finding | Decision |
|---|---|---|
| `ui-ux-pro-max`, `ux` domain, query "alert severity accessibility color not only" | Do not convey information by colour alone; use icons and text; 4.5:1 text contrast | Adopted. Severity is a labelled badge with an icon and a level marker; edge and node encodings use shape, line style and text in addition to colour. |
| `ui-ux-pro-max`, `web` domain, "virtualize large list keyboard" | Virtualise lists over about 50 items; interactive elements need keyboard handlers | Partly adopted. All lists are **paged** (50 rows) with the existing `Pagination`, which keeps the DOM small without a new dependency; the topology uses node caps and aggregation. All interactive graph elements have keyboard handlers. |
| `ui-ux-pro-max`, `chart` domain, "network graph relationship nodes" | Best type is a network graph; accessibility "very poor", provide an adjacency list; libraries named: D3, Vis.js, Cytoscape.js | Adopted: an **adjacency table** is a first-class view. Libraries **not** adopted for Phase 4 (see 6.5). |
| `ui-ux-pro-max`, `--design-system` for "security monitoring dashboard dark dense data table" | Returned a "Comparison Table + CTA" landing page pattern, a light palette (`#F8FAFC`), an orange CTA, Fira fonts loaded from Google Fonts | **Rejected.** It targets marketing pages. It contradicts the existing closed token palette, the dark-only design, the offline requirement and the production CSP (`style-src 'self'`, `font-src 'self'`). Its useful general lines (focus visible, reduced motion, no emoji icons, 150 to 300 ms transitions, responsive checks) already hold in the project. |
| `ui-ux-designer` (read earlier in this session) | Task-first information hierarchy, explicit states, responsive rules | Applied to section 3 (hierarchy and states per screen). |
| Existing `DESIGN_SYSTEM.md` | "Not covered yet" lists the topology graph, charts, modals, virtualisation | This document is where the topology graph is specified; modals stay out (non-modal panels and inline confirmation). |

## 2. Cross-cutting specification

### 2.1 Routes and navigation

The sidebar already contains three Phase 4 placeholders in this order: **Network Topology**, **Threat
Detection**, **Policies & Rules**. They are activated, not duplicated.

| Hash route | Screen | Sidebar entry |
|---|---|---|
| `#/threats` | Threat Overview | Threat Detection |
| `#/alerts` | Security Alerts (list) | (section link under Threat Detection) |
| `#/alerts/<id>` | Alert Investigation Details | Threat Detection stays highlighted |
| `#/history` | Detection History | (section link) |
| `#/topology` | Network Topology | Network Topology |
| `#/rules` | Detection Rules and Configuration | Policies & Rules, renamed **Detection Rules** |
| `#/risk/<deviceId>` | Device Risk Profile | Device Inventory stays highlighted |

Code changes this implies (all small and listed so reviewers can find them): `RouteId`, `PAGE_TITLES`,
`NAV_ITEMS` (set `route`) in `routes.ts`; `KNOWN` and `TAKES_PARAM` (`alerts`, `risk`) in `useHashRoute.ts`;
the `Page` switch in `App.tsx`; a per-route layout flag (`wide: true` for `topology`) because the shell wraps every
page in `max-w-5xl` (1024 px), which is too narrow for a graph. Parameters stay raw strings and each page
validates them (`/^[1-9]\d{0,15}$/` as `DevicesPage.parseId` does). Filters are encoded in the hash query
(`#/alerts?status=open&severity=high&device=12`) and read once at mount with `useHashQuery`, as Flow Explorer does,
so links from other screens can pre-filter.

A small `SectionNav` (link list with `aria-current="page"`, same focus ring) sits at the top of Overview, Alerts and
History so users move between them without adding sidebar items. There is no `Tabs` component today; `SectionNav` is
navigation (links), not a tab panel, so it needs no tab semantics.

### 2.2 Shared components (new, in `components/ui` or `features/security`)

| Component | Purpose | Notes |
|---|---|---|
| `SeverityBadge({level})` | `info`, `low`, `medium`, `high`, `critical` | Built on `StatusBadge`. Tones: info → `info`; low → `neutral`; medium → `warning`; high → `critical`; critical → `critical` with a stronger border and a four-step level marker. The visible text is always the level name. A test fails if two levels render the same text. No new colour token. |
| `ConfidenceChip({level})` | `low`, `medium`, `high` | Text "Confidence: high" with an icon; deliberately not a tone colour, so it is never confused with severity. |
| `RiskScore({value, breakdown?})` | Number 0 to 100 | Always followed by "A score orders alerts. It is not a probability." (once per screen, in a footnote). |
| `BasisBadge({basis})` | `observed`, `inferred`, `inventory`, `unknown` | Text plus icon plus (for topology) a line style; see 6.2. |
| `StatTile` | Extracted from the private `Stat` in `ActivityPage.tsx` | Moving it is a pure refactor and is done in the first UI milestone with its existing tests. |
| `EvidenceList({items})` | Evidence lines with basis badge, time, and an expandable structured detail | Captured text is rendered as text only. |
| `ScoreBreakdown({risk})` | Table: factor, value, reason, and the product line | The formula is printed in full. |
| `NumberField` | `TextField` with `inputMode="decimal"`, min, max, unit, validation message | There is no number or slider field today. |
| `InlineConfirm` | A bordered region that replaces an action button and asks "Are you sure?" with two buttons | Mirrors the existing "replace capture" confirmation in `PacketsPage`; no modal. |
| `TopologyCanvas`, `AdjacencyTable` | See section 6 | |

Reused unchanged: `Panel`, `Table`/`SortTh`/`Th`/`Td`, `Pagination`, `StateView` (`loading`, `empty`, `error`,
`permission`, `disconnected`), `RequestError`, `StaleNotice`, `DetailPanel`, `DefinitionList`, `Button`,
`TextField`, `SelectField`, `CheckboxField`, `RadioField`, `ProgressBar`, `Skeleton`, `EndpointLabel`,
`SessionPicker`, `ConfidenceBadge` for flows (the flow and device `ConfidenceBadge`s are different components
and must not be conflated).

### 2.3 Data loading pattern

`useRequest` for loads, `usePolling` for refresh, `useDebouncedValue` (300 ms) for search. While a detection run is
active, Overview and Alerts poll every 5 s with `reloadQuietly` (no spinner, no flicker); idle screens do not poll. The
user-initiated reload keeps the old rows visible and shows the `role="status"` "Updating..." line used in Packet
Explorer. Superseded requests are aborted by `useRequest`. Every list shows "as of <time>" with `aria-live="polite"`.

### 2.4 Wording rules for all screens

Banned: attack, malicious, compromised, infected, hacked, safe, clean, threat actor. Preferred: "pattern consistent with",
"possible", "indicator", "observed", "not evaluated". An empty alert list always reads "No alerts from the sessions
analysed" with what was analysed, never "No threats". Alert titles, summaries and explanations come from the server
(fixed templates); the UI does not compose security statements from captured text.

### 2.5 Accessibility baseline for every Phase 4 screen

One `h1` (focus moves to it on navigation, existing behaviour); landmark regions via `Panel`; tables in named focusable
regions; sortable headers use `aria-sort`; status never by colour alone; visible focus ring (global rule); `prefers-reduced-motion`
respected (no new animation is introduced besides the existing spinner); 4.5:1 text contrast with existing tokens (no new
token is planned; if one is needed it is measured on all four surfaces first); icon-only buttons have `aria-label`; all
graph interactions are reachable by keyboard; `axe-core` runs in each screen's test as `PacketsPage.test.tsx` does today.

### 2.6 States vocabulary (used in the per-screen tables)

* **Loading:** `StateView loading` on first load only; afterwards `isRefreshing` status line.
* **Empty:** `StateView empty` with a reason and a next step.
* **Error:** `RequestError` (maps 401/403/network/other as today); with old data present, `StaleNotice`.
* **Partial / not evaluated:** a warning-toned note listing what was not analysed and why (coverage, baseline not ready, file without local address).
* **Backend unavailable:** the existing `BackendGate`.

## 3. Screens

Each screen lists: purpose, layout (wireframe), components, hierarchy, interactions, filters and search, states, responsive behaviour.

### 3.1 Threat Overview (`#/threats`)

**Purpose.** Answer, in this order: what was analysed, is anything open that needs attention, which devices stand out,
and what could not be evaluated.

```
 [Overview | Alerts | History]                                          (SectionNav)
 +- Detection status ---------------------------------------------------------------+
 |  Analysing: live capture on Ethernet, 12 min, 168,349 packets.  Events dropped: 0  |
 |  Baseline: ready for 3 of 14 devices · Rules evaluating 13 of 27 · Not evaluated 4 |
 +------------------------------------------------------------------------------------+
 [Open alerts 7] [High 1] [Medium 3] [Low or info 3] [Devices with open alerts 4]      (StatTiles)
 +- Alerts over time (7 days) ------------------------+ +- Highest-risk open alerts ---+
 |  stacked bars by severity + data table alternative  | |  1  High  Gateway MAC changed|
 |                                                     | |  2  Med   Port scan pattern  |
 +-----------------------------------------------------+ +------------------------------+
 +- Devices by risk ----------------------------------+ +- What was not analysed -------+
 |  table: device, risk, open alerts, last alert       | |  - 4 rules need a baseline   |
 +-----------------------------------------------------+ |  - opened files: no direction |
                                                         +-------------------------------+
```

**Components.** `Panel`, `StatTile` (grid `grid-cols-2 md:grid-cols-3 lg:grid-cols-5`), hand-written SVG stacked bar chart in
the same pattern as `TrafficChart` (role `img`, text summary, `<details>` data table), top-alerts list, devices-by-risk
`Table`, `DefinitionList` for status.

**Hierarchy.** Status strip first (trust in the data), then counts, then trend, then lists. The "What was not analysed"
panel is always present, even when empty ("All enabled rules were evaluated.").

**Interactions.** Tiles link to `#/alerts?severity=...`; a list row links to `#/alerts/<id>`; a device row links to `#/risk/<id>`;
the status strip links to `#/rules` for "not evaluated" and to `#/packets` to start a capture when idle.

**Filters.** One control: range (`Last session`, `24 hours`, `7 days`, `30 days`); default 7 days.

**States.** Loading: skeleton tiles and one `StateView loading`. Empty (no run ever): "No capture has been analysed yet" with a
button to Packet Explorer. Empty (runs exist, no alerts): "No alerts from the sessions analysed" plus counts. Error/stale: standard.
Partial: events dropped > 0 shows a warning "Coverage reduced during the last run".

**Responsive.** ≥ 1024 px: tiles in one row, two-column panels. 900 to 1023 px: tiles wrap to 3 per row, panels stack. Below 900 px
(browser dev only): single column.

### 3.2 Security Alerts (`#/alerts`)

**Purpose.** Triage: find, sort and open alerts.

```
 [Overview | Alerts | History]
 +- Alerts ----------------------------------------------------------- [Refresh] -+
 |  Search [............]  Status [Open+Ack ▾] Severity [All ▾] Category [All ▾]    |
 |  Rule [All ▾]  Device [..]  Min risk [0]  Range [7 days ▾]       as of 14:03:22  |
 |  +------+------+----------------------------+-----------------+--------+-------+ |
 |  |Sever.| Risk | Alert                      | About           | Status | Last  | |
 |  | High |  60  | Gateway MAC changed        | 192.168.1.1     | Open   | 14:02 | |
 |  | Med  |  55  | Port scan pattern (REC-001)| 192.168.1.23    | Open   | 13:58 | |
 |  +------+------+----------------------------+-----------------+--------+-------+ |
 |  Showing 1-50 of 123                                  [Previous] [Next]          |
 +----------------------------------------------------------------------------------+
```

**Components.** `Panel`, filter grid (`grid gap-3 md:grid-cols-3`), `Table` with `SortTh` on Severity, Risk, Last seen; first cell is the
`aria-pressed`-style opener used elsewhere (here an `<a href="#/alerts/ID">` because the detail is a page); `SeverityBadge`;
`EndpointLabel` for the entity when it is an IP/device; `StatusBadge` for status; `Pagination` (50).

**Columns.** Severity, Risk, Alert (title; rule id and occurrences in small text), About (entity), Status, Last seen (observed time; a "file replay" tag
when the source is a file), Confidence.

**Filters and search.** Status (default Open + Acknowledged + Investigating), Severity, Category, Rule, Device (select from devices with alerts),
IP/MAC/domain text, Min risk, Range. Search matches title, entity key and note, substring, server-side, debounced. Default sort: risk descending,
then last seen. Filters are mirrored into the hash query so a view can be copied.

**Interactions.** Row opens the detail. Keyboard: tab to a row link, Enter opens. No bulk actions in Phase 4 (YAGNI; status is changed in detail).

**States.** Loading, empty ("No alerts match these filters" with a Clear filters button, or "No alerts from the sessions analysed"), error with retry,
stale notice, refreshing status line. A `list_capped`-style notice is not needed (server paging).

**Responsive.** The table scrolls inside its region; the filter grid goes 3 → 2 → 1 columns; no horizontal page scroll.

### 3.3 Alert Investigation Details (`#/alerts/<id>`)

**Purpose.** Let an investigator decide: what exactly was seen, why it scored what it did, what else it could be, what to do next.

```
 < Back to alerts
 +- Port scan pattern (TT-REC-001) ---------------------------------------------------+
 |  [Medium] [Confidence: high] Risk 60   Status [Open ▾]  Note [......] [Save]        |
 |  192.168.1.23 → 192.168.1.1 · 14:02:11 to 14:02:58 (packet time) · seen 2 times     |
 |  "A pattern consistent with scanning: 41 TCP ports probed on one host in 47 s."     |
 +------------------------------------------------------------------------------------+
 +- Evidence (observed) --------------------------+ +- Score breakdown ----------------+
 |  [observed] 41 distinct ports, 86% unanswered   | |  0.50 severity × 1.00 confidence  |
 |  [observed] ports 1-1024 range, first 14:02:11  | |  × 1.20 context = 60              |
 |  [observed] sample flows (20) ...               | |  +0.10 corroboration (sweep)      |
 +-------------------------------------------------+ |  +0.10 sensitive target (gateway) |
 +- What else this could be ----+ +- What this cannot tell you --+ +-------------------+
 |  - a network scanner you ran | |  - slow scans over longer    |
 |  - a peer-to-peer client     | |  - scans not crossing this PC|
 +------------------------------+ +------------------------------+
 +- Related ---------------------------------------------------------------------------+
 |  Same entity: Host sweep pattern (Med, Open)  ·  Device: Laptop (risk 72) → #/risk/12|
 |  Flow Explorer: #/flows?ip=192.168.1.23   Topology: #/topology?focus=ip:192.168.1.23 |
 |  Packet Explorer filter: [ip.addr == 192.168.1.23 && ip.addr == 192.168.1.1] (copy)   |
 +------------------------------------------------------------------------------------+
 +- Activity (audit trail) ------------------- +- Thresholds in force (collapsed) ------+
```

**Components.** Header `Panel`; `SeverityBadge`, `ConfidenceChip`, `RiskScore`; status `SelectField` limited to **allowed
transitions** returned by the server; note `TextField`; `EvidenceList`; `ScoreBreakdown`; two plain lists (benign explanations, blind spots) always present;
`DefinitionList` for entity and window; related links (plain `<a href="#/...">` in the existing link style); `<code className="select-all ...">` for the Packet Explorer
filter string (no Packet Explorer deep link exists today; `PacketsPage` does not read the URL); audit `Table`.

**Hierarchy.** Summary and status first, then evidence, then score, then alternative explanations and blind spots **side by side with equal weight**
(to counter confirmation bias), then related items, then history.

**Interactions.** Status change saves via `PATCH`; transitions that matter use `InlineConfirm` ("Mark as false positive. The rule will still count this in History."). Actions offered:
Acknowledge, Investigate, Resolve, Mark false positive, "Suppress this rule for this entity" (reason required, optional expiry). Button labels use "mark as"
language. There is no "block" or "respond" action anywhere.

**States.** Loading; not found (`StateView empty` "Alert not found. It may have been removed by retention"); error; stale; saving (button `loading`); save conflict (server returns
`invalid_status_transition`, shown at the control). Evidence capped: "30 of 41 evidence items kept" from `evidence_dropped`. Source file: banner "This alert comes from an opened capture file; times are from the packets, not from now".

**Responsive.** Two-column panels stack below `lg`; the DetailPanel pattern is not used here because the alert is the page.

### 3.4 Network Topology (`#/topology`)

Detailed in section 6. Layout summary:

```
 +- Network topology ------------------------------------------------ [Graph | List] -+
 |  Session [Current ▾]  Window [Session ▾]  Show [Observed ☑ Inferred ☑ Inventory ☑]   |
 |  Group by [Role ▾]  Only with alerts [ ]  Min bytes [0]  Search [......]  [-] [+] [Fit]|
 |  Coverage: captured on Ethernet (Wi-Fi style vantage). Visible: this computer's      |
 |  conversations and broadcast/multicast from others. Not visible: other devices' ...  |
 |  +------------------------------------------------------+ +-- Selected: Router ----+ |
 |  |                  (graph canvas, full width)          | |  Basis: observed        | |
 |  |                                                      | |  Seen 14 days ...       | |
 |  +------------------------------------------------------+ +-------------------------+ |
 |  Legend: shapes, line styles, badges                                                  |
 +--------------------------------------------------------------------------------------+
```

### 3.5 Detection Rules and Configuration (`#/rules`)

**Purpose.** See what the engine checks, change thresholds safely, understand why a rule is not running.

```
 +- Detection ------------------------------------------------------------------------+
 |  [x] Analyse sessions for threat indicators          Baseline: ≥ 4 h and ≥ 2 sessions |
 |  Retention: [180] days  [5,000] alerts   Half-life for device risk [7] days   [Save]  |
 +--------------------------------------------------------------------------------------+
 +- Rules ----------------------------------------------------------------------------+
 |  Category [All ▾]  State [All ▾]  Search [....]                                      |
 |  +---+----------+--------------------------------+---------+---------------------+ |
 |  |On | ID       | Rule                           | Severity| Status              | |
 |  |[x]| TT-REC-001| Vertical port scan pattern    | Medium  | Evaluating · 2 / 7d | |
 |  |[ ]| TT-TRF-001| Outbound volume spike         | Low     | Not evaluated: baseline not ready |
 |  +---+----------+--------------------------------+---------+---------------------+ |
 +--------------------------------------------------------------------------------------+
 +- Rule: TT-REC-001 (details panel, below) ----------------------------------------------+
 |  Description · Logic · Telemetry needed · False-positive risks · Blind spots (read only) |
 |  Parameters: distinct ports [20] (5 to 1000)  window s [60] (10 to 3600)  [Reset] [Save]|
 |  Suppressions for this rule: table · Change history: table                              |
 +------------------------------------------------------------------------------------------+
 +- Danger zone: Delete all security history [Delete…]  (InlineConfirm: type nothing, two clicks) -+
```

**Components.** `Panel`, `CheckboxField` for enable switches (each with a visible label "Enable TT-REC-001" via `aria-label`), `Table`, `DetailPanel` (below the
list, as Flow Explorer does), `NumberField` generated from the server's parameter metadata (`name`, `type`, `default`, `min`, `max`, `unit`, `description`), `InlineConfirm`.

**Behaviour.** Client validation mirrors the server's bounds; the server is authoritative and returns `parameter_out_of_range` with the allowed range, shown next to the field.
A saved change takes effect for the **next run** (an open run keeps its rules; the UI says so). Rules whose required telemetry is unavailable (for example a session captured before the new fields existed)
show "Needs data this session lacks". Presets are not offered.

**States.** Loading, error, empty (should not happen: the catalogue is built in), saving, conflict, "changes take effect on the next analysed session".

**Responsive.** The parameter form is a single column; the rules table scrolls in its region.

### 3.6 Device Risk Profile (`#/risk/<deviceId>`)

**Purpose.** Show one device's security-relevant history and what drives its score.

```
 < Device inventory   Laptop-Anna (192.168.1.23)  [This computer]
 +- Risk -------------------------------------------+ +- Your notes ----------------------+
 |  72  "Orders devices. Not a probability."         | |  Role [workstation ▾] Trust [known]|
 |  Highest open: Medium · 3 open alerts · half-life 7 d| | Note [............] [Save]       |
 +---------------------------------------------------+ +-----------------------------------+
 +- Contributing alerts ------------------------------------------------------------------+
 |  Alert                     Severity  Score  Age   Weight  Contribution                 |
 +----------------------------------------------------------------------------------------+
 +- Typical behaviour (learned) ------------------+ +- Recent activity --------------------+
 |  Baseline: 6 sessions, 9.5 h on this network    | |  Flows: #/flows?device=12            |
 |  Protocols: TLS, DNS, HTTP · Applications: ... | |  Topology: #/topology?focus=device:12 |
 +-------------------------------------------------+ +---------------------------------------+
```

**Components.** `Panel`, `DefinitionList`, contributions `Table` that prints `s_i`, `d_i` and the contribution so the number can be reproduced by hand,
`SelectField` for role and trust (labelled "set by you"), `EndpointLabel`.

**States.** Device not found (reuse the devices wording); no alerts ("No alerts for this device in the retention period. This does not mean nothing happened:
only sessions that were analysed are covered."); baseline not ready (shows hours and sessions still needed); error/stale as usual.

A small **Security** panel is added to the existing Device detail (`DevicesPage`): score, open-alert count and a link to this page. This is the only edit to a Phase 1 screen.

**Responsive.** Panels stack below `lg`.

### 3.7 Detection History (`#/history`)

**Purpose.** Review what has been analysed and past (closed) alerts.

```
 [Overview | Alerts | History]
 +- Analysed sessions ------------------------------------------------------------------+
 |  Start · Source · Interface or file · Duration · Packets · Events dropped · Alerts new/updated · Suppressed · Notes |
 +--------------------------------------------------------------------------------------+
 +- Alerts per day (30 days) ---- SVG bars + data table ---+ +- Rules that fired -------+
 +- Closed alerts ----------------------------------------------------------------------+
 |  Status [Resolved ▾] Range [30 days ▾] Search [....]  (same table as Alerts)           |
 +--------------------------------------------------------------------------------------+
```

**Components.** `Table` for runs (sortable by start), SVG chart (stacked by severity) with table alternative, `Table` for rule hit counts, the alerts table component with a
status preset.

**Interactions.** A run row shows its warnings expanded in place (`<details>`); a run links to the alerts it created (`#/alerts?run=<id>`).

**States.** No runs: "No sessions have been analysed yet". Runs with warnings highlighted with warning tone and text ("Coverage reduced: 1.8% of events dropped").

**Responsive.** Tables scroll in their regions; chart and rule list stack below `lg`.

## 4. Existing screens touched

| Screen | Change | Reason |
|---|---|---|
| Overview | A "Threat detection" panel (open alerts, last run, link). Also fix the stale sentence that says capture sessions are not available. | Entry point; stale text found during investigation. |
| Device Inventory detail | "Security" panel (3.6). | Link to risk profile. |
| Flow Explorer | None required. Alert links use existing `?ip=` and `?device=` query parameters. | Avoid editing Phase 3 screens. |
| Packet Explorer | None. Alert detail shows the filter string to copy. | No URL filter parameter exists. |
| `DESIGN_SYSTEM.md`, `FLOWS.md`, `OVERVIEW.md`, `SECURITY_MODEL.md` | Updated when implementation lands (stale screen counts, the "not a verdict" paragraph cross-referenced to alerts, new data in the threat model). | Keep docs true. |

## 5. Frontend testing plan

* One test file per screen (`ThreatOverviewPage.test.tsx`, `AlertsPage.test.tsx`, `AlertDetailPage.test.tsx`, `TopologyPage.test.tsx`,
  `RulesPage.test.tsx`, `RiskProfilePage.test.tsx`, `HistoryPage.test.tsx`) using `stubBackend` and new builders in `src/test/backend.ts`.
* Each test covers loading, empty, error, stale, and the main interaction; one axe-core run per screen; a banned-words test over rendered text.
* `SeverityBadge` test: five levels render five distinct texts and icons.
* `useHashRoute` tests for the new routes and malformed parameters.
* Real-window checks over the DevTools protocol (the method used for Phase 3) for every screen at 900, 1024 and 1440 px wide:
  no horizontal page overflow, no console errors, timings recorded, long-task and timer-stall observers for the topology.

## 6. Network topology design

### 6.1 Node types

| Type | What it is | Basis of its existence | Shape |
|---|---|---|---|
| `this_computer` | The capture vantage | observed (own interface) | circle with ring, labelled "This computer" |
| `device` | Inventory device (linked by MAC, or by IP only with the label) | inventory; communication attributes observed | circle |
| `gateway` | Default gateway from the session vantage, matched to the inventory when possible | inventory + observed | square |
| `unresolved_host` | On-link IP seen in traffic with no inventory match | observed | circle, dashed outline, badge "unresolved" |
| `remote_host` | Off-link IP | observed | small circle |
| `remote_group` | Aggregated remote hosts by name evidence (SNI/DNS/HTTP host), otherwise by application, otherwise "Other remote hosts" | observed, grouping inferred | rounded square with count |
| `application` | Application/service label from Phase 3 classification (confirmed or probable only) | inferred by Phase 3 method, shown with its confidence | diamond |
| `segment` | An interface network (CIDR) as a container | inventory | large rounded rectangle containing its devices |
| `group` | UI aggregation of many devices (by role, vendor or segment) | inferred (user-chosen grouping) | rounded square with count |

### 6.2 Edge types and encoding

| Edge | Meaning | Basis | Line style | Confidence |
|---|---|---|---|---|
| `communication` | At least one flow between the two endpoints was observed | observed | solid; width from log(bytes) in 3 steps | `confirmed` if both endpoints are resolved and flows are bidirectional; `probable` if one-sided or IP-only match |
| `via_gateway` | Off-link flows from a device carried in frames addressed to the gateway's MAC | observed (frame evidence) | solid thin | `confirmed` when the MAC evidence exists |
| `via_gateway` (no frame evidence) | Off-link destination assumed to pass the gateway | inferred | dashed | `probable` |
| `application_use` | A device used an application with Phase 3 confidence | inferred (Phase 3 method) | dotted | the flow confidence |
| `name_service` | A client sent DNS queries to a resolver | observed | solid thin with "DNS" label | `confirmed` |
| (alert overlay) | An alert involves this node or edge | n/a | thick outline + alert icon + count; never replaces the basis style | n/a |

Not drawn as lines: **inventory membership** (a device belongs to a segment) is containment; **same segment** is containment; **unknown** is never a line.
Unknown relationships are listed in the coverage panel as text ("Communication between other devices on this network cannot be seen from this position").

A line is never drawn between two LAN devices unless a flow between them was observed. Encoding uses shape, line style, label and badge in addition to colour. Colour is only an
accent (alert overlay uses `critical`, selection uses `accent`, the rest `fg-muted`).

### 6.3 Data sources and relationship confidence

Sources in precedence: live flow engine (current session), saved session flows, `topology_edges`/`_days` (history), inventory (`devices`,
`device_addresses`), session vantage (gateways, interface MAC, DNS servers, promiscuous flag), alerts (overlay). Each edge carries `basis`, `confidence`,
`first_seen`, `last_seen`, `flows`, `bytes`, `protocols[]`, `applications[]` and `evidence[]` (up to 5 lines of text). Confidence reuses the flow vocabulary (`confirmed`,
`probable`, `unknown`) and the existing explanation style ("by IP only", "by MAC and IP").

### 6.4 Coverage (never omitted)

The API returns a `coverage` object and the screen prints it above the graph:
`vantage` (interface, promiscuous), `local_addresses`, `gateways`, `direction_known`, `visibility` (one of `own_traffic_and_broadcast`, `promiscuous_switched`, `unknown`), and
`cannot_see` (fixed sentences). For a file: "Opened file: the vantage point is unknown; local and remote cannot be told apart; relationships shown are only those in the file."
A test asserts that a capture built like a Wi-Fi client (only the client's unicast and others' broadcast) produces **no** edge between two third-party devices.

### 6.5 Layout, rendering and scale

* **Layout (deterministic, no physics):** centre = this computer (or the gateway for files); ring 1 = on-link devices inside their segment containers, ordered by segment then
  `last_seen`; outer sectors = remote groups ordered by bytes; applications placed on the arc between their device and group when shown. Positions come from a stable hash of node keys, so the
  same data yields the same picture on every refresh and in tests. Complexity O(n log n) in the number of rendered nodes.
* **Why not a library now:** D3, Vis.js and Cytoscape.js were named by the chart guidance. A force-directed layout is non-deterministic (harder to test), adds a dependency and bundle size
  (no bundle policy exists, only baselines), and is not needed for a hub-and-spoke network. Revisit if real captures prove the layout inadequate; the `TopologyCanvas` interface (nodes, edges, selection, callbacks) hides the renderer.
* **Renderer:** SVG. Caps: 400 rendered nodes and 1,200 rendered edges. Above the cap the server aggregates (below). The CSP allows inline SVG; no canvas, worker or `eval` is required.
* **Aggregation tiers (server side, `group_by` = `role` | `vendor` | `segment` | `none`):** (1) more than 150 devices → devices grouped; (2) remote hosts always grouped by name evidence, then application, then
  "Other remote hosts"; (3) parallel edges between the same two rendered nodes are merged into one with counts; (4) a node with more than 25 edges shows its top 25 by bytes and a "+N more" edge to a group. Clicking a group node expands it in place until the caps are reached
  (then it opens in the list view).
* **Large networks:** 5,000 inventory devices must render within the caps by grouping into segments and roles; the list view pages 50 at a time.
* **Interactions:** pan (drag, arrow keys), zoom (wheel, `+`/`-`, buttons), Fit, select (click or Enter), hover/focus highlight of neighbours, double-click or `E` to expand a group, `Escape` to clear selection. Mouse hover is never required: all information is available on selection.
* **Keyboard:** nodes are `role="button"` in a roving-tabindex group; arrow keys move to the nearest neighbour; Enter selects; a visible focus ring uses the global style.
* **Accessible alternative:** the **List** view is an adjacency table (From, To, Kind, Basis, Confidence, Flows, Bytes, First seen, Last seen, Alerts) with `Pagination`, filterable by the same controls, and selection syncs between views. The graph has an `aria-label` summary ("Network graph: 24 nodes, 31 relationships, 3 with alerts").
* **Time:** the Window control (`Session`, `24 hours`, `7 days`, `30 days`, `All`) switches between the live/selected session graph and the history table. "New" edges (first seen inside the window) get a "new" badge in the list and a thicker outline in the graph. History never contains edges from opened files.

### 6.6 Filtering and grouping

Controls: Session, Window, Basis checkboxes (observed, inferred, inventory), Confidence, Node type, Group by, Only with alerts, Min bytes, Application, Protocol, Search (address, name, MAC, vendor).
Filters are mirrored in the hash query. Filtering never removes the coverage statement.

### 6.7 Details panel (non-modal `DetailPanel`)

Node: identity (`EndpointLabel`), role/trust (from annotation), first/last seen, basis of each fact, open alerts (links), top peers, applications, protocols, links to `#/risk/<id>`, `#/flows?device=<id>` or `?ip=`.
Edge: both endpoints, kind, basis, confidence with the **reason** ("Observed: 14 flows, both directions"), counters, protocols, applications, first/last seen, alerts, evidence lines, the Packet Explorer filter text if the session is still loaded.

### 6.8 States

Loading: `StateView loading`. Empty: "No relationships observed yet" with the coverage text. Partial: "Graph reduced to the 400 most active nodes; N groups". Error: `RequestError`. Stale: `StaleNotice`. File sessions: banner explaining the missing vantage. No inventory: nodes shown as unresolved, with a link to Device Discovery.

### 6.9 Responsive

≥ 1440 px: graph and details side by side. 1024 to 1439 px: details below the graph. 900 to 1023 px: toolbar wraps, graph minimum height 480 px, details below. The list view is the default below 900 px (browser dev only).

## 7. Open UI decisions for approval

1. Rename the sidebar entry "Policies & Rules" to "Detection Rules" for Phase 4 (broader policy features are not planned).
2. Allow `wide` pages (topology only) to use the full content width.
3. Accept `SectionNav` as the navigation inside the Threat Detection area instead of adding more sidebar entries.
4. Accept that Packet Explorer deep links (a filter in the URL) are **not** part of Phase 4; alerts show a copyable filter, as Flow Explorer does today.
