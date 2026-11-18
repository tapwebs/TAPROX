# Phase 6 UI/UX specification: Investigations & Forensics

Status: **specification for approval**. Extends [DESIGN_SYSTEM.md](development/DESIGN_SYSTEM.md) and follows the
accessibility, dark-graphite visual system, and honest epistemic standards of
[PHASE4_UI_UX_SPECIFICATION.md](PHASE4_UI_UX_SPECIFICATION.md) and
[PHASE5_UI_UX_SPECIFICATION.md](PHASE5_UI_UX_SPECIFICATION.md).

---

## 1. Design principles & epistemic discipline

* **Visual tokens:** Dark graphite surfaces (`canvas`, `surface`, `inset`, `raised`), restrained cyan accent,
  `Inter` UI text (`14 px` body) + `monospace` for hashes (`SHA-256`), IP/MACs, IDs (`CASE-2026-0001`, `EV-0001`),
  and timestamps. `Panel`, `Table`, `StatTile`, `DetailPanel`, `Pagination`, `StateView`, `InlineConfirm`.
* **Never color alone:** All case statuses (`Open`, `Active`, `Sealed`, `Closed`), integrity verdicts
  (`Verified`, `Tamper Mismatch`, `Missing File`, `Unverified`), severities (`SeverityBadge`), confidence
  (`ConfidenceChip`), and epistemic basis (`BasisBadge`: `Observed`, `Inferred`, `Inventory`, `Analyst Note`)
  render explicit icon + text labels.
* **Preserving honesty:** The UI clearly separates **observed facts** (original packet/flow/alert/TLS
  snapshots), **inferred correlations** (rule-based links with stated caveats), and **analyst notes** (human
  interpretation). Never displays claims like *"Root cause proven 100%"* or *"Verified clean"*.
* **No HTML sinks or unsafe links:** Case titles, notes, file paths, indicators, and snapshot payloads render
  strictly as text (`<code>` / `<pre>` / `<span>`), never `dangerouslySetInnerHTML`, never clickable external URLs.

---

## 2. Navigation, routes, and activation

Activates **both** Phase 6 placeholder entries in `apps/dashboard/src/app/routes.ts`:
* `NAV_ITEMS`:
  * `{ label: "Investigations", icon: FolderSearch, phase: 6, route: "investigations" }`
  * `{ label: "Reports & Evidence", icon: FileText, phase: 6, route: "reports" }`
* `RouteId`: adds `"investigations"` and `"reports"`.
* `PAGE_TITLES`:
  * `"investigations": "Investigations"`
  * `"reports": "Reports & Evidence"`

Hash routes (`useHashRoute.ts`):
* `#/investigations` — Case list, status/severity filters, search, and **New Investigation** creation panel.
* `#/investigations/<id>` — Single case workspace (`id` validated strictly as `/^[1-9]\d{0,15}$/`). Optional
  `?tab=evidence|timeline|correlations|notes|custody|export` selects active sub-tab safely via allowlist.
* `#/reports` — **Reports & Evidence** hub: cross-case vaulted evidence status, one-click global **Integrity
  Audit**, **Audit Log** viewer, exported dossier/bundle archive, and **Offline Bundle Verifier** form.

---

## 3. Screen architecture & workflows

### 3.1 `#/investigations` — Case Registry & Creation

```
+- Investigations Summary ------------------------------------------------------------+
|  [Open/Active: 3]   [Sealed: 2]   [Vaulted Items: 28]   [Integrity: All Verified]   |
+-------------------------------------------------------------------------------------+

+- New Investigation (collapsible or top card) ---------------------------------------+
|  Title [..............................]  Type [Incident ▾]  Severity [Medium ▾]      |
|  Operator / Actor [local-operator     ]  Scope summary [..........................]  |
|  [ ] I am authorized to open and preserve forensic evidence under this case scope   |
|                                                                [Create Investigation]
+-------------------------------------------------------------------------------------+

+- Case Registry ---------------------------------------------------------------------+
|  Search case ref / title / actor [............]   Status [All ▾]   Severity [All ▾] |
|  Table: Case Ref · Title · Status · Severity · Evidence · Integrity · Lead · Updated|
|  Pagination (25 per page)                                                           |
+-------------------------------------------------------------------------------------+
```

* `"Create Investigation"` remains disabled until Title, Scope summary, Actor, and the authorization checkbox are filled/checked.
* Clicking a case row opens `#/investigations/<id>`.

### 3.2 `#/investigations/<id>` — Case Workspace

Top persistent case header strip:
* Case ref (`CASE-2026-0001`), title, `StatusBadge` (`Open`/`Active`/`Sealed`/`Closed`), `SeverityBadge`, lead actor, custody head (`Seq #14 · sha256:8f2a…`), integrity pill (`Verified` with timestamp or critical alert banner if `Mismatch`), and header actions:
  * **Verify Integrity** button (`POST /verify` — runs deterministic full snapshot + vault + custody chain check).
  * **Seal Case** / **Close Case** / **Reopen Case** via explicit `InlineConfirm` + required `reason` text input (never one-click silent status lock!).
* Locked-case banner when `status === "sealed" | "closed"`: explains cleanly that evidence acquisition and notes are locked until reopened with a recorded custody reason.

Sub-navigation tabs (`SectionNav` pattern from `WebInspectorPage`):

1. **`Overview`:** Incident summary, scope authorization statement, evidence breakdown by kind, latest conclusion note (if any), blind-spots notice (*"Findings reflect locally attached snapshots and passive observations; correlations are heuristic links requiring analyst judgment."*).
2. **`Evidence (N)`:**
   * **Attach Evidence** toolbar:
     * `"Attach from TAPNETTRACK"` (opens selector listing recent Alerts, Flow Sessions, Devices, Web Inspections — with warning banner when source session is ephemeral/subject to Phase 3 pruning).
     * `"Attach PCAPNG File"` (OS path input matching Phase 2 `OpenCapture`, vault-copy toggle default ON with size preview, explicit authorization confirmation).
   * Table: `EV-0001`, Kind, Title, Basis (`Observed`/`Inventory`), Storage (`Snapshot`/`Vault Copy`/`External Link`), `SHA-256` (truncated monospace + copy button), Integrity (`Verified`/`Mismatch`/`Missing`), Acquired At, Actor.
   * Row click opens `DetailPanel` inspecting full **Provenance**, redacted canonical JSON preview, and SHA-256 comparison (`Expected` vs `Last Computed`).
3. **`Timeline (N)`:**
   * Unified chronological stream merging timestamps across `investigation_evidence` and `investigation_notes`.
   * Filter by `Basis` (`Observed`, `Inferred`, `Analyst Note`), `Time Source` (`Packet Clock`, `Wall Clock`, `Remote TLS Cert`), or text filter.
   * Each timeline card shows UTC timestamp, **Time Precision Badge** (preventing silent mixing of capture clocks with wall clocks), Event Kind, Title, source `EV-xxxx` / `NOTE-xxxx` pill, and concise detail.
4. **`Correlations (N)`:**
   * Button **"Run Deterministic Correlation"** (`POST /correlate`) disabled when `sealed`/`closed`.
   * Lists indicator clusters (`IP`, `MAC`, `Hostname`, `Cert SHA-256`, `Alert Group`), `BasisBadge` (`Inferred`), `ConfidenceChip`, narrative rationale, linked `EV-xxxx` chips, and explicit **Limitations** box (*"Shared gateway/NAT IP may cover multiple hosts"* etc.).
5. **`Forensic Notes (N)`:**
   * Immutable revision ledger: displays active note thread + expandable **"View earlier revisions"** when `supersedes_note_id` is set (earlier text preserved verbatim, never erased).
   * Composer: Note Kind (`Observation`, `Hypothesis`, `Correlation Review`, `Conclusion`, `Limitation`), Confidence, Title, Body, multi-select `Cite Evidence (EV-xxxx)`, Actor, **"Append Note"** (or **"Append Revision"** targeting an existing note).
6. **`Chain of Custody (N)`:**
   * Chronological `Seq #1 .. #N` table: `Seq`, `Timestamp (UTC)`, `Actor`, `Surface`, `Action`, `Evidence/Note Ref`, `Artifact SHA-256`, `Prev Hash`, `Event Hash`.
   * Chain Continuity Banner: `SHA-256 Chain Intact (N links verified)` or `CRITICAL: Chain Break at Seq #k`.
7. **`Export Report`:**
   * Choose format (`Markdown (.md)`, `JSON Dossier (.json)`, `Verifiable ZIP Bundle (.zip)`), toggle `Include vaulted PCAPNG files` (shows total projected ZIP size), Actor attribution, **"Generate & Download Export"**.
   * Shows generated `bundle_sha256` immediately for external verification recording, plus history of prior case exports.

### 3.3 Cross-module `"Add to Investigation…"` pivot flow

Added non-destructively inside:
* `AlertDetailPage.tsx` (`#/alerts/<id>`)
* `FlowsPage.tsx` (`FlowDetails` panel & session summary)
* `DevicesPage.tsx` (device detail drawer)
* `PacketsPage.tsx` (current capture / saved capture header)
* `WebInspectorPage.tsx` (`#/web-inspector/<id>` result strip)

Flow:
1. User clicks **"Attach to Investigation…"** -> opens accessible `DetailPanel` / dialog (`Esc` closes, focus returns cleanly).
2. Shows read-only preview of what snapshot/file will be preserved + notice *"Original record remains untouched; Phase 6 stores a hashed copy inside the selected case."*
3. User chooses an existing `open`/`active` case (or quick-creates a scoped case) and clicks **"Confirm Attach"**.
4. Displays confirmation toast with link `#/investigations/<id>?tab=evidence` (never navigates away unexpectedly unless user clicks the link).

### 3.4 `#/reports` — Reports & Evidence Hub

* **Vault & Integrity Summary:** Global counts of active/sealed cases, total vaulted bytes vs quota (`4 GiB`), last global audit verdict, and **"Verify All Cases Now"** button (`POST /api/v1/reports/verify-all`) showing live progress bar and per-case pass/fail results.
* **Saved Exports Registry:** Filterable list of all `report_exports` across cases with `bundle_sha256`, `format`, `custody_head_seq`, and quick re-export/case link.
* **Offline Bundle Verifier:** Drag/drop or path-select (within Tauri/local sandbox) or local file picker (`<input type="file">`) for a `.zip` bundle / `dossier.json` -> uploads to loopback `POST /api/v1/investigations/verify-bundle` (capped at upload/unpack limit) and displays verified vs failed `SHA256SUMS` and custody chain proof.
* **System Audit Log:** Filterable (`category`, `outcome`, `actor`, text search) paginated table displaying the hash-chained installation `audit_events` ledger (including any `refused_sealed_mutation` or `refused_cross_case_id` security events).

---

## 4. Accessibility, responsiveness, and test criteria

* **Breakpoints:** Full verified layout at **900 px**, **1024 px**, and **1440 px** (`pageOverflow === 0`, `mainOverflow === 0`). Long SHA-256 digests and paths wrap with `break-all` or live inside `overflow-x-auto` containers.
* **Keyboard accessibility:** Full `Tab`/`Shift+Tab` focus ring across tabs, modals, tables, and `InlineConfirm` controls; arrow keys or standard tab-stop navigation on `SectionNav`.
* **Vitest + `axe-core` tests:**
  * Initial empty/uninitialized states, disabled buttons until authorization checked, sealed-case UI lock state, tamper-mismatch high-contrast alert banner.
  * Immutable note revision display (both superseded text and new revision visible).
  * Hostile strings (`<script>alert(1)</script>`, `[x](javascript:...)`) inside case title, note body, evidence title, and audit details rendered strictly as text.
  * Zero banned certainty words (`"proven safe"`, `"100% certain"`, `"cleaned"`) and zero `axe-core` accessibility violations.

