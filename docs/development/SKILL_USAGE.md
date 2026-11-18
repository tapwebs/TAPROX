# Skill usage evidence (Phases 0 and 1)

Skills live in `C:\Users\USER\.kiro\skills\` (30 directories). This file lists what was **actually
opened and followed**, how much of each file was read, where the instructions shaped the work,
and where the work **deviated** from a skill. Nothing here is claimed from memory of a skill's
title.

## Skills read and applied

| Skill | What was read | Applied to | Evidence |
|---|---|---|---|
| `using-superpowers` | `SKILL.md`, whole file | Process: check skills before acting; user instructions outrank skills | Skills were read before any code was written; deviations from other skills are recorded below under the user's explicit instructions |
| `brainstorming` | `SKILL.md`, whole file | Classified the work as **architectural** (new project, no existing flow). Design questions that the brief already answered were not re-asked | `docs/development/PHASE0_PLAN.md` Â§1 to Â§5 (assessment, compatibility decisions, desktop/backend protocol, capture boundary) |
| `writing-plans` | `SKILL.md`, whole file | Plan with file map, ordered tasks each ending in a runnable verification, and a "Review focus" list of failure modes the tests do not cover directly | `PHASE0_PLAN.md` Â§6 to Â§8; the review-focus items were checked by the independent review |
| `executing-plans` | `SKILL.md`, whole file | Inline execution, one task at a time; whole-branch review by a fresh reviewer; rulings recorded; fix pass test-first | Commits `d6aa04f`, `1891f0d`, `f5fc856`, `3329437`, then the review-fix commit; rulings listed below |
| `test-driven-development` | `SKILL.md`, whole file (not `writing-good-tests.md`) | Red-green for backend, dashboard logic and UI, and the Rust supervisor. Each RED run was read before implementing. Mutation checks were used to prove security tests can fail | See "Test-first record" below |
| `karpathy-guidelines` | `SKILL.md`, whole file | Surgical scope: only Phase 0, no later modules; no unrequested abstractions; removed code I had made unnecessary (the retry button, `ALLOWED_HOSTS`, the `Exception` handler) | `git diff` shows no Phase 1+ code: `backend/app/services/` contains only `capture/`, and `native/`, `integrations/`, `configs/` and the other later-phase directories were not created |
| `verification-before-completion` | `SKILL.md`, whole file | No completion claim without a fresh run. Cases where a batch of edits and a test run were mixed in one tool call were re-run on the final state | Final report numbers come from runs after the last edit |
| `requesting-code-review` | `SKILL.md` and `code-reviewer.md` | Dispatched a fresh, read-only reviewer (`semantic_reviewer`) with requirements, git range, known limitations, rulings and the plan's review focus | Verdict "with fixes": 0 Critical, 6 Important, 18 Minor. The 6 Important and 17 of the Minor items were fixed; the last Minor item (capture-probe timing) is documented in the baseline rather than changed |
| `receiving-code-review` | `SKILL.md`, whole file | Each finding was reproduced or checked against the code before changing anything; one finding exposed a bug in my own test helper; nothing was implemented on trust | `backend/tests/test_security.py` (WebSocket positive control), reproduction script outputs in the session |
| `finishing-a-development-branch` | `SKILL.md`, whole file | Full suites run on the final tree; the integration decision (merge, PR, keep) is left to the user; no push, no merge | See the final report |
| `ui-ux-designer` | `SKILL.md`, whole file (not `resources/implementation-playbook.md`) | Token-based design system, accessibility first, state design (loading, empty, error), documented decisions | `docs/development/DESIGN_SYSTEM.md`, `apps/dashboard/src/index.css` |
| `ui-ux-pro-max` | `SKILL.md` first 120 lines; **ran** `scripts/search.py` four times: `--design-system`, `--domain ux`, `--domain color`, `--stack html-tailwind` | Accessibility and interaction rules (focus-visible, `role="alert"`, empty-state actions, reduced motion, SVG icons, active-nav state, deep links by hash); contrast verified numerically. Its suggested "matrix green on black" palette was **not** used: the product brief asks for graphite and cyan/blue | `DESIGN_SYSTEM.md` "Decisions"; the contrast table was computed |
| `tailwind-patterns` | `SKILL.md`, whole file | Tailwind 4 CSS-first `@theme`, semantic tokens, container queries (`@sm`), no `tailwind.config.js`, no `@apply` | `apps/dashboard/src/index.css`, `DefinitionList.tsx` |
| `tailwind-design-system` | `SKILL.md`; `resources/implementation-playbook.md` **lines 1 to 160 only** | Token hierarchy and the component architecture idea. The playbook's shadcn-style `hsl(var(--x))` and `tailwindcss-animate` examples were **not** followed (Tailwind 3 style; no new dependency) | `index.css` removes the default palette (`--color-*: initial`) |
| `angular-ui-patterns` | `SKILL.md` **lines 1 to 140 only** | Only the framework-independent rules: show loading only when there is no data, always surface errors, empty states, skeleton vs spinner. No Angular code or syntax | `lib/useRequest.ts` (`isLoading` vs `isRefreshing`), `components/ui/StateView.tsx` |

## Skills not used, and why

| Skill | Reason |
|---|---|
| `systematic-debugging` | Not opened. Failures during the work (the FastAPI route inventory, the Starlette `httpx` deprecation, WebSocket test defects) were diagnosed ad hoc by reproducing them; I do not claim the skill's workflow |
| `subagent-driven-development`, `dispatching-parallel-agents` | Not opened. Tasks depended on each other's interfaces (contract, protocol, client), so there was no genuinely independent parallel work. One fresh reviewer was used at the end instead |
| `using-git-worktrees` | Not opened. The repository was empty, so a local `git init`, an empty baseline commit on `main` and a `phase-0/foundation` branch served as the isolation |
| `find-skills`, `agent-memory-mcp`, `diagnosing-superpowers` | Not opened; nothing in the work called for them |
| `3d-web-experience`, `threejs-skills` | Not opened. No genuine 3D visualization is justified in Phase 0, and no 3D dependency was added |
| `writing-skills`, `archify`, `graphify`, `seo-*` | Unrelated to this work |

## Deviations from skill workflows (recorded as rulings)

* **Brainstorming gate.** The architectural path asks for interactive questions, per-section design
  approval and an approved written spec before planning. The user supplied the full architecture
  and instructed "inspect, plan, then implement Phase 0", so the master document was treated as
  the approved spec and no separate approval round was held. *Cost if wrong:* the user might have
  wanted to review the plan first; the plan is committed and the work is on a branch.
* **Plan format.** The plan is saved in `docs/development/` (the user's documentation layout), not
  `docs/superpowers/plans/`, and it is condensed: it has no `Spec:` header line, no
  "Global Constraints" block and no per-step checkboxes.
* **Ledger.** The `executing-plans` progress ledger and its helper scripts were not used (they are
  shell scripts and the work was tracked by commits). *Cost if wrong:* none for this session.
* **TDD exemptions.** No test-first for: dependency manifests and tool configuration; the Tauri
  wiring in `lib.rs`/`main.rs`, capabilities and CSP (verified by launching the real app and by
  `scripts/smoke-desktop.ps1`); CSS tokens (verified visually, by measured contrast and by axe);
  `scripts/dev.mjs` and `scripts/compare-files.mjs` (verified by running them);
  `SO_EXCLUSIVEADDRUSE` (reviewed only).
* **Review-fix pass.** The skill says to fix Critical and Important findings in one pass, each
  test-first. Fixed that way: all six Important findings (unexecutable tool binary, hardening and
  CORS headers on error and refusal responses, non-UTF-8 backend output, the UI claiming a dead
  backend was connected, silent failed refreshes, `find_library` running compilers) and these
  Minor ones: strict Host matching, WebSocket tests with a positive control, the foreign-keys
  test, the `/health` 503 shape guard, 403 wording, "Not elevated", token redaction in `Debug`,
  the token-write race, the PID-based timeout check, `chmod` only on directories we create,
  monotonic uptime, the dev-token bundle leak, and the doc inaccuracies (`details`, missing file,
  plan data directory, bundle sizes, reproducible evidence via `scripts/smoke-desktop.ps1`).
  **Not acted on:** parallelising or caching the capture probes (no measured problem; recorded in
  the baseline), `cargo audit` (not installed), Job Object or `PDEATHSIG` hardening (the
  stdin-EOF design meets the requirement), and a `restart_backend` command (a Phase 2 decision;
  the UI no longer offers a retry that cannot work). The mutation checks and canary builds remain
  ad hoc, not committed.

## Test-first record

| Area | RED observed | Notes |
|---|---|---|
| `Settings`, security layer, errors | `ModuleNotFoundError` for each module, then the 27-test security suite | Mutation check: disabling origin / token / host / no-store each fails 1 to 6 tests |
| Database, health, capture prerequisites, runtime, contract | Collection errors (missing modules), then assertion failures | Real child-process tests for the runtime protocol |
| Review fixes (backend) | 9 assertion failures + a collection error for `check_libpcap` | Includes a defect in my own WebSocket test helper, found because the positive control failed |
| Dashboard | Unresolved imports, then assertion failures (16 for the review pass) | Canary build: old `main.tsx` leaks the token (1 hit), new one does not (0) |
| Rust supervisor | 10 unit failures on `unimplemented!()` stubs; a compile error for `shutdown_within` in the review pass | Mutation check: reverting lossy decoding or the `Debug` redaction fails exactly the intended test |

# Phase 1

Same rule as above: only what was actually opened and followed is claimed. Phase 1 ran in the same
working session as Phase 0, so the skills listed under Phase 0 were read **before** Phase 1 started;
they were not re-opened. Only `systematic-debugging` was read newly for Phase 1.

## Read for Phase 1

| Skill | What was read | How it shaped the work |
|---|---|---|
| `systematic-debugging` | `SKILL.md`, whole file, at the start of Phase 1 | Root cause before fix, one hypothesis at a time, measure instead of guessing. See "Debugging record" |

## Practices from Phase 0 skills that were applied again (skills not re-read)

| Skill (read in Phase 0) | Phase 1 use | Evidence |
|---|---|---|
| `test-driven-development` | Every behaviour change had a test seen failing first, including all 12 review fixes. Where an old test had encoded a bug it was rewritten and the reason recorded | `PHASE1_REVIEW.md`; the red runs are in the session history, not committed |
| `requesting-code-review` | A fresh read-only reviewer was given the requirements, git range, known limitations and the failure modes to probe. (The first attempt was cancelled before it started and was repeated.) | `PHASE1_REVIEW.md`; the full review document is outside the repo at `C:\Users\USER\tapnettrack-reviews\` |
| `receiving-code-review` | Each finding was checked against the code before changing it (C1 was confirmed by reading `service.py`, `devices.py` and the badge). Findings that were accurate were fixed; three were left open and listed, not argued away | `PHASE1_REVIEW.md` "Not fixed" |
| `verification-before-completion` | No completion claim without a fresh run. Several times a batch that mixed edits with a test run showed results for the old code; each was re-run on the final state. Counts below come from runs after the last edit | See the final report |
| `karpathy-guidelines` | Scope held to Phase 1: no capture, no Phase 2+ module, no new dependency | `git diff a8a833b..HEAD --stat` |

## Debugging record (`systematic-debugging`)

* **Scan progress froze at "5 of 253" in the browser.** Isolated by layer: the backend polled over
  plain HTTP advanced steadily (so not the scan), then the page's own requests were counted (they
  stopped), then `document.hidden` was read (it had flipped to true in headless Edge). Cause: the
  test browser reported itself hidden, and the page correctly pauses polling then. The real defect it
  exposed was that the page did not refresh when the window became visible again. A test was
  written, then the fix.
* **The Interfaces page scrolled sideways.** Measured, then found by hiding each element in turn
  and watching the document width; the culprit was an `sr-only` header cell escaping its scroll
  region. An earlier guess (the table's minimum width) was disproved by the measurement.
* **A disconnected Wi-Fi adapter showed an IPv4 address.** Windows was asked directly before
  touching the code: it reports a deprecated leftover DHCP lease, so the provider was right and the
  UI label was wrong.
* **Harness stalls** (not product bugs) were bounded with per-call timeouts, and a 25-navigation
  stress run showed no hang before they were put down to the harness.

## Not used in Phase 1, and why

| Skill | Reason |
|---|---|
| `brainstorming`, `writing-plans`, `executing-plans` | Not re-opened. The user supplied a full specification; the plan is `PHASE1_PLAN.md`, executed inline |
| `finishing-a-development-branch` | Not re-opened. The branch is left for the owner to merge locally or keep; nothing was pushed (project rule) |
| `using-git-worktrees` | Not used; a local branch from the Phase 0 commit served as isolation |
| `subagent-driven-development`, `dispatching-parallel-agents` | Not used; the work was sequential and interdependent. One reviewer sub-agent was used at the end |
| `ui-ux-pro-max`, `ui-ux-designer`, `tailwind-*`, `angular-ui-patterns` | Not re-run. Phase 1 reuses the Phase 0 design system and tokens; the design search script was not run again |
| `3d-web-experience`, `threejs-skills` | No 3D visualisation in Phase 1 |

---

# Phase 3

Skills that exist in the Kiro skills folder and were **read** before work started: `karpathy-guidelines`,
`test-driven-development`, `verification-before-completion`, `ui-ux-designer`. No installed skill covers
Python, FastAPI, networking or security; none is claimed. `ui-ux-pro-max` and its design-search script were not run: Phase 3 reuses the Phase 0
tokens and primitives and adds no new visual language.

## How each was applied

* **karpathy-guidelines (simplicity, surgical changes).** One tshark process feeds both the list and the
  flows (no second dissector); the engine runs inline instead of adding queues; no new dependency; the
  chart is plain SVG. The Phase 2 files changed only where a confirmed defect required it.
* **test-driven-development.** Each module (classification, engine, store, aggregates, device linking,
  API) got its tests first and was seen failing (missing module or missing parameter) before the code.
  Two exceptions are stated plainly: the aggregate tests ran after the module existed because tool calls
  in that batch executed out of order, and the dashboard page tests were written together with the pages.
  Three behaviours were found by running real tools and then got a failing test first: the
  "still waiting for the capture driver" notice, the hung-listing message and its 30 s back-off, and the
  O(n) eviction (a regression test that took 7.2 s before the fix).
* **verification-before-completion.** Counts in the reports come from runs in the same session. The flow
  numbers were checked against an independent source (tshark's own per-conversation view of the same
  file), not against the code under test. A criterion that could not be verified is reported as such.
* **ui-ux-designer.** Reused the Phase 0 design system and primitives; honest empty, loading, error and
  "unknown" states; status shown by text and icon, never colour alone; the chart has a text alternative
  and a data table; a stable landmark structure was checked with axe (it caught a duplicate landmark name).

## Bugs found by measurement or by real tools

* **`dumpcap -D` hung** on this machine. Cause: Npcap was installed in Administrator-only mode, so Windows
  waits for a UAC prompt each time. Diagnosed from the registry value, a `consent.exe` process that
  appeared with each attempt, and `dumpcap --version` working while `-D` did not. Added a prerequisite
  warning, a clear message, a waiting notice, and a back-off so prompts do not stack.
* **"Backend not reachable" shown for a slow listing.** The listing timeout (30 s) was longer than the
  dashboard's request timeout (15 s), so the explanation never arrived. Timeout is now 12 s.
* **Eviction was O(n)** when the flow table was full of active flows (7.2 s for 40,000 new flows); now
  constant time.
* **The packet list stopped at 100,000 packets in a live capture** because tshark was told to stop there;
  flows would have stopped too. tshark now decodes up to 2,000,000 packets and the list keeps the first
  100,000.

## Phase 4, M5 to M11

Skills actually read in this session before the work: `test-driven-development`, `verification-before-completion`,
`systematic-debugging`, `finishing-a-development-branch`, `requesting-code-review` (read during M1 to M4). No further skill
was read for M5 to M11. The `ui-ux-pro-max` search script was not run again: the screens follow
`PHASE4_UI_UX_SPECIFICATION.md`, which records that earlier search. Tests for the new code were written after the code in this
pass, not before; the failures found (a protocol-name case bug, grouping of remote hosts, accessibility heading order,
duplicate keys in the merged alert list) were fixed from the failing output.

## Phase 4 final gap closure

Read in this pass: `test-driven-development` (applied: failing tests first for the rules, the grouping and the Alerts and Topology
controls; not possible for the security tests, which describe existing behaviour), `verification-before-completion` (applied:
one fresh full regression pass before the report, results copied from the command output) and `ui-ux-designer` (applied: the
checklist for states, keyboard use, no colour-only meaning and responsive checks was followed; it gave no new rule). The
`ui-ux-pro-max` rule's search script was not run again. Earlier skills are not re-read.

## Phase 4 last four items

Read: `systematic-debugging` (applied to the queue overflow: reproduced it with a test first, traced the 20,000-event burst back to
`after_finish` offering it in one call, changed one place, re-ran the reproduction), `test-driven-development` and
`verification-before-completion` (read earlier in the session and applied again: tests before code for all four items, one full
regression pass with its output read at the end). `ui-ux-designer` was not read again; the UI additions follow the conventions already
in the screens. The `ui-ux-pro-max` search script was not run.
