# Skill usage: design, quality and workflow (Phase 0)

The repository was empty at the start, so there was **no existing code to audit or optimize**.
No optimization was performed; `OPTIMIZATION_AUDIT.md` and `OPTIMIZATION_REPORT.md` were therefore
not created. What was done instead: the design system and engineering workflow were established
with the skills below, and a measured baseline was recorded
([PERFORMANCE_BASELINE.md](PERFORMANCE_BASELINE.md)) so that later optimization can be compared
against real numbers.

Only skills that were genuinely opened and applied are in the table. How much of each file was
read, and the skills that were not used, are in [SKILL_USAGE.md](SKILL_USAGE.md).

| Skill | Why selected | Instructions inspected | How applied | Evidence |
|---|---|---|---|---|
| `ui-ux-designer` | Establish a professional, accessible, token-based interface | `SKILL.md`, whole file | Token architecture, accessibility-first states, documented design decisions | [DESIGN_SYSTEM.md](DESIGN_SYSTEM.md); `apps/dashboard/src/index.css`; 106 dashboard tests incl. axe-core on both screens |
| `ui-ux-pro-max` | Design-system search and UX/accessibility rules for a dark data-dense product | `SKILL.md` lines 1 to 120; ran `search.py` (`--design-system`, `--domain ux`, `--domain color`, `--stack html-tailwind`) | Focus-visible ring, `role="alert"`/`status`, empty states with actions, reduced motion, SVG icons (Lucide), active-nav state, hash deep links. Contrast of every text token computed (lowest 5.35:1). The suggested green-on-black palette was rejected in favour of the brief's graphite and cyan | DESIGN_SYSTEM.md "Colour tokens and measured contrast" and "Decisions" |
| `tailwind-patterns` | Tailwind CSS 4 conventions | `SKILL.md`, whole file | CSS-first `@theme`, semantic tokens, container queries, no JS config, no `@apply` | `index.css`, `DefinitionList.tsx` (`@sm:` classes) |
| `tailwind-design-system` | Token hierarchy and component structure | `SKILL.md`; `implementation-playbook.md` lines 1 to 160 | Brand → semantic → component token idea; default palette removed so only tokens exist. Tailwind 3 style config and `tailwindcss-animate` from its example were not used | `index.css` (`--color-*: initial`); `src/components/ui/` |
| `angular-ui-patterns` | Framework-independent loading, error and empty-state rules (no Angular introduced) | `SKILL.md` lines 1 to 140 | Skeleton only when there is no data; errors always surfaced; distinct `isLoading` / `isRefreshing` | `lib/useRequest.ts` and its tests; `StateView.tsx`; `StaleNotice` |
| `karpathy-guidelines` | Keep the change small and verifiable | `SKILL.md`, whole file | Phase 0 scope only; deleted code that my own changes made unnecessary; success criteria stated as tests | `git diff befe252..HEAD` contains no Phase 1+ modules |
| `test-driven-development` | Feature and bug-fix discipline | `SKILL.md`, whole file | Red-green for logic and UI; mutation checks for security-critical tests; exemptions listed in SKILL_USAGE.md | Test-first record in SKILL_USAGE.md |
| `requesting-code-review` | Independent review before declaring the phase done | `SKILL.md`, `code-reviewer.md` | Fresh read-only reviewer with requirements, git range, rulings and review focus | Review verdict "with fixes"; 6 Important findings, all fixed test-first (details in SKILL_USAGE.md) |
| `receiving-code-review` | Evaluate feedback technically, not performatively | `SKILL.md`, whole file | Reproduced the top findings before changing code; fixed one at a time, test-first; recorded what was not acted on and why | Reproduction output (OSError, missing headers, lenient Host); SKILL_USAGE.md "Deviations" |
| `verification-before-completion` | No claims without fresh evidence | `SKILL.md`, whole file | Re-ran every suite on the final tree; re-ran a gate when edits and test runs had been mixed in one step | Final report |
| `brainstorming`, `writing-plans`, `executing-plans` | Planning and execution workflow | `SKILL.md` of each, whole file | Classification, plan with review focus, inline execution; deviations recorded in SKILL_USAGE.md | [PHASE0_PLAN.md](PHASE0_PLAN.md) |
| `finishing-a-development-branch` | Decide how to integrate | `SKILL.md`, whole file | Verified the suites, left merge, push and PR to the user | Final report |
| `using-superpowers` | Skill discipline | `SKILL.md`, whole file | Skills read before work started | SKILL_USAGE.md |

## Requested skills that were not used

`systematic-debugging`, `subagent-driven-development`, `dispatching-parallel-agents`,
`find-skills`, `agent-memory-mcp`, `diagnosing-superpowers`, `3d-web-experience`: not opened. The
reasons are in [SKILL_USAGE.md](SKILL_USAGE.md). No 3D dependency was introduced.
