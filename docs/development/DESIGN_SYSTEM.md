# TAPNETTRACK design system

Direction: a dark, dense investigation workstation. Deep graphite surfaces, one restrained cyan
accent, semantic status colours that are always paired with an icon and text. Technical data is
shown compactly (14 px base text, 5 px corners) but with enough contrast and spacing to stay
readable during long sessions.

Tokens live in `apps/dashboard/src/index.css` (`@theme`, Tailwind CSS 4, CSS-first). The default
Tailwind palette is **removed** (`--color-*: initial`), so screens can only use the tokens below.

## Colour tokens and measured contrast

Ratios were computed with the WCAG formula (not eyeballed). Minimum is across the four surfaces.

| Token | Value | Use | Contrast (min to max) |
|---|---|---|---|
| `canvas` | `#0b0e13` | App background | n/a |
| `inset` | `#0e1218` | Recessed rows inside a panel | n/a |
| `surface` | `#11151c` | Panels, sidebar, header | n/a |
| `raised` | `#171c25` | Hover, active nav, secondary buttons | n/a |
| `line` | `#232a36` | Decorative dividers | decorative only |
| `line-strong` | `#5d6879` | Outlines of controls | 3.03 to 3.43 (needs 3:1) |
| `fg` | `#e6eaf0` | Primary text | 14.15 to 16.01 |
| `fg-muted` | `#a3adbc` | Secondary text, labels | 7.53 to 8.52 |
| `fg-subtle` | `#8591a3` | Tertiary text, planned items | 5.35 to 6.05 |
| `accent` | `#5cc8e0` | Focus ring, selection | 8.78 to 9.93 |
| `accent-strong` / `on-accent` | `#2bb5d3` / `#04222b` | Primary button | 6.82 |
| `link` | `#6ea8ff` | Links, info | 7.08 to 8.02 |
| `success` | `#3fd09b` | Healthy, installed | 8.71 to 9.86 |
| `warning` | `#ebb04a` | Incomplete, elevated | 8.82 to 9.98 |
| `critical` | `#f27474` | Unhealthy, errors | 6.12 to 6.93 |
| `neutral` | `#9aa5b5` | Neutral status | 6.85 to 7.75 |

## Typography and density

* **Inter Variable**, self-hosted through `@fontsource-variable/inter` (the app is offline-first and
  the production CSP allows only `'self'` fonts). Monospace stack for addresses, versions and
  paths: `ui-monospace, Cascadia Mono, SF Mono, Consolas, …`.
* Body 14 px / 1.45, labels 12 px, page title 16 px semibold. Radii 2/3/5/8 px.
* Spacing uses the default Tailwind scale; panels use `p-4`, rows `gap-y-2`.

## Components (`src/components`)

| Component | Purpose | Notes |
|---|---|---|
| `Panel` | Labelled region with title, description, actions | `<section aria-labelledby>`; heading is the accessible name |
| `DefinitionList` | Dense label/value rows | `<dl>`; container query (`@sm`) switches between stacked and two columns |
| `StatusBadge` | Status | Icon + text, never colour alone |
| `Button` | Actions | `type="button"` default; `loading` disables, sets `aria-busy`, keeps its name |
| `StateView` | Every non-happy state | Variants `loading`, `empty`, `error`, `permission`, `disconnected` |
| `Skeleton` | Placeholder for content of known shape | `aria-hidden`, motion-reduced |
| `RequestError` | Maps a failed request to a state | 401 → permission (credentials rejected); 403 → "refused this request" with the code, because the Host/Origin guard answers 403 and the credentials are not the problem; network → disconnected with retry; else error with retry |
| `StaleNotice` | A refresh failed but older data is still shown | Says why, offers retry, and labels the data on screen with the time it was fetched |
| `BackendGate` | Waits for the backend connection | starting / failed. No retry button on failure: the shell never restarts the backend, so the text says to reopen the app |
| `Table`, `Th`, `SortTh`, `RowTh`, `Td` | Data tables | A real `<table>` in a focusable scroll region (so a wide table can be scrolled with the keyboard) that is also the positioning context (`relative`), because visually hidden header text otherwise escapes and widens the page. `SortTh` is a real button inside the header and exposes `aria-sort`. `RowTh` makes the first cell a row header so screen readers announce which row a cell belongs to |
| `TextField`, `SelectField`, `CheckboxField`, `RadioField` | Form controls | Visible label tied to the control; hint and error are linked with `aria-describedby`; a checkbox/radio description sits outside its `<label>` so the control's name stays short |
| `ProgressBar` | Scan progress | `role="progressbar"` with `aria-valuetext`; with an unknown total it is indeterminate and shows no invented percentage |
| `Pagination` | Server-side paging | Labelled `nav`; "Showing 51-100 of 123" is `aria-live="polite"`; Previous/Next disable at the ends |
| `DetailPanel` | Details beside a list | Non-modal `<aside>` (the list stays usable); focus moves to its heading on open; Escape or Close dismisses it; Escape typed in a text field or select is left to that control |
| `Sidebar`, `Header` | Shell | see below |

State behaviour follows one rule: **a skeleton is shown only when there is nothing to show yet**.
A reload keeps the current data on screen and shows activity on the button (`useRequest`
distinguishes `isLoading` from `isRefreshing`). Errors always say what happened, including when a
refresh fails while old data is on screen (`StaleNotice`, with the data labelled by its fetch
time). Errors offer a way out only if one exists: permission errors and a dead backend do not
offer a retry that could not succeed. The Overview's backend panel shows "As of <time>" and has a
Refresh button because it is a snapshot. The privileges row says "Not elevated" rather than
"Standard user", since an administrator running a non-elevated process is also not elevated.

The `empty` variant is used by Phase 1: an empty inventory (`No devices yet`, with a link to run a
scan) is deliberately different from a search that matches nothing (`No devices match`, with a
*Clear filters* action), so a user is never told the inventory is empty when a filter is the reason.

### Patterns introduced in Phase 1

* **Quiet polling.** `useRequest` has `reloadQuietly()` for automatic refreshes: data stays on
  screen and no spinner appears (`isRefreshing` stays false), while `isPending` lets a poll skip a
  tick instead of overlapping a request. `usePolling` pauses while the window is hidden and
  refreshes at once when it becomes visible again.
* **Observed and inferred are separate panels** in the device details, each with a one-line
  statement of what it is. The explanation of a *confirmed* sighting depends on how the device was
  seen (it replied to a probe, or it is this computer's own interface).
* **Recency, never liveness.** Device state reads `Active`, `Not seen recently`, `Previously
  observed`. The word offline is not used anywhere, and a test fails if it appears.
* **Consent before action.** An active scan's *Start* stays disabled until the authorisation box
  is ticked, and the form states how many addresses it will probe.
* **Honest labels over tidy ones.** An address Windows keeps on a disconnected adapter is shown
  as `not in use`; a randomised MAC reads `Randomised address`, not `Unknown vendor`.
* **State in the URL.** The open device and the scan filter live in the hash
  (`#/devices/12?scan=<id>`), so links work and Back behaves; table filters stay in the page.

## Navigation

All 15 modules from the product architecture are listed in order. Only screens that exist are
links (Overview, Network Interfaces, Device Discovery, Device Inventory, Settings). The other 10 are `aria-disabled` entries with a "Phase N" tag and are
not keyboard stops, so nothing looks clickable that does nothing. Current page: `aria-current="page"`
plus an accent edge.

## Accessibility

* Skip link; landmarks (`nav`, `main`, `header`, `aside`); one `h1` per page which receives focus
  after navigation so assistive technology announces the change.
* One global `:focus-visible` ring (2 px accent, 9+:1 contrast against the canvas).
* Errors use `role="alert"`, loading uses `role="status"` with an accessible name, and the
  "last checked" line is `aria-live="polite"`.
* `prefers-reduced-motion` disables animations globally.
* Icon-only entries (narrow sidebar) keep their text for screen readers (`sr-only`).
* Automated: axe-core runs on the rendered Overview, Settings and all three Phase 1 screens
  (including the open details panel and the running-scan state) with zero violations (colour
  contrast excluded because jsdom has no layout; covered by the table above). It found one real
  defect during Phase 1: two sections labelled the same as the tables inside them created
  duplicate landmarks.
* Selection is announced (ria-pressed on interface buttons), tables name their sorted column
  (ria-sort), and every control is reachable and operable by keyboard.

## Responsive behaviour

Measured with real viewport emulation (Chrome DevTools protocol), not just window resizing:
no horizontal overflow at 375, 768, 1024 and 1440 px (document width equals viewport width and no
element extends past the right edge). Below 1024 px the sidebar collapses to a 3.5 rem icon rail;
at 1024 px and above it is 18.5 rem with labels and phase tags. The desktop window has a 900×600
minimum.

Phase 1 was checked the same way against the **real backend, adapters and LAN** at all four widths
(12 page/width combinations, no console errors). That found a defect jsdom could not: a table's
visually hidden header text escaped its scroll region and made the Interfaces page scroll sideways
at 1024, 768 and 375 px (fixed, with a regression test on the structure that prevents it). Wide
tables scroll inside their own labelled region on narrow screens; the page itself never does.

## Decisions

* **Palette:** the design-guideline search suggested a "matrix green on black" style for
  cybersecurity products. The product brief asks for graphite and restrained cyan/blue, which was
  followed. Green is reserved for "success".
* **Icons:** Lucide (SVG). No emoji, no icon fonts.
* **No gradients, glass effects, decorative charts or 3D.** There is no data to chart yet, and a
  3D visualization is not justified at this stage, so no 3D library was added.
* **Dark only.** A light theme is not designed; `color-scheme: dark` is declared.

## Not covered yet

Table virtualization (server-side paging keeps the DOM at 50 rows, so none was needed), resizable
panels, topology graph, charts, modal dialogs (the details panel is non-modal on purpose); real
screen-reader testing; high-contrast mode; localization.
