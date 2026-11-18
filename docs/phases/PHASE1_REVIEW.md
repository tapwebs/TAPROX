# Phase 1: independent review and what was done about it

A fresh, read-only reviewer examined the whole Phase 1 diff (`a8a833b..HEAD`, 10 commits at the time,
111 files) against the requirements, my known limitations and a list of failure modes. It ran the
backend and dashboard suites itself (570 and 337 passed) and changed nothing. Verdict: **approve with
fixes**. Every finding was checked against the code before it was changed, and each fix was written
test-first (the new test was seen failing first). Fixes are in commit `ea36176`.

## Fixed

| # | Finding | Fix | Evidence |
|---|---|---|---|
| C1 | **Critical.** A neighbor-cache entry the OS marked `stale` was stamped with the scan time, so a device that had left days ago could show as green **Active** after any passive scan (the "never claim presence from a cache" mirror of the "never claim offline" rule) | A stale sighting is history only: it never moves `last_seen`, and a device known only from such entries is capped at "not seen recently". The API state and the SQL filter apply the same rule | 7 repository tests, a service test through a real passive scan, an API test; the default-order query-plan test still passes |
| I1 | The Linux probe was not tied to the chosen interface (a source-address bind does not pick the egress interface) and accepted any `/proc/net/arp` row, so a host could be credited to the wrong interface | The datagram is bound to the interface where allowed, and only rows learned on that device count as an answer. The service passes the interface name | Linux tests with a kernel stub that resolves on another device; a test that every probe carries the interface |
| I2 | An IPv6 sighting overwrote the confidence/source/interface behind the IPv4 address, so a host that had just answered ARP could read "IPv6 neighbor table, stale" | Those fields now always belong to one sighting | Rewritten repository test (the old one had encoded the bug) |
| I3 | "It did not answer a probe" was shown for every `probable` device, including after a passive scan that probes nothing | Text states only what the OS knows, and says a remembered address is not evidence of presence | Unit tests over every source |
| I4 | The "I am authorised" box survived a change of interface and a finished scan | Consent resets on interface change, mode change and after a scan starts | Two page tests |
| I5 | The details panel showed the previous device's data and history page when another was chosen, and "not found" together with the old data | The panel is keyed by device | Three page tests |
| I6 | "Passive sends nothing" was untrue with name lookup on (the default); the Active consent omitted the IPv6 ping and the Linux UDP datagram | Descriptions and consent now name everything that is sent | Page tests; DISCOVERY.md corrected |
| I7 | SECURITY_MODEL cited a test that refuses the upgrade when the backup fails; none existed | Test added (and one that a current database never needs a backup) | `test_migration_0002.py` |
| I8 | A passive scan called cache entries "devices found" | Passive results say "listed in the operating system's neighbor table" and that this is not a check of presence | Page tests |
| M1 | A scan thread that could not start left the job slot taken forever | Slot released, the row marked failed, 503 `scan_not_started` | Service test |
| M2 | A name lookup cut off by its time limit looked the same as "no name" | A warning is added | Two service tests |
| M3 | The size preview counted this computer's own address, which is never probed | It is subtracted | Page test |
| M7 | A literal tab in API.md, a stale "130 passed", an overclaim that the vendor caveat is next to every vendor, an inaccurate backend docstring | Corrected | Doc diff |

## Not fixed, and why

| # | Finding | Status |
|---|---|---|
| M4 | SQLite DDL in migration 0002 may not be atomic on Python 3.12, and no test covers a failed migration | **Open.** A backup is taken first so no data is at risk, but a half-applied migration would need the backup restored by hand. Worth fixing before a release that ships real user data |
| M5 | An address change during a scan is not warned (the source address is fixed at the start) | **Open.** Interface changes are detected lazily; documented |
| M6 | A router or extender that answers ARP for many addresses (proxy ARP) makes one device with many addresses and can crowd out its own history | **Open.** The data is honest; the presentation is poor |
| - | `ensure_scannable` checks the destination range only, not that it is on the interface's network (the service guarantees that) | Accepted: it is a second net, described as a range check |
| - | A `WinDLL` is loaded on every probe; an unused `_Row` ctypes class is used only by a size test | Accepted for Phase 1 (correct, slightly wasteful) |

## What the reviewer checked and found sound

The scan boundary on Windows (targets derive only from the interface's own network, are checked twice,
and cannot reach a public address; /31 and /32 are refused; the source address is always one inside
the target); the single job slot and shutdown ordering; cancellation during reverse DNS; duplicate
MACs within one scan and one MAC on two interfaces; repository identity rules and LIKE escaping; the
ctypes struct offsets and buffer lifetimes; and the dashboard's polling and tracking logic.
