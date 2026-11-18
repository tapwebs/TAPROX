# TAPNETTRACK Phase 1 Implementation Plan

> Written with the `writing-plans` skill, executed inline (`executing-plans`), test-first
> (`test-driven-development`), debugged with `systematic-debugging`. The user's Phase 1 assignment is
> the spec. All work is local; no remote exists or will be configured.

**Goal:** A working Network Interface Manager, an authorized-LAN Device Discovery engine, and a
persistent Device Inventory, each with real backend data behind real screens.

**Baseline:** branch `phase-1/network-discovery` created from `a8a833b` (Phase 0). Windows is the
primary platform; Linux providers exist and are tested with fixtures and under WSL.

## 1. What already exists and will be reused (not duplicated)

| Existing | Reuse |
|---|---|
| `create_app(settings, engine)`, lifespan, `app.state` | Add `interfaces` and `discovery` services; new optional keyword arguments only, so Phase 0 callers and tests are unchanged |
| `api/v1` router with `require_token`, error envelope, Host/Origin guard | New routers are included in it; the "every route needs a token" test covers them automatically |
| Alembic + `init_database` | Migration `0002`; **backup-before-migrate is added now** because Phase 0's docs promised it with the first schema change |
| `services/capture/prerequisites.py` approach (absolute paths, no shell, timeouts) | Same subprocess rules for the Linux provider and the IPv6 nudge |
| `useRequest`, `RequestError`/`StaleNotice`, `StateView`, `Panel`, `DefinitionList`, `StatusBadge`, `Button` | Reused; new form and table primitives are added only where none exists |
| Contract workflow (`contracts:export` / `generate` / `check`) | Unchanged |

## 2. Design decisions

### Interfaces
* **Windows provider: `GetAdaptersAddresses` through `ctypes`** (in-process, no dependency, no
  PowerShell). Gives GUID, friendly name, description, MAC, `IfType`, operational status, unicast
  addresses with prefix length and DAD state, gateways, DNS, MTU, link speed. Hardware class
  (physical / USB / virtual) comes from the adapter's `PnpInstanceID` in the registry (read-only).
* **Linux provider:** `ip -j addr` / `ip -j route`, `/sys/class/net`, `/etc/resolv.conf`.
* Platform-neutral `RawInterface` dataclass is produced by providers; one `build_interface` function
  derives the API model so classification rules exist once.
* **Two separate questions, never merged:** `connection` (connected / disconnected / unknown) and
  `support` (supported / unsupported + reason). A disconnected Ethernet port is supported; a
  loopback or tunnel is unsupported. Capture support is reported as `unverified` (Phase 2 verifies
  it) or `unsupported`; it is never assumed.
* **Change detection without a background task:** a thread-safe `InterfaceManager` refreshes on
  demand (2 s cache) and diffs consecutive snapshots into events (`appeared`, `removed`,
  `connected`, `disconnected`, `address_changed`). Detection therefore happens while a screen polls.
  Interfaces that vanish stay in the list as `present: false` for the session so removal and
  reconnection are visible.

### Discovery
* **Active IPv4:** Windows `SendARP` (true ARP, no admin, no Npcap, no raw sockets), source address
  pinned to the chosen interface, bounded thread pool. Linux: an unprivileged UDP datagram that
  makes the kernel resolve ARP, then `/proc/net/arp`.
* **Passive:** OS neighbor table (`GetIpNetTable2` on Windows, `ip -j neigh` on Linux) for IPv4 and
  IPv6. IPv6 active discovery is a best-effort all-nodes multicast echo that fills the OS neighbor
  cache, then the cache is read.
* **Safety rules enforced server-side:** only the interface's own connected network or a subnet of
  it; private and link-local ranges only; at most a /22 (1022 hosts); explicit
  `confirm_authorized` for active scans; one active scan at a time; hard deadline (120 s).
* **Honesty rules:** "no response" is recorded as nothing, never as "offline". Neighbor-table
  entries carry their OS state: `Reachable` is *probable*, `Stale` is *stale*; only a reply to our
  own ARP request is *confirmed*. Multicast, broadcast and our own addresses are filtered out.
* **One scan thread per job** (not an asyncio task, not unbounded): it owns a per-scan pool, a cancel
  event and a deadline; shutdown cancels and joins it. API handlers only read a locked progress
  object, so the event loop is never blocked.

### Inventory and identity
* A device is identified by **MAC address** (unique). DHCP change: same MAC, new IP → one device,
  two address-history rows. IP reuse: same IP, different MAC → two devices. **MAC randomization:**
  locally administered MACs are flagged `mac_randomized`; the same physical device that rotates its
  address *will* appear as several devices, and the UI says so. Nothing is merged by guesswork.
* Tables: `devices`, `device_addresses` (IP history), `device_observations` (append-only evidence,
  capped per device), `discovery_scans`. No packet data.
* Facts are separated from inferences in the API: observed (IP, MAC, hostname via reverse DNS,
  neighbor state) versus inferred (vendor from the OUI prefix, randomized-MAC flag, confidence).
* State is derived from `last_seen` at query time: `active` (seen within 15 min), `inactive`
  (within 7 days), `previously_observed` (older). "Inactive" means "not observed recently", and the
  UI says so.
* Vendor names come from a local copy of the IEEE registry (MA-L, MA-M, MA-S) with a re-runnable
  update script.

## 3. Architectural risks and mitigations

| # | Risk | Mitigation |
|---|---|---|
| R1 | `ctypes` struct layouts for `GetAdaptersAddresses` / `GetIpNetTable2` are easy to get subtly wrong | Partial structs read via the OS-reported `Length`; `sizeof` assertions; values compared with PowerShell ground truth in a committed verification script |
| R2 | `SendARP` blocks up to about 3 s per unanswered host and cannot be cancelled | Bounded pool, cancel flag checked before each probe, scan deadline; cancellation latency is at most one probe timeout and is documented |
| R3 | Scanning the wrong network | Targets are derived from the interface, never free-form; private/link-local only; size cap; explicit confirmation |
| R4 | Phantom data: 169.254 addresses on disconnected adapters, multicast/broadcast neighbor rows | DAD-state filtering; unicast-only filtering; both seen on this machine and tested |
| R5 | Identity errors (DHCP, MAC randomization) | MAC-keyed identity with address history; flags instead of merging |
| R6 | Blocking the event loop or leaking threads | Sync handlers run in the thread pool; one tracked scan thread; shutdown joins it; startup marks stale `running` scans `interrupted` |
| R7 | First schema change on a user's database | Alembic `0002`, consistent SQLite backup (last 3 kept) before migrating an existing database, tested |
| R8 | Linux code is not exercised by Windows development | Fixture-driven unit tests plus a real run under WSL |
| R9 | Large inventories | Server-side filter/sort/pagination (max 500), indexes, `EXPLAIN QUERY PLAN` test, 10 000-row timing test |
| R10 | Generic "every route needs a token" test substitutes path parameters | New routes keep auth as a router dependency; test is re-run |

## 4. Tasks (each ends in a runnable verification)

1. **Interface model, providers, manager** (tests first) and `/api/v1/interfaces*`.
2. **OUI database** and lookup.
3. **Migration `0002` + backup-before-migrate**, models, repository, `/api/v1/devices*`.
4. **Discovery engine**, backends, service, `/api/v1/discovery/*`.
5. **Real Windows verification** script: compare against PowerShell, then scan the authorized LAN.
6. **Frontend**: client, selection context, Interfaces, Discovery, Inventory screens.
7. **Docs, skill evidence, independent review, fixes, full gates, desktop smoke.**

## 5. Review focus

* A scan that is cancelled during the reverse-DNS phase.
* Duplicate observations of the same MAC within one scan (ARP + neighbor table).
* The same MAC appearing on two interfaces (dual-homed / VM host-only networks).
* Interface removed while a scan runs on it.
* A hostile or malformed CIDR (`0.0.0.0/0`, public ranges, IPv6, whitespace).
