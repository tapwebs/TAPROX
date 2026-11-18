# Discovery and device inventory (Phase 1)

This document explains how TAPNETTRACK finds devices on the local network, what it records, and
which claims it deliberately refuses to make. Everything here is implemented and tested; limits
that remain are listed at the end.

## What it does

1. **Network interfaces.** Lists the computer's adapters (Wi-Fi, Ethernet, USB, virtual) with MAC,
   IPv4/IPv6 with prefix, gateway, DNS, link state and type. It notices connect, disconnect, address
   change and removal.
2. **Discovery.** Finds devices on a network this computer is connected to, either by reading what
   the operating system already knows (*passive*) or by also sending ARP requests (*active*).
3. **Inventory.** Stores what was seen in SQLite so that it can be listed, searched, sorted,
   filtered and inspected later, with the history behind each device.

## Observed versus inferred

The API and the UI keep these apart on purpose.

| Observed (the network showed us) | Inferred (we concluded) |
|---|---|
| MAC address | Manufacturer, from the first bits of the MAC (IEEE registry) |
| IP address, and every address seen before | "Randomised or virtual" address, from the locally-administered bit |
| Host name returned by reverse DNS (attributed to the lookup, not to the device) | Recent activity (`active` / `not seen recently` / `previously observed`) |
| When and how it was seen, and the confidence of that sighting | |

Things TAPNETTRACK **never** claims: that a device is *offline* because it did not answer; what
operating system or kind of device it is; that two different MACs are the same device.

## Identity rules

* A device **is** its MAC address.
* Same MAC, new IP (a DHCP change): one device with another row in its address history.
* Same IP, different MAC: two devices. The address history shows both held the address.
* A MAC with the locally-administered bit set is flagged `mac_randomized` and gets no manufacturer.
  The same phone can appear under several such MACs. They are **not** merged, because merging would
  be a guess.
* `last_seen` never moves backwards. The "current" IP, interface, source and confidence always
  describe **one** sighting, the latest one that is evidence of presence; with equal timestamps the
  stronger evidence wins.
* **A remembered address is not presence.** An entry the operating system lists as `stale` is
  stored as history but never moves `last_seen`, and a device known only from such entries is never
  `active` (at most "not seen recently"). Otherwise one passive scan would show every host the
  cache still remembers, including ones that left days ago, as seen a moment ago.
* An IPv6 sighting does not replace a device's current IPv4 address in the list (people recognise
  IPv4), and it does not overwrite the confidence, source or interface behind that address either:
  those always belong to the same sighting. It is still recorded in the address history.
## Confidence

| Value | Meaning |
|---|---|
| `confirmed` | The device answered an ARP request this computer sent, or it is this computer's own interface |
| `probable` | The operating system lists it as recently reachable, but it did not answer a probe |
| `stale` | The operating system lists it but has not confirmed it lately |

On Windows `SendARP` was shown to verify on the wire: stale cache entries returned to `reachable`
after being probed (measured, see `PHASE1_VERIFICATION.md`). On Linux the probe reports only entries
the probe itself caused; hosts the kernel already had cached are reported from the neighbor table
with their real state.

## Sources

| `source` | Where the observation came from |
|---|---|
| `arp` | A reply to an ARP request this computer sent |
| `os_neighbor_table` | The operating system's IPv4 neighbor (ARP) cache |
| `ndp` | The operating system's IPv6 neighbor cache |
| `local_interface` | This computer's own interface, read from the operating system |

## Safety limits (each has a test)

* **Active scanning needs explicit authorisation.** The request must carry `confirm_authorized:
  true`; the UI will not enable *Start* until the user ticks the box, and shows how many addresses
  will be probed first.
* **Only the connected private network.** Targets are derived from the chosen interface's own
  network, never from free-form input. A requested subnet must lie inside that network. Allowed
  ranges are an explicit list: `10/8`, `172.16/12`, `192.168/16`, `169.254/16`. Python's
  `is_private` is not used because it also accepts loopback and test networks.
* **Size cap.** At most a /22 (1022 hosts). A larger network must be narrowed first.
* **A second check in the backends.** The Windows and Linux backends independently refuse any probe
  target outside those ranges, so a bug in the service cannot send a probe to a public address.
* **One scan at a time**, with a 120 s hard limit and cancellation. Cancelling or timing out keeps
  what was already found.
* **Nothing blocks the web server.** The scan runs on one tracked thread; probes run on a bounded
  pool of daemon threads that stops on cancel, deadline, or when every call fails. The thread is
  joined at shutdown before the database closes.
* **No raw packets and no exploitation.** Nothing is captured, nothing is stored from the wire
  except the MAC, IP and timing of a sighting. No ports are scanned: on Linux the one datagram per address goes to the UDP discard port only to make the kernel resolve the address.
* **Passive sends no probes.** A passive scan reads a table. If host-name lookup is on (the
  default) it still asks the configured DNS server about the addresses it lists, which can leave
  the computer; it can be switched off. The Active consent names everything an active scan sends:
  ARP requests, one IPv6 multicast ping where the interface has IPv6, and on Linux a small UDP
  datagram per address.

## Platform backends

| | Windows | Linux |
|---|---|---|
| Interfaces | `GetAdaptersAddresses` through `ctypes` | `ip -j addr`, `/sys/class/net`, `/etc/resolv.conf` |
| Neighbor table | `GetIpNetTable2` (IPv4 and IPv6) | `ip -j neigh` |
| Active probe | `SendARP`, source pinned to the interface; no administrator rights, no packet driver | A UDP datagram to the discard port, bound to the chosen interface, makes the kernel resolve the address; only a `/proc/net/arp` row learned on that interface counts as an answer |
| IPv6 nudge | `ping -6 ff02::1%<ifindex>` by absolute path | `ping -6 ff02::1%<name>` by absolute path, name validated |

No dependency was added for any of this. External programs are called by absolute path with fixed
arguments, no shell and a timeout.

## Data model (migration `0002`)

`devices`, `device_addresses` (unique per device, IP and interface), `device_observations`
(append-only, capped at 200 per device, newest kept) and `discovery_scans`. `ip_sort` is a
fixed-width hex string so addresses sort numerically using an index. Device *state* is not stored:
it is computed from `last_seen` and the confidence of the latest evidence when read (active within
15 minutes, inactive within 7 days; stale-only devices are capped at inactive).
The first schema change also introduced **backup before migrate**: the database is copied with the
SQLite backup API into `backups/` (newest three kept), and the upgrade is refused if the backup
fails. A database written by a newer version is refused untouched.

## Known limitations

* **Silence is ambiguous.** A device that does not answer may be asleep, busy, or ignoring ARP.
  Phones with power saving often do not answer promptly (one took 1.1 s in testing). A single scan
  can miss devices.
* **Only the local layer-2 segment.** Devices behind a router are not seen. Wi-Fi client isolation
  or VLANs can hide devices from ARP.
* **The vendor name is who made the network chip,** not what the device is, and the registry can
  be out of date or list a reseller. Randomised MACs have none.
* **Host names** come from reverse DNS. Many home routers do not publish names for DHCP clients, so
  most devices will have none.
* **One local network interface per scan,** and one scan at a time.
* **IPv6 discovery is best effort.** The multicast ping may be blocked by firewalls (Windows blocks
  inbound echo by default). Failure produces a warning, never a failed scan.
* **Windows virtual adapters are real interfaces:** scanning VMware or WSL networks works but
  mostly finds the host itself.
* **The OUI file** (`backend/app/data/oui.tsv`) is a snapshot dated 2026-11-05. Refresh it with
  `backend/scripts/update_oui.py`. A packaged build (Phase 7) must include this data file.
* **Linux was verified with the test suite on Ubuntu 24.04 (WSL) but not with a live scan on a
  physical Linux LAN.** WSL's virtual network cannot exercise real ARP discovery.
* **Interface changes are noticed when interfaces are read** (the Interfaces screen polls every
  5 s). There is no background watcher, so a change while no screen is open is seen at the next
  read.
