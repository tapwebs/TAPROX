# Phase 1 verification on real hardware

What was checked, how, what it found, and what it could not check. Dated 2026-11-05.

Machine: Windows 11 (10.0.26200), not elevated. One wired Ethernet adapter (Realtek 2.5 GbE,
192.168.1.7/24, gateway and DNS 192.168.1.1), a disconnected Intel Wi-Fi adapter, VMware VMnet1 and
VMnet8, and the WSL virtual switch. The LAN is the owner's home network; the scan was authorised by
the owner in the Phase 1 task and limited to `192.168.1.0/24` on the Ethernet adapter.

## 1. Backend against PowerShell and the real LAN

`backend/scripts/verify_phase1_windows.py` compares TAPNETTRACK with what Windows itself reports, so
that a parsing mistake cannot agree with itself, and then runs an ARP scan, a cancellation and a
cache experiment. Output of the final run, unedited:

---
# Phase 1 verification on 2026-11-05 15:18 UTC (win32)

## Interfaces: our provider vs PowerShell
- Listing latency over 20 calls: median 4.8 ms, max 8.5 ms
- PASS: PowerShell reports adapters (5 adapters)
- PASS: Wi-Fi: ifIndex (17 vs 17)
- PASS: Wi-Fi: MAC (28:0c:50:f8:d1:6c vs 28:0c:50:f8:d1:6c)
- PASS: Wi-Fi: connection (disconnected vs Disconnected)
- PASS: VMware Network Adapter VMnet8: ifIndex (11 vs 11)
- PASS: VMware Network Adapter VMnet8: MAC (00:50:56:c0:00:08 vs 00:50:56:c0:00:08)
- PASS: VMware Network Adapter VMnet8: connection (connected vs Up)
- PASS: VMware Network Adapter VMnet8: IPv4 address/prefix ([('192.168.159.1', 24)] vs [('192.168.159.1', 24)])
- PASS: VMware Network Adapter VMnet8: default gateway ([] vs [])
- PASS: VMware Network Adapter VMnet8: DNS servers ([] vs [])
  - VMware Network Adapter VMnet8: 192.168.159.1/24 network 192.168.159.0/24, discovery: active ok
- PASS: VMware Network Adapter VMnet1: ifIndex (6 vs 6)
- PASS: VMware Network Adapter VMnet1: MAC (00:50:56:c0:00:01 vs 00:50:56:c0:00:01)
- PASS: VMware Network Adapter VMnet1: connection (connected vs Up)
- PASS: VMware Network Adapter VMnet1: IPv4 address/prefix ([('192.168.75.1', 24)] vs [('192.168.75.1', 24)])
- PASS: VMware Network Adapter VMnet1: default gateway ([] vs [])
- PASS: VMware Network Adapter VMnet1: DNS servers ([] vs [])
  - VMware Network Adapter VMnet1: 192.168.75.1/24 network 192.168.75.0/24, discovery: active ok
- PASS: Ethernet: ifIndex (5 vs 5)
- PASS: Ethernet: MAC (30:56:0f:1e:2e:c7 vs 30:56:0f:1e:2e:c7)
- PASS: Ethernet: connection (connected vs Up)
- PASS: Ethernet: IPv4 address/prefix ([('192.168.1.7', 24)] vs [('192.168.1.7', 24)])
- PASS: Ethernet: default gateway (['192.168.1.1'] vs ['192.168.1.1'])
- PASS: Ethernet: DNS servers (['192.168.1.1'] vs ['192.168.1.1'])
  - Ethernet: 192.168.1.7/24 network 192.168.1.0/24, discovery: active ok
- PASS: vEthernet (WSL (Hyper-V firewall)): ifIndex (55 vs 55)
- PASS: vEthernet (WSL (Hyper-V firewall)): MAC (00:15:5d:df:23:7a vs 00:15:5d:df:23:7a)
- PASS: vEthernet (WSL (Hyper-V firewall)): connection (connected vs Up)
- PASS: vEthernet (WSL (Hyper-V firewall)): IPv4 address/prefix ([('172.29.128.1', 20)] vs [('172.29.128.1', 20)])
- PASS: vEthernet (WSL (Hyper-V firewall)): default gateway ([] vs [])
- PASS: vEthernet (WSL (Hyper-V firewall)): DNS servers ([] vs [])
  - vEthernet (WSL (Hyper-V firewall)): 172.29.128.1/20 network 172.29.128.0/20, discovery: active ok (too_large)
- Interfaces we list that Get-NetAdapter hides: ['Local Area Connection* 1', 'Local Area Connection* 10', 'Loopback Pseudo-Interface 1']

## Neighbor table: our GetIpNetTable2 reader vs Get-NetNeighbor
- Read latency over 20 calls: median 2.72 ms
- Unicast entries: ours 8, PowerShell 8; only-PowerShell 0, only-ours 0
- PASS: neighbor tables agree (at most 2 differences allowed for entries that changed between reads)
  - if 5: 192.168.1.1 -> 30:4f:75:ea:00:ef
  - if 5: 192.168.1.11 -> 4c:bd:8f:87:97:4c
  - if 5: 192.168.1.4 -> c4:3a:35:8e:42:d8
  - if 5: 192.168.1.6 -> f6:eb:c2:43:8a:d4
  - if 6: 192.168.75.254 -> 00:50:56:fe:58:1b
  - if 11: 192.168.159.254 -> 00:50:56:fc:cf:54
  - if 17: 192.168.1.1 -> 30:4f:75:ea:00:ef
  - if 55: 172.29.142.9 -> 00:15:5d:35:20:5f

## Active discovery on the local network (authorised by --i-am-authorized)
- Interface: Ethernet (30:56:0f:1e:2e:c7), network 192.168.1.0/24
- Scan completed: 253/253 addresses in 24.0 s (11 probes/s), 5 device(s) found
- PASS: scan completed
- PASS: every address was probed
  - answered ARP: 192.168.1.1 -> 30:4f:75:ea:00:ef (Zhone Technologies, Inc.)
  - answered ARP: 192.168.1.11 -> 4c:bd:8f:87:97:4c (Hangzhou Hikvision Digital Technology Co.,Ltd.)
  - answered ARP: 192.168.1.2 -> b2:ff:72:3f:5d:b1 (no vendor: randomised address)
  - answered ARP: 192.168.1.4 -> c4:3a:35:8e:42:d8 (FN-LINK TECHNOLOGY LIMITED)
  - answered ARP: 192.168.1.6 -> f6:eb:c2:43:8a:d4 (no vendor: randomised address)
- PASS: every host that answered ARP is now in the OS neighbor table
- In the OS cache before the scan but silent to our probes: none
  (A cached host that does not answer ARP is asleep, gone or filtering: it is NOT reported as offline.)
- Devices answering ARP that the OS did not have cached beforehand: ['b2:ff:72:3f:5d:b1']
- Cancel after 1 s: status cancelled, stopped in 2.38 s, 53/253 probed
- PASS: cancel ends the scan
- PASS: cancel returns within 6 s (2.38 s)
- Experiment: does SendARP answer from the OS cache? (latency of probing cached hosts)
  - 192.168.1.1 (cache state 'reachable'): answered in 14 ms
  - 192.168.1.4 (cache state 'reachable'): answered in 16 ms
  - 192.168.1.6 (cache state 'stale'): answered in 16 ms
  - 192.168.1.11 (cache state 'stale'): answered in 15 ms

## Experiment: SendARP versus the OS neighbor cache
- Cached entries that were 'stale' when the experiment began: ['192.168.1.11', '192.168.1.2', '192.168.1.6']
  - 192.168.1.11: stale -> probe answered in 13 ms -> reachable
  - 192.168.1.2: stale -> probe answered in 13 ms -> reachable
  - 192.168.1.6: stale -> probe answered in 16 ms -> reachable
- Verified on the wire: 3 of 3 stale entries became 'reachable' after the probe

**Result: all checks passed**
---

### What this shows

* **Interfaces.** For every adapter, ifIndex, MAC, connection state, IPv4 address and prefix,
  default gateway and DNS servers match `Get-NetAdapter`, `Get-NetIPAddress`, `Get-NetRoute` and
  `Get-DnsClientServerAddress`. Listing takes about 5 ms.
* **Neighbor table.** The `GetIpNetTable2` reader returns the same unicast entries as
  `Get-NetNeighbor`.
* **Discovery.** 253 of 253 addresses probed in 24 s. Devices that answered were identified with
  the right manufacturers. Two had randomised MACs and correctly received no vendor. Each of the
  hosts that answered is in the operating system's neighbor table afterwards.
* **Cancellation** against real `SendARP` calls took about 2.4 s (calls already in flight finish).
* **`SendARP` goes on the wire.** Cached entries that had gone `stale` became `reachable` again
  after being probed, in 3 of 3 cases on this run (and 3 of 3 and 2 of 2 on earlier runs). A cache
  lookup alone would not change the state. This is why a reply to the Windows probe is recorded
  as `confirmed`. The Linux probe cannot show this, so it reports only entries the probe itself
  caused.

### What it does not show

* **A single scan is not a census.** The same LAN returned 4, 5 and 6 devices on separate runs
  (4 + 6 earlier, 5 here), because phones answer ARP late or not at all when idle. The tool does not
  call a silent device offline and the documentation says that a scan can miss devices.
* **The vendor column proves little.** It says who made the network chip.
* **Only one physical LAN, one machine and one operating system.** Nothing here is evidence for
  Linux discovery on real hardware, other networks, VLANs or Wi-Fi isolation.
* **Nothing was run elevated.** That is intended (no administrator rights are needed) but means the
  elevated case was not observed.
* The 24 s duration is for a /24 on this network. A /22 is an estimate, not a measurement.

## 2. Dashboard driven through the real UI

(Run on the code as it was before the review fixes in [PHASE1_REVIEW.md](PHASE1_REVIEW.md); the fixes changed wording, consent handling and the Linux probe, not layout. The real desktop window was checked again afterwards: backend connected, all real adapters listed, the discovery form and inventory rendered, no console errors, clean shutdown.)

A throw-away harness (not committed) started the real backend in an empty data directory and the
dashboard, then drove them in headless Edge over the DevTools protocol exactly as a user would:
open each screen, choose an interface, run a passive scan, run an active scan with the consent box,
watch progress, cancel one, open the inventory, search, open a device, close it with Escape. It
repeated the screens at 1440, 1024, 768 and 375 px, measured horizontal overflow, and watched the
console. Result of the final run: all steps completed, UI cancellation took 2.1 to 2.4 s and kept
the partial result, no element overflowed at any of the 12 page and width combinations, and the
browser console had **no errors or warnings**.

### Defects this found that unit tests could not

| Found by | Defect | Fix |
|---|---|---|
| Layout measurement at 1024/768/375 px | The Interfaces page scrolled sideways: a table's visually hidden header text escaped its scroll region and widened the page | Scroll container made the positioning context; regression test on that structure |
| Layout measurement | Wide tables could stretch their grid cell | `min-w-0` on panels and page grids |
| A scan's progress froze at 5 of 253 in the harness | `usePolling` pauses while the window is hidden, as designed, but did not refresh when the window became visible again, so the data stayed stale until the next tick. (The freeze itself was the headless browser reporting itself hidden.) | Refresh immediately on becoming visible; test added |
| Looking at the real Interfaces list | Windows keeps the old DHCP lease on a disconnected Wi-Fi adapter, so it was listed as `Disconnected 192.168.1.8/24` as if that address were in use | Labelled `not in use`; test added |
| Looking at the real device panel | This computer's own interface was explained as having "replied to an ARP request" | Explanation now depends on how the device was seen; test added |
| axe-core on the open panel | Two sections were labelled the same as the tables inside them (duplicate landmarks) | Plain containers; the tables carry the names |

### What the harness could not check

* **The Tauri webview and its production CSP.** The harness used Edge against the Vite dev server,
  not the packaged WebView2 window. The production CSP (`style-src 'self'`) forbids inline style
  attributes in markup; the progress bar sets its width through the CSSOM, which CSP allows, but
  this was checked by reasoning and the previous phase's CSP tests, not by observing the progress
  bar in the release window.
* **Screen readers.** Only automated accessibility checks (axe-core) and keyboard tests were used.
* **Colour contrast** of the new screens. They use only the Phase 0 tokens whose contrast was
  measured; the new screens' rendered contrast was not measured separately.
