# Phase 3 verification

Branch `phase-3/flow-intelligence`. Nothing is committed yet (awaiting approval).

Sections are in the order the work happened. Where a later section corrects or replaces an earlier one, the earlier text says so. The current state is in **Results** and **Deferred or limited**.

## Results

| Check | Result |
|---|---|
| Backend (Windows) `pytest` | 887 passed, 3 skipped, 0 failed (final run, after the filter optimization) |
| Backend `ruff`, `ruff format`, `mypy --strict` | clean (121 source files) |
| Backend on Linux (WSL Ubuntu) | 868 passed, 16 skipped, 0 failed. **Not re-run since**: it predates 6 later backend tests (884 collected then, 890 now) and the filter changes |
| Dashboard `vitest` / `tsc` / `eslint` / `build` | 400 passed (28 files) / clean / clean / built |
| Rust `fmt` / `clippy -D warnings` / `cargo test` | clean / clean / 25 passed |
| `npm run contracts:check` | up to date |
| Desktop debug and release build + `smoke-desktop.ps1` | both built after the last code change; every check passed |
| `dumpcap`/`tshark` processes before and after the full backend run | 0 and 0 |

## Real data, real tools

**Frames built byte by byte, decoded by the real tshark 4.6.9** (`test_flow_real_tshark.py`, skipped when
Wireshark is absent): TCP handshake and close, RST, TLS ClientHello with and without a server name, HTTP
Host, DNS query and answer, mDNS over IPv6, ICMP echo, IPv6 TCP. This is what proves the field names,
the `True`/`False` and `0x0012` formats and the comma-separated repeats the parser relies on. The display
filter offered for a flow selects exactly that flow's packets.

**A real capture** (Phase 2, Ethernet adapter 192.168.1.7, 30 s of ordinary web, DNS and ping traffic,
10,783 packets, 10,932,373 bytes) was used three ways.

1. *Independent comparison.* tshark's own per-packet fields, grouped by 5-tuple by a separate script,
   give 87 conversations and 10,783 packets. TAPNETTRACK built 87 flows with the same packet count and
   the same IP byte total. The one difference was in the comparison script, not the product: an ICMP
   error that quotes a UDP header was keyed by its inner ports there, while the engine (by design) keeps
   it as an ICMP flow between the two hosts.
2. *Live pipeline with the real tshark.* A stand-in for `dumpcap` replayed the real file's blocks at
   twice the speed into the production pump, the real `tshark -r - -l`, the flow engine and the API,
   with the real Windows interface list (so the local address 192.168.1.7 was known). Result: 10,783
   packets, 87 flows (same as the file), states `capture_ended` 52, `closed` 29, `reset` 6. Sent bytes
   416,976 = tshark's own total for that source. Received 10,511,976 plus 3,421 "neither end is this
   computer" = 10,515,397 = tshark's total. Stop took 3.1 s, the tshark process was gone afterwards, no
   temporary file was left, and the 87 flows were saved to SQLite. Eight applications/services were
   named (DNS, mDNS, NTP, SSDP, NetBIOS name service, Wikipedia, Microsoft services, Google services);
   the biggest flow (9.7 MiB of TLS to 101.2.42.76) stayed **Unclassified** because the capture began
   mid-connection and no server name was captured.
3. *The real desktop window.* The built debug app (WebView2, driven over the DevTools protocol) with the
   real Python backend, in a throw-away data folder. A passive device discovery filled the inventory
   from the OS neighbour table, the file was opened through the Packet Explorer, and each screen was
   read. The Packet Explorer showed the real rows, an explained invalid filter (`nonsense`), the `dns`
   filter (24 packets), a packet's layers and hex/ASCII. Network Activity showed 87 flows, 10,783
   packets, 10.4 MiB, "Unknown" for sent/received (a file has no local address), the traffic graph with a
   text alternative, top devices and destinations with names that flows revealed, and the protocol and
   application mix. Flow Explorer showed 87 flows over two pages, sorted by bytes, filtered by protocol
   (DNS: 1 flow), searched (`example`: 4 flows), and opened the largest flow's detail (tuple, counters per
   direction, "Source chosen by: a guess", TCP handshake "not seen", evidence, limitations, the Packet
   Explorer filter). Application Intelligence listed confirmed, probable and Unclassified groups with
   their evidence. Devices were linked "by IP only" and labelled so (a file gives no MAC check). The
   console had no errors; afterwards no backend, dumpcap, tshark or temporary file remained. A saved
   session from an earlier run was still listed after the app restarted.

The same script (`scripts/live-check/run-live-check.ps1`) is committed so anyone can repeat it.

## Live capture through the dashboard (real dumpcap, real Npcap)

*Historical: this first run happened while Npcap was in Administrator-only mode. Live capture without any prompt was verified later: see "Live capture as a normal user after the Npcap change".*

Run with `scripts\live-check\run-live-check.ps1 -Mode Live` as the **normal, unelevated user**, with Npcap
still in Administrator-only mode (nothing was reinstalled, no registry value, UAC setting or Net Protector
process was changed, and the application was not elevated). The user was at the machine; I did not observe
whether Windows showed an approval prompt, only that the capture started within the first poll.

First live run (Ethernet, 192.168.1.7, promiscuous off, about 30 s of web, DNS and ping traffic that the
script generated, on top of whatever else the machine was doing):

| | |
|---|---|
| Capture state | Preparing â†’ Capturing within seconds; 23,513 packets after 8 s |
| While capturing | Network Activity updated live (42 flows, 30 active, 30,842 packets, 34.9 MiB at one reading); Flow Explorer showed 49 live rows; the graph drew 10 intervals |
| Stop | Completed; 116,572 packets, 132.0 MiB, 34 s |
| Packet list limit | Honest: "Only the first 100,000 packets are listed; the other 16,572 are saved" |
| Flows | 65 flows (60 bidirectional, 5 one-sided; 41 capture ended, 18 closed, 6 reset); 15 of 65 with an application |
| Sent / received | 10.1 MiB / 121.9 MiB; tshark's own totals for the saved file: 10,562,759 / 127,843,899 bytes = the same |
| Protocols | HTTP 5 flows (118.8 MiB), TLS 33, TCP 17, DNS 6, ICMP 2, SSDP 1, NTP 1 |
| Applications | GitHub (1.5 MiB), Wikipedia, Microsoft services, â€¦ each with method and evidence. The 118.8 MiB HTTP downloads (a Windows update already in progress when the capture began) stayed **Unclassified**: the Host header was an IP address |
| Device link | The local computer is shown as "This computer" and linked to its inventory device; the gateway likewise |
| Filters | An invalid filter (`nonsense`) was explained by tshark's message; packet detail showed layers and hex/ASCII |
| Save and reopen | Saved through the UI; reopened: 116,572 packets, 65 flows, direction "Unknown" (a file has no local address) |
| Independent check | Same saved file, tshark's own fields grouped by 5-tuple: 116,572 packets and the same IP byte total; 65 flows against 67 tshark conversations. The two extra are one ICMP error that quotes three UDP DNS packets, which the comparison script keyed by the inner ports and the engine (by design) keeps as one ICMP flow: 6 packets, 708 bytes either way |
| Cleanup | After closing the window: 0 dumpcap/tshark processes, 0 backend processes, 0 temporary capture files, 0 console errors |

A second live run (4,052 packets, 2.8 MiB) also started, captured and cleaned up the same way (0 processes,
0 temporary files) but its script was derailed at the display-filter step: the window had moved to the
Settings page, most likely from a manual click, and it was not reproduced.

*(Superseded by "Packet Explorer display filters on a large capture", which measured this.)* Not conclusively measured at the time: how long a display filter takes to show on a 116,572-packet capture. The script's
fixed 2.5 s wait read the old rows in the first run. `tshark -Y dns` alone takes 1.1 s on that 138 MB file,
and the extra decoded columns add about 44%, so several seconds are expected; the Packet Explorer keeps
showing the previous rows meanwhile without a busy indicator. A small improvement, not made here.

Earlier on this machine, before Npcap's setting was understood, unanswered Windows prompts made
`dumpcap -D` hang. That is handled by the Settings warning, the timeout message and the back-off described
below; it is Npcap's Administrator-only behaviour and was not worked around.

What this did not prove at the time: capture with no Windows approval at all. The owner later set Npcap to the non-administrator setting and restarted Windows; that case is verified below. No capture helper was needed.

What was done about the Administrator-only mode, as confirmed integration defects (each with a failing test
first): a Settings warning that names the mode; a clear 503 message when `dumpcap` does not answer, shorter
than the dashboard's 15 s timeout (a 30 s first attempt showed "Backend not reachable" instead); a "Still
waiting for the capture driver" notice on a capture that stays in Preparing; a back-off so a hung listing is
not repeated for 30 s; a one-minute memory of the interface list.

One unexplained observation: a `dumpcap` process (promiscuous, parent already gone) from 09:21 existed
before the Phase 3 runs began. Its origin is not known and it was ended by hand. Every full backend run and
every desktop run since left none behind.

## Running as a standard user (no administrator, no UAC)

**Where administrator prompts come from.** Nothing in TAPNETTRACK asks for elevation. Searched: the Tauri
config and Windows manifest (the built debug and release executables contain no `requireAdministrator` or
`highestAvailable`), the build and run scripts (no `RunAs`, no self-elevation), the backend (it starts
`dumpcap` and `tshark` with a plain argument list), and the installer settings (bundling is off). The only
source of prompts was Npcap's **Administrator-only mode** (`AdminOnly = 1`), which makes Windows ask each
time `dumpcap` opens the driver. The one remaining code that mentions elevation is correct and kept: a
warning if the backend is ever *run* as administrator, and a warning if Npcap is in Administrator-only mode.
So no application code needed to change to remove an elevation request, and none was.

**Token elevation of every process, read from the access token** (`scripts\live-check\Get-ProcessElevation.ps1`,
sampled every 0.5 s during a desktop run from a normal, non-elevated PowerShell; the account is an
administrator in a filtered token, so "Limited" is the normal-user token):

| Process | Parent | Elevated | Integrity |
|---|---|---|---|
| tapnettrack-desktop.exe | the shell | No | Medium |
| msedgewebview2.exe (6 processes) | the desktop | No | Medium (renderers Low) |
| python.exe (launcher and backend) | the desktop / launcher | No | Medium |
| tshark.exe (3, for the file) | the backend | No | Medium |
| conhost.exe (5) | its owner | No | Medium |

17 processes sampled, 0 elevated, 0 unreadable. The reader was checked against controls: this PowerShell
and Explorer read as not elevated; `services.exe` is refused (access denied), so a protected process cannot
masquerade as unelevated. No elevated process was available, so the "Full" token type was not exercised.
No `consent.exe` (UAC) process appeared; after closing the window 0 desktop, backend, `dumpcap` or `tshark`
processes and 0 temporary capture files remained.

Checked at the command line as the same user: `dumpcap -D` 0.05 s and `tshark -D` 0.39 s, no prompt, and each
lists only `NPF_Loopback`.

**Live capture as a standard user: NOT VERIFIED at that point (historical; resolved below).** `dumpcap -D` lists only the loopback adapter, and a
capture on the Ethernet adapter fails with: "You do not have permission to capture on device ... (The helper
program for "Admin-only Mode" must be allowed to make changes to your device)". The registry now says
`AdminOnly = 0`, yet the running Npcap driver still behaves in Administrator-only mode: it enforces the
setting it loaded, so it most likely needs to be reloaded (restart Windows). Reloading it was not done
here (it needs administrator rights and is Npcap configuration, outside this task). An earlier live run in
this phase captured 116,572 packets; that was before this state, with Npcap prompts approved.

**Defect found while checking, fixed (failing test first).** With the driver in this state the Packet
Explorer said "The capture driver does not offer this interface (it may be virtual or filtered)" and Settings
showed no warning, which blames the adapter and gives nothing to act on. When the driver offers nothing but
loopback, the reason now says so and tells the user to restart Windows if Npcap was just installed or
reconfigured, or to see Settings. The ordinary "not offered" message is unchanged for other cases.

## Live capture as a normal user after the Npcap change

State: Npcap `AdminOnly = 0` set by the owner, Windows restarted. TAPNETTRACK was not changed for this and was never elevated. Npcap, UAC and Net Protector were not touched by this work.

* `dumpcap -D` and `tshark -D` list the physical adapters (Wi-Fi, VMnet1, VMnet8, Local Area Connection* 1 and 10, Ethernet, loopback) with no UAC prompt and no `consent.exe`.
* Full scripted run on Ethernet (`-Mode Live`): 253,491 packets, 218.4 MiB, 44 s of capture, 113 flows; every screen worked, save and reopen worked, no console errors. 29 processes sampled, 0 elevated. Afterwards: window closed, 0 backend, 0 dumpcap/tshark, 0 temporary capture files.
* 10-minute soak (`-Mode Soak -Minutes 10`, 14:04:00 to 14:15:54): see the investigation below.
* Final targeted check after the filter optimization (`-Mode Soak -Minutes 3`): 10,892 packets, 5.8 MiB, 336 flows after save and reopen; the `dns` filter showed its result in 1.1 s; 22 processes sampled, 0 elevated; nothing left running. The 10-minute soak was not repeated: the optimization changes only the filter command and the Packet Explorer screen, not capture, the shared packet data or process lifecycle.

## Performance and resources (measured)

| | |
|---|---|
| Flow engine alone | 47,000 packets/s (every packet a different flow, table full) |
| Whole pipeline on a real file | 19,000 packets/s, limited by tshark |
| Cost of the extra decoded fields | +44% tshark time over the Phase 2 columns |
| Memory at the 50,000-flow limit | 68 MB held, 73 MB peak |
| Queries over 50,000 flows | sorted page 322 ms, application statistics 268 ms, summary 15 ms; live results reused for 0.5 s |
| Bugs found by measuring | O(n) eviction (7.2 s for 40,000 new flows, now constant time); the live packet list would have stopped at 100,000 packets |

## Linux

WSL Ubuntu ran the same backend suite earlier in Phase 3 (868 passed, 16 skipped). The tests that need Windows APIs or a
real tshark are skipped there. **The Linux suite was not re-run after the last round of changes.** No physical Linux capture was run and none is claimed.

## Deferred or limited

* Capture without any Windows approval (Administrator-only Npcap needs one; a helper is future work).
* Display filtering during a LIVE capture: each refresh re-reads the growing file, and this was not benchmarked.
* A request the browser abandons (a superseded or cancelled filter) does not stop its tshark process at once; it ends by itself (limit: 120 s).
* Packet Explorer lists at most 100,000 packets; the UI says so, and the capture file keeps and saves all of them. Filter results are capped the same way.
* The Linux suite (WSL) was not re-run after the last changes; no physical Linux capture was run.
* Flows from a file are linked to the inventory "by IP only" (24 h rule); only a live capture on the
  inventory's own network can confirm a MAC.
* Flows beyond 50,000 per session drop the oldest finished ones; totals still include them.
* No de-duplication of retransmitted packets; no byte-level (payload) counters; frame length is used.
* Application recognition is a short, deliberate list of services; everything else is Unclassified.
* Query results for the live session are recomputed at most every 0.5 s.

## Investigation: "the desktop app closes by itself during live capture"

Skills read for this: `systematic-debugging` (plus `karpathy-guidelines`, `test-driven-development`, `verification-before-completion` earlier in Phase 3). No installed skill covers Tauri, FastAPI or Windows internals.

Evidence gathered before any change:
- Code audit: the only exit path in the desktop shell is the normal `RunEvent::Exit` (stops the backend). Nothing exits the app when the backend or capture ends. The backend exits only when its stdin closes. No watchdog, idle timer or `window.close`/`exit` call exists. The manifest requests no elevation.
- Windows Application log: no crash, hang or Windows Error Reporting entry for tapnettrack, python, dumpcap or tshark (only unrelated Edge-updater entries).
- The earlier scripted runs ended with the script itself calling `CloseMainWindow()` (about 2 minutes after launch), which looks exactly like "the app closed by itself".

Reproduction as a standard user (`run-live-check.ps1 -Mode Soak -Minutes 10`, Ethernet, 14:04:00 to 14:15:54, desktop pid 14464):
- Capture ran 622 s: 168,349 packets, 159.9 MiB, 713 flows. The window stayed open and the backend stayed healthy for the whole 11 min 54 s. The packet list, flows and applications kept updating.
- Stop, save, reopen worked (reopened file shows 168,349 packets, 713 flows). 26 processes sampled, 0 elevated, no JS errors (`problems: none`).
- After the script closed the window: desktop exited, 0 backend, 0 dumpcap/tshark, 0 temp capture files left.
- Whole process tree memory rose from about 640 MiB to about 1 GiB during capture and fell back after stop; handles stayed flat (about 4,600).

The closure was therefore the check script closing the window at the end of its run (`CloseMainWindow`), not an application crash: no Windows crash record, no Rust panic path, no backend exit trigger, and a 10-minute run with the window left alone stayed open. This is stated from the evidence above; I did not watch the user's own session.

Result: the unexpected closure did NOT reproduce. No application defect was found, so no application code changed. The only change is to the check script: `-Mode Soak`, a resource sampler, and an explicit report line saying whether the app had already exited by itself or the script closed it.

(An earlier version of this note said a `dns` filter on the 168,000-packet capture did not return in 60 s. That was wrong: see the next section.)

## Packet Explorer display filters on a large capture

Correction: the earlier "no result within 60 s" was a mistake in the soak driver, not a hang. It waited until every listed row said `DNS`, but the filter `dns` also matches 49 ICMP errors that quote DNS (463 DNS + 49 ICMP = 512 rows), so the wait could never succeed. The filter returned in a few seconds.

What the pipeline does: the dashboard checks the filter (`POST /capture/filter/validate`, one tshark), then `GET /capture/packets?display_filter=` runs ONE tshark over the capture file, parses its rows, keeps them for paging/sorting, and returns one page. The UI never receives more than one page.

Measured in the real desktop window (File mode, normal user, `-Mode Filter`, 165 MiB / 168,349 packets, tshark 4.6.9):

| Filter | Matches | Before: total / `/packets` | After: total / `/packets` |
|---|---|---|---|
| `dns` | 512 | 5.05 s / 4.73 s | 2.94 s / 2.65 s |
| `tcp.port == 443` | 164,395 (first 100,000 listed, shown with the existing "list is full" notice) | 5.45 s / 5.19 s | 2.82 s / 2.51 s |
| `ip.addr == 192.168.1.1` | 600 | 5.14 s / 4.78 s | 2.94 s / 2.66 s |

1,000-packet and 10,000-packet captures took 0.8 to 1.2 s before and after (dominated by starting tshark). Longest UI timer stall was 12 to 19 ms and no long task ran in any case. Backend memory peak on the large capture: 204 MiB before, 153 MiB after.

Causes found: (1) the filter run printed the 21 decoded flow columns that this output never uses, costing about half of tshark's time (A/B on the same file, same rows: `dns` 4.2 s to 2.1 s, `tcp.port == 443` 10.8 s to 5.1 s); (2) every `/packets` request with a filter, even a cached one, started another tshark to re-validate it; (3) a filter that exceeded 30 s was killed and the rows read so far were returned as if complete; (4) the page showed no sign of work after the 0.2 s validation step.

Changes: the filter command asks for the list columns only (`tshark_filter_argv`, `parse_list_row`); a cached filter is not re-validated; the timeout is 120 s and a timeout is an error ("the result would be incomplete") that is not remembered; Packet Explorer shows "Checking the filter..." then "Updating the packet list...", keeps the previous rows visible, shows "(N found)" when the result arrives, says when the filter could not be applied, and ignores Apply again for the filter already running. Superseded requests are aborted in the browser, and their results are discarded.

Not changed: the 100,000-row list limit (existing, announced in the UI); the server does not stop a tshark whose request the browser abandoned (it ends by itself); with a filter applied during a LIVE capture, each refresh re-reads the growing file.
