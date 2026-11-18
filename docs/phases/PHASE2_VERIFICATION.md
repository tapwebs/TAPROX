# Phase 2 verification

Branch `phase-2/packet-capture`. Nothing is committed yet (awaiting approval).

## Results

| Check | Result |
|---|---|
| Backend (Windows) `pytest` | 729 passed, 3 skipped |
| Backend `ruff`, `mypy --strict` | clean (102 source files) |
| Backend on Linux (WSL Ubuntu) | 723 passed, 8 skipped, 1 failed on first run. The failure was a test-tool defect (the fake dumpcap ignored a polite stop mid-stream); fixed, then the capture tests re-ran on Linux: 45 of 45 passed |
| Dashboard `vitest` / `tsc` / `eslint` / `build` | 375 passed / clean / clean / built |
| Rust `fmt` / `clippy -D warnings` / `test` | clean / clean / 25 passed |
| `npm run contracts:check` | up to date |
| Desktop debug and release build + `smoke-desktop.ps1` | both built; every check passed |
| Real backend on this machine | `/capture/interfaces` lists the 8 real adapters as not capturable with the reason; `/capture/start` returns `503 capture_tools_missing` naming Wireshark; state stays `idle` |

## What was and was not tested against real tools

* **Real child processes, fake Wireshark.** The service tests run `tests/fake_tools/fake_dumpcap.py`
  and `fake_tshark.py` as genuine subprocesses: real pipes, real signals, real termination, real
  PCAPNG bytes. This proves the pipeline, bounds, state machine and cleanup. It does **not** prove
  Wireshark's own output format or Npcap behaviour.
* **Real capture was run after Wireshark 4.6.9 was installed** (see below). Before that: The first real capture needs: install Wireshark, then Start in
  the Packet Explorer. Until then "real Windows capture" is **DEFERRED**, not passed.
* No physical Linux capture was run (WSL has no usable capture device and no `dumpcap`).

## Skills

Read: `karpathy-guidelines`, `test-driven-development`, `verification-before-completion`,
`ui-ux-designer`. No installed skill covers Tauri/Rust, FastAPI, networking or security.

## Deferred or limited

* tshark output is parsed with `-T fields` using `_ws.col.*` columns; a Wireshark version that changes
  them would need a parser update (guarded by `parse_row`, which drops malformed lines).
* A filtered view is capped at the list limit (100,000 rows) and is recomputed when new packets
  arrive, so very large live captures with a filter get slower.
* Windows Ctrl+Break delivery needs a console group; when it cannot be delivered the stop falls back
  to terminate (safe: only whole blocks are kept).
* Only one capture or opened file at a time. No capture-time (BPF) filter and no ring buffer.

## Real Windows capture (Wireshark 4.6.9, Npcap 1.88, not elevated)

Tools: `C:\Program Files\Wireshark\dumpcap.exe` and `tshark.exe`, both 4.6.9. The prerequisites
endpoint reported all three checks `ok`. `dumpcap -D` listed 11 devices; the app mapped the 8 it knows
by NPF GUID (Ethernet `1fe8efe0-…` is capturable, disconnected adapters and loopback give a reason).

Two runs through the API with the real backend code on the real Ethernet adapter (192.168.1.7),
promiscuous off, with ordinary HTTPS/HTTP/DNS/ping traffic generated for 30 s:

| | Run 1 | Run 2 |
|---|---|---|
| Packets / bytes | 14,854 / 13,615,331 | 10,783 / 10,932,373 |
| Listed in the table | all (0 dropped) | all (0 dropped) |
| Stop request to completed | 3.1 s | 3.2 s |
| dumpcap/tshark left afterwards | none | none |

Run 2 checks:
* Packet count 10,783 and byte total match `capinfos` and `tshark -z io,phs` on the saved file.
* Rows (number, source, destination, length) match `tshark -T fields` for the first packets; real
  protocols appear (TCP, TLSv1.2, SSL, DNS, mDNS, HTTP, ICMP).
* Filters: `ip` 10,783, `ipv6` 0, `tcp` 10,722, `udp` 45, `dns` 24, `http` 2, `icmp` 17,
  `tcp.port == 443` 10,641, `ip.addr == 192.168.1.7` 10,768. `tcp.port ==` and `nonsense` were
  rejected with tshark's own message.
* Detail: TCP, DNS and mDNS packets decoded into frame/eth/ip/tcp|udp/dns|mdns layers. The hex of
  packet 5327 is byte-identical to `tshark -x`.
* Save: written, no `.part` file left, a second save to the same path refused. Reopen: 10,783
  packets, state `completed` after 0.7 s. A non-PCAPNG file was refused; a file cut at 5,000,003 bytes
  opened with 4,340 packets and the warning that the last 135 bytes were ignored.
* Temp files: none left after shutdown. No dumpcap/tshark processes at any point after stop.

No integration defect was found, so no application code changed after this run. Open returns
`preparing` immediately and the list fills within about a second (the dashboard polls).

Not covered by the run: the dashboard window itself was not driven against the live capture (its
tests use a stubbed backend), and no interface-unplug, permission-denied or promiscuous capture was
tried with the real tools.