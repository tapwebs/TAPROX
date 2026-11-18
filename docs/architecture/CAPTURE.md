# Packet capture and Packet Explorer (Phase 2)

TAPNETTRACK captures with Wireshark's own tools and does not reimplement them. It needs `dumpcap`
and `tshark` (and Npcap on Windows). It installs nothing and does not run as administrator. Without
them the app stays usable: the Packet Explorer shows what is missing and Settings shows the full check.

## Data flow

```
dumpcap -i <device> -w - -F pcapng [-p]          (fixed argv, no shell)
        │ stdout: PCAPNG stream
        ▼
   pump thread ── BlockScanner: keeps only COMPLETE blocks
        ├──► private temp file  <data>/capture/captures/tapnettrack-capture-<uuid>.pcapng  (0600)
        └──► tshark -r - -l -n -T fields  ──► RowStore (bounded, 100,000 rows)
                                                   │
        GET /api/v1/capture/packets (paged, sorted, searched, filtered) ◄── dashboard polls
```

* One pipeline, one `CaptureService`, one session at a time. The service is the single source of
  truth for state; the dashboard only polls it.
* Packet and byte counts come from the PCAPNG stream itself, so they stay right if `tshark` dies.
* Display filters are validated by `tshark` itself and applied with `tshark -r <temp file> -Y <filter>`.
  There is no custom filter parser. Filtering never changes the capture.
* Packet detail runs `tshark -T json` for one packet. The bytes are read straight from the capture
  file, so the hex dump is exactly what was captured. Nothing is invented.
* Opening a file uses the same path: scan the file block by block (never loaded whole), then `tshark -r`.

## States

`idle → preparing → capturing → stopping → completed`, or `failed`. A failure keeps what was
captured ("N packets were captured before it stopped and can still be saved"). Failure codes:
`capture_permission_denied`, `capture_interface_gone`, `capture_failed`.

Stop sends Ctrl+Break (Windows) or SIGINT (Linux), waits 3 s, then terminates, then kills. A hard
stop is safe because only whole blocks are ever kept. Shutdown stops both tools, so no process is orphaned.

## Interfaces and promiscuous mode

An interface is capturable only if `dumpcap -D` offers it. On Windows the match is by the NPF GUID, on
Linux by exact name. The id sent by the UI must be one TAPNETTRACK discovered itself; arbitrary
device strings and executable paths are never accepted. dumpcap is promiscuous unless `-p` is given,
so TAPNETTRACK passes `-p` **by default** and enables promiscuous mode only when the user ticks it.
TAPNETTRACK sends no packets.

## Limits

| Limit | Value |
|---|---|
| Packets in the list | 100,000 (first ones kept; the capture file keeps everything and `list_dropped` says how many) |
| Page size | 1 to 500 rows per request |
| Live capture size | stops by itself at 1 GiB with a warning |
| Optional request limits | `max_packets` ≤ 10,000,000, `max_seconds` ≤ 86,400 |
| One block | 16 MiB (a larger block marks the stream corrupt) |
| Packet detail | 2,000 fields, depth 8, 2,000 characters per value, 65,535 bytes shown |
| Filter / search text | 1,000 / 200 characters |

Filtered and sorted views read the temporary file, not browser memory. The browser holds one page.

## Save and open

* Save copies only whole blocks to a hidden `.part` file next to the target, flushes it, checks it by
  re-scanning, and publishes it with a hard link that fails if the name exists. An existing file is
  never overwritten and an interrupted save leaves no partial `.pcapng`.
* Paths must be absolute, end in `.pcapng`, contain no `..`, no control characters, no UNC or device
  paths, and be at most 260 characters. The folder must already exist.
* Open validates the file (PCAPNG header, block structure) before anything is parsed. A file cut off
  in the middle is opened up to its last complete block and says so.
* The temporary file of an unsaved capture is deleted when the next capture or file replaces it, at
  shutdown, and at the next start if the app crashed.

## Not in this phase

Flows, application intelligence, detection, topology, HTTPS interception, replay or injection.
