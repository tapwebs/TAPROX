# Flow and application intelligence (Phase 3)

Flows turn the packets of a capture into conversations: who talked to whom, over what, how much, for
how long, and (when the packets themselves show it) which service was used. Everything is computed
locally from the packets the Packet Explorer already has. Nothing leaves the machine.

## Data flow

```
dumpcap ─► pump ─► temp .pcapng (the evidence, unchanged from Phase 2)
              └─► tshark -T fields  ──► reader thread ──┬─► Packet Explorer rows (first 100,000)
                    (one process, one extra set of      └─► FlowEngine (this session's flows)
                     decoded columns, no 2nd dissector)         │
                                                                 └─ at the end: saved to SQLite
GET /api/v1/flows/…  ◄── FlowService ◄── live engine  (current session)
                                     ◄── SQLite       (the last 5 sessions)
```

* **One source of truth for live flows**: the `FlowEngine` owned by the capture session. A finished
  session is saved to SQLite (`flow_sessions`, `flows`, migration 0003) and read back by the same
  query code, so a past session answers exactly as it did live.
* **No second dissector.** The same `tshark -T fields` process that feeds the Packet Explorer prints
  21 more decoded fields per packet (protocol layers, Ethernet and IP addresses, ports, TCP flags,
  DNS names and answers, TLS server name, HTTP Host). A field tshark did not decode stays empty.
* **Bounded queues.** The engine runs inline in the thread that already reads tshark's output. The
  only queue is the operating system pipe between the processes, which is bounded: a slow engine slows
  tshark down, and in the worst case `dumpcap` drops packets and reports them, as in Phase 2.
* **Analysis limit**: tshark decodes at most 2,000,000 packets per session (live or file). The
  Packet Explorer list keeps the first 100,000 of them. Past 2,000,000 the capture continues and is
  saved, and a warning says flow analysis stopped.

## What a flow is

A flow is keyed by `(transport, endpoint A, endpoint B)` with the two endpoints sorted, so A→B and B→A
are one conversation. Endpoints are `(IP address, port)`. TCP and UDP use ports; ICMP, ICMPv6 and other
IP protocols (GRE, ESP, SCTP …) pair by address only. IPv4 and IPv6 are separate address families.
Two conversations that merely share an address are never merged. Non-IP traffic (ARP, LLDP, STP) is
counted in the totals (`non_ip_packets`) and is not a flow.

The transport comes from the **outer** IP header's protocol number. A packet that carries another IP
header inside it (an ICMP error quoting a TCP packet, a tunnel) is never given the inner ports.

Every flow has separate packet and byte counters per direction, and `started_by` says whether this computer or another device started it (unknown for a file). It is about who opened the conversation, not which way most bytes went. "Bytes" are captured frame lengths
(`frame.len`), headers included.

**Which side is the "source"?** The side that started the flow: the TCP SYN sender, or the receiver of
a SYN-ACK when the SYN was not captured, otherwise whoever sent the first packet captured.
`initiator_basis` (`syn`, `syn_ack`, `first_packet`) says which, so a guess is labelled as a guess.
Sent/received (upload/download) does **not** depend on this: it uses the capturing computer's own
addresses, and is "unknown" for an opened file, which has none.

## Lifecycle

All times are **packet timestamps**, so a file replays the same as a live capture.

| State | Meaning |
|---|---|
| `active` | Packets are still arriving (within the idle limit) |
| `closed` | A FIN was seen from both sides |
| `reset` | A RST was seen |
| `idle_timeout` | Nothing arrived for the idle limit of its kind |
| `capture_ended` | The capture stopped first. Nothing is implied about the connection |

A missing FIN or RST is never reported as a failure. A closed or reset flow stays attached for 10 s so
late ACKs are counted, then a packet on the same ports (or a new SYN) starts a **new** flow. A packet
that arrives after the idle limit also starts a new flow, as flow exporters do.

| Idle limit | Default |
|---|---|
| Established TCP | 300 s |
| TCP SYN that was never answered | 60 s |
| UDP | 60 s |
| ICMP and other IP protocols | 30 s |
| Linger after FIN/FIN or RST | 10 s |

Retransmitted or duplicated packets are counted each time: each was on the wire. There is no
de-duplication.

## Protocol and application identification

Rules, strongest evidence first. **Port numbers are never used.**

1. **A name the flow itself revealed** (TLS/QUIC server name, HTTP Host) that belongs to a known
   service → that service, `confirmed` (the client asked for that name).
2. **A name from an earlier DNS answer** in the same capture for the remote address → `probable`
   (one address can serve many names).
3. **An application protocol tshark decoded** from the packets (DNS, mDNS, DHCP, SSH, SMTP, FTP, NTP,
   SSDP, SMB, WireGuard, OpenVPN, IKE …) → that service, `confirmed` as to the protocol.
4. **TLS, HTTP, QUIC** name the transport, not an application: the flow is `Encrypted traffic` or `Web`
   with no application, and `unknown`.
5. Anything else is `Unclassified` / `unknown`.

The service list (`app/services/flows/classify.py`) is short on purpose: only domains that clearly
belong to one service, matched on whole labels (`notyoutube.com` and `youtube.com.evil.example` do not
match). An unlisted server name is shown as evidence and names no application.

Every classification carries its **evidence** (what was seen) and **limitations** (what it cannot tell):
TLS contents are encrypted; no server name may mean a mid-connection start, a resumed session or
Encrypted Client Hello; a VPN hides the inner application; one IP address is shared by many services;
encrypted DNS (DoH/DoT) does not appear as DNS. Classification describes traffic. It is **not** a
security verdict, and an unknown or unlisted endpoint is not suspicious.

## Linking flows to the device inventory

An IP address does not say who has it (DHCP moves addresses, devices change MACs). A link is made only
on evidence that still holds:

* **`ip_and_mac`**: the address is on the capturing computer's own network, so the Ethernet address in
  its packets is that host's. If it equals the inventory's MAC the link is certain; if it **differs** the
  link is refused and the contradiction is reported.
* **`ip_only`**: no such check is possible (an opened file, or an address behind the router). Used only
  when the inventory saw that address within 24 hours of the traffic, and always labelled "by IP only".
* The Ethernet address of a packet to an off-link host is the router's and is never used.
* A locally administered MAC is flagged (`mac_randomized`); nothing is merged.
* Unknown endpoints remain plain endpoints.

## Limits

Measured on the development machine (Windows 11, Python 3.12):

| Limit | Value | Measured |
|---|---|---|
| Flows kept per session | 50,000 (oldest finished first, then least recently active) | 68 MB held at the limit (about 1.4 KB per flow) |
| Saved sessions | newest 5 | up to about 12 MB of flows each |
| Engine speed | n/a | 47,000 packets/s alone; the whole pipeline is limited by tshark (about 19,000 packets/s on a 10,783-packet file) |
| Extra tshark decoding | n/a | +44% tshark time over the Phase 2 columns |
| Queries at 50,000 flows | memoised for 0.5 s while live | sorted page 322 ms, application statistics 268 ms |
| Timeline | 600 buckets, which double in width as a capture grows | |

A "found by measurement" fix: choosing the least recently used active flow to evict used to scan the
whole table; the active table is now ordered by recent activity, so eviction is constant time.

## API

See [API.md](../api/API.md#flows-phase-3). Flow ids are `session-flow`. `session=current` is what the
Packet Explorer shows now; an integer is a saved session.
