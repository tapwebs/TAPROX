# Phase 4 detection rules and risk scoring

Status: **specification. Implemented: TT-REC-001 (M2), the nine rules of M3, the six DNS rules of M4 and, in M5 and M6, TT-DEV-001 to -006, TT-TRF-001, -002, -004, -005 and TT-APP-001 (section 11 records where they differ from the text below).** Earlier status: TT-REC-001 (M2) and the nine rules of M3 are implemented (TT-REC-002, -003, -004, -005,
TT-TRF-003, -006, TT-APP-002, -003, -004; section 9 records exactly what they do) and the six DNS rules of M4 (section 10).
Every other rule here is planning only. Part of the
Phase 4 specification; read
[PHASE4_ARCHITECTURE.md](PHASE4_ARCHITECTURE.md) first for the event model, module boundaries and the
wording policy.

Every threshold below is an **initial default to be calibrated**. None has been validated against a
labelled dataset. A rule that is marked "default off" stays off until its alert volume has been measured on
real captures and judged acceptable (roadmap milestone M10).

## 1. Common definitions

| Term | Definition |
|---|---|
| Entity | The thing an alert is about: a device (inventory id), an IP address, a MAC, a domain, or a network. Every entity has a stable key used for deduplication. |
| Initiator | The flow source chosen by the Phase 3 engine (`initiator_basis`: `syn`, `syn_ack` or `first_packet`). Rules that depend on who started a connection use only `syn`/`syn_ack` initiators and say so when the basis is a guess. |
| Failed TCP attempt | A TCP flow with a SYN and no SYN-ACK, or with an RST and no more than 2 packets from the responder. "Who sent the RST" is unknown in the engine and is not claimed. |
| Window | Sliding window in **packet time**. Counters are evicted by packet-time ticks, so replaying a file gives the same result as the live run. |
| Local, on-link, off-link | From `LocalScope` (local addresses, interface networks). For an opened file there is no local address: direction is `unknown`, only private ranges are known, and direction-dependent rules are skipped or run in a reduced, labelled mode. |
| Baseline | Per-device (or per-network) statistics learned from live sessions on the same network. Never learned from opened files. Not ready until the readiness rule is met (section 6). A baseline rule with no ready baseline does **not** fire and is shown as "not evaluated". |
| Self-activity | ARP probes, pings and name lookups made by TAPNETTRACK's own discovery scans. Matched by the local MAC/IP and the scan's start/end times. Excluded from recon rules and counted. |
| Capped set | A set that stops growing at 1,024 elements per entity per window. A capped set reports "at least N". |

Rule identifiers are stable: `TT-<category>-<number>`. A rule has a `version`; changing logic bumps it, and
each alert records the version that produced it.

## 2. Scoring

### 2.1 The three values

* **Severity** is fixed by the rule (with the escalation conditions written in the rule).
* **Confidence** is computed from stated conditions inside the rule (never guessed).
* **Risk score** is computed from both plus a bounded context multiplier.

### 2.2 Formula

```
risk = min(100, round(100 × W_sev[severity] × W_conf[confidence] × M_ctx))

W_sev:   info 0.10   low 0.25   medium 0.50   high 0.75   critical 1.00
W_conf:  low 0.50    medium 0.75   high 1.00
M_ctx = clamp(1 + Σ context factors, 0.50, 1.50)
```

Context factors (each shown by name and value in the alert):

| Factor | Value | Condition |
|---|---|---|
| Corroboration | +0.10 per additional distinct rule category, at most +0.20 | Other findings on the same entity inside the correlation window (10 min) |
| Recurrence | +0.05 per recurrence, at most +0.10 | The same dedup key fired again after being resolved or in a later window |
| Sensitive target | +0.10 | The target is the gateway, a configured DNS server, or this computer |
| User marked known | −0.20 | The entity is annotated "known" (device annotation) |
| Reduced coverage | −0.10 and confidence capped at `medium` | More than 1% of events were dropped during the window |
| Self-activity share | rule-specific, down to suppression | Part of the evidence came from TAPNETTRACK's own scan |

Properties that are tested: the score is deterministic, monotonic non-decreasing in severity and in
confidence, always within 0 to 100, and reproducible when the same file is replayed. No Phase 4 rule has
base severity `critical`: passive metadata alone cannot establish critical impact, so the level is
reserved.

Worked example: a vertical port scan pattern (severity `medium`, confidence `high`) with one corroborating
sweep from the same source (+0.10) and the gateway as target (+0.10): `100 × 0.50 × 1.00 × 1.20 = 60`.
The alert shows: "Severity medium. Confidence high (86% of 41 probes unanswered). Score 60 = 0.50 × 1.00 ×
1.20; factors: corroboration +0.10 (host sweep), sensitive target +0.10 (gateway)."

The UI states beside every score: "A score orders alerts. It is not a probability of harm."

### 2.3 Device risk profile

For a device, the profile score combines its open and recent alerts without letting many weak alerts exceed
one strong one:

```
device_risk = round(100 × (1 − Π over alerts i of (1 − s_i/100 × d_i)))
d_i = 0.5 ^ (age_days_i / half_life_days)      half_life_days default 7, range 1..90
```

Only alerts in states `open`, `acknowledged` or `investigating` count, plus resolved ones within the decay.
`false_positive` and `suppressed` count zero. The profile lists each contributing alert with its `s_i` and
`d_i`.

## 3. Telemetry required

| Event | Existing fields | New tshark fields needed |
|---|---|---|
| `FlowOpened`, `FlowRetired` | Everything in `FlowRecord` | none |
| `DnsObserved` | `dns.qry.name`, `dns.flags.response`, `dns.a`, `dns.aaaa` | `dns.flags.rcode`, `dns.qry.type` |
| `IcmpObserved` | `ip.proto` (transport), `frame.len` | `icmp.type`, `icmp.code`, `icmpv6.type` |
| `ArpObserved` | `frame.protocols` (contains `arp`), `eth.src`, `eth.dst` | `arp.opcode`, `arp.src.hw_mac`, `arp.src.proto_ipv4`, `arp.dst.proto_ipv4` |
| `TickSummary` | `FlowPacket.length`, addresses | none |

That is 9 new fields. Each is appended to `FLOW_FIELDS`, so existing column positions stay valid.

## 4. Default state at a glance

| Default on | Default off until noise is measured |
|---|---|
| REC-001, REC-002, REC-003, TRF-003, DNS-001, DNS-002, DNS-003, DEV-001, DEV-003, DEV-004, APP-003, APP-004 | REC-004, REC-005, TRF-001, TRF-002, TRF-004, TRF-005, TRF-006, DNS-004, DNS-005, DNS-006, DEV-002, DEV-005, DEV-006, APP-001, APP-002 |

Baseline-dependent rules (TRF-001, TRF-002, TRF-004, TRF-005, DEV-005, DEV-006, APP-001) additionally need a
ready baseline.

## 5. Rule catalogue

Format for each rule: category, logic, telemetry, parameters (default [min, max]), window, severity,
confidence, false-positive risks, evidence, blind spots, test cases. "Evidence" is what is copied into
`alert_evidence` (flow tuples are copied, not referenced, because flows are pruned).

### 5.1 Reconnaissance-like activity

#### TT-REC-001 Vertical port scan pattern
* **Category:** reconnaissance.
* **Logic:** per (source IP, destination IP), count distinct destination ports of TCP flows the source
  initiated (`syn` basis). Fire when the count reaches the threshold inside the window. Compute the
  failed-attempt ratio from `FlowRetired`/unanswered-after-5-s checks.
* **Telemetry:** `FlowOpened`, `FlowRetired`. UDP and SCTP are not counted in Phase 4.
* **Parameters:** `distinct_ports` 20 [5, 1000]; `window_s` 60 [10, 3600]; `high_confidence_failed_ratio` 0.8 [0.5, 1.0].
* **Window:** `window_s`, sliding.
* **Severity:** medium. Escalates to high when distinct ports ≥ 10 × threshold.
* **Confidence:** high if failed ratio ≥ 0.8; medium if 0.4 to 0.8; low if most attempts were answered (an
  application using many ports looks like this).
* **False-positive risks:** peer-to-peer clients, FTP passive and RPC dynamic ports, health checkers and
  load balancers, an authorised vulnerability scanner run by the owner.
* **Evidence:** source, destination, number of distinct ports, port list as ranges (first 50 ranges),
  failed ratio, first and last time, up to 20 flow tuples with their final state.
* **Blind spots:** slow scans spread over longer than the window; scans split across several sources; UDP
  scans; scans that never crossed this vantage point; a source seen only from a Wi-Fi vantage when targets
  are other LAN hosts.
* **Tests:** 19 ports → no alert; 20 ports → alert; 20 ports over 61 s → no alert; repeated same port counts
  once; 85% failed → confidence high, 30% failed → low; 200 ports → severity high; flows from the local
  discovery scan are excluded and counted; file replay and live replay produce identical alerts.

#### TT-REC-002 Host sweep pattern
* **Category:** reconnaissance.
* **Logic:** per source, count distinct destination hosts probed on the same (transport, destination port),
  or ICMP echo requests, inside the window. Record whether the destinations are consecutive addresses.
* **Telemetry:** `FlowOpened`, `FlowRetired`, `IcmpObserved` (type 8, 128).
* **Parameters:** `distinct_hosts` 25 [5, 1000]; `window_s` 60 [10, 3600]; `sequential_share` 0.6 [0.3, 1.0].
* **Severity:** medium.
* **Confidence:** high if ≥ 80% unanswered and ≥ `sequential_share` of destinations are consecutive; medium if
  only one holds; low if the destinations answered (service discovery looks like this).
* **False positives:** inventory and monitoring tools, printer/Chromecast/IoT discovery in apps, backup
  software locating peers, game LAN discovery, endpoint protection scans.
* **Evidence:** source, port or ICMP, number of hosts, address range summary, answered/unanswered counts, sample tuples.
* **Blind spots:** probes to hosts the vantage cannot see; multicast/broadcast discovery (counted separately,
  never as a sweep); IPv6 sweeps of a /64 are not feasible and not detected.
* **Tests:** 24 vs 25 hosts; ICMP echo variant; non-sequential answered destinations → low; sweep started by
  TAPNETTRACK's own scan → excluded; only multicast destinations → no alert.

#### TT-REC-003 ARP sweep pattern
* **Category:** reconnaissance.
* **Logic:** per sender MAC, count distinct target IPs in ARP requests inside the window. Exclude address
  conflict probes (sender IP `0.0.0.0`, at most 3 targets) and the gateway.
* **Telemetry:** `ArpObserved` (new).
* **Parameters:** `distinct_targets` 30 [5, 1000]; `window_s` 30 [5, 600].
* **Severity:** medium. **Confidence:** medium if ≥ `sequential_share` consecutive; low otherwise. (ARP replies are
  unicast and usually invisible from a client vantage, so "unanswered" is not used.)
* **False positives:** router/AP housekeeping, network scanners and inventory tools, a freshly joined device
  refreshing its table, hypervisor hosts.
* **Evidence:** sender MAC and vendor, targets as ranges, request count, time span.
* **Blind spots:** a switch that does not flood broadcasts to this port; captures on a different VLAN.
* **Tests:** 29 vs 30 targets; probe pattern excluded; own discovery scan excluded.

#### TT-REC-004 Repeated connection attempts to one service
* **Category:** reconnaissance (default off).
* **Logic:** per (source, destination, destination port) count TCP flows opened in the window with at least
  half failed or shorter than 2 s. This pattern also fits password guessing, but the engine cannot see
  authentication, so the alert never claims it.
* **Parameters:** `attempts` 30 [10, 1000]; `window_s` 120 [30, 3600]; `short_flow_s` 2 [0.5, 30].
* **Severity:** low; medium if attempts ≥ 5 × threshold **and** the port is in the labelled "remote
  administration" hint list (22, 23, 3389, 5900, 445). The list is a port hint stated in the evidence, not an
  identification of the service.
* **Confidence:** medium if ≥ 80% failed, low otherwise.
* **False positives:** a client retry loop against an unavailable server, misconfigured mail/chat clients,
  health checks, VPN reconnect storms.
* **Evidence:** tuple, attempts, failed share, duration histogram, first/last time.
* **Blind spots:** attempts over one long-lived connection (many guesses, one flow), TLS-wrapped services.
* **Tests:** 29 vs 30; the port hint escalates severity; successful long flows do not count as short.

#### TT-REC-005 Sequential port access
* **Category:** reconnaissance (default off, supporting rule).
* **Logic:** at least 10 flows from one source to one destination inside the window whose destination ports form
  ascending or descending runs of step 1 covering ≥ 70% of the flows.
* **Parameters:** `min_flows` 10 [5, 200]; `run_share` 0.7 [0.4, 1.0]; `window_s` 60 [10, 600].
* **Severity:** low. **Confidence:** medium. When REC-001 fires on the same pair, this rule's finding is merged into
  that alert as evidence instead of raising a second alert. **M3 decision: the merge adds no corroboration factor** (section 9).
* **False positives:** ephemeral client port ranges are source ports, not destination ports, so they do not
  match; sequential service ports (for example a cluster using consecutive ports) can.
* **Evidence:** ports in order with timestamps. **Blind spots:** randomised scan order (by design not detected).
* **Tests:** ordered scan; shuffled ports → no alert; merged into REC-001 when both fire.

### 5.2 Traffic anomalies

#### TT-TRF-001 Outbound volume spike (baseline)
* **Category:** traffic anomaly (default off). Requires direction known (live session) and a ready baseline.
* **Logic:** bytes sent by a local device per 60 s window compared with its baseline median and median
  absolute deviation. Fire when value ≥ `abs_min_bytes` and value ≥ median + `k` × 1.4826 × MAD and value ≥
  `ratio_min` × median.
* **Telemetry:** `TickSummary` host counters; flows for evidence.
* **Parameters:** `abs_min_bytes` 52,428,800 (50 MiB) [1 MiB, 100 GiB]; `k` 6 [3, 20]; `ratio_min` 5 [2, 100]; `window_s` 60 [10, 600].
* **Severity:** low; medium if value ≥ 20 × median.
* **Confidence:** medium with at least 240 baseline windows (4 h); low with 60 to 239; below 60 the rule is not evaluated.
* **False positives:** backups, cloud sync, video calls, software updates, an intentional large upload.
* **Evidence:** window bytes, baseline median and MAD, sample count, top 5 destinations by bytes with their
  names where evidence exists, applications involved.
* **Blind spots:** encrypted content is never inspected; baseline drift; a first session after a long gap.
* **Tests:** below `abs_min_bytes` never fires; spike on a stable baseline fires; noisy baseline (high MAD) does not; baseline not ready → "not evaluated"; file replay never updates the baseline.

#### TT-TRF-002 Large outbound transfer to a destination not seen before (baseline)
* **Category:** traffic anomaly (default off). Direction known and baseline ready.
* **Logic:** an off-link flow with `bytes_fwd` ≥ `min_bytes`, forward-to-reverse ratio ≥ `ratio`, whose
  destination IP and name evidence are not in the device's baseline peer set.
* **Parameters:** `min_bytes` 104,857,600 (100 MiB) [10 MiB, 100 GiB]; `ratio` 20 [5, 1000].
* **Severity:** low; medium at ≥ 1 GiB. **Confidence:** low; medium if the destination also has no name evidence (no SNI, no HTTP host, no DNS answer).
* **Wording:** "Large outbound transfer to a destination not seen before." The word "exfiltration" is not used.
* **False positives:** cloud backups, video upload, `git push`, game updates uploading telemetry.
* **Evidence:** flow tuple, bytes each way, duration, destination name evidence or "none", first-seen status of the destination.
* **Blind spots:** many small transfers; traffic through a VPN or a known cloud provider; peers learned with IP churn (CDNs).
* **Tests:** just under and over `min_bytes`; known peer → no alert; ratio below 20 → no alert; unknown direction (file) → not evaluated.

#### TT-TRF-003 High connection failure rate
* **Category:** traffic anomaly (default on).
* **Logic:** per source, failed TCP attempts ÷ attempts inside the window, with a minimum attempt count.
* **Parameters:** `min_attempts` 30 [10, 5000]; `failed_ratio` 0.5 [0.2, 1.0]; `window_s` 120 [30, 3600]. IPv6 attempts that were abandoned within 300 ms while an IPv4 flow to the same name succeeded are not counted (dual-stack fallback).
* **Severity:** low; medium at ≥ 200 attempts. **Confidence:** medium.
* **False positives:** an offline service, firewall drops, VPN reconnect storms, captive networks.
* **Evidence:** attempts, failures, top destinations by failure count, tuples.
* **Blind spots:** UDP failures are invisible; "failed" is inferred from handshake bits.
* **Tests:** 29 vs 30 attempts; 49% vs 50%; dual-stack fallback excluded.

#### TT-TRF-004 Connection frequency spike (baseline)
* **Category:** traffic anomaly (default off). Baseline ready.
* **Logic:** new flows per minute per source against baseline median and MAD, with an absolute floor.
* **Parameters:** `abs_min_per_min` 120 [30, 100000]; `ratio_min` 8 [3, 200]; `window_s` 60 [30, 600].
* **Severity:** low. **Confidence:** low; medium if the baseline has ≥ 240 windows.
* **False positives:** opening a web page with many resources, torrent clients, application start-up.
* **Evidence:** rate, baseline stats, top destinations. **Blind spots:** same as TRF-001.
* **Tests:** floor respected; ratio respected; baseline not ready → not evaluated.

#### TT-TRF-005 Protocol not previously seen for this device (baseline)
* **Category:** traffic anomaly (default off). Baseline ready.
* **Logic:** the decoded protocol of a flow (Phase 3 `protocol`) is not in the device's baseline protocol set,
  with at least `min_flows` flows and `min_bytes` bytes. Reported once per device per protocol per day.
* **Parameters:** `min_flows` 3 [1, 100]; `min_bytes` 10,240 [0, 1 GiB]; bucket one day (fixed).
* **Severity:** info. **Confidence:** low; medium when the protocol is on the "management/legacy" hint list (telnet, ftp, smb, rdp, vnc, snmp).
* **False positives:** any new application. **Evidence:** protocol, first flow, bytes, peers. **Blind spots:** protocol identity comes from tshark's decoding; encrypted payloads are only "tls".
* **Tests:** repeat in the same day → one alert; below `min_flows` → none.

#### TT-TRF-006 Regular-interval connections (beacon-like)
* **Category:** traffic anomaly (experimental, default off).
* **Logic:** per (source, destination IP, destination port), at least `min_events` flow openings whose
  inter-arrival coefficient of variation ≤ `max_cv` and mean interval between `min_interval_s` and
  `max_interval_s`, and whose bytes per flow are similar (CV ≤ 0.25).
* **Parameters:** `min_events` 10 [6, 100]; `max_cv` 0.1 [0.01, 0.5]; `min_interval_s` 5 [1, 3600]; `max_interval_s` 3600 [10, 86400].
* **Severity:** info. **Confidence:** low. **Wording:** "Regular-interval connections", never "beaconing".
* **False positives:** NTP, update checks, monitoring agents, chat keep-alives, IoT heartbeats, mail polling, telemetry from the operating system.
* **Evidence:** interval list (first 30), mean, CV, bytes per flow.
* **Blind spots:** jittered or slow intervals; traffic to CDNs; intervals longer than the window the session lasts.
* **Tests:** exact 30 s interval fires; ±40% jitter does not; fewer than 10 events does not.

### 5.3 DNS intelligence

DNS is attributed to the **client** (query source). If the client uses a forwarding router, only the router
is visible as the client; the alert says so.

#### TT-DNS-001 High DNS query rate
* **Logic:** queries per client per window ≥ threshold, or ≥ `ratio_min` × baseline median when a baseline is ready. (M4: the baseline branch is not active; see section 10.)
* **Telemetry:** `DnsObserved` (queries). mDNS (port 5353, `.local`) and LLMNR are excluded and counted.
* **Parameters:** `queries` 300 [30, 100000]; `window_s` 60 [10, 3600]; `ratio_min` 8 [3, 100].
* **Severity:** low. **Confidence:** low; medium if the unique-name count ≥ 50% of queries.
* **False positives:** browser prefetch, ad-heavy pages, application start-up, torrent clients, security software.
* **Evidence:** counts, unique names, top 10 names, query types.
* **Blind spots:** encrypted DNS (DoH/DoT) is invisible; a forwarding router hides the real client.
* **Tests:** 299 vs 300; mDNS excluded; repeated identical name counts as queries but not unique names.

#### TT-DNS-002 High NXDOMAIN rate
* **Logic:** per client, responses with rcode 3 (NXDOMAIN) ÷ responses inside the window, with a minimum response count.
* **Telemetry:** `DnsObserved.rcode` (new). Responses are matched to queries by client, server and name inside the window.
* **Parameters:** `min_responses` 20 [10, 5000]; `nxdomain_ratio` 0.5 [0.2, 1.0]; `window_s` 120 [30, 3600].
* **Severity:** low; medium if NXDOMAIN ≥ 100 and unique failing names ≥ 50.
* **Confidence:** medium if unique failing names ≥ 50% of NXDOMAIN responses; low otherwise.
* **False positives:** search-suffix expansion, WPAD/captive probes, local names resolved against public DNS, stale bookmarks, ad blockers returning NXDOMAIN by design (a resolver that blocks by NXDOMAIN makes this rule noisy; the evidence lists the resolver).
* **Evidence:** responses, NXDOMAIN count, unique names (first 20), resolver.
* **Blind spots:** DoH/DoT; resolvers that answer 0.0.0.0 instead of NXDOMAIN.
* **Tests:** 19 vs 20 responses; ratio boundary; builder with rcode 3 decoded by the real tshark.

#### TT-DNS-003 Many unique subdomains under one parent domain
* **Logic:** per (client, parent domain), distinct query names inside the window ≥ threshold. The parent domain
  uses a bundled public-suffix list (source and licence recorded when added); without it the rule falls back to the last two labels and says so.
* **Parameters:** `unique_names` 50 [10, 5000]; `window_s` 300 [60, 3600].
* **Severity:** medium. **Confidence:** medium if the mean first-label length ≥ 25 or most queries are TXT/NULL/CNAME types; low otherwise.
* **Wording:** "Many unique names under one domain (pattern also seen in DNS tunnelling)".
* **False positives:** content networks with hashed host names, security/anti-spam lookups, operating-system telemetry, cloud storage endpoints.
* **Evidence:** parent domain, count, mean label length, 20 sample names, query types.
* **Blind spots:** slow tunnels; tunnels that reuse a small set of names; DoH.
* **Tests:** 49 vs 50; a different parent resets the count; suppression per parent domain works. (M4: suppression waits for M9; separate findings per client and parent are tested instead.)

#### TT-DNS-004 Long or high-entropy query names
* **Logic:** at least `count` queries from one client in the window whose first label has length ≥ `min_label_len`
  or Shannon entropy ≥ `entropy_bits` with length ≥ 16. Excludes `.local`, `.arpa`, service-discovery names (`_tcp`, `_udp`).
* **Parameters:** `count` 10 [3, 1000]; `min_label_len` 40 [20, 63]; `entropy_bits` 3.8 [3.0, 5.0]; `window_s` 300 [60, 3600].
* **Severity:** low. **Confidence:** low (entropy alone is a weak indicator). Default off.
* **False positives:** CDN and cloud host names, anti-virus and reputation lookups, tracking identifiers.
* **Evidence:** sample names, lengths, entropies. **Blind spots:** word-list generators produce low-entropy names; short tunnels.
* **Tests:** English words below, random base32 above; `.local` excluded.

#### TT-DNS-005 Unusual query types
* **Logic:** at least `count` queries of type TXT (16), NULL (10) or ANY (255) from one client in the window.
* **Telemetry:** `DnsObserved.qtype` (new).
* **Parameters:** `count` 20 [5, 1000]; `window_s` 300 [60, 3600].
* **Severity:** low. **Confidence:** low; medium if combined with DNS-003 on the same parent (correlation). Default off. (M4: implemented as the distinct-rule corroboration factor; see section 10.)
* **False positives:** mail servers checking SPF/DKIM, service verification, diagnostics.
* **Evidence:** types and counts, names. **Blind spots:** DoH.
* **Tests:** counts per type; correlation raises the factor.

#### TT-DNS-006 DNS sent to a resolver not configured on this interface
* **Logic:** for **this computer** only: DNS requests to a server that is not in the interface's configured DNS servers, its gateway, or a link-local/private resolver. (M4 decision: only explicitly configured servers count as configured; see section 10.)
* **Parameters:** `min_queries` 5 [1, 1000]; `window_s` 600 [60, 3600].
* **Severity:** info. **Confidence:** medium (configuration is known). Default off.
* **False positives:** deliberate public resolver, VPN, WSL/Docker/Hyper-V resolvers, split DNS.
* **Evidence:** resolver address, counts, configured servers at capture time. **Blind spots:** encrypted DNS; traffic of other devices.
* **Tests:** configured server → none; unknown public resolver → alert; file replay (no configuration) → not evaluated.

### 5.4 Device behaviour

#### TT-DEV-001 New device in the inventory
* **Logic:** after a network's inventory has had a completed scan older than `network_age_h`, a discovery scan records a device whose `first_seen` is newer and that is not annotated "known". Runs when a scan finishes (inventory hook).
* **Parameters:** `network_age_h` 24 [0, 720]; `min_inventory_size` 3 [1, 100].
* **Severity:** info. **Confidence:** high that this MAC is new to the inventory; the alert says nothing about what the device is.
* **False positives:** a guest's phone, a randomised-MAC phone that rotates its address (flagged `mac_randomized` and shown as such), a new appliance.
* **Evidence:** MAC, vendor, randomised flag, first-seen time, scan id, source and confidence of the observation.
* **Blind spots:** devices that do not answer discovery; a cloned MAC.
* **Tests:** first scan on a network → no alerts; second scan finds a new MAC → one alert; known annotation → none; randomised MAC labelled.

#### TT-DEV-002 MAC seen in traffic but not in the inventory
* **Logic:** a frame source MAC from the on-link trust rule (`DeviceResolver`: a packet MAC is trusted only for local or on-link addresses) that is absent from `devices`, seen in at least `min_packets` packets.
* **Parameters:** `min_packets` 5 [1, 1000]; `window_s` 600 [60, 86400].
* **Severity:** info. **Confidence:** medium. Default off: experimental until measured on a Wi-Fi vantage.
* **False positives:** inventory not refreshed, routers' secondary MACs, virtual MACs.
* **Evidence:** MAC, vendor, protocols seen, packet count. **Blind spots:** a client vantage sees few third-party MACs (mostly broadcast); promiscuous mode on switched networks sees little more.
* **Tests:** off-link MAC (router) ignored; on-link unknown MAC alerts; inventory MAC ignored.

#### TT-DEV-003 One IP claimed by more than one MAC
* **Logic:** inside `window_s`, an IPv4 address is claimed by ≥ 2 distinct MACs in ARP sender fields, or an on-link flow's trusted MAC contradicts the inventory MAC for that IP (the `device_note` condition from Phase 3), with the contradiction repeating.
* **Parameters:** `window_s` 600 [60, 86400]; `min_sightings` 2 [2, 50]; `flip_count_high` 3 [2, 20].
* **Severity:** medium; high if the IP is the gateway or the claim alternates ≥ `flip_count_high` times.
* **Confidence:** medium; high only if both MACs sent ARP replies for the IP alternately. Locally administered MACs are noted.
* **Wording:** "The same IP address was announced by two different MAC addresses." It is **not** called ARP spoofing.
* **False positives:** DHCP lease reuse, VRRP/HSRP virtual MACs, NIC teaming, Wi-Fi repeaters that rewrite MACs, hypervisor switches, a device with a wired and a wireless MAC.
* **Evidence:** IP, MACs with vendor, ordered sightings with time and source (ARP or flow), inventory MAC.
* **Blind spots:** claims that never crossed this vantage; IPv6 (NDP is not extracted in Phase 4).
* **Tests:** one claim → none; two MACs one after another with a lease change gap → low confidence; alternating three times → high severity; gateway IP escalates.

#### TT-DEV-004 Gateway MAC changed
* **Logic:** the MAC observed for a gateway IP (from the session's saved gateways plus ARP/flow evidence) differs from the last stored gateway MAC for that network.
* **Parameters:** none beyond `enabled`. The last gateway MAC is stored per network (`device_annotations`/baseline, see the database design).
* **Severity:** high. **Confidence:** medium; high if it flips back within the window.
* **False positives:** router replacement or reset, failover pairs, ISP equipment swap, mesh networks.
* **Evidence:** gateway IP, old and new MAC with vendors, times, evidence source, whether the vendor changed.
* **Blind spots:** first session on a network has no previous value (not evaluated); gateways learned only from interface data.
* **Tests:** same MAC → none; changed → alert; first session → not evaluated; user "known" annotation lowers the factor.

#### TT-DEV-005 New communication relationship on the local network (baseline)
* **Logic:** an on-link private peer (device or IP) that a device has not exchanged flows with in its baseline, with ≥ `min_flows` flows. External destinations are deliberately excluded (new external destinations are ordinary).
* **Parameters:** `min_flows` 3 [1, 100]; `baseline_days_min` 3 [1, 90]. Digest bucket one day.
* **Severity:** low. **Confidence:** low. Default off.
* **False positives:** any new LAN interaction (printing, file share, casting). **Evidence:** pair, first flow, protocols, bytes.
* **Blind spots:** only relationships that crossed the vantage are known; a Wi-Fi client sees its own relationships only.
* **Tests:** known peer → none; new peer → one digest alert per day.

#### TT-DEV-006 Newly observed listening service (baseline)
* **Logic:** (a) a local or on-link host answers a SYN with SYN-ACK from port P and (host, P) is not in the baseline set; or (b) for this computer, a connection initiated by another host is accepted on a port not previously listening.
* **Parameters:** `min_connections` 2 [1, 100].
* **Severity:** low; medium if the initiator is off-link (inbound from the Internet).
* **Confidence:** high that a service answered (handshake observed); the meaning is unknown.
* **False positives:** file sharing, casting, development servers, game hosting, updates delivery optimisation.
* **Evidence:** host, port, initiator, handshake bits, first time. **Blind spots:** services that never received a connection during capture; UDP services.
* **Tests:** inbound accepted port in baseline → none; new port → alert; off-link initiator escalates.

### 5.5 Application and protocol intelligence

#### TT-APP-001 Application not previously seen for this device (baseline)
* **Logic:** a flow application (confidence `confirmed` or `probable`) not in the device's baseline application set, with ≥ `min_flows` flows and ≥ `min_bytes` bytes. One digest alert per device per day listing the new applications.
* **Parameters:** `min_flows` 3 [1, 100]; `min_bytes` 10,240 [0, 1 GiB].
* **Severity:** info. **Confidence:** the flow's own classification confidence, capped at `medium`. Default off.
* **False positives:** any newly installed or newly used application. **Evidence:** application names with classification method and evidence lines from Phase 3, flows, bytes. **Blind spots:** applications Phase 3 does not know are "Unclassified" and never trigger this rule.
* **Tests:** unclassified traffic never alerts; digest groups several apps.

#### TT-APP-002 Decoded protocol on an unusual port
* **Logic:** tshark decoded protocol P (from `layers`) among {dns, http, tls, ssh} on a destination port outside that protocol's usual set (static, small, shown in the rule).
* **Parameters:** `min_flows` 3 [1, 100]; usual-port sets are part of the rule definition and displayed read-only.
* **Severity:** info. **Confidence:** medium. Default off.
* **False positives:** development servers, self-hosted services, media servers, VPN-like tools.
* **Evidence:** protocol, port, tuple, first time. **Blind spots:** tshark only decodes by heuristic for some protocols; a tunnelled protocol appears as its carrier.
* **Tests:** TLS on 8443 allowed by the usual set; TLS on 31337 alerts; port-53 non-DNS is not claimed.

#### TT-APP-003 Unusually large or sustained ICMP exchange
* **Logic:** an ICMP or ICMPv6 flow with ≥ `packets` packets, or mean packet length ≥ `mean_len` bytes with ≥ 50 packets, or ≥ `bytes` bytes, inside the window.
* **Parameters:** `packets` 1000 [100, 1000000]; `mean_len` 200 [100, 1500]; `bytes` 1,048,576 [65536, 1 GiB]; `window_s` 120 [30, 3600].
* **Severity:** low. **Confidence:** low (payload is not inspected). **Wording:** "Unusually large or sustained ICMP exchange".
* **False positives:** ping with large payload, path-MTU tests, monitoring, VPN keep-alives.
* **Evidence:** tuple, packets, bytes, mean length, ICMP types (when extracted). **Blind spots:** small covert payloads; ICMP errors that quote other packets.
* **Tests:** 999 vs 1000 packets; mean length rule needs the 50-packet floor.

#### TT-APP-004 Cleartext protocol in use
* **Logic:** a flow whose decoded layers include one of: telnet, ftp, tftp, rlogin, rsh, pop, imap (without TLS), snmp (v1/v2c), ldap (without TLS). Reports the **protocol name only**. No content, no credentials, no command text is requested from tshark or stored.
* **Parameters:** `min_flows` 1 [1, 100]; `protocols` (subset toggles).
* **Severity:** low. **Confidence:** high that the protocol was decoded; the alert states that the protocol carries data unencrypted, not that anything sensitive was sent.
* **False positives:** lab or legacy equipment, intentional local tests. Plain HTTP is excluded on purpose (ubiquitous, captive portals).
* **Evidence:** protocol, endpoints, bytes, first time. **Blind spots:** protocols on non-standard ports that tshark does not decode.
* **Tests:** each protocol builder decoded by real tshark; HTTP never alerts; content never appears in evidence (asserted by scanning stored evidence for the builder's payload bytes).

## 6. Baselines

* **Learned from:** live sessions only, on the same network (interface network CIDR and gateway MAC). Opened files may
  *use* a baseline but never *update* it.
* **Stored per device:** bounded sets (protocols ≤ 64, applications ≤ 128, on-link peers ≤ 512, listening
  ports ≤ 128, external peers ≤ 1,024, exact sets with least-recently-used eviction) and bounded series (bytes out
  and new flows per 60 s window, last 1,440 windows, median and MAD recomputed at run end).
* **Ready when:** cumulative live capture ≥ `baseline_hours_min` (default 4 h) **and** ≥ `baseline_sessions_min`
  (default 2) sessions on that network, **and** the device was seen in ≥ 60 windows. Until then the dependent rules
  report "not evaluated (baseline not ready)" on the Rules screen and on the Overview.
* **Reset:** per device and per network, with confirmation. A baseline can be disabled for a device annotated "ignore".
* **Poisoning limits:** windows that produced an open alert from a baseline rule are excluded from the baseline update, so a
  sustained anomaly does not become "normal" automatically.

## 7. Suppression and annotation

* **Per-entity rule suppression:** (rule, entity key, reason, optional expiry). Findings are still counted in History.
* **Device annotation:** role (`gateway`, `dns_server`, `server`, `printer`, `iot`, `workstation`, `unspecified`),
  trust (`unreviewed`, `known`, `ignored`). Role affects the "sensitive target" factor; `known` lowers context;
  `ignored` silences baseline rules for that device. Annotations are the user's statements and are labelled as such.

## 8. Rule-level testing standard

Every rule ships with:

1. Boundary unit tests: threshold − 1, threshold, threshold + 1, and window − 1 s / window + 1 s.
2. A deterministic fixture (hand-built events) and, where fields are new, a byte-built PCAPNG decoded by the real tshark.
3. A benign near-miss fixture that must **not** alert (listed in the rule above).
4. A serialisation test: the stored alert round-trips with evidence, factors and wording-policy checks (no banned words, at
   least one benign explanation and one blind spot).
5. A replay-equivalence test: live-style replay and file load give identical alerts.
6. A bounded-state test: 10,000 sources do not exceed the state cap, and the cap is reported.

## 9. M3 implementation record (approved resolutions and exact behaviour)

M3 implements TT-REC-002, TT-REC-003, TT-REC-004, TT-REC-005, TT-TRF-003, TT-TRF-006, TT-APP-002, TT-APP-003 and
TT-APP-004. Where the catalogue above was open, the project owner approved the resolutions below. All thresholds remain
initial defaults to be calibrated (M11); none has been validated on a labelled dataset.

**Default state, and what the product can change.** On by default: REC-002, REC-003, TRF-003, APP-003, APP-004 (and
REC-001). Off by default: **REC-004, REC-005, TRF-006, APP-002**. The product has no way to switch a rule on or change a
parameter until the rule-settings screen and API of M9 exist; the engine reads its settings from `RuleSettings`, and M3
does not read the `detection_rules` table. The four default-off rules are therefore exercised by tests only. Values
below are the defaults, with the allowed range in brackets.

**Cross-rule behaviour**

* **How a TCP attempt is judged (TT-REC-001, -002, -004, TT-TRF-003).** The flow engine publishes `FlowResponded` on the
  first reply to a seen bare SYN (`established`, `refused` or `answered`), so a connection that is still open is resolved
  when its handshake is seen, not when it retires. A flow that finished is judged from its record: SYN-ACK or replies seen is
  answered (replies without a captured SYN-ACK are an asymmetric capture, not a failure); a reset with at most two responder
  packets is failed (as in M2); nothing back is silent. A silent or pending-after-5-s attempt is *failed* only when the
  capture has shown at least one TCP reply or echo reply in the run; otherwise it is *unknown*. Attempts under 5 s old are
  *pending*. Pending and unknown attempts are in neither the failed count nor the attempt count. `observed` carries
  `answered`, `failed`, `unanswered_provisional`, `pending_recent` and `unknown`.

* **Corroboration counts distinct rule IDs on the same entity, not categories.** Two different rules of one category
  corroborate each other (+0.10 each, at most +0.20). A rule never corroborates itself.
* **Own scan activity.** A discovery scan started from TAPNETTRACK is recorded (`SelfActivity`, in memory, 64 scans, 1 h).
  For a live capture only, TT-REC-001, -002, -003 and -005 ignore packets sent from this computer's own MAC address (and,
  for echo requests, its own IP address) while a scan is running (plus or minus 2 s) and the engine counts
  them (`self_activity_excluded`, once per event). There is no permanent
  exclusion of the local host. An opened file never uses this record, because its packet times are not this computer's
  clock.
* **Merging a supporting rule (TT-REC-005).** A finding of a rule with `supports = TT-REC-001` is not an alert of its own.
  If an open TT-REC-001 alert exists for the same source and target it is added to that alert as up to three evidence
  items (replacing what the rule merged before) and storage receives an update of the scan alert. Otherwise it is held,
  measured in packet time, for the rule's `window_s` after the finding's last packet. When TT-REC-001 fires during the hold
  the held finding is merged into it. When the hold passes, or the run ends, it is reported on its own. At most 1,000
  findings are held; the oldest is released early (`held_released_early`). The merge adds no corroboration factor.

**TT-REC-002 Host sweep pattern** (on, medium). `distinct_hosts` 25 [5, 1000]; `window_s` 60 [10, 3600];
`sequential_share` 0.6 [0.3, 1.0]. Counts distinct destinations of TCP bare-SYN connections on one destination port, and of
ICMP/ICMPv6 echo requests (types 8 and 128; replies 0 and 129 only answer). UDP is not counted. Multicast and broadcast
destinations are not hosts; they are counted in `multicast_or_broadcast_ignored`. Sequential share = adjacent sorted IPv4
pairs that differ by 1, divided by (distinct hosts minus 1), so IPv6 hosts dilute it. Confidence: high if at least 80% are
unanswered **and** sequential; medium if only one holds; low otherwise. Up to 1,024 hosts per source and port are kept;
beyond that the alert says "at least N". *Known noise:* ordinary browsing to 25 or more hosts on one port is a
low-confidence finding (risk 25); calibration is M11 work, and the volume on the reference capture is in the verification
record.

**TT-REC-003 ARP sweep pattern** (on, medium). `distinct_targets` 30 [5, 1000]; `window_s` 30 [5, 600];
`sequential_share` 0.6. Per sender MAC, distinct targets of ARP requests. Medium confidence if the targets are sequential
(share at least the setting), else low. Excluded: address-conflict probes (sender IP 0.0.0.0 with at most 3 distinct
targets), requests for the default gateway, and requests whose sender is the gateway address. Evidence shows the MAC and
whether it is locally administered; **no vendor lookup**. Up to 1,024 targets per sender.

**TT-REC-004 Repeated connection attempts to one service** (off, low). `attempts` 30 [10, 1000]; `window_s` 120 [30, 3600];
`short_flow_s` 2.0 [0.5, 30]. Per (source, destination, port). A *bad* attempt is a failed one (SYN with no SYN-ACK, or a
quick reset) or an answered one shorter than `short_flow_s`. Fires when bad x 2 >= attempts. Attempts still pending are not
bad. Severity medium at 5 x `attempts` or more **and** port 22, 23, 445, 3389 or 5900 (a hint, stated as such);
otherwise low. Confidence medium if failed / attempts >= 0.8, else low. The text never says password, credential or guess.

**TT-REC-005 Sequential port access** (off, low, confidence medium). `min_flows` 10 [5, 200]; `run_share` 0.7 [0.4, 1.0];
`window_s` 60 [10, 600]. Per (source, destination), in the order the connections were seen: ports that step by +1 (or by -1)
form a run of at least 2; the finding needs min_flows connections in the window and runs covering at least `run_share` of
them. Up to 1,024 connections per pair. Merging: see above.

**TT-TRF-003 High connection failure rate** (on, low; medium at 200 or more attempts; confidence medium).
`min_attempts` 30 [10, 5000]; `failed_ratio` 0.5 [0.2, 1.0]; `window_s` 120 [30, 3600]. Failure means what it means for
TT-REC-001, including that an attempt with no outcome 5 s after it started counts as unanswered (provisionally).
*Dual-stack approximation:* an IPv6 attempt that lasted 0.3 s or less, followed within 1 s of its last packet by a completed
IPv4 connection from the same source to the same destination port, is excluded from both counts and counted in
`dual_stack_fallbacks`. This is an approximation, **not hostname correlation**, and no DNS telemetry was added for it.
Up to 4,096 attempts per source.

**TT-TRF-006 Regular-interval connections** (off, experimental, info severity, low confidence). `min_events` 10 [6, 100];
`max_cv` 0.1 [0.01, 0.5]; `min_interval_s` 5 [1, 3600]; `max_interval_s` 3600 [10, 86400]. Per (source, destination,
port), TCP flows that had a SYN. The gaps are taken from each flow's `first_seen`, sorted, so the order in which flows
retire does not matter. Population coefficient of variation of the gaps <= `max_cv`, mean gap inside the range, and the
bytes per flow similar (CV <= 0.25, mean > 0; a fixed part of the rule). The last 100 flows of a key are kept ("at least"
when more were seen); a key silent for twice `max_interval_s` is dropped; at most 10,000 keys. The wording is "Regular-interval
connections"; it never says beaconing.

**TT-APP-002 Decoded protocol on an unusual port** (off, info severity, medium confidence). `min_flows` 3 [1, 100]. A
decoded application layer on a port outside that protocol's usual set. Usual ports: dns 53, 853, 5353, 5355; http 80, 8000,
8008, 8080, 8888; tls 443, 465, 563, 636, 853, 993, 995, 8443, 9443; ssh 22, 2222. The port alone never classifies: a decoded
layer is required. Agent's guards, flagged for review: a TCP flow needs a SYN; a UDP flow counts only if its destination port is
lower than its source port; the count is per run with a 1 h idle expiry and 10,000 keys. Entity = destination IP; secondary =
`protocol:port`.

**TT-APP-003 Unusually large or sustained ICMP exchange** (on, low, confidence low). `packets` 1000 [100, 1000000];
`mean_len` 200 [100, 1500]; `bytes` 1,048,576 [65,536, 1 GiB]; `window_s` 120 [30, 3600]. Two paths: a rolling per-pair
packet count (1-second buckets from `IcmpObserved`, so a long exchange is found before its flow retires) and per-flow totals
when an ICMP or ICMPv6 flow retires. The mean-length condition needs at least 50 packets. The target is the peer, so the
"sensitive target" factor applies. At most 10,000 pairs and 200,000 buckets.

**TT-APP-004 Cleartext protocol in use** (on, low, confidence high). `min_flows` 1 [1, 100] and one on/off switch
`enable_<protocol>` (0 or 1) for each of telnet, ftp, tftp, rlogin, rsh, pop, imap, ldap. POP, IMAP and LDAP are skipped when
a TLS layer is present. HTTP is not included. **SNMP is not detected**: a decoded SNMP layer cannot tell v1/v2c (cleartext)
from v3 (which can be encrypted), and no extra decoded field was added. Entity = the server (destination IP); secondary = the
protocol. **Evidence is the protocol name, the endpoints, byte counters and flow tuples. Payload bytes are never read into
an event and never stored**; a test searches the database and WAL file bytes for a marker sent in every protocol.

## 10. M4 implementation record (DNS rules, approved decisions and exact behaviour)

M4 implements TT-DNS-001 to TT-DNS-006 and the bundled Public Suffix List. All thresholds are untuned defaults to be
calibrated in M11. **On by default: TT-DNS-001, -002, -003. Off by default: TT-DNS-004, -005, -006**, and the product cannot
switch a rule on until the rule-settings screen and API of M9 exist, so those three are exercised by tests only. No API
endpoint, migration or schema was added; the rules appear in the existing `GET /api/v1/detection/status`.

**Approved decisions that change or settle section 5.3**

1. **Public Suffix List.** The full list is bundled in `app/data/public_suffix_list.dat`. Source, retrieval date, list version,
   MPL-2.0 licence and SHA-256 are in `app/data/README.md` and a test keeps that record equal to the file. The application
   never reads it from the network.
2. **mDNS and LLMNR.** `DnsObserved` now carries `server_port` and `transport`, taken from the packet (no new tshark field).
   A query or answer is multicast name service, and is excluded and counted (`local_name_service_ignored`), when the server
   port is 5353 or 5355 or the server address is multicast.
3. **Hostile names.** The packet parser already keeps every decoded name as inert text (control characters removed, at most 255
   characters). M4 keeps that original text in the event and builds a separate analysis form (`names.normalize`: lowercase, no
   trailing dot, bounded to 512 characters and 128 labels, with a validity flag). An ill-formed name is still counted as an
   observation. Names appear only in an evidence item's `data`, cut to fit its size limit, never in a title, summary, `why` or
   evidence text, so a name such as "attack.example" cannot trip the wording policy or alter a finding's text.
4. **DNS-001 `ratio_min`** (8, 3 to 100) is registered and has no effect; the comparison with a client's own usual rate needs
   baselines (M6). The blind-spot text says so.
5. **DNS-003 and DNS-005** correlate through the existing distinct-rule corroboration (+0.10): both findings are for the same
   client, so they share a correlation group, and both state the parent domain (`parent` and `top_parent`).
6. **Suppression** is deferred to M9. Findings are separate per client and parent domain (DNS-003) so a later suppression can
   target one of them.
7. **DNS-002** counts responses by response code, and uses the question name carried in the response for the set of failing
   names. There are no transaction IDs, so responses are not matched to individual queries.
8. **DNS-006** treats only explicitly configured DNS servers as configured. The gateway, private and link-local addresses are
   not trusted for what they are. This replaces the wording in 5.3.
9. **Noise** is measured and reported, not required to be zero (see `PHASE4_VERIFICATION.md`).
10. **Wording** is cautious ("a pattern also observed in DNS tunnelling"); every DNS blind-spot list names encrypted DNS (DoH and
    DoT).

**Shared behaviour.** DNS is attributed to the client (the source of the query); a forwarding router would be seen as the
client and the blind-spot text says so. Windows are measured in packet time, inclusive at both ends, and judged on each
one-second tick. State is bounded per rule: 10,000 clients (or client and parent pairs), 100,000 entries, 10,000 distinct names per
key; beyond a bound the oldest state goes, the engine counts it (`state_evictions`, `cap_hits`) and the finding says "at least".

**TT-DNS-001 High DNS query rate** (on, low). `queries` 300 [30, 100000]; `window_s` 60 [10, 3600]; `ratio_min` 8 [3, 100] (inert).
Counts queries per client; answers are not counted. Confidence is medium when at least half the queries are for distinct names,
else low. Evidence: counts and query types, the ten most-asked names with counts, the time span.

**TT-DNS-002 High NXDOMAIN rate** (on, low). `min_responses` 20 [10, 5000]; `nxdomain_ratio` 0.5 [0.2, 1.0]; `window_s` 120
[30, 3600]. Counts responses to a client that carry a response code; a response without one is set aside and counted
(`rcode_missing`). Fires when the share with code 3 reaches the ratio. Severity medium at 100 or more NXDOMAIN with 50 or more
different failing names. Confidence medium when different failing names are at least half the NXDOMAIN responses. Evidence:
counts, the first 20 failing names, the resolvers with their response counts.

**TT-DNS-003 Many unique names under one parent domain** (on, medium). `unique_names` 50 [10, 5000]; `window_s` 300 [60,
3600]. Counts distinct normalised query names per (client, parent domain); the parent is the registrable domain from the bundled
list, so `www.example.co.uk` and `shop.example.co.uk` share `example.co.uk` while `one.co.uk` and `two.co.uk` do not. A private
suffix such as `github.io` makes each site its own parent. If the list is not available the last two labels are used and the
finding says so (`suffix_list`: `bundled` or `fallback`). Confidence is medium when the mean first-label length is at least 25 or
more than half the names were asked with TXT, NULL or CNAME queries. Evidence: the parent, the count, the mean label length, 20
sample names, the query types.

**TT-DNS-004 Long or high-entropy query names** (off, low). `count` 10 [3, 1000]; `min_label_len` 40 [20, 63]; `entropy_bits` 3.8
[3.0, 5.0]; `window_s` 300 [60, 3600]. A query qualifies when its first label has at least `min_label_len` characters, or at
least 16 characters and a Shannon entropy of at least `entropy_bits` bits per character. `.local`, `.arpa` and `_tcp`/`_udp`
names are excluded and counted. Evidence: counts and sample names with their first-label length and entropy.

**TT-DNS-005 Unusual query types** (off, low). `count` 20 [5, 1000]; `window_s` 300 [60, 3600]. Counts queries of type TXT (16),
NULL (10) or ANY (255) per client, by type. Only the type of the first question in a packet is read. Evidence: counts by type, the
parent domains, sample names.

**TT-DNS-006 DNS sent to a resolver not configured on this interface** (off, info; live captures only). `min_queries` 5 [1,
1000]; `window_s` 600 [60, 3600]. For this computer only: queries to a server that is not one of the interface's configured DNS
servers, one finding per resolver. If the configured servers are not known nothing is judged and the queries are counted
(`configuration_unknown`). Evidence: the resolver, the count, the configured servers.

**Known limits of these rules**

* tshark gives no name at all for a query whose labels contain bytes above 0x7f, so such a packet is not an observation here.
  Names tshark does decode, including control characters shown as escapes, are counted.
* A Shannon entropy computed over a short label is biased low; 24-character random labels often score under 3.8. DNS-004 will
  miss some of them.
* The Public Suffix List is a dated snapshot and can group a new suffix wrongly.
* DNS-005 reads only the first question of a packet, and DNS-002 does not match responses to queries.
* Encrypted DNS is invisible. A client behind a forwarder is seen as the forwarder.

## 11. M5 and M6: device and baseline rules as implemented

Every rule below is off by default except TT-DEV-001, -003 and -004. None has been validated on labelled real traffic.

| Rule | Default | What differs from section 5 |
|---|---|---|
| TT-DEV-001 | on | Runs from the discovery-scan hook (`inventory_hook.py`): needs an earlier completed scan of the same interface at least `network_age_h` older, and `min_inventory_size` devices known before the scan. Devices marked `known` raise nothing. |
| TT-DEV-002 | off | Counts **flow-opening packets** from the hardware address (`min_packets`), not every frame, because the telemetry carries flow events. Only on-link source addresses are trusted. Needs a live session. |
| TT-DEV-003 | on | Version 2. Two sources: ARP sender fields (low confidence for a single change of hardware address, medium for repeated changes, severity high for the gateway or from `flip_count_high` changes), and flow-opening packets from an on-link address other than this computer whose frame hardware address differs from the one the inventory holds for that address as its **current** address (an address a device used earlier does not count, so a reused lease is not a contradiction). The contradiction must repeat `min_sightings` times inside `window_s`; confidence is low, evidence is labelled `inventory` and `observed`. Wording never says "spoofing". |
| TT-DEV-004 | on | Compares the first hardware address seen for the gateway with the one stored for the network by an earlier live session. The first live session on a network stores it and raises nothing. A hardware address that is later accepted as new is stored at the end of a live session. |
| TT-TRF-001, -004 | off | Version 2. Evidence now lists the five busiest destinations of the window: TT-TRF-001 by bytes sent from flows that **finished** inside the window, TT-TRF-004 by connections opened. A transfer still open when the window ended is not counted and the evidence says so (`complete: false`); with none known it says no destination is known. At most 64 destinations per device and window are tracked. A device with fewer than 60 baseline windows is skipped and counted (`no_baseline`). Confidence is medium from 240 windows. |
| TT-TRF-002 | off | Needs the destination absent from the device's learned external peers. Confidence low when a server name is visible, medium when none is. |
| TT-TRF-005 | off | Protocol names are compared as decoded; the legacy hint list is lower-case. |
| TT-DEV-005, TT-APP-001 | off | As specified. |
| TT-DEV-006 | off | Version 2. Case (a): a host on the network answered a handshake on a port not in its baseline. Case (b): the same for **this computer** (a connection started by another host was accepted on a port it was not listening on). Case (b) is labelled (`observed.case = this_computer`, title "New listening service on this computer") and, because this computer is the capture point, a ready baseline with no listening ports stored for it counts as an empty set instead of "no baseline". Severity is medium when the initiator is outside the network, otherwise low. Both cases rest on a seen handshake reply. |

**Baselines.** A baseline belongs to a network (first interface network plus first gateway). It is learned only from live
sessions (a file never creates or updates one), in bounded sets (protocols 64, applications 128, local peers 512,
listening ports 128, external peers 1,024) and up to 1,440 one-minute windows per device, summarised as median and MAD.
Ready means at least `baseline_hours_min` (default 4) hours **and** `baseline_sessions_min` (default 2) sessions. A minute in
which a baseline rule raised an alert is left out of what is learned, so an unusual burst does not become normal. A device is
keyed by its inventory id when its address is in the inventory, otherwise by `ip:<address>`. All baseline rules sit in
`rules/baselined.py` and the device rules in `rules/device.py` (the roadmap named separate files per rule).
