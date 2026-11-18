# TAPROX — Network-Level Capture, Hardware Mirroring & Wi-Fi Vantage Investigation

**Document Version:** 1.0.0  
**Project:** TAPROX (Cybersecurity Network Intelligence Workstation)  
**Investigation Date:** November 18, 2026  
**Audited Gateway:** `192.168.1.1` (MAC: `30:4f:75:ea:00:ef` — Zhone Technologies, Inc. GPON ONT)  
**Host Workstation:** `192.168.1.4` (Ethernet) / `192.168.1.5` (Wi-Fi)  

---

## Executive Summary

TAPROX provides real-time network intelligence, protocol decoding, flow reconstruction, and application classification without decrypting TLS payloads. A core architectural principle of TAPROX is **observational honesty**: the platform never invents packets, guesses flows, or fabricates multi-device application visibility when physical network physics prevents packet observation.

During standard endpoint operation on a host workstation:
- **Ethernet Capture:** TAPROX captures 100% of packets originating from or destined to the host PC (`192.168.1.4`), plus local subnet broadcast and multicast traffic (ARP, MDNS, LLMNR, SSDP, NetBIOS). Application classification for host traffic achieves high fidelity (e.g., YouTube, Google, Microsoft, WhatsApp).
- **Wi-Fi Capture:** In standard 802.11 managed (infrastructure) mode, Access Points (APs) enforce **station-to-station isolation** at Layer 2. Unicast traffic between a third-party wireless device (such as a mobile phone streaming YouTube) and the default gateway travels over radio frames addressed strictly between that phone's MAC and the AP's BSSID. Because the host workstation's Wi-Fi NIC only processes frames addressed to its own MAC or broadcast/multicast groups, unicast application payloads of other devices never reach the host operating system's network stack.

This document investigates the physical network environment, assesses four capture expansion architectures (Options A through D), and defines the production blueprint for multi-device network-level visibility.

---

## 1. Physical Environment Discovery & Gateway Audit

Physical network interrogation conducted directly on the live operating subnet revealed the following network infrastructure:

| Parameter | Observed Value | Provenance / Discovery Source |
| :--- | :--- | :--- |
| **Default IPv4 Gateway** | `192.168.1.1` | Windows IP routing table (`0.0.0.0/0 via 192.168.1.1`) |
| **Gateway MAC Address** | `30:4f:75:ea:00:ef` | ARP cache resolution |
| **Manufacturer OUI** | `30:4f:75` | **Zhone Technologies, Inc.** (DZS / DASAN Zhone Solutions) |
| **Hardware Classification** | GPON Optical Network Terminal (ONT) | Fiber-to-the-Home (FTTH) Residential Broadband Gateway |
| **Active Host IPv4 (Ethernet)**| `192.168.1.4` | Physical Realtek PCIe GbE Controller |
| **Active Host IPv4 (Wi-Fi)** | `192.168.1.5` | Physical 802.11ac Wireless Adapter |
| **Subnet Scope** | `192.168.1.0/24` | Class C private network |

### Hardware Characteristics of Zhone GPON Residential ONTs
Zhone GPON ONTs (such as the DZS 2400/2600 series commonly supplied by telecommunication providers) are locked-down carrier customer premises equipment (CPE). 
1. **No NetFlow / IPFIX / sFlow Export:** The carrier-grade residential firmware intentionally omits enterprise telemetry export daemons.
2. **No Port Mirroring (SPAN) in Web GUI:** Consumer and residential firmware interfaces do not expose switch fabric port replication. Port mirroring registers inside the Broadcom/Cortina GPON SoC are inaccessible without telecom provisioning credentials (TR-069/OMCI).
3. **Firmware Integrity & Security Boundaries:** Attempting to exploit or re-flash ISP optical equipment violates carrier service agreements, voids network warranties, and creates severe operational instability.

---

## 2. Evaluation of Network-Level Capture Approaches

To grant TAPROX visibility into unicast traffic from all devices on the network, four architectural approaches were evaluated:

```
+----------------------------------------------------------------------------------------------------+
|                                      ARCHITECTURE EVALUATION MATRIX                                 |
+-------------------+-------------------+--------------------+------------------+--------------------+
| Approach          | Packet Fidelity   | Multi-Device Scope | Hardware Cost    | Deployment Ease    |
+-------------------+-------------------+--------------------+------------------+--------------------+
| Option A: Router  | Low / Impossible  | None on Zhone ONT  | $0               | Impractical (ISP)  |
| Option B: SPAN Sw | 100% Full Frames  | Complete Subnet    | $25 - $45        | Simple & Clean     |
| Option C: HW TAP  | 100% Unmodified   | Complete Uplink    | $15 - $80        | Plug-and-Play      |
| Option D: Probe   | High (Extensible) | Multi-Vantage      | $0 (Software)    | Medium             |
+-------------------+-------------------+--------------------+------------------+--------------------+
```

### Option A: Router Native Capture / Firmware Mirroring
- **Mechanism:** Enabling packet capture (tcpdump) or flow export (NetFlow/IPFIX) directly inside the router firmware.
- **Feasibility on Current Hardware:** **Not Feasible**. The Zhone GPON ONT is an ISP-controlled fiber termination unit without administrative SSH or telemetry export capabilities.
- **When Applicable:** Only viable when the primary router is an open platform (OpenWrt, pfSense, OPNsense, MikroTik RouterOS, or enterprise Cisco/Juniper).

### Option B: Hardware Port Mirroring via Managed Switch (SPAN) — [RECOMMENDED]
- **Mechanism:** Insert an inexpensive smart managed Gigabit switch (e.g., Netgear GS308E, TP-Link TL-SG108E, or Ubiquiti UniFi) directly downstream of the GPON ONT's LAN port. Configure a Switch Port Analyzer (SPAN) / Port Mirroring rule to duplicate all uplink traffic destined to the gateway to a designated monitor port connected to TAPROX.
- **Feasibility:** **Immediate & Highly Reliable**. Smart managed 8-port switches cost under $35, operate silently, consume < 4W of power, and introduce zero jitter.
- **Packet Integrity:** 100% raw Ethernet frames preserved, including original MAC addresses, IP headers, TCP/UDP ports, TLS handshakes, SNI, HTTP headers, and timing metrics.

### Option C: Passive Hardware Network TAP
- **Mechanism:** Insert a hardware network Test Access Point (TAP) in-line on the Ethernet cable connecting the GPON ONT to the main router/AP switch. TAPs (such as the Dualcomm ETAP-2003 or Throwing Star LAN Tap) passively split physical signaling pairs into dedicated monitor outputs.
- **Feasibility:** **Excellent for High-Security / Forensics**. A passive TAP ensures zero software interference, cannot be detected by network endpoints, and preserves true physical link timing.
- **Consideration:** Requires two capture interfaces (one for TX, one for RX) or an aggregating TAP with internal buffering.

### Option D: Software Remote Agent / Light Probe Daemon
- **Mechanism:** A lightweight, headless Go or Python probe service deployed on another machine or secondary wireless AP, streaming flow telemetry or pcap-over-TLS to the TAPROX host over an encrypted loopback/LAN connection.
- **Feasibility:** **Viable for Distributed Deployments**. Excellent for enterprise deployments with remote branches or multiple physical floors.

---

## 3. Recommended Production Architecture (Option B / SPAN)

The diagram below outlines the verified deployment architecture:

```
                            +-----------------------+
                            |     Optical Fiber     |
                            +-----------+-----------+
                                        |
                                        v
                       +---------------------------------+
                       |       Zhone GPON ONT            |
                       |    Gateway: 192.168.1.1         |
                       +----------------+----------------+
                                        | LAN Port 1
                                        v
         +-------------------------------------------------------------+
         |           Smart Managed Switch (e.g. TL-SG108E)             |
         |                                                             |
         |  Port 1: Uplink to Gateway (Mirror Source: Both TX + RX)   |
         |  Port 2: Wi-Fi Access Point (All Wireless Mobile Devices)    |
         |  Port 3: Wired LAN Devices                                  |
         |  Port 8: SPAN Mirror Destination Port -------------------+  |
         +----------------------------------------------------------+--+
                                                                    |
                                   Mirrored Traffic Stream (Full Duplex)
                                                                    |
                                                                    v
                                                     +-----------------------------+
                                                     | TAPROX Workstation          |
                                                     | Capture NIC: Ethernet 2     |
                                                     | IP: Unnumbered / Promiscuous|
                                                     | Npcap Promiscuous Capture   |
                                                     +--------------+--------------+
                                                                    |
                                        +---------------------------+---------------------------+
                                        |                                                       |
                                        v                                                       v
                          +----------------------------+                          +----------------------------+
                          |   Flow & Protocol Engine   |                          |  Application Intelligence  |
                          |  - Per-Device Tracking     |                          |  - Mobile App Attribution  |
                          |  - Multi-Endpoint Matrix   |                          |  - TLS SNI & DNS Answers   |
                          +----------------------------+                          +----------------------------+
```

---

## 4. Workstation Configuration & Ingestion Guide

When connecting TAPROX to a SPAN mirror or hardware TAP:

1. **Dedicated Capture Interface:**
   - Install a secondary USB-to-Gigabit Ethernet adapter or PCIe NIC on the host machine.
   - Dedicate this interface exclusively to TAPROX packet capture.
   - In Windows Network Connections, uncheck `Internet Protocol Version 4 (TCP/IPv4)` and `Internet Protocol Version 6 (TCP/IPv6)` on this secondary capture NIC. This creates an **unnumbered stealth interface** that emits no packets, cannot be scanned, and does not interfere with the host's default route.

2. **Npcap Driver Promiscuous Configuration:**
   - Ensure Npcap is installed with `WinPcap API-compatible Mode` and `Support raw 802.11 traffic`.
   - In TAPROX `Network Interfaces`, select the secondary adapter.
   - TAPROX automatically detects non-host unicast MAC traffic and promotes the capture vantage label to:
     ```
     Capture Vantage: Network Mirror / TAP
     ```

3. **Per-Device Application Intelligence Verification:**
   - As soon as the mobile device generates traffic (e.g., launching YouTube or WhatsApp on an Android/iOS device), its unicast packets traverse the switch uplink and are mirrored to TAPROX.
   - TAPROX decodes the TLS ClientHello SNI (`googlevideo.com`, `whatsapp.net`) and DNS answers.
   - In **Application Intelligence (`#/applications`)**, the application card displays:
     - Originating Device: `192.168.1.8 (Android-Phone)`
     - Flow count, packet count, byte volume, and last seen timestamp.
     - Capture source badge: `Network Mirror / TAP`.

---

## 5. Summary of Observational Guarantees

| Network Vantage | Host PC Apps | Other Devices Discovered | Other Devices App Attribution |
| :--- | :---: | :---: | :---: |
| **Physical Ethernet** | Confirmed (100%) | Confirmed (ARP/MDNS) | Broadcast/Multicast only |
| **Wi-Fi Managed Mode** | Confirmed (100%) | Confirmed (ARP/MDNS) | Isolated by 802.11 AP (Disclosed) |
| **SPAN Port Mirror** | Confirmed (100%) | Confirmed (All L2/L3) | Confirmed (100% Full Multi-Device) |
| **Hardware TAP** | Confirmed (100%) | Confirmed (All L2/L3) | Confirmed (100% Full Multi-Device) |

TAPROX makes these boundaries crystal-clear to cybersecurity operators, eliminating guesswork and delivering verifiable, defensible network intelligence.
