"""Verify Phase 1 against the real machine: interfaces, neighbor table and (optionally) discovery.

Everything is compared with what PowerShell itself reports (Get-NetAdapter, Get-NetIPAddress,
Get-NetRoute, Get-DnsClientServerAddress, Get-NetNeighbor), so a mistake in our own parsing cannot
agree with itself. Nothing is changed on the machine. A throw-away database in a temp folder is
used; your data directory is not touched.

    uv run --no-sync python -m scripts.verify_phase1_windows                  # read-only checks
    uv run --no-sync python -m scripts.verify_phase1_windows --i-am-authorized  # + an ARP scan

The ARP scan sends one ARP request per host address of the chosen interface's own private network
(at most a /22). Only use --i-am-authorized on a network you are allowed to scan.
"""

import argparse
import json
import statistics
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any

from app.database import init_database
from app.schemas.discovery import ScanRequest
from app.services.discovery.factory import default_backend
from app.services.discovery.service import DiscoveryService
from app.services.interface_manager import default_provider
from app.services.interface_manager.manager import InterfaceManager
from app.services.netutil import is_unicast_ip, is_unicast_mac, normalize_mac

POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
_REPORT: list[str] = []
_FAILED: list[str] = []


def say(line: str = "") -> None:
    _REPORT.append(line)
    print(line)


def check(ok: bool, what: str, detail: str = "") -> None:
    say(f"- {'PASS' if ok else 'FAIL'}: {what}" + (f" ({detail})" if detail else ""))
    if not ok:
        _FAILED.append(what)


def powershell(script: str) -> Any:
    done = subprocess.run(  # noqa: S603 - fixed absolute path and fixed script text, no user input
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )
    text = done.stdout.strip()
    return json.loads(text) if text else []


def as_list(value: Any) -> list[dict[str, Any]]:
    # ConvertTo-Json collapses one-element arrays to a bare object and empty ones to nothing.
    return value if isinstance(value, list) else ([value] if value else [])


def os_view() -> dict[str, list[dict[str, Any]]]:
    script = (
        "$ErrorActionPreference='Stop';"
        "@{adapters=@(Get-NetAdapter|Select-Object Name,InterfaceGuid,ifIndex,Status,MacAddress);"
        "ips=@(Get-NetIPAddress -AddressFamily IPv4|Select-Object InterfaceIndex,IPAddress,PrefixLength);"
        "routes=@(Get-NetRoute -DestinationPrefix '0.0.0.0/0'|Select-Object InterfaceIndex,NextHop);"
        "dns=@(Get-DnsClientServerAddress -AddressFamily IPv4|Select-Object InterfaceIndex,ServerAddresses)}"
        "|ConvertTo-Json -Depth 4 -Compress"
    )
    raw = powershell(script)
    return {key: as_list(raw.get(key)) for key in ("adapters", "ips", "routes", "dns")}


def os_neighbors() -> set[tuple[int, str, str]]:
    rows = as_list(
        powershell(
            "@(Get-NetNeighbor|Where-Object {$_.LinkLayerAddress}|"
            "Select-Object InterfaceIndex,IPAddress,LinkLayerAddress,State)|ConvertTo-Json -Compress"
        )
    )
    found = set()
    for row in rows:
        mac, ip = (
            normalize_mac(str(row["LinkLayerAddress"])),
            str(row["IPAddress"]).partition("%")[0],
        )
        if mac and is_unicast_mac(mac) and is_unicast_ip(ip):
            found.add((int(row["InterfaceIndex"]), ip, mac))
    return found


def verify_interfaces(manager: InterfaceManager) -> None:
    say("## Interfaces: our provider vs PowerShell")
    timings = []
    for _ in range(20):
        began = time.perf_counter()
        listing = manager.snapshot(force=True)
        timings.append((time.perf_counter() - began) * 1000)
    say(
        f"- Listing latency over 20 calls: median {statistics.median(timings):.1f} ms, max {max(timings):.1f} ms"
    )
    ours = {n.id: n for n in listing.interfaces}
    view = os_view()
    check(
        bool(view["adapters"]), "PowerShell reports adapters", f"{len(view['adapters'])} adapters"
    )

    for adapter in view["adapters"]:
        guid = str(adapter["InterfaceGuid"]).strip("{}").lower()
        nic = ours.get(guid)
        name = adapter["Name"]
        if nic is None:
            check(False, f"{name}: present in our listing")
            continue
        index = int(adapter["ifIndex"])
        up = adapter["Status"] == "Up"
        check(nic.os_index == index, f"{name}: ifIndex", f"{nic.os_index} vs {index}")
        want_mac = normalize_mac(str(adapter["MacAddress"]) or None)
        check(nic.mac == want_mac, f"{name}: MAC", f"{nic.mac} vs {want_mac}")
        check(
            (nic.connection == "connected") == up,
            f"{name}: connection",
            f"{nic.connection} vs {adapter['Status']}",
        )
        if not up:
            continue
        want_ips = {
            (r["IPAddress"], int(r["PrefixLength"]))
            for r in view["ips"]
            if r["InterfaceIndex"] == index
        }
        got_ips = {(a.address, a.prefix_length) for a in nic.ipv4}
        check(
            got_ips == want_ips,
            f"{name}: IPv4 address/prefix",
            f"{sorted(got_ips)} vs {sorted(want_ips)}",
        )
        want_gw = {
            r["NextHop"]
            for r in view["routes"]
            if r["InterfaceIndex"] == index and r["NextHop"] != "0.0.0.0"
        }
        got_gw = {g for g in nic.gateways if ":" not in g}
        check(
            got_gw == want_gw, f"{name}: default gateway", f"{sorted(got_gw)} vs {sorted(want_gw)}"
        )
        want_dns: set[str] = set()
        for r in view["dns"]:
            if r["InterfaceIndex"] == index:
                servers = r["ServerAddresses"]
                want_dns |= set(servers if isinstance(servers, list) else [servers])
        got_dns = {d for d in nic.dns_servers if ":" not in d}
        check(
            got_dns == want_dns, f"{name}: DNS servers", f"{sorted(got_dns)} vs {sorted(want_dns)}"
        )
        for a in nic.ipv4:
            say(
                f"  - {name}: {a.address}/{a.prefix_length} network {a.network}, discovery: "
                f"{'active ok' if nic.discovery.active else 'passive only'}"
                + (f" ({nic.discovery.reason_code})" if nic.discovery.reason_code else "")
            )
    extras = sorted(
        n.name
        for g, n in ours.items()
        if g not in {str(a["InterfaceGuid"]).strip("{}").lower() for a in view["adapters"]}
    )
    say(f"- Interfaces we list that Get-NetAdapter hides: {extras or 'none'}")
    say()


def verify_neighbors() -> None:
    say("## Neighbor table: our GetIpNetTable2 reader vs Get-NetNeighbor")
    backend = default_backend()
    timings = []
    for _ in range(20):
        began = time.perf_counter()
        entries = backend.read_neighbors()
        timings.append((time.perf_counter() - began) * 1000)
    say(f"- Read latency over 20 calls: median {statistics.median(timings):.2f} ms")
    ours = {
        (e.if_index or 0, e.ip, e.mac)
        for e in entries
        if is_unicast_mac(e.mac)
        and is_unicast_ip(e.ip)
        and e.state not in ("incomplete", "unreachable")
    }
    theirs = {t for t in os_neighbors()}
    # The table moves between two reads, so allow a small number of differences but report them.
    missing, extra = theirs - ours, ours - theirs
    say(
        f"- Unicast entries: ours {len(ours)}, PowerShell {len(theirs)}; only-PowerShell {len(missing)}, only-ours {len(extra)}"
    )
    check(
        len(missing) + len(extra) <= 2,
        "neighbor tables agree (at most 2 differences allowed for entries that changed between reads)",
    )
    for entry in sorted(ours):
        say(f"  - if {entry[0]}: {entry[1]} -> {entry[2]}")
    say()


def run_scan(service: DiscoveryService, nic_id: str, network: str | None) -> Any:
    request = ScanRequest(
        interface_id=nic_id, mode="active", network=network, confirm_authorized=True
    )
    began = time.monotonic()
    started = service.start(request)
    while service.current() is not None:
        time.sleep(0.1)
    scan = service.get(started.id)
    assert scan is not None
    return scan, time.monotonic() - began


def verify_scan(manager: InterfaceManager, interface_id: str | None, network: str | None) -> None:
    say("## Active discovery on the local network (authorised by --i-am-authorized)")
    chosen = next(
        (
            n
            for n in manager.snapshot().interfaces
            if (
                n.id == interface_id
                if interface_id
                else n.discovery.active
                and n.kind in ("ethernet", "wifi")
                and n.connection == "connected"
            )
        ),
        None,
    )
    if chosen is None:
        check(False, "a connected Ethernet/Wi-Fi interface with a private IPv4 network was found")
        return
    say(f"- Interface: {chosen.name} ({chosen.mac}), network {network or chosen.discovery.network}")
    backend = default_backend()
    before = {
        (e.if_index or 0, e.ip, e.mac): e.state
        for e in backend.read_neighbors()
        if e.if_index == chosen.os_index
        and is_unicast_mac(e.mac)
        and is_unicast_ip(e.ip)
        and e.state not in ("incomplete", "unreachable")
    }

    with tempfile.TemporaryDirectory(prefix="tapnettrack-verify-") as tmp:
        engine = init_database(Path(tmp))
        service = DiscoveryService(engine, manager, backend)
        scan, wall = run_scan(service, chosen.id, network)
        say(
            f"- Scan {scan.status}: {scan.targets_done}/{scan.targets_total} addresses in {wall:.1f} s "
            f"({scan.targets_done / max(wall, 0.001):.0f} probes/s), {scan.devices_found} device(s) found"
        )
        for warning in scan.warnings:
            say(f"  - warning: {warning}")
        check(scan.status == "completed", "scan completed")
        check(scan.targets_done == scan.targets_total, "every address was probed")

        from sqlalchemy import select
        from sqlalchemy.orm import Session

        from app.models.device import Device

        with Session(engine) as session:
            devices = {d.mac: d for d in session.scalars(select(Device))}
        answered = {
            (chosen.os_index or 0, d.last_ip, mac)
            for mac, d in devices.items()
            if d.last_source == "arp" and d.last_ip
        }
        after = {(e.if_index or 0, e.ip, e.mac) for e in backend.read_neighbors()}
        for entry in sorted(answered):
            found = devices[entry[2]]
            vendor = found.vendor or (
                "no vendor: randomised address"
                if found.mac_randomized
                else "vendor not in the registry"
            )
            say(f"  - answered ARP: {entry[1]} -> {entry[2]} ({vendor})")
        check(answered <= after, "every host that answered ARP is now in the OS neighbor table")
        scanned = ip_network(network or chosen.discovery.network or "0.0.0.0/32")
        silent = sorted(
            k
            for k in before
            if k not in answered and ":" not in k[1] and ip_address(k[1]) in scanned
        )
        say(
            f"- In the OS cache before the scan but silent to our probes: {[(s[1], s[2]) for s in silent] or 'none'}"
        )
        say(
            "  (A cached host that does not answer ARP is asleep, gone or filtering: it is NOT reported as offline.)"
        )
        found_macs = set(devices)
        known = {e[2] for e in before}
        say(
            f"- Devices answering ARP that the OS did not have cached beforehand: "
            f"{sorted(m for m in found_macs if m not in known and m != chosen.mac) or 'none'}"
        )
        engine.dispose()

        # Cancellation against the real SendARP calls.
        engine = init_database(Path(tmp) / "cancel")
        service = DiscoveryService(engine, manager, backend)
        started = service.start(
            ScanRequest(
                interface_id=chosen.id, mode="active", network=network, confirm_authorized=True
            )
        )
        time.sleep(1.0)
        asked = time.monotonic()
        service.cancel(started.id)
        service.wait_idle(30)
        latency = time.monotonic() - asked
        final = service.get(started.id)
        assert final is not None
        say(
            f"- Cancel after 1 s: status {final.status}, stopped in {latency:.2f} s, "
            f"{final.targets_done}/{final.targets_total} probed"
        )
        check(final.status in ("cancelled", "completed"), "cancel ends the scan")
        check(latency < 6, "cancel returns within 6 s", f"{latency:.2f} s")
        engine.dispose()

    say("- Experiment: does SendARP answer from the OS cache? (latency of probing cached hosts)")
    for key, state in list(before.items())[:4]:
        if ":" in key[1]:
            continue
        began = time.perf_counter()
        mac = backend.arp_probe(chosen.ipv4[0].address, key[1], timeout=3)
        say(
            f"  - {key[1]} (cache state '{state}'): {'answered' if mac else 'no answer'} in "
            f"{(time.perf_counter() - began) * 1000:.0f} ms"
        )
    say()


def experiment_cache(manager: InterfaceManager, interface_id: str | None) -> None:
    """Does SendARP verify a host on the wire, or return what the OS already had cached?

    Wait until cached IPv4 entries on the interface go 'stale', probe each, and see whether the OS
    marks it 'reachable' again. That only happens if a request/reply really crossed the network.
    """
    say("## Experiment: SendARP versus the OS neighbor cache")
    nic = next((n for n in manager.snapshot().interfaces if n.id == interface_id), None)
    if nic is None or not nic.ipv4:
        check(False, "interface for the cache experiment found")
        return
    backend = default_backend()

    def mine() -> dict[str, str]:
        return {
            e.ip: e.state
            for e in backend.read_neighbors()
            if e.if_index == nic.os_index
            and ":" not in e.ip
            and is_unicast_mac(e.mac)
            and is_unicast_ip(e.ip)
        }

    deadline = time.monotonic() + 120
    stale: list[str] = []
    while time.monotonic() < deadline and not stale:
        stale = sorted(ip for ip, state in mine().items() if state == "stale")
        if not stale:
            time.sleep(5)
    say(
        f"- Cached entries that were 'stale' when the experiment began: {stale or 'none (never went stale in 120 s)'}"
    )
    flipped = 0
    for ip in stale[:5]:
        before = mine().get(ip)
        began = time.perf_counter()
        mac = backend.arp_probe(nic.ipv4[0].address, ip, timeout=3)
        took = (time.perf_counter() - began) * 1000
        after = mine().get(ip)
        flipped += before == "stale" and after == "reachable"
        say(
            f"  - {ip}: {before} -> probe {'answered' if mac else 'no answer'} in {took:.0f} ms -> {after}"
        )
    if stale:
        say(
            f"- Verified on the wire: {flipped} of {min(len(stale), 5)} stale entries became 'reachable' after the probe"
        )
    say()


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "--i-am-authorized",
        action="store_true",
        help="also run an ARP scan of the interface's own private network",
    )
    parser.add_argument("--interface-id")
    parser.add_argument("--network", help="narrower IPv4 subnet (CIDR) to scan")
    parser.add_argument(
        "--cache-experiment",
        action="store_true",
        help="wait for cached entries to go stale and probe them (needs --interface-id)",
    )
    args = parser.parse_args()
    if sys.platform != "win32":
        print("This script verifies the Windows backend and must run on Windows.")
        return 2

    say(f"# Phase 1 verification on {datetime.now(UTC):%Y-%m-%d %H:%M} UTC ({sys.platform})")
    say()
    manager = InterfaceManager(default_provider(), ttl_seconds=0)
    verify_interfaces(manager)
    verify_neighbors()
    if args.i_am_authorized:
        verify_scan(manager, args.interface_id, args.network)
        if args.cache_experiment:
            experiment_cache(manager, args.interface_id)
    else:
        say("_Active scan skipped (pass --i-am-authorized to run it)._")
    say(
        f"**Result: {'FAILED' if _FAILED else 'all checks passed'}**"
        + (f" ({len(_FAILED)} failed)" if _FAILED else "")
    )
    return 1 if _FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())
