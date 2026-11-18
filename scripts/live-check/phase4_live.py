"""Practical live validation of Phase 4 on this machine, with real capture and passive discovery.

Run with the backend's python from the repo root:   backend\\.venv\\Scripts\\python.exe scripts\\live-check\\phase4_live.py
It runs the real backend (real dumpcap/tshark, real interface) against a throw-away data folder and a short baseline window
(18 s of live time, 2 sessions). It sends only ordinary traffic (a few web requests, DNS lookups and pings of the gateway) and
passive discovery (reads the operating-system neighbour table; sends nothing). Active scans are not used.

What it checks, and what it has to alter to check it:
  1. Baseline readiness: not ready after one live session, ready after the second (time and session minimums both needed).
  2. Gateway-MAC memory: the MAC stored for the network equals the operating system's own entry for the gateway.
  3. TT-DEV-004 on real frames: the stored MAC is changed in the database to a different value (standing in for a replaced
     router) and a third live session must raise the alert. This is the one deliberate alteration, and it is printed.
  4. TT-DEV-001: two passive scans on one interface, with one device row deleted between them, so that scan 2 records it
     as new. The deletion stands in for "a device appeared"; the rule's own gating (earlier scan, inventory size) is real.
"""

import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import delete, select, update  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from app.core.config import Settings  # noqa: E402
from app.database import init_database  # noqa: E402
from app.main import create_app  # noqa: E402
from app.models.detection import NetworkProfile  # noqa: E402
from app.models.device import Device  # noqa: E402

TOKEN = "T" * 43
SESSION_SECONDS = 25
results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, ok, detail))
    print(("PASS  " if ok else "FAIL  ") + name + (f"  [{detail}]" if detail else ""), flush=True)


def traffic(stop: threading.Event, gateway: str | None) -> None:
    hosts = ["example.com", "wikipedia.org", "github.com"]
    while not stop.is_set():
        for h in hosts:
            try:
                socket.getaddrinfo(h, 443)
                urllib.request.urlopen(f"https://{h}/", timeout=4).read(2048)  # noqa: S310
            except Exception:  # noqa: BLE001 - offline hosts are fine; the capture still sees the attempt
                pass
            if gateway:
                subprocess.run(["ping", "-n", "2", gateway], capture_output=True, check=False)  # noqa: S603, S607
            if stop.wait(0.5):
                return


def neighbour_mac(ip: str) -> str | None:
    out = subprocess.run(["arp", "-a", ip], capture_output=True, text=True, check=False).stdout  # noqa: S603, S607
    m = re.search(r"([0-9a-f]{2}(?:-[0-9a-f]{2}){5})", out, re.I)
    return m.group(1).lower().replace("-", ":") if m else None


def main() -> int:
    data = Path(tempfile.mkdtemp(prefix="tt-live-")) / "data"
    engine = init_database(data)
    app = create_app(Settings(data_dir=data, api_token=TOKEN), engine)
    with TestClient(app, base_url="http://127.0.0.1", headers={"Authorization": f"Bearer {TOKEN}"}) as c:
        capturable = {i["interface_id"] for i in c.get("/api/v1/capture/interfaces").json()["interfaces"] if i["capturable"]}
        net = c.get("/api/v1/interfaces").json()["interfaces"]
        mine = next((i for i in net if i["id"] in capturable and i["connection"] == "connected" and i["gateways"]), None)
        if mine is None:
            print("no connected, capturable interface with a gateway")
            return 2
        iface = mine["id"]
        gateway = (mine.get("gateways") or [None])[0]
        print(f"interface {mine.get('name')} ({iface}), gateway {gateway}", flush=True)
        c.put("/api/v1/detection/settings", json={"baseline_hours_min": 0.005, "baseline_sessions_min": 2}).raise_for_status()
        c.put("/api/v1/detection/rules/TT-DEV-001", json={"params": {"network_age_h": 0, "min_inventory_size": 1}}).raise_for_status()

        def live_session(label: str) -> None:
            stop = threading.Event()
            worker = threading.Thread(target=traffic, args=(stop, gateway), daemon=True)
            r = c.post("/api/v1/capture/start", json={"interface_id": iface, "max_seconds": SESSION_SECONDS + 20})
            if r.status_code >= 400:
                raise SystemExit(f"capture would not start: {r.status_code} {r.text[:300]}")
            worker.start()
            time.sleep(SESSION_SECONDS)
            c.post("/api/v1/capture/stop")
            stop.set()
            worker.join(timeout=10)
            end = time.time() + 60
            while time.time() < end:
                runs = c.get("/api/v1/detection/runs").json()["items"]
                if runs and runs[0]["status"] != "running" and c.get("/api/v1/capture/status").json()["state"] not in ("running", "stopping"):
                    break
                time.sleep(1)
            run = c.get("/api/v1/detection/runs").json()["items"][0]
            print(f"  {label}: run {run['id']} {run['status']}, {run['events_processed']} events, baseline_updated={run['baseline_updated']}, warnings={run['warnings']}", flush=True)

        # 1. readiness
        live_session("session 1")
        nets = c.get("/api/v1/detection/networks").json()["items"]
        check("a live session creates the network profile", len(nets) == 1, f"{len(nets)} network(s)")
        n1 = nets[0] if nets else {}
        check("one session is not enough for a ready baseline", n1.get("sessions") == 1 and n1.get("baseline_ready") is False, json.dumps({k: n1.get(k) for k in ("sessions", "live_seconds", "baseline_ready")}))
        live_session("session 2")
        n2 = c.get("/api/v1/detection/networks").json()["items"][0]
        check("two sessions and enough live time make the baseline ready", n2["baseline_ready"] and n2["sessions"] == 2 and n2["live_seconds"] >= 18, json.dumps({k: n2.get(k) for k in ("sessions", "live_seconds", "baseline_ready", "baseline_devices")}))
        check("baseline rows were stored for devices seen", n2["baseline_devices"] > 0, str(n2["baseline_devices"]))

        # 2. gateway MAC memory
        expected = neighbour_mac(gateway) if gateway else None
        check("the stored gateway MAC equals the operating system's entry", bool(expected) and n2["gateway_mac"] == expected, f"stored {n2['gateway_mac']}, system {expected}")

        # a baseline rule now runs
        c.put("/api/v1/detection/rules/TT-TRF-005", json={"enabled": True}).raise_for_status()
        live_session("session 3 (unchanged gateway)")
        status = c.get("/api/v1/detection/status").json()
        states = status["runs"][0]["rule_states"]
        check("a baseline rule is evaluating once the baseline is ready", states.get("TT-TRF-005") == "evaluating", str(states.get("TT-TRF-005")))
        alerts = c.get("/api/v1/alerts?limit=200").json()["items"]
        check("an unchanged gateway MAC raises no TT-DEV-004 alert", not any(a["rule_id"] == "TT-DEV-004" for a in alerts))

        # 3. TT-DEV-004 on real frames, with the stored MAC altered
        fake = "02:00:00:aa:bb:cc"
        with Session(engine) as s:
            s.execute(update(NetworkProfile).values(gateway_mac=fake))
            s.commit()
        print(f"  ALTERED the stored gateway MAC to {fake} (stands in for a replaced router)", flush=True)
        live_session("session 4 (stored MAC altered)")
        alerts = c.get("/api/v1/alerts?limit=200").json()["items"]
        dev4 = [a for a in alerts if a["rule_id"] == "TT-DEV-004"]
        check("a gateway MAC that differs from the stored one raises TT-DEV-004", len(dev4) >= 1, f"{len(dev4)} alert(s)")
        n4 = c.get("/api/v1/detection/networks").json()["items"][0]
        check("the new MAC replaces the stored one afterwards", n4["gateway_mac"] == expected, f"stored {n4['gateway_mac']}")

        # 4. TT-DEV-001 with passive scans
        def scan() -> str:
            r = c.post("/api/v1/discovery/scans", json={"interface_id": iface, "mode": "passive", "resolve_names": False})
            r.raise_for_status()
            sid = r.json()["id"]
            end = time.time() + 90
            while time.time() < end and c.get(f"/api/v1/discovery/scans/{sid}").json()["status"] in ("queued", "running"):
                time.sleep(1)
            time.sleep(2)
            return sid

        scan()
        time.sleep(1)
        with Session(engine) as s:
            victim = s.scalars(select(Device).where(Device.last_ip.is_not(None)).order_by(Device.id.desc())).first()
            total = len(s.scalars(select(Device)).all())
            if victim is None or total < 2:
                check("TT-DEV-001: the first scan found at least two devices", False, f"{total} device(s)")
            else:
                vmac = victim.mac
                s.execute(delete(Device).where(Device.id == victim.id))
                s.commit()
                print(f"  DELETED inventory device {vmac} between the scans so the second scan records it as new", flush=True)
                scan()
                al = [a for a in c.get("/api/v1/alerts?limit=200").json()["items"] if a["rule_id"] == "TT-DEV-001"]
                check("TT-DEV-001 reports a device the second scan added", any(a["entity_key"] == vmac for a in al), f"{len(al)} alert(s) for {[a['entity_key'] for a in al]}")
    failed = [r for r in results if not r[1]]
    print(f"\n{len(results) - len(failed)} of {len(results)} checks passed; data folder {data}")
    os._exit(1 if failed else 0)


if __name__ == "__main__":
    sys.exit(main())
