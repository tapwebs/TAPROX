"""Seeds a throw-away TAPNETTRACK data folder with a small device inventory so the Phase 4 screens have devices to show.

Run with the backend's python:  seed-phase4.py <data dir>
The addresses match the reference capture's local network (192.168.1.0/24). Nothing here touches real data.
"""

import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "backend"))

from sqlalchemy.orm import Session  # noqa: E402

from app.database import init_database  # noqa: E402
from app.models.device import Device, DeviceAddress  # noqa: E402

ROWS = [
    ("aa:bb:cc:00:00:01", "192.168.1.1", "router", "Acme Networks"),
    ("aa:bb:cc:00:00:07", "192.168.1.7", "laptop", "Pear"),
    ("aa:bb:cc:00:00:23", "192.168.1.23", "phone", "Pear"),
    ("aa:bb:cc:00:00:30", "192.168.1.30", "tv", "Zeta"),
    ("aa:bb:cc:00:00:50", "192.168.1.50", "printer", "Acme Printers"),
]


def main(data_dir: Path) -> None:
    engine = init_database(data_dir)
    now = datetime.now(UTC)
    with Session(engine) as s:
        for i, (mac, ip, name, vendor) in enumerate(ROWS):
            seen = now - timedelta(days=3 - min(i, 2))
            d = Device(mac=mac, vendor=vendor, hostname=name, first_seen=seen, last_seen=now, last_ip=ip, confidence="confirmed", last_source="arp")
            s.add(d)
            s.flush()
            s.add(DeviceAddress(device_id=d.id, ip=ip, ip_sort=ip, family=4, interface_id="seed", first_seen=seen, last_seen=now))
        s.commit()
    engine.dispose()
    print(f"seeded {len(ROWS)} devices in {data_dir}")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
