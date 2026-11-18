"""Vendor lookup from a local copy of the IEEE OUI registry (MA-L, MA-M and MA-S).

A vendor is *inferred* from the first bits of a MAC address; it says who made the network chip, not
what the device is. Addresses with the locally-administered bit set (virtual adapters, privacy
randomisation) are not manufacturer assignments, so they never get a vendor.

The data file is a compact `PREFIX<TAB>Organisation` list built by scripts/update_oui.py.
"""

import csv
import io
import re
from collections.abc import Iterable
from functools import cache
from pathlib import Path

from app.services.netutil import is_locally_administered, normalize_mac

_HEX = re.compile(r"[0-9A-F]+")
_PREFIX_LENGTHS = (9, 7, 6)  # 36-bit, 28-bit, 24-bit assignments: the longest match wins
DATA_FILE = Path(__file__).resolve().parents[2] / "data" / "oui.tsv"


class OuiDatabase:
    def __init__(self, entries: dict[str, str], source: str | None) -> None:
        self._entries = entries
        self.source = source

    def __len__(self) -> int:
        return len(self._entries)

    @classmethod
    def load(cls, path: Path) -> "OuiDatabase":
        entries: dict[str, str] = {}
        source: str | None = None
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return cls({}, None)  # no data file: every lookup is simply "unknown"
        for line in lines:
            if line.startswith("# source:"):
                source = line.removeprefix("# source:").strip()
                continue
            prefix, tab, name = line.partition("\t")
            if tab and len(prefix) in _PREFIX_LENGTHS and _HEX.fullmatch(prefix) and name.strip():
                entries[prefix] = name.strip()
        return cls(entries, source)

    def lookup(self, mac: str | bytes | None) -> str | None:
        canonical = normalize_mac(mac)
        if canonical is None or is_locally_administered(canonical):
            return None
        digits = canonical.replace(":", "").upper()
        for length in _PREFIX_LENGTHS:
            vendor = self._entries.get(digits[:length])
            if vendor is not None:
                return vendor
        return None


@cache
def default_database() -> OuiDatabase:
    return OuiDatabase.load(DATA_FILE)


def build_compact(csv_texts: Iterable[str], *, source: str) -> str:
    """Merge IEEE registry CSV exports into the compact file format."""
    merged: dict[str, str] = {}
    for text in csv_texts:
        for row in csv.DictReader(io.StringIO(text)):
            prefix = (row.get("Assignment") or "").strip().upper()
            name = " ".join((row.get("Organization Name") or "").split())
            if len(prefix) not in _PREFIX_LENGTHS or not _HEX.fullmatch(prefix):
                continue
            if not name or name.lower() == "private":
                continue  # undisclosed assignments carry no usable vendor name
            merged[prefix] = name
    body = "\n".join(f"{prefix}\t{name}" for prefix, name in sorted(merged.items()))
    return f"# source: {source}\n{body}\n"
