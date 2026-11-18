"""Rebuild backend/app/data/oui.tsv from the IEEE Registration Authority's public registries.

    cd backend && uv run python -m scripts.update_oui

Downloads MA-L, MA-M and MA-S (about 5 MB), merges them into the compact format used by
app.services.discovery.oui, and records the retrieval date. Nothing is uploaded.
"""

import urllib.request
from datetime import UTC, datetime

from app.services.discovery.oui import DATA_FILE, build_compact

REGISTRIES = {
    "MA-L": "https://standards-oui.ieee.org/oui/oui.csv",
    "MA-M": "https://standards-oui.ieee.org/oui28/mam.csv",
    "MA-S": "https://standards-oui.ieee.org/oui36/oui36.csv",
}


def fetch(url: str) -> str:
    request = urllib.request.Request(  # noqa: S310 - fixed https URLs above
        url, headers={"User-Agent": "TAPNETTRACK-oui-update/1.0 (local development)"}
    )
    with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310
        body: bytes = response.read()
    return body.decode("utf-8-sig")


def main() -> None:
    texts = [fetch(url) for url in REGISTRIES.values()]
    today = datetime.now(UTC).date().isoformat()
    registries = ", ".join(REGISTRIES)
    source = f"IEEE Registration Authority {registries} (standards-oui.ieee.org), retrieved {today}"
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    DATA_FILE.write_text(build_compact(texts, source=source), encoding="utf-8", newline="\n")
    count = DATA_FILE.read_text(encoding="utf-8").count("\n") - 1
    print(f"wrote {count} assignments to {DATA_FILE}")


if __name__ == "__main__":
    main()
