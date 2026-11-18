from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

ScanMode = Literal["passive", "active"]
ScanStatus = Literal["running", "completed", "cancelled", "timed_out", "failed", "interrupted"]
ScanPhase = Literal["preparing", "probing", "ipv6", "neighbors", "resolving"]


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    interface_id: str = Field(
        pattern=r"^[A-Za-z0-9._:@-]{1,64}$", description="Interface id from /interfaces."
    )
    mode: ScanMode = Field(
        description="passive: read the operating system's neighbor table and send nothing. "
        "active: also send ARP requests to the addresses of the connected private network."
    )
    network: str | None = Field(
        default=None,
        max_length=43,
        description="Optional narrower IPv4 subnet (CIDR) inside the interface's own network. "
        "Defaults to the interface's network.",
    )
    confirm_authorized: bool = Field(
        default=False,
        description="Required for active scans: confirms you are allowed to probe this network.",
    )
    resolve_names: bool = Field(
        default=True, description="Look up host names (reverse DNS) for the devices found."
    )


class Scan(BaseModel):
    id: str
    interface_id: str
    interface_name: str
    mode: ScanMode
    network: str | None = Field(description="The IPv4 network that was (or is being) probed.")
    status: ScanStatus
    phase: ScanPhase | None = Field(description="What a running scan is doing; null once finished.")
    cancel_requested: bool
    targets_total: int = Field(description="IPv4 addresses to probe (0 for passive scans).")
    targets_done: int
    devices_found: int = Field(description="Distinct devices seen in this scan, excluding this PC.")
    started_at: datetime
    finished_at: datetime | None
    elapsed_seconds: float
    resolve_names: bool
    error_code: str | None
    error_message: str | None
    warnings: list[str]


class CurrentScan(BaseModel):
    scan: Scan | None = Field(description="The scan that is running now, or null when idle.")


class ScanList(BaseModel):
    scans: list[Scan]
    total: int
    limit: int
    offset: int
