from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

CaptureState = Literal["idle", "preparing", "capturing", "stopping", "completed", "failed"]
PacketSort = Literal["number", "time", "source", "destination", "protocol", "length"]


class CaptureInterface(BaseModel):
    interface_id: str
    name: str
    capturable: bool = Field(
        description="dumpcap offers this interface and it is connected. Whether this user may "
        "capture on it is only known when a capture starts."
    )
    reason: str | None = Field(description="Why it cannot be captured on, when it cannot.")


class CaptureInterfaceList(BaseModel):
    interfaces: list[CaptureInterface]
    tools_ready: bool
    problem: str | None = Field(
        description="Why no interface can be listed, e.g. dumpcap is missing."
    )


class CaptureLimits(BaseModel):
    max_listed_packets: int = Field(
        description="Packets shown in the list; the rest are still saved."
    )
    max_file_bytes: int = Field(description="A live capture stops by itself at this size.")


CaptureEndReason = Literal[
    "stopped_by_request",  # the Stop button / API
    "stopped_at_size_limit",
    "stopped_session_replaced",  # a new capture or file replaced this one
    "stopped_shutdown",
    "capture_limit_reached",  # dumpcap exited 0 after the packet or time limit that was asked for
    "tool_exited_by_itself",  # dumpcap exited 0 with no stop requested and no limit set
    "tool_failed",  # dumpcap ended with an error
    "start_failed",
]


class CaptureTermination(BaseModel):
    """Why a live capture ended, for diagnosis. No packet content; it never changes the state."""

    stop_requested: bool = Field(description="Something asked the capture to stop before it ended.")
    stop_source: Literal["user_request", "size_limit", "session_replaced", "shutdown"] | None = (
        Field(description="What asked for the stop; null when no stop was requested.")
    )
    dumpcap_exit_code: int | None = Field(
        description="dumpcap's exit code. A requested stop makes it exit with code 1 on Windows, "
        "so the code alone does not say whether a stop was requested."
    )
    tshark_exit_code: int | None
    reason: CaptureEndReason
    final_state: Literal["completed", "failed"]


class CaptureStatus(BaseModel):
    state: CaptureState
    source: Literal["live", "file"] | None
    interface_id: str | None
    interface_name: str | None
    promiscuous: bool | None
    started_at: datetime | None
    elapsed_seconds: float
    packets: int = Field(
        description="Packets in the capture, counted from the capture file itself."
    )
    captured_bytes: int
    listed_packets: int = Field(description="Packets decoded into the list so far.")
    list_dropped: int = Field(description="Packets saved but not listed because the list is full.")
    dropped_by_capture: int | None = Field(
        description="Packets the operating system dropped before capture, from dumpcap's summary. "
        "Known only after a live capture ends; null when not reported."
    )
    file_name: str | None
    file_size: int
    unsaved: bool = Field(description="A live capture that has not been saved to a file you chose.")
    saved_to: str | None
    error_code: str | None
    error_message: str | None
    warnings: list[str]
    limits: CaptureLimits
    termination: CaptureTermination | None = Field(
        default=None,
        description="Why a live capture ended; null while it runs and for opened files.",
    )


class StartCaptureRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    interface_id: str = Field(pattern=r"^[A-Za-z0-9._:@-]{1,64}$")
    promiscuous: bool = Field(
        default=False,
        description="Listen to traffic addressed to other devices on the network too. Off unless "
        "you choose it; some networks and policies treat it as sensitive.",
    )
    max_packets: int | None = Field(default=None, ge=1, le=10_000_000)
    max_seconds: int | None = Field(default=None, ge=1, le=86_400)


class PacketRow(BaseModel):
    number: int
    time: float = Field(description="Capture time, seconds since the Unix epoch.")
    source: str
    destination: str
    protocol: str
    length: int
    info: str


class PacketPage(BaseModel):
    rows: list[PacketRow]
    total: int = Field(
        description="Rows matching the filter and search (capped by the list limit)."
    )
    offset: int
    limit: int
    display_filter: str | None
    list_capped: bool = Field(description="More packets exist than the list can hold.")


class PacketField(BaseModel):
    name: str
    value: str
    children: list["PacketField"] = []


class PacketLayer(BaseModel):
    name: str
    fields: list[PacketField]
    truncated: bool


class PacketDetail(BaseModel):
    number: int
    layers: list[PacketLayer]
    data_hex: str = Field(description="The captured bytes of this packet as hexadecimal text.")
    data_length: int
    original_length: int
    data_truncated: bool


class FilterCheckRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    display_filter: str = Field(min_length=1, max_length=1000)


class FilterCheck(BaseModel):
    valid: bool
    error: str | None


class SaveCaptureRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str = Field(min_length=1, max_length=520, description="Absolute path ending in .pcapng.")


class SavedCapture(BaseModel):
    path: str
    packets: int
    size: int


class OpenCaptureRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str = Field(min_length=1, max_length=520, description="Absolute path of a .pcapng file.")
