from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

DeviceState = Literal["active", "inactive", "previously_observed"]
Confidence = Literal["confirmed", "probable", "stale"]


class ObservedFacts(BaseModel):
    """What the network actually showed us. Every field here came from a reply or a table entry."""

    ip: str | None = Field(description="The address most recently seen with this MAC.")
    interface_id: str | None = Field(description="The local interface the sighting came through.")
    hostname: str | None = Field(
        description="A name returned by reverse DNS. The DNS server's claim, not proof of identity."
    )
    hostname_source: str | None
    first_seen: datetime
    last_seen: datetime
    source: str = Field(
        description="How the latest sighting was made: arp, ndp, os_neighbor_table or "
        "local_interface."
    )
    confidence: Confidence = Field(
        description="confirmed: replied to our own probe; probable: the OS neighbor table lists it "
        "as recently reachable; stale: the OS lists it but has not confirmed it lately."
    )


class InferredFacts(BaseModel):
    """Conclusions drawn from the observations. Treat these as hints, not facts."""

    vendor: str | None = Field(
        description="Who made the network chip, from the first bits of the MAC. Not what the "
        "device is."
    )
    vendor_basis: Literal["oui"] | None
    mac_randomized: bool = Field(
        description="The MAC is locally administered: a virtual adapter or a privacy-randomised "
        "address. The same device may appear under other MACs."
    )
    state: DeviceState = Field(
        description="How recently it was observed. Not being observed is not proof of being "
        "offline."
    )


class Device(BaseModel):
    id: int
    mac: str
    is_local: bool = Field(description="This MAC belongs to one of this computer's own interfaces.")
    observed: ObservedFacts
    inferred: InferredFacts


class DeviceAddress(BaseModel):
    ip: str
    family: Literal[4, 6]
    interface_id: str
    first_seen: datetime
    last_seen: datetime


class DeviceDetail(Device):
    addresses: list[DeviceAddress] = Field(description="Every address seen, newest first.")


class DeviceList(BaseModel):
    devices: list[Device]
    total: int = Field(description="Devices matching the filters, ignoring paging.")
    limit: int
    offset: int
    generated_at: datetime


class DeviceObservation(BaseModel):
    id: int
    observed_at: datetime
    source: str
    ip: str | None
    interface_id: str | None
    confidence: Confidence
    neighbor_state: str | None
    hostname: str | None
    scan_id: str | None


class DeviceObservationList(BaseModel):
    observations: list[DeviceObservation]
    total: int
    limit: int
    offset: int
