"""Saved flow records. Only flow summaries are stored: no packet payloads and no packet list.

A capture session's flows are written when the capture ends and kept for the newest few sessions.
The packets themselves stay in the PCAPNG file the user chose to save.
"""

from datetime import datetime

from sqlalchemy import Float, ForeignKey, SmallInteger, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.types import UtcDateTime


class FlowSession(Base):
    __tablename__ = "flow_sessions"

    id: Mapped[int] = mapped_column(primary_key=True)
    source: Mapped[str] = mapped_column(String(8))  # live | file
    interface_id: Mapped[str | None] = mapped_column(String(64), default=None)
    interface_name: Mapped[str | None] = mapped_column(String(255), default=None)
    file_name: Mapped[str | None] = mapped_column(String(255), default=None)
    started_at: Mapped[datetime] = mapped_column(UtcDateTime, index=True)
    ended_at: Mapped[datetime | None] = mapped_column(UtcDateTime, default=None)
    status: Mapped[str] = mapped_column(String(16))  # running | completed | failed
    packets: Mapped[int] = mapped_column(default=0)
    bytes: Mapped[int] = mapped_column(default=0)
    totals_json: Mapped[str | None] = mapped_column(Text, default=None)
    timeline_json: Mapped[str | None] = mapped_column(Text, default=None)
    timeline_width: Mapped[int] = mapped_column(default=1)
    local_addresses_json: Mapped[str | None] = mapped_column(Text, default=None)
    local_networks_json: Mapped[str | None] = mapped_column(Text, default=None)
    warnings_json: Mapped[str | None] = mapped_column(Text, default=None)
    # The session vantage (revision 0006). NULL for sessions saved before it: vantage not recorded.
    gateways_json: Mapped[str | None] = mapped_column(Text, default=None)
    dns_servers_json: Mapped[str | None] = mapped_column(Text, default=None)
    interface_mac: Mapped[str | None] = mapped_column(String(17), default=None)
    promiscuous: Mapped[bool | None] = mapped_column(default=None)
    network_key: Mapped[str | None] = mapped_column(String(64), default=None)


class FlowRow(Base):
    __tablename__ = "flows"
    __table_args__ = (UniqueConstraint("session_id", "seq", name="uq_flows_session_seq"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[int] = mapped_column(
        ForeignKey("flow_sessions.id", ondelete="CASCADE"), index=True
    )
    seq: Mapped[int]
    transport: Mapped[str] = mapped_column(String(24))
    ip_version: Mapped[int] = mapped_column(SmallInteger)
    src_ip: Mapped[str] = mapped_column(String(45))
    dst_ip: Mapped[str] = mapped_column(String(45))
    src_port: Mapped[int | None] = mapped_column(default=None)
    dst_port: Mapped[int | None] = mapped_column(default=None)
    initiator_basis: Mapped[str] = mapped_column(String(12))
    first_seen: Mapped[float] = mapped_column(Float)
    last_seen: Mapped[float] = mapped_column(Float)
    first_packet: Mapped[int]
    last_packet: Mapped[int]
    packets_fwd: Mapped[int]
    packets_rev: Mapped[int]
    bytes_fwd: Mapped[int]
    bytes_rev: Mapped[int]
    state: Mapped[str] = mapped_column(String(16))
    tcp_bits: Mapped[int] = mapped_column(SmallInteger, default=0)
    mac_src: Mapped[str | None] = mapped_column(String(17), default=None)
    mac_dst: Mapped[str | None] = mapped_column(String(17), default=None)
    mac_dst_hint: Mapped[str | None] = mapped_column(String(17), default=None)
    protocol: Mapped[str] = mapped_column(String(40))
    application: Mapped[str | None] = mapped_column(String(64), default=None)
    category: Mapped[str] = mapped_column(String(48))
    method: Mapped[str] = mapped_column(String(24))
    confidence: Mapped[str] = mapped_column(String(12))
    evidence_json: Mapped[str | None] = mapped_column(Text, default=None)
    meta_json: Mapped[str | None] = mapped_column(Text, default=None)
