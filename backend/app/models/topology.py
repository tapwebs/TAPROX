"""Topology history (revision 0006): relationships seen in live sessions, with a count per day.

Opened files never write here. Nothing in these tables is a packet or a payload.
"""

from datetime import datetime

from sqlalchemy import BigInteger, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.types import UtcDateTime


class TopologyEdge(Base):
    __tablename__ = "topology_edges"
    __table_args__ = (
        Index("ix_topology_edges_last_seen", "last_seen_at"),
        Index("ix_topology_edges_a", "a_key"),
        Index("ix_topology_edges_b", "b_key"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    edge_key: Mapped[str] = mapped_column(String(200), unique=True)
    kind: Mapped[str] = mapped_column(String(16))
    a_key: Mapped[str] = mapped_column(String(64))
    b_key: Mapped[str] = mapped_column(String(64))
    a_label: Mapped[str] = mapped_column(String(80))
    b_label: Mapped[str] = mapped_column(String(80))
    basis: Mapped[str] = mapped_column(String(10))
    confidence: Mapped[str] = mapped_column(String(10))
    first_seen_at: Mapped[datetime] = mapped_column(UtcDateTime)
    last_seen_at: Mapped[datetime] = mapped_column(UtcDateTime)
    flows: Mapped[int] = mapped_column(default=0)
    bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    protocols_json: Mapped[str] = mapped_column(Text, default="[]")
    applications_json: Mapped[str] = mapped_column(Text, default="[]")


class TopologyEdgeDay(Base):
    __tablename__ = "topology_edge_days"

    edge_id: Mapped[int] = mapped_column(
        ForeignKey("topology_edges.id", ondelete="CASCADE"), primary_key=True
    )
    day: Mapped[str] = mapped_column(String(10), primary_key=True)  # ISO date
    flows: Mapped[int] = mapped_column(default=0)
    bytes: Mapped[int] = mapped_column(BigInteger, default=0)
