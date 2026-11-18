from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class AppMeta(Base):
    """Small key/value table for installation-level facts (e.g. when the database was created)."""

    __tablename__ = "app_meta"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(String(512))
