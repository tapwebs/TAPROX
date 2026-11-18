"""Alembic environment: migrations always run on a connection handed in by app.database.migrate."""

from alembic import context

from app.models import (  # noqa: F401  (register models on Base.metadata)
    alert,
    app_meta,
    detection,
    device,
    discovery_scan,
    flow,
    forensics,
    topology,
    web_inspector,
)
from app.models.base import Base

connection = context.config.attributes["connection"]
context.configure(connection=connection, target_metadata=Base.metadata)

with context.begin_transaction():
    context.run_migrations()
