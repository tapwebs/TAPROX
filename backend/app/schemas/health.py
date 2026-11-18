from datetime import datetime
from typing import Literal

from pydantic import BaseModel


class DatabaseHealth(BaseModel):
    status: Literal["ok", "error"]
    schema_version: str | None
    initialized_at: datetime | None


class HealthResponse(BaseModel):
    status: Literal["ok", "unhealthy"]
    service: Literal["tapnettrack-backend"]
    version: str
    api_version: Literal["v1"]
    started_at: datetime
    uptime_seconds: float
    database: DatabaseHealth
