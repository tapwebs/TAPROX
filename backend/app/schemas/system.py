from datetime import datetime
from typing import Literal

from pydantic import BaseModel


class PrerequisiteCheck(BaseModel):
    """Result of looking for one native capture prerequisite. Nothing here is simulated."""

    id: Literal["capture_library", "dumpcap", "tshark"]
    name: str
    required_for: str
    status: Literal["ok", "missing", "error"]
    version: str | None
    path: str | None
    detail: str | None
    remediation: str | None


class PlatformInfo(BaseModel):
    os: Literal["windows", "linux", "unsupported"]
    os_version: str
    architecture: str
    elevated: bool


class CapturePrerequisitesResponse(BaseModel):
    """What was found on this machine.

    "tools ready" means the tools are installed and runnable. It does not prove that this user may
    capture on a given interface; that is only known when a capture is started (Phase 2).
    """

    platform: PlatformInfo
    checks: list[PrerequisiteCheck]
    capture_tools_ready: bool
    analysis_tools_ready: bool
    warnings: list[str]
    checked_at: datetime
