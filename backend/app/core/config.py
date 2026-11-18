"""Validated runtime settings.

Everything security-relevant is checked once, here, so the rest of the backend can trust it.
The backend binds loopback only; there is deliberately no host setting.
"""

from __future__ import annotations

import os
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

LOOPBACK_HOST = "127.0.0.1"

# Origins used by the Tauri 2 webview: Windows (http/https), Linux and macOS (custom scheme).
DEFAULT_ALLOWED_ORIGINS = (
    "http://tauri.localhost",
    "https://tauri.localhost",
    "tauri://localhost",
)

# secrets.token_urlsafe(32) yields 43 characters from this alphabet.
_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{32,256}")
# scheme://host[:port], no path/query, no wildcard. Host characters are restricted on purpose.
_ORIGIN_PATTERN = re.compile(r"[a-z][a-z0-9+.-]*://[A-Za-z0-9.-]+(:\d{1,5})?")


class SettingsError(ValueError):
    """Raised when startup settings are unsafe or malformed."""


@dataclass(frozen=True, slots=True)
class Settings:
    data_dir: Path
    api_token: str = field(repr=False)
    port: int = 0
    allowed_origins: tuple[str, ...] = DEFAULT_ALLOWED_ORIGINS

    def __post_init__(self) -> None:
        if not _TOKEN_PATTERN.fullmatch(self.api_token):
            raise SettingsError(
                "API token must be 32-256 URL-safe characters (A-Z a-z 0-9 _ -); "
                "refusing to start without a strong token."
            )
        if not 0 <= self.port <= 65535:
            raise SettingsError(f"Invalid port {self.port}; use 0 for an ephemeral port.")
        for origin in self.allowed_origins:
            if not _ORIGIN_PATTERN.fullmatch(origin):
                raise SettingsError(
                    f"Invalid allowed origin {origin!r}; wildcards are not allowed."
                )


def default_data_dir(
    env: Mapping[str, str] | None = None,
    platform: str | None = None,
    home: Path | None = None,
) -> Path:
    """Per-user application data directory (parameters exist so each OS branch is testable)."""
    env = os.environ if env is None else env
    platform = sys.platform if platform is None else platform
    home = Path.home() if home is None else home
    if platform == "win32":
        base = env.get("LOCALAPPDATA")
        return (Path(base) if base else home / "AppData" / "Local") / "TAPNETTRACK"
    xdg = env.get("XDG_DATA_HOME")
    return (Path(xdg) if xdg else home / ".local" / "share") / "tapnettrack"
