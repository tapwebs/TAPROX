"""Redacted rotating logging configuration for the local backend."""

from __future__ import annotations

import logging
import re
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

MAX_LOG_BYTES = 2 * 1024 * 1024
BACKUP_COUNT = 2
LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"

_BEARER_RE = re.compile(r"(?i)(Bearer\s+)[A-Za-z0-9\-._~+/]+=*")
_HEADER_SECRET_RE = re.compile(
    r"(?i)((?:X-Tapnettrack-Token|Authorization|Set-Cookie|Cookie)\s*[:=]\s*)(?:Bearer\s+)?([^\r\n,;\s]+)"
)
_QUERY_SECRET_RE = re.compile(
    r"(?i)([?&](?:token|api_key|apikey|password|passwd|secret|session|auth)=)([^&\s]+)"
)
_URL_USERINFO_RE = re.compile(r"(?i)(https?://)([^:@/\s]+:[^@/\s]+@)")
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]+")


def redact_text(text: str, session_token: str | None = None) -> str:
    """Scrub tokens, auth/cookie headers, URL credentials, query secrets, and control chars."""
    scrubbed = text
    if session_token:
        scrubbed = scrubbed.replace(session_token, "[REDACTED]")
    scrubbed = _BEARER_RE.sub(r"\1[REDACTED]", scrubbed)
    scrubbed = _HEADER_SECRET_RE.sub(r"\1[REDACTED]", scrubbed)
    scrubbed = _QUERY_SECRET_RE.sub(r"\1[REDACTED]", scrubbed)
    scrubbed = _URL_USERINFO_RE.sub(r"\1[REDACTED]@", scrubbed)
    scrubbed = _CONTROL_CHARS_RE.sub(" ", scrubbed)
    return scrubbed


class RedactingFilter(logging.Filter):
    """Logging filter that redacts sensitive tokens and headers from formatted messages."""

    def __init__(self, session_token: str | None = None) -> None:
        super().__init__()
        self._session_token = session_token

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        record.msg = redact_text(message, self._session_token)
        record.args = None
        return True


def configure_logging(
    data_dir: Path | None = None,
    *,
    session_token: str | None = None,
    max_bytes: int = MAX_LOG_BYTES,
    backup_count: int = BACKUP_COUNT,
) -> Path | None:
    """Configure root stderr and optional rotating file logging with secret redaction."""
    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
        existing.close()

    root.setLevel(logging.INFO)
    formatter = logging.Formatter(LOG_FORMAT)
    redactor = RedactingFilter(session_token)

    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setFormatter(formatter)
    stderr_handler.addFilter(redactor)
    root.addHandler(stderr_handler)

    if data_dir is None:
        return None

    logs_dir = data_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    log_path = logs_dir / "backend.log"
    file_handler = RotatingFileHandler(
        log_path,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    file_handler.addFilter(redactor)
    root.addHandler(file_handler)
    return log_path
