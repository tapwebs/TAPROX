"""Pure deterministic canonical JSON serialization and SHA-256 hashing (Phase 6)."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

CANONICAL_VERSION = 1
HASH_ALGORITHM = "sha256"


def normalize_for_hash(value: Any) -> Any:
    """Convert dates and nested structures deterministically for canonical JSON."""
    if isinstance(value, datetime):
        dt = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
        return dt.astimezone(UTC).isoformat()
    if isinstance(value, Mapping):
        return {str(k): normalize_for_hash(v) for k, v in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return [normalize_for_hash(item) for item in value]
    if isinstance(value, float):
        # Avoid -0.0 drift while keeping normal finite floats deterministic.
        return 0.0 if value == 0.0 else value
    return value


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize any JSON-compatible mapping/value using sorted keys and compact UTF-8."""
    normalized = normalize_for_hash(value)
    text = json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return text.encode("utf-8")


def canonical_json_str(value: Any) -> str:
    """Return canonical UTF-8 JSON string with sorted keys and compact separators."""
    return canonical_json_bytes(value).decode("utf-8")


def canonical_sha256(value: Any) -> str:
    """Return SHA-256 hex digest of the canonical JSON serialization of ``value``."""
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def sha256_bytes(data: bytes) -> str:
    """Return SHA-256 hex digest of raw bytes."""
    return hashlib.sha256(data).hexdigest()

