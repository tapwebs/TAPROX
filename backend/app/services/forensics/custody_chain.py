"""Pure append-only SHA-256 hash-chain builder and verifier (Phase 6)."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from app.services.forensics.canonical import canonical_sha256

GENESIS_HASH = "0" * 64


@dataclass(frozen=True, slots=True)
class ChainLinkInput:
    seq: int
    payload: Mapping[str, Any]
    prev_sha256: str
    event_sha256: str


@dataclass(frozen=True, slots=True)
class ChainVerificationResult:
    valid: bool
    checked_links: int
    first_invalid_seq: int | None
    error: str | None
    head_seq: int
    head_sha256: str


def compute_chain_hash(payload: Mapping[str, Any], prev_sha256: str) -> str:
    """Compute SHA-256 over canonical link payload plus previous link digest."""
    return canonical_sha256({"prev_sha256": prev_sha256, "payload": dict(payload)})


def verify_hash_chain(
    links: Sequence[ChainLinkInput],
    *,
    expected_head_sha256: str | None = None,
) -> ChainVerificationResult:
    """Verify contiguous sequence numbers (1..N), backlinks, and payload digests."""
    if not links:
        if expected_head_sha256 is not None and expected_head_sha256 != GENESIS_HASH:
            return ChainVerificationResult(
                valid=False,
                checked_links=0,
                first_invalid_seq=None,
                error="head_hash_mismatch",
                head_seq=0,
                head_sha256=GENESIS_HASH,
            )
        return ChainVerificationResult(
            valid=True,
            checked_links=0,
            first_invalid_seq=None,
            error=None,
            head_seq=0,
            head_sha256=GENESIS_HASH,
        )

    expected_prev = GENESIS_HASH
    expected_seq = 1
    checked = 0
    for link in links:
        if link.seq != expected_seq:
            return ChainVerificationResult(
                valid=False,
                checked_links=checked,
                first_invalid_seq=link.seq,
                error="sequence_gap_or_order",
                head_seq=expected_seq - 1,
                head_sha256=expected_prev,
            )
        if link.prev_sha256 != expected_prev:
            return ChainVerificationResult(
                valid=False,
                checked_links=checked,
                first_invalid_seq=link.seq,
                error="prev_hash_mismatch",
                head_seq=expected_seq - 1,
                head_sha256=expected_prev,
            )
        computed = compute_chain_hash(link.payload, link.prev_sha256)
        if link.event_sha256 != computed:
            return ChainVerificationResult(
                valid=False,
                checked_links=checked,
                first_invalid_seq=link.seq,
                error="event_hash_mismatch",
                head_seq=expected_seq - 1,
                head_sha256=expected_prev,
            )
        expected_prev = link.event_sha256
        expected_seq += 1
        checked += 1

    if expected_head_sha256 is not None and expected_prev != expected_head_sha256:
        return ChainVerificationResult(
            valid=False,
            checked_links=checked,
            first_invalid_seq=checked,
            error="head_hash_mismatch",
            head_seq=checked,
            head_sha256=expected_prev,
        )
    return ChainVerificationResult(
        valid=True,
        checked_links=checked,
        first_invalid_seq=None,
        error=None,
        head_seq=checked,
        head_sha256=expected_prev,
    )

