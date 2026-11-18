"""Isolated per-case PCAPNG evidence vault and streaming SHA-256 verification (Phase 6)."""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from app.services.capture.paths import PathRefused, validate_open_path
from app.services.capture.pcapng import PcapngError, scan_file

DEFAULT_MAX_VAULT_FILE_BYTES = 512 * 1024 * 1024  # 512 MiB
DEFAULT_MAX_TOTAL_VAULT_BYTES = 4 * 1024 * 1024 * 1024  # 4 GiB
STREAM_CHUNK_BYTES = 1024 * 1024


class VaultRefused(ValueError):
    """Raised when an artifact path or PCAPNG payload is unsafe or invalid."""


class VaultQuotaError(VaultRefused):
    """Raised when vaulting a file would exceed per-file or global vault quotas."""


@dataclass(frozen=True, slots=True)
class AcquiredFileResult:
    storage_mode: str  # vault_file | external_linked_file
    content_sha256: str
    file_size_bytes: int
    packets: int
    captured_bytes: int
    vault_relpath: str | None
    external_path_recorded: str


def case_vault_dir(data_dir: Path, case_uid: str) -> Path:
    if not case_uid or any(sep in case_uid for sep in ("/", "\\", "..")):
        raise VaultRefused("Invalid investigation directory identifier.")
    return (data_dir / "investigations" / case_uid / "vault").resolve()


def resolve_vault_path(data_dir: Path, case_uid: str, relpath: str) -> Path:
    """Resolve a stored relative vault filename strictly inside the case vault directory."""
    if not relpath or any(part in ("..", "") for part in Path(relpath).parts):
        raise VaultRefused("Invalid relative vault path.")
    base = case_vault_dir(data_dir, case_uid)
    candidate = (base / relpath).resolve()
    if not candidate.is_relative_to(base) or candidate == base:
        raise VaultRefused("Vault path escapes investigation isolation boundary.")
    return candidate


def stream_sha256(path: Path) -> str:
    """Compute SHA-256 hex digest in constant memory."""
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(STREAM_CHUNK_BYTES):
            digest.update(chunk)
    return digest.hexdigest()


def total_vault_bytes(data_dir: Path) -> int:
    root = data_dir / "investigations"
    if not root.is_dir():
        return 0
    total = 0
    for item in root.rglob("*"):
        if item.is_file() and not item.is_symlink():
            total += item.stat().st_size
    return total


def _validate_local_pcapng(source_path: str) -> tuple[Path, int, int, int]:
    try:
        path = validate_open_path(source_path)
    except PathRefused as exc:
        raise VaultRefused(str(exc)) from exc
    if path.is_symlink():
        raise VaultRefused("Symbolic links are not permitted as forensic evidence paths.")
    resolved = path.resolve()
    if resolved != path:
        # Refuse path traversal through symlinked parent directories.
        for parent in path.parents:
            if parent.is_symlink():
                raise VaultRefused("Paths traversing symbolic links are not permitted.")
    if resolved.suffix.lower() != ".pcapng":
        raise VaultRefused("Evidence file must use the .pcapng extension.")
    try:
        scan = scan_file(resolved)
    except (OSError, PcapngError) as exc:
        raise VaultRefused(f"Invalid or unreadable PCAPNG file: {exc}") from exc
    size = resolved.stat().st_size
    return resolved, size, scan.packets, scan.captured_bytes


def acquire_pcapng_artifact(
    *,
    data_dir: Path,
    case_uid: str,
    evidence_ref: str,
    source_path: str,
    vault_copy: bool,
    max_file_bytes: int = DEFAULT_MAX_VAULT_FILE_BYTES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_VAULT_BYTES,
) -> AcquiredFileResult:
    """Validate and hash a PCAPNG file without modifying it, optionally copying to the vault."""
    resolved, size, packets, captured_bytes = _validate_local_pcapng(source_path)
    digest = stream_sha256(resolved)

    if not vault_copy:
        return AcquiredFileResult(
            storage_mode="external_linked_file",
            content_sha256=digest,
            file_size_bytes=size,
            packets=packets,
            captured_bytes=captured_bytes,
            vault_relpath=None,
            external_path_recorded=str(resolved),
        )

    if size > max_file_bytes:
        raise VaultQuotaError(
            f"Capture file ({size} bytes) exceeds per-file vault cap ({max_file_bytes} bytes); "
            "explicitly opt in to external linking instead."
        )
    used = total_vault_bytes(data_dir)
    if used + size > max_total_bytes:
        raise VaultQuotaError(f"Vault quota exceeded ({used + size} > {max_total_bytes} bytes).")

    vault_dir = case_vault_dir(data_dir, case_uid)
    vault_dir.mkdir(parents=True, exist_ok=True)
    rel_name = f"{evidence_ref}_{digest[:12]}.pcapng"
    dest = resolve_vault_path(data_dir, case_uid, rel_name)
    tmp_dest = dest.with_name(f".{rel_name}.part")
    if dest.exists() or tmp_dest.exists():
        raise VaultRefused("Vault artifact target already exists; refusing silent overwrite.")

    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    fd = os.open(tmp_dest, flags, 0o600)
    try:
        copied_hash = hashlib.sha256()
        with os.fdopen(fd, "wb") as dst, resolved.open("rb") as src:
            while chunk := src.read(STREAM_CHUNK_BYTES):
                dst.write(chunk)
                copied_hash.update(chunk)
        if copied_hash.hexdigest() != digest:
            raise VaultRefused("Source PCAPNG changed during vault copy.")
        os.replace(tmp_dest, dest)
        # Mark read-only so accidental tools do not mutate vaulted evidence.
        os.chmod(dest, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
    except Exception:
        if tmp_dest.exists():
            tmp_dest.unlink(missing_ok=True)
        raise

    return AcquiredFileResult(
        storage_mode="vault_file",
        content_sha256=digest,
        file_size_bytes=size,
        packets=packets,
        captured_bytes=captured_bytes,
        vault_relpath=rel_name,
        external_path_recorded=str(resolved),
    )


def verify_file_artifact(
    *,
    data_dir: Path,
    case_uid: str,
    storage_mode: str,
    vault_relpath: str | None,
    external_path: str | None,
    expected_sha256: str,
) -> tuple[str, str | None]:
    """Recompute SHA-256 of a vaulted or external file artifact without altering it."""
    if storage_mode == "vault_file":
        if not vault_relpath:
            return ("missing_external", None)
        try:
            target = resolve_vault_path(data_dir, case_uid, vault_relpath)
        except VaultRefused:
            return ("mismatch", None)
        if not target.is_file() or target.is_symlink():
            return ("missing_external", None)
    elif storage_mode == "external_linked_file":
        if not external_path:
            return ("missing_external", None)
        try:
            path = validate_open_path(external_path)
        except PathRefused:
            return ("missing_external", None)
        if not path.is_file() or path.is_symlink():
            return ("missing_external", None)
        target = path.resolve()
    else:
        return ("unverified", None)

    actual = stream_sha256(target)
    return ("verified" if actual == expected_sha256 else "mismatch", actual)
