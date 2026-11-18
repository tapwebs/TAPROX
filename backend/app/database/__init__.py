"""SQLite storage: engine configuration, schema migrations and backup before migrating."""

import os
import sqlite3
import sys
from datetime import UTC, datetime
from pathlib import Path

from alembic.util.exc import CommandError
from sqlalchemy import Engine
from sqlalchemy.exc import SQLAlchemyError

from app.database.engine import DATABASE_FILENAME, create_db_engine
from app.database.migrate import current_schema_version, pending_upgrade_from, upgrade_to_head

__all__ = ["DatabaseInitError", "current_schema_version", "init_database"]

BACKUPS_KEPT = 3


class DatabaseInitError(RuntimeError):
    """Startup cannot continue; the message is safe to show to the user."""


def _backup_before_migrating(db_path: Path, from_revision: str) -> None:
    """Copy the database, consistently (SQLite backup API, WAL-safe), before it is upgraded."""
    folder = db_path.parent / "backups"
    created = not folder.exists()
    folder.mkdir(exist_ok=True)
    if created and sys.platform != "win32":
        os.chmod(folder, 0o700)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    target = folder / f"tapnettrack-{from_revision}-{stamp}.db"
    source = sqlite3.connect(db_path)
    try:
        destination = sqlite3.connect(target)
        try:
            source.backup(destination)
        finally:
            destination.close()
    finally:
        source.close()
    # Keep only the newest few; names end in a sortable UTC timestamp.
    older = sorted(folder.glob("tapnettrack-*.db"), key=lambda p: p.stem.rsplit("-", 1)[-1])[
        :-BACKUPS_KEPT
    ]
    for path in older:
        path.unlink(missing_ok=True)


def init_database(data_dir: Path) -> Engine:
    """Create the data directory and database if needed and migrate it to the latest schema.

    An existing database that is older than this version is backed up first; a database from a
    newer version is refused untouched.
    """
    try:
        created = not data_dir.exists()
        data_dir.mkdir(parents=True, exist_ok=True)
        if created and sys.platform != "win32":
            os.chmod(data_dir, 0o700)  # only a directory we made; never tighten one we were given
    except OSError as exc:
        raise DatabaseInitError(
            f"Cannot use data directory {data_dir}: {exc.strerror or exc}"
        ) from exc

    db_path = data_dir / DATABASE_FILENAME
    existed = db_path.exists() and db_path.stat().st_size > 0
    engine = create_db_engine(db_path)
    try:
        if existed:
            old = pending_upgrade_from(engine)
            if old is not None:
                try:
                    _backup_before_migrating(db_path, old)
                except (OSError, sqlite3.Error) as exc:
                    raise DatabaseInitError(
                        f"Could not back up the database before upgrading it ({exc}); "
                        "the upgrade was not attempted so no data is at risk."
                    ) from exc
        upgrade_to_head(engine)
    except CommandError as exc:
        engine.dispose()
        raise DatabaseInitError(
            "The database was created by a newer version of TAPROX; "
            "refusing to open it so existing data is not damaged."
        ) from exc
    except SQLAlchemyError as exc:
        engine.dispose()
        raise DatabaseInitError(f"Cannot open the database in {data_dir}: {exc}") from exc
    except DatabaseInitError:
        engine.dispose()
        raise
    return engine
