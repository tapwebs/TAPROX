from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from alembic.util.exc import CommandError
from sqlalchemy import Engine

MIGRATIONS_DIR = Path(__file__).parent / "migrations"


def _config() -> Config:
    config = Config()  # no alembic.ini: the script location is the only setting we need
    config.set_main_option("script_location", str(MIGRATIONS_DIR))
    return config


def upgrade_to_head(engine: Engine, target: str = "head") -> None:
    config = _config()
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, target)


def current_schema_version(engine: Engine) -> str | None:
    with engine.connect() as connection:
        return MigrationContext.configure(connection).get_current_revision()


def head_revision() -> str:
    head = ScriptDirectory.from_config(_config()).get_current_head()
    if head is None:  # pragma: no cover - the package always ships migrations
        raise RuntimeError("No database migrations are installed.")
    return head


def pending_upgrade_from(engine: Engine) -> str | None:
    """The current revision when this database is *older* than the code and will be migrated.

    Returns None for a fresh database, an up-to-date one, and one from a *newer* version (whose
    revision this code does not know); the upgrade itself then refuses the newer database.
    """
    current = current_schema_version(engine)
    if current is None or current == head_revision():
        return None
    try:
        ScriptDirectory.from_config(_config()).get_revision(current)
    except CommandError:
        return None
    return current
