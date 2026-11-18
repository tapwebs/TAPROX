from pathlib import Path
from typing import Any

from sqlalchemy import URL, Engine, create_engine, event

DATABASE_FILENAME = "tapnettrack.db"


def create_db_engine(db_path: Path) -> Engine:
    # check_same_thread=False: FastAPI runs sync endpoints on a thread pool; SQLAlchemy's pool
    # guarantees one connection is used by one thread at a time.
    engine = create_engine(
        URL.create("sqlite", database=str(db_path)),
        connect_args={"check_same_thread": False},
    )

    @event.listens_for(engine, "connect")
    def configure_connection(dbapi_connection: Any, _: object) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")  # SQLite ignores FKs unless asked, per connection
        cursor.execute("PRAGMA journal_mode=WAL")  # readers do not block the writer
        cursor.execute("PRAGMA synchronous=NORMAL")  # durable enough with WAL, much faster
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.close()

    return engine
