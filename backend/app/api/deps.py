from collections.abc import Iterator

from fastapi import Request
from sqlalchemy.orm import Session


def get_session(request: Request) -> Iterator[Session]:
    """One database session per request, closed afterwards. Sync, so it runs off the event loop."""
    with Session(request.app.state.engine) as session:
        yield session
