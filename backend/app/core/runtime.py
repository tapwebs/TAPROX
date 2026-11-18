"""Process entrypoint: `python -m app`.

Protocol with the supervisor (the Tauri shell):
  1. The supervisor starts this process with `--token-stdin` and writes the API token as the first
     line of stdin. The token is never passed in argv or the environment, where other processes of
     the same user could read it.
  2. The backend binds 127.0.0.1 on an ephemeral port, migrates the database, starts serving, and
     only then prints one JSON line on stdout: {"event": "ready", "host": ..., "port": ...}.
  3. Stdin stays open. When it closes (the supervisor exited or crashed) the backend shuts down, so
     it can never be orphaned.

Exit codes: 0 clean shutdown, 2 configuration/token error, 3 data directory/database error.
"""

import argparse
import asyncio
import json
import logging
import os
import socket
import sys
import threading
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import BinaryIO

import uvicorn

from app import __version__
from app.core.config import (
    DEFAULT_ALLOWED_ORIGINS,
    LOOPBACK_HOST,
    Settings,
    SettingsError,
    default_data_dir,
)
from app.core.logging import configure_logging
from app.database import DatabaseInitError, init_database
from app.main import create_app

TOKEN_ENV_VAR = "TAPNETTRACK_API_TOKEN"  # noqa: S105 - the variable's name, not a secret

log = logging.getLogger("tapnettrack")


class TokenError(ValueError):
    """No usable API token was supplied."""


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="tapnettrack-backend", description=__doc__.split("\n")[0])
    parser.add_argument(
        "--data-dir", type=Path, default=None, help="Directory for the database and evidence."
    )
    parser.add_argument(
        "--port", type=int, default=0, help="Loopback port; 0 picks a free one (default)."
    )
    parser.add_argument(
        "--token-stdin",
        action="store_true",
        help=f"Read the API token from the first line of stdin (otherwise from ${TOKEN_ENV_VAR}).",
    )
    parser.add_argument(
        "--allowed-origin",
        action="append",
        default=[],
        metavar="ORIGIN",
        help="Additional browser origin allowed to call the API (e.g. a dev server). Repeatable.",
    )
    return parser.parse_args(argv)


def read_token(*, stdin_flag: bool, stdin: BinaryIO, environ: Mapping[str, str]) -> str:
    if stdin_flag:
        token = stdin.readline().decode("ascii", errors="replace").strip()
        if not token:
            raise TokenError("--token-stdin was given but stdin did not provide a token.")
        return token
    token = environ.get(TOKEN_ENV_VAR, "").strip()
    if not token:
        raise TokenError(
            "No API token. Pass --token-stdin and write the token to stdin, "
            f"or set {TOKEN_ENV_VAR}. Refusing to start an unauthenticated backend."
        )
    return token


def build_settings(args: argparse.Namespace, *, token: str) -> Settings:
    return Settings(
        data_dir=args.data_dir if args.data_dir else default_data_dir(),
        api_token=token,
        port=args.port,
        allowed_origins=(*DEFAULT_ALLOWED_ORIGINS, *args.allowed_origin),
    )


def format_ready_line(*, port: int, pid: int, version: str) -> str:
    return json.dumps(
        {"event": "ready", "host": LOOPBACK_HOST, "port": port, "pid": pid, "version": version}
    )


def bind_loopback(port: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if sys.platform == "win32":
        # Without this, another process could bind the same port with SO_REUSEADDR and
        # intercept traffic.
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)  # type: ignore[attr-defined,unused-ignore]
    sock.bind((LOOPBACK_HOST, port))
    return sock


def _exit_when_stdin_closes(server: uvicorn.Server, stdin: BinaryIO) -> None:
    stdin.read()  # blocks until EOF: the supervisor is gone
    log.info("stdin closed; supervisor is gone, shutting down")
    server.should_exit = True


async def _serve(app: object, sock: socket.socket, *, watch_stdin: bool, stdin: BinaryIO) -> None:
    config = uvicorn.Config(app, log_level="warning", access_log=False, lifespan="on")  # type: ignore[arg-type]
    server = uvicorn.Server(config)
    serving = asyncio.create_task(server.serve(sockets=[sock]))
    # uvicorn exposes startup completion only as the `started` flag, so poll it briefly.
    while not server.started and not serving.done():  # noqa: ASYNC110
        await asyncio.sleep(0.02)
    if server.started:
        port = sock.getsockname()[1]
        print(format_ready_line(port=port, pid=os.getpid(), version=__version__), flush=True)
        if watch_stdin:
            threading.Thread(
                target=_exit_when_stdin_closes,
                args=(server, stdin),
                daemon=True,
                name="stdin-watchdog",
            ).start()
    await serving


def main(argv: Sequence[str] | None = None) -> int:
    # The supervisor decodes our output as UTF-8. Without this a Windows pipe carries the console
    # code page, and any non-ASCII path or message in a startup error would be undecodable.
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    configure_logging()
    args = parse_args(argv)
    stdin = sys.stdin.buffer
    try:
        token = read_token(stdin_flag=args.token_stdin, stdin=stdin, environ=os.environ)
        settings = build_settings(args, token=token)
    except (TokenError, SettingsError) as exc:
        log.error("Configuration error: %s", exc)
        print(f"tapnettrack-backend: {exc}", file=sys.stderr)
        return 2
    try:
        log_path = configure_logging(settings.data_dir, session_token=token)
        log.info(
            "Starting tapnettrack-backend v%s (data_dir=%s, log=%s)",
            __version__,
            settings.data_dir,
            log_path,
        )
    except OSError as exc:
        log.warning("File logging unavailable in %s: %s", settings.data_dir, exc)
    try:
        engine = init_database(settings.data_dir)
    except DatabaseInitError as exc:
        log.error("Database initialization failed: %s", exc)
        print(f"tapnettrack-backend: {exc}", file=sys.stderr)
        return 3

    try:
        sock = bind_loopback(settings.port)
    except OSError as exc:
        log.error("Failed to bind %s:%s: %s", LOOPBACK_HOST, settings.port, exc)
        print(
            f"tapnettrack-backend: cannot bind {LOOPBACK_HOST}:{settings.port}: {exc}",
            file=sys.stderr,
        )
        engine.dispose()
        return 2
    log.info("Listening on %s:%s", LOOPBACK_HOST, sock.getsockname()[1])
    try:
        asyncio.run(
            _serve(create_app(settings, engine), sock, watch_stdin=args.token_stdin, stdin=stdin)
        )
    finally:
        sock.close()
    return 0
