"""Application factory."""

import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime

from fastapi import FastAPI
from sqlalchemy import Engine

from app import __version__
from app.api.v1 import router as v1_router
from app.core.config import Settings
from app.core.errors import install_error_handlers
from app.core.security import install_security
from app.services.capture.service import CaptureService
from app.services.detection.config_store import ConfigStore
from app.services.detection.service import DetectionService
from app.services.detection.store import AlertStore
from app.services.discovery.backend import DiscoveryBackend
from app.services.discovery.factory import default_backend
from app.services.discovery.service import DiscoveryService
from app.services.flows.service import FlowService
from app.services.flows.store import FlowStore
from app.services.forensics.service import ForensicsService
from app.services.interface_manager import InterfaceProvider, default_provider
from app.services.interface_manager.manager import InterfaceManager
from app.services.self_activity import SelfActivity
from app.services.topology.service import TopologyService
from app.services.web_inspector.service import WebInspectorService


def create_app(
    settings: Settings,
    engine: Engine,
    *,
    interface_provider: InterfaceProvider | None = None,
    discovery_backend: DiscoveryBackend | None = None,
    capture_service: CaptureService | None = None,
) -> FastAPI:
    """Build the app around an already-initialised database.

    The caller initialises the database first so a startup failure (unwritable directory, database
    from a newer version) is reported as a clear message before any server starts.
    `interface_provider` and `discovery_backend` exist so automated tests can supply deterministic
    stand-ins; the running application always uses the real ones for this operating system.
    """

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.discovery.recover()  # a scan still marked 'running' died with the last process
        app.state.capture.recover()  # temporary capture files left by a crash
        app.state.detection.recover()  # aborted runs, alert retention, starts the alert writer
        app.state.web_inspector.recover()  # mark any interrupted inspections cancelled
        app.state.forensics.recover()
        try:
            yield
        finally:
            app.state.forensics.shutdown()
            app.state.web_inspector.shutdown()  # abort active inspection socket & join worker
            app.state.capture.shutdown()  # stop dumpcap/tshark: no orphaned processes
            app.state.detection.shutdown()  # workers drain, then the alert writer stores the rest
            app.state.discovery.shutdown()  # stop and join the scan thread before the database goes
            app.state.engine.dispose()

    # Interactive docs and the schema endpoint are off at runtime: they would be unauthenticated
    # surface. The contract is exported offline with scripts/export_contract.py.
    app = FastAPI(
        title="TAPROX Backend",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.engine = engine
    app.state.started_at = datetime.now(UTC)  # shown to users
    app.state.started_monotonic = time.monotonic()  # used for durations; immune to clock changes
    app.state.interfaces = InterfaceManager(interface_provider or default_provider())
    # When our own discovery scan sends probes (detection ignores those).
    app.state.self_activity = SelfActivity()
    app.state.discovery = DiscoveryService(
        engine,
        app.state.interfaces,
        discovery_backend or default_backend(),
        activity=app.state.self_activity,
    )
    flow_store = FlowStore(engine)
    app.state.detection = DetectionService(
        store=AlertStore(engine),
        own_activity=app.state.self_activity.contains,
        config=ConfigStore(engine),
        vantage_sink=flow_store.save_vantage,
    )
    app.state.discovery.on_scan_finished = app.state.detection.inventory_scan_finished
    app.state.capture = capture_service or CaptureService(
        app.state.interfaces,
        settings.data_dir / "capture",
        flow_store=flow_store,
        tap_factory=app.state.detection.tap_factory,
    )
    app.state.flows = FlowService(app.state.capture, flow_store, engine)
    app.state.topology = TopologyService(engine, flow_store, app.state.capture)
    app.state.web_inspector = WebInspectorService(
        engine, blocked_port=settings.port if settings.port > 0 else None
    )
    app.state.forensics = ForensicsService(engine, settings.data_dir)
    flow_store.on_session_saved = app.state.topology.record_session

    install_error_handlers(app)
    install_security(app, settings)  # also turns unexpected exceptions into the 500 envelope
    app.include_router(v1_router, prefix="/api/v1")
    return app
