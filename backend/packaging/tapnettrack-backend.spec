# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller --onedir specification for the TAPNETTRACK local backend."""

from pathlib import Path
from PyInstaller.utils.hooks import collect_submodules

BACKEND_ROOT = Path(SPECPATH).parent.resolve()

hiddenimports = [
    *collect_submodules("app.models"),
    *collect_submodules("app.database.migrations"),
    "uvicorn.logging",
    "uvicorn.loops",
    "uvicorn.loops.auto",
    "uvicorn.protocols",
    "uvicorn.protocols.http",
    "uvicorn.protocols.http.auto",
    "uvicorn.protocols.http.h11_impl",
    "uvicorn.protocols.websockets",
    "uvicorn.protocols.websockets.auto",
    "uvicorn.lifespan",
    "uvicorn.lifespan.on",
    "sqlalchemy.dialects.sqlite",
    "alembic.runtime.migration",
    "alembic.script",
    "cryptography",
]

datas = [
    (
        str(BACKEND_ROOT / "app" / "database" / "migrations"),
        "app/database/migrations",
    ),
]

a = Analysis(
    [str(BACKEND_ROOT / "app" / "__main__.py")],
    pathex=[str(BACKEND_ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["pytest", "_pytest", "ruff", "mypy", "httpx2", "tkinter"],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="tapnettrack-backend",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="tapnettrack-backend",
)

