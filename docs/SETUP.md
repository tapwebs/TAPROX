# TAPNETTRACK Setup, Upgrade & Operations Guide

## Supported Platforms
- **Windows 10 (22H2+) and Windows 11 x64** (`x86_64-pc-windows-msvc`).
- Installs **per-user** by default to `%LOCALAPPDATA%\Programs\TAPNETTRACK\` with **no Administrator elevation required**.

## Offline Installation
1. Run `TAPNETTRACK_<version>_x64-setup.exe`.
2. The installer embeds the Microsoft Edge WebView2 Evergreen Standalone Installer (`offlineInstaller` mode) so no internet connection is required during setup.
3. Launch **TAPNETTRACK** from the Start Menu or Desktop shortcut.

## Optional Live Packet Capture Prerequisites
Overview, Device Discovery, Web Inspector, and Investigations & Forensics work out of the box with zero external tools.
To enable **live packet capture** and **PCAPNG dissection** in Packet Explorer:
1. Install **Wireshark** (provides `dumpcap.exe` and `tshark.exe` in `%ProgramFiles%\Wireshark`).
2. Install **Npcap** **without** *"Restrict Npcap driver's access to Administrators only"* so standard un-elevated users can capture without UAC prompts.
3. Verify status in **Settings → Capture Prerequisites** inside TAPNETTRACK.

## User Data, Backups & Diagnostics
All user data is stored separately from the program binaries in `%LOCALAPPDATA%\TAPNETTRACK\`:
- `tapnettrack.db` — SQLite WAL database
- `backups/` — Automatic WAL-safe pre-migration backups (newest 3 retained)
- `investigations/` — Case evidence vaults and exported bundles
- `logs/backend.log` — Rotating redacted diagnostic logs (`2 MiB × 3` files max; tokens, cookies, and auth headers are scrubbed)

## Upgrades, Rollback & Uninstall
- **Upgrade:** Run the newer `TAPNETTRACK_<version>_x64-setup.exe`. Only `%LOCALAPPDATA%\Programs\TAPNETTRACK\` is replaced; on first launch the backend backs up `tapnettrack.db` into `backups/` before running Alembic migrations.
- **Downgrade / Rollback:** If an older binary opens a database from a newer schema revision, TAPNETTRACK refuses to start rather than corrupting tables. Restore a backup from `backups/` or reinstall the newer version.
- **Uninstall:** Removes the application binaries and shortcuts only. `%LOCALAPPDATA%\TAPNETTRACK\` is **never** deleted automatically.

## Building & Releasing from Source (Developers)
- Build frozen backend only: `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-backend.ps1 -Clean`
- Build full unsigned local test release (`UNSIGNED_DEV_RELEASE`): `npm run release:windows`
- Sign production release with an Authenticode certificate:
  `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/release-windows.ps1 -CertThumbprint <THUMBPRINT>`

