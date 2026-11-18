# TAPNETTRACK — Notices & Third-Party Redistribution Policy

## 1. Project Intellectual Property & Source Distribution
TAPNETTRACK is currently designated as a **private source distribution** (`"private": true` in `package.json`).
- All rights are reserved by the original project authors.
- **No open-source license (such as MIT, Apache 2.0, or GPL) is granted by default.**
- Public redistribution, commercial bundling, or external publishing requires prior written approval from the repository owner.

---

## 2. Third-Party Redistribution Restrictions & Licensing Boundaries

TAPNETTRACK intentionally does not bundle, vendor, or silently install certain third-party components due to redistribution restrictions:

### 2.1 Npcap (Packet Capture Driver for Windows)
- **Copyright & License:** Npcap is copyright Insecure.Com LLC ("The Nmap Project").
- **Redistribution Restriction:** The free version of Npcap is licensed strictly for individual end-user installation. It **must not be bundled, redistributed, or silently installed** inside third-party installers without a commercial OEM redistribution license from Nmap Project / Insecure.Com LLC.
- **Project Compliance:** TAPNETTRACK never bundles Npcap. The application detects existing installations at runtime via `C:\Windows\System32\Npcap\wpcap.dll` and directs users to download the official installer directly from [npcap.com](https://npcap.com/).

### 2.2 Wireshark & TShark / Dumpcap
- **Copyright & License:** GNU General Public License (GPL) v2+.
- **Compliance:** TAPNETTRACK does not distribute Wireshark binaries in source or release packages. It discovers existing, externally installed `dumpcap.exe` and `tshark.exe` executables in `%ProgramFiles%\Wireshark` and communicates solely via process argv pipes.

### 2.3 Microsoft Edge WebView2 Evergreen Runtime
- **Copyright & License:** Microsoft Corporation.
- **Redistribution:** The Microsoft Edge WebView2 Evergreen Standalone Installer (`MicrosoftEdgeWebView2RuntimeInstallerX64.exe`) embedded in the release package is distributed in accordance with the Microsoft Edge WebView2 Runtime Redistribution terms.

---

## 3. Dependency Inventory & License Bill of Materials (SBOM)

The complete breakdown of all runtime and build dependencies, along with their respective PyPI, npm, and Crates.io source origins, is documented in the generated release Bill of Materials:
- See [dist/release/TAPNETTRACK-0.1.0-windows-x64/SBOM.md](file:///d:/Tapwebs_Projects/cyberProject/TAPNETTRACK/dist/release/TAPNETTRACK-0.1.0-windows-x64/SBOM.md)
  - **Python Runtime:** 21 packages (FastAPI, SQLAlchemy, Alembic, Cryptography, Pydantic, Starlette, Uvicorn, etc.)
  - **Frontend Runtime:** 11 packages (React, React-DOM, Lucide-React, Inter font, Tauri API)
  - **Rust Crates:** 407 crates (Tauri 2, WRY, Tao, Tokio, Windows-sys)

