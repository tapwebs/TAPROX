# TAPNETTRACK — Complete External Dependency Specification

This document details all external tools, interpreters, runtimes, packet capture libraries, and build dependencies required to build, test, and operate TAPNETTRACK.

---

## 1. Dependency Overview Matrix

| Tool / Component | Classification | Minimum Supported | Tested Version | Required For | Official Source / Download |
|---|---|---|---|---|---|
| **Python** | Core Backend (Source) | `3.12.0` | `3.12.10` | Running FastAPI backend, database migrations, rule engine | [python.org](https://www.python.org/downloads/) |
| **Node.js** | Core Frontend (Source) | `22.12.0` (LTS) | `24.14.1` | Dashboard TypeScript build, Vite dev server | [nodejs.org](https://nodejs.org/) |
| **npm** | Package Manager | `10.9.0` | `11.13.0` | Installing dashboard and API contracts packages | Bundled with Node.js |
| **Rust Toolchain** | Desktop Shell (Build) | `1.85.0` | `1.99.1` | Compiling Tauri 2 desktop supervisor shell | [rustup.rs](https://rustup.rs/) |
| **MSVC C++ Build Tools** | Windows Linker (Build) | VS 2022 Build Tools | VS 2022 v17.x | Compiling native Rust crates (`x86_64-pc-windows-msvc`) | [visualstudio.microsoft.com](https://visualstudio.microsoft.com/visual-cpp-build-tools/) |
| **Microsoft Edge WebView2** | Desktop Runtime | Evergreen | `1.3.315.17` | Rendering React frontend inside Tauri 2 window | [developer.microsoft.com](https://developer.microsoft.com/en-us/microsoft-edge/webview2/) |
| **Wireshark (`dumpcap`, `tshark`)** | Packet Capture Tool | `4.2.0` | `4.6.9` | **Optional:** Live packet capture and Wireshark filter dissection | [wireshark.org](https://www.wireshark.org/download.html) |
| **Npcap** | Packet Capture Driver | `1.70` | `1.90` | **Optional:** Low-level NDIS packet capture on Windows | [npcap.com](https://npcap.com/#download) |
| **Git** | Source Control | `2.40.0` | `2.53.0` | Cloning repository and managing source code | [git-scm.com](https://git-scm.com/) |

---

## 2. Distinction: End-User vs. Source Developer

### For End Users (Packaged Distribution)
If you install the prebuilt installer (`TAPNETTRACK_<version>_x64-setup.exe`):
- **Zero Python, Node.js, npm, or Rust required.** The backend is frozen as a self-contained `--onedir` bundle (`tapnettrack-backend.exe` + `_internal/`).
- **WebView2 Runtime** is verified on startup or installed from the embedded offline installer.
- **Wireshark and Npcap remain strictly optional:** Overview, Device Discovery (ARP), Network Topology, Web Inspector, and Investigations/Forensics all work without them. Only Packet Explorer requires Wireshark.

### For Developers & Security Researchers (Building from Source)
Cloning and running from source requires:
1. Python `>= 3.12` with `uv` or virtualenv (`backend/.venv`).
2. Node.js `>= 22.12.0` and `npm`.
3. Rust `>= 1.85.0` with `cargo` and MSVC tools (if building the desktop shell).

---

## 3. Detailed Component Verification Guide

### 3.1 Python 3.12+
* **Purpose:** Powers the authenticated loopback API (`127.0.0.1:<port>`), SQLite database migrations via Alembic, real-time flow engine, threat detection rules, and forensic evidence vault.
* **Verification Command:**
  ```powershell
  python --version
  ```
  *Expected Output:* `Python 3.12.x` (or newer).
* **Package Installation:**
  ```powershell
  python -m venv backend/.venv
  .\backend\.venv\Scripts\Activate.ps1
  pip install -r requirements.txt
  ```

### 3.2 Node.js & npm
* **Purpose:** Runs the React 19 + Tailwind CSS 4 dashboard, manages client API contracts from OpenAPI schema, and executes client unit tests via Vitest.
* **Verification Command:**
  ```powershell
  node --version
  npm --version
  ```
  *Expected Output:* `v22.12.0+` (Node) and `10.9.0+` (npm).
* **Package Installation:**
  ```powershell
  npm install
  ```

### 3.3 Rust & MSVC Build Tools
* **Purpose:** Compiles `apps/desktop/src-tauri` into `tapnettrack-desktop.exe`, implementing the un-elevated child process supervisor, 256-bit CSPRNG token handoff over stdin, Windows Job Object termination, and WebView2 window hosting.
* **Verification Command:**
  ```powershell
  rustc --version
  cargo --version
  ```
  *Expected Output:* `rustc 1.85.0+` and `cargo 1.85.0+`.

### 3.4 Microsoft Edge WebView2 Runtime
* **Purpose:** Embeds the Chromium-based webview that renders the dashboard UI inside the native Windows desktop application.
* **Verification Command (PowerShell):**
  ```powershell
  Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}" -Name pv
  ```
  *Expected Output:* Displays version string (e.g., `131.0.2903.112`).

### 3.5 Optional: Wireshark (`dumpcap.exe` & `tshark.exe`)
* **Purpose:** Provides un-elevated packet capture (`dumpcap`) and protocol tree dissection (`tshark`) for the Packet Explorer module.
* **Verification Command:**
  ```powershell
  & "C:\Program Files\Wireshark\dumpcap.exe" --version
  & "C:\Program Files\Wireshark\tshark.exe" --version
  ```
  *Expected Output:* `Dumpcap (Wireshark) 4.2.x+` and `TShark (Wireshark) 4.2.x+`.

### 3.6 Optional: Npcap Packet Capture Library
* **Purpose:** Windows kernel-level driver for capturing Ethernet and 802.11 frames on physical network adapters.
* **Verification Command (PowerShell):**
  ```powershell
  Test-Path "C:\Windows\System32\Npcap\wpcap.dll"
  ```
  *Expected Output:* `True`.
* **Important Installation Note:** When installing Npcap, ensure **"Restrict Npcap driver's access to Administrators only"** is **UNCHECKED** so standard un-elevated user accounts can capture packets without UAC prompts.

