# Capture prerequisites, permissions and limitations

TAPNETTRACK starts and runs without any of these. Without them the Overview and Settings screens
say exactly which tool is missing and how to install it. Nothing is simulated.

## What TAPNETTRACK looks for

| Component | Used for | Windows | Linux |
|---|---|---|---|
| Capture library | Packet capture | **Npcap** (`System32\Npcap\wpcap.dll`; version from the installer's uninstall entry) | **libpcap**, loaded by name (`libpcap.so.0.8`, then `libpcap.so`) through the dynamic linker; nothing is executed to find it |
| `dumpcap` | Packet acquisition (Packet Explorer) | `%ProgramFiles%\Wireshark`, `%ProgramFiles(x86)%\Wireshark`, then `PATH` | `/usr/bin`, `/usr/sbin`, `/usr/local/bin`, `/usr/local/sbin`, then `PATH` |
| `tshark` | Dissection and display filters (Packet Explorer) | same | same |

Lookup uses absolute directories only, and well-known install locations come before `PATH` so a
user-writable `PATH` entry cannot shadow the real tool. The current directory is never searched.
Each tool is run once as `<tool> --version` with a 5 second timeout.

## Windows

1. Install Wireshark from <https://www.wireshark.org/download.html>. Keep the **Npcap** option
   selected (Npcap can also be installed alone from <https://npcap.com>).
2. Re-check in **Settings → Capture prerequisites**.
3. Do not run TAPNETTRACK as Administrator to "make capture work". If Npcap was installed with
   "Restrict Npcap driver's access to Administrators only", reinstall Npcap without it so
   a standard user can capture. TAPNETTRACK shows a warning when the backend is elevated.

### Npcap "Administrator-only mode" (found during Phase 3 verification)

If Npcap was installed with **"Restrict Npcap driver's access to Administrators only"** (registry
`HKLM\SYSTEM\CurrentControlSet\Services\npcap\Parameters\AdminOnly = 1`), a normal user cannot use
the driver directly. Each time `dumpcap` lists interfaces or starts a capture, Windows shows an
administrator (UAC) prompt through `NpcapHelper.exe`, and `dumpcap` waits for it. Symptoms:
`dumpcap -D` hangs, the Packet Explorer says "dumpcap did not answer in time", a started capture stays
"Preparing" with a "Still waiting for the capture driver" notice.

TAPNETTRACK detects the setting (a warning in Settings), explains the wait, remembers the interface list
for a minute and does not repeat a hung listing for 30 s, so one session needs about two approvals.
It never runs the backend as administrator. To remove the prompts, reinstall Npcap and leave that
option unticked. The prompts are Windows' own: nothing here can or should approve them.

### After installing or reconfiguring Npcap

Npcap's driver keeps the access rules it loaded. After Npcap is installed, reinstalled or its
Administrator-only setting is changed, `dumpcap -D` may list only the loopback adapter, and a capture fails
with a permission error, until Windows is restarted. TAPNETTRACK says this in the Packet Explorer instead
of blaming the adapter. It never changes Npcap and never runs as administrator to work around it.

## Linux

1. Install: `sudo apt install tshark libpcap0.8` (Debian/Ubuntu) or
   `sudo dnf install wireshark-cli libpcap` (Fedora).
2. Allow non-root capture: `sudo dpkg-reconfigure wireshark-common` (answer Yes), then add your
   user: `sudo usermod -aG wireshark $USER` and log out and in. This grants `cap_net_raw` and
   `cap_net_admin` to `dumpcap` only.
3. Do not run the backend as root.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| dumpcap or tshark shows **Not found** | Wireshark not installed, or installed in a custom location not on `PATH` | Install it, or add its folder to `PATH` |
| **Problem** with "timed out" or "Could not run" | The file is corrupt, for another CPU architecture, or blocked by security software | Reinstall Wireshark or allow the file, then re-check |
| Npcap shows **Not found** but Wireshark is installed | Npcap was not selected during installation | Re-run the Wireshark or Npcap installer |
| **Elevated** warning | The app was started as Administrator/root | Start it as a normal user |
| Everything **Installed** but capture later fails with "permission denied" | Standard user lacks capture rights | Windows: Npcap admin-only option; Linux: `wireshark` group membership |

## Limitations (Phase 0)

* "Installed" means present and runnable. Whether this user may capture on a particular interface
  is only known when a capture starts, which does not exist yet.
* The Npcap version comes from the registry; a corrupted Npcap that still has its DLL is reported
  as installed.
* Zeek, Nmap and mitmproxy are optional integrations for later phases and are not detected yet.
* macOS is not a target; the platform is reported as `unsupported` there.
