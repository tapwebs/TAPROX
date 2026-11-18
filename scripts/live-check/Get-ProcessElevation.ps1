<#
.SYNOPSIS
  Reads the real access-token elevation of a running process (not just "did it start").
.DESCRIPTION
  Dot-source this file, then call:  Get-ProcessElevation -Id <pid>
  Returns Elevated (True/False), ElevationType (Default = normal user token, Full = elevated,
  Limited = filtered token of an administrator), the Windows integrity level, and the owner.
  A process this (non-elevated) session cannot open is reported as Elevated = $null with Detail
  "access denied": for TAPNETTRACK's own processes that would itself be a red flag, because a normal
  user can always open its own normal-user processes.
#>
if (-not ("TapNetTrack.TokenInfo" -as [type])) {
  Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
namespace TapNetTrack {
  public static class TokenInfo {
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool GetTokenInformation(IntPtr token, int cls, IntPtr buffer, int length, out int returned);
    [DllImport("advapi32.dll")] static extern IntPtr GetSidSubAuthority(IntPtr sid, uint index);
    [DllImport("advapi32.dll")] static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);

    // Returns "elevated;type;integrity" or "denied;<win32 error>".
    public static string Query(int pid) {
      IntPtr process = OpenProcess(0x1000 /* PROCESS_QUERY_LIMITED_INFORMATION */, false, pid);
      if (process == IntPtr.Zero) return "denied;" + Marshal.GetLastWin32Error();
      IntPtr token = IntPtr.Zero;
      try {
        if (!OpenProcessToken(process, 0x0008 /* TOKEN_QUERY */, out token)) return "denied;" + Marshal.GetLastWin32Error();
        int elevated = ReadInt(token, 20); // TokenElevation
        int type = ReadInt(token, 18);     // TokenElevationType: 1 default, 2 full, 3 limited
        int rid = ReadIntegrity(token);
        return elevated + ";" + type + ";" + rid;
      } finally {
        if (token != IntPtr.Zero) CloseHandle(token);
        CloseHandle(process);
      }
    }
    static int ReadInt(IntPtr token, int cls) {
      IntPtr buffer = Marshal.AllocHGlobal(4);
      try { int n; return GetTokenInformation(token, cls, buffer, 4, out n) ? Marshal.ReadInt32(buffer) : -1; }
      finally { Marshal.FreeHGlobal(buffer); }
    }
    static int ReadIntegrity(IntPtr token) {
      int n; GetTokenInformation(token, 25 /* TokenIntegrityLevel */, IntPtr.Zero, 0, out n);
      if (n <= 0) return -1;
      IntPtr buffer = Marshal.AllocHGlobal(n);
      try {
        if (!GetTokenInformation(token, 25, buffer, n, out n)) return -1;
        IntPtr sid = Marshal.ReadIntPtr(buffer);
        int count = Marshal.ReadByte(GetSidSubAuthorityCount(sid));
        return Marshal.ReadInt32(GetSidSubAuthority(sid, (uint)(count - 1)));
      } finally { Marshal.FreeHGlobal(buffer); }
    }
  }
}
"@
}

function Get-ProcessElevation {
  param([Parameter(Mandatory)][int] $Id)
  $raw = [TapNetTrack.TokenInfo]::Query($Id)
  $parts = $raw -split ";"
  if ($parts[0] -eq "denied" -and $parts[1] -eq "87") {   # ERROR_INVALID_PARAMETER: no such process any more
    return [pscustomobject]@{ Id = $Id; Elevated = $null; ElevationType = "unknown"; Integrity = "unknown"; Detail = "process had already exited" }
  }
  if ($parts[0] -eq "denied") {
    return [pscustomobject]@{ Id = $Id; Elevated = $null; ElevationType = "unknown"; Integrity = "unknown"; Detail = "access denied (Win32 error $($parts[1]))" }
  }
  $integrity = switch ([int]$parts[2]) { 0x1000 { "Low/Untrusted" } 0x2000 { "Medium" } 0x3000 { "High" } 0x4000 { "System" } default { "Other ($($parts[2]))" } }
  if ([int]$parts[2] -lt 0x2000) { $integrity = "Low" }
  $type = switch ([int]$parts[1]) { 1 { "Default (normal user token)" } 2 { "Full (elevated)" } 3 { "Limited (filtered token)" } default { "unknown" } }
  [pscustomobject]@{ Id = $Id; Elevated = ([int]$parts[0] -ne 0); ElevationType = $type; Integrity = $integrity; Detail = "" }
}
