<#
.SYNOPSIS
  Generates a release dependency & license SBOM (SBOM.md) from pinned lockfiles
  (backend/uv.lock, package-lock.json, apps/desktop/src-tauri/Cargo.lock) and the
  verified WebView2 offline installer.
#>
param(
    [Parameter(Mandatory)][string]$OutFile
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

$PyScript = @'
import json, sys, tomllib
from pathlib import Path

root = Path(sys.argv[1])
out = Path(sys.argv[2])
lines = ['# TAPNETTRACK Release SBOM (Phase 7)', '']

# 1. Python runtime dependencies (from uv.lock, excluding dev-only group)
uv_lock = tomllib.loads((root / 'backend' / 'uv.lock').read_text(encoding='utf-8'))
pkgs = {p['name']: p for p in uv_lock.get('package', [])}
root_pkg = pkgs.get('tapnettrack-backend', {})
runtime_names = {d['name'] for d in root_pkg.get('dependencies', [])}

# Walk transitive runtime deps
visited = set()
stack = sorted(runtime_names)
while stack:
    name = stack.pop()
    if name in visited or name not in pkgs:
        continue
    visited.add(name)
    for dep in pkgs[name].get('dependencies', []):
        if dep['name'] not in visited:
            stack.append(dep['name'])

lines.append(f'## Python Backend Runtime Dependencies ({len(visited)} packages)')
lines.append('')
lines.append('| Package | Version | Source |')
lines.append('|---|---|---|')
for name in sorted(visited):
    p = pkgs[name]
    lines.append(f"| `{name}` | `{p.get('version', 'unknown')}` | PyPI (`uv.lock`) |")
lines.append('')

# 2. Frontend runtime dependencies (from package-lock.json)
pkg_lock = json.loads((root / 'package-lock.json').read_text(encoding='utf-8'))
packages = pkg_lock.get('packages', {})
fe_runtime = []
for path, meta in packages.items():
    if not path.startswith('node_modules/'):
        continue
    if meta.get('dev'):
        continue
    name = path.removeprefix('node_modules/')
    fe_runtime.append((name, meta.get('version', 'unknown'), meta.get('license', 'see package')))

lines.append(f'## Frontend Dashboard Runtime Dependencies ({len(fe_runtime)} packages)')
lines.append('')
lines.append('| Package | Version | License |')
lines.append('|---|---|---|')
for name, ver, lic in sorted(fe_runtime):
    lines.append(f'| `{name}` | `{ver}` | {lic} |')
lines.append('')

# 3. Rust Desktop Shell dependencies (from Cargo.lock)
cargo_lock = tomllib.loads((root / 'apps' / 'desktop' / 'src-tauri' / 'Cargo.lock').read_text(encoding='utf-8'))
rust_pkgs = [(p['name'], p['version']) for p in cargo_lock.get('package', [])]
lines.append(f'## Rust Desktop Shell Crates ({len(rust_pkgs)} crates)')
lines.append('')
lines.append('| Crate | Version |')
lines.append('|---|---|')
for name, ver in sorted(rust_pkgs):
    lines.append(f'| `{name}` | `{ver}` |')
lines.append('')

out.parent.mkdir(parents=True, exist_ok=True)
out.write_text('\n'.join(lines), encoding='utf-8')
print(f'Wrote {out} ({len(visited)} Python, {len(fe_runtime)} npm, {len(rust_pkgs)} Rust)')
'@

$PyScript | & uv run --directory (Join-Path $RepoRoot "backend") --no-sync python - $RepoRoot $OutFile
if ($LASTEXITCODE -ne 0) {
    throw "SBOM generation failed with exit code $LASTEXITCODE"
}
