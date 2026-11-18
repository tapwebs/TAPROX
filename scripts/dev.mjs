// Development launcher.
//
//   npm run dev            backend + Vite, open http://127.0.0.1:5173 in a browser
//   npm run dev:desktop    Tauri dev window (the Rust shell starts the backend itself)
//
// Browser mode uses the same protocol as the desktop shell: a fresh random token is written to the
// backend's stdin, the loopback port is read from its "ready" line, and both are handed to Vite as
// dev-only variables (see apps/dashboard/src/lib/connection/sources.ts). Nothing is written to disk.

import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { createInterface } from "node:readline";

const root = resolve(import.meta.dirname, "..");
const backendDir = join(root, "backend");
const python =
  process.platform === "win32"
    ? join(backendDir, ".venv", "Scripts", "python.exe")
    : join(backendDir, ".venv", "bin", "python");
// Node is started directly on the tools' entry scripts, so no shell is involved on any OS.
const viteScript = join(root, "node_modules", "vite", "bin", "vite.js");
const tauriScript = join(root, "node_modules", "@tauri-apps", "cli", "tauri.js");
const desktop = process.argv.includes("--desktop");
const VITE_ORIGIN = "http://127.0.0.1:5173";

if (!existsSync(python)) {
  console.error(`Backend environment not found. Run: uv sync --directory backend\n(expected ${python})`);
  process.exit(1);
}

const children = [];
function stopAll() {
  for (const child of children) {
    if (child.exitCode !== null || child.pid === undefined) continue;
    if (process.platform === "win32") spawnSync("taskkill", ["/pid", String(child.pid), "/T", "/F"]);
    else child.kill("SIGTERM");
  }
}
process.on("SIGINT", () => process.exit(130));
process.on("SIGTERM", () => process.exit(143));
process.on("exit", stopAll);

function run(script, args, options) {
  const child = spawn(process.execPath, [script, ...args], { stdio: "inherit", ...options });
  children.push(child);
  child.on("exit", (code) => process.exit(code ?? 0));
  return child;
}

if (desktop) {
  run(tauriScript, ["dev"], {
    cwd: join(root, "apps", "desktop"),
    env: { ...process.env, TAPNETTRACK_BACKEND_PYTHON: python, TAPNETTRACK_BACKEND_DIR: backendDir },
  });
} else {
  const token = randomBytes(32).toString("base64url");
  const backend = spawn(
    python,
    ["-m", "app", "--token-stdin", "--port", "0", "--data-dir", join(root, "data"), "--allowed-origin", VITE_ORIGIN],
    { cwd: backendDir, stdio: ["pipe", "pipe", "inherit"] },
  );
  children.push(backend);
  backend.on("exit", (code) => {
    console.error(`backend exited (code ${code})`);
    process.exit(code ?? 1);
  });
  backend.stdin.write(`${token}\n`); // keep stdin open: closing it tells the backend to stop

  const lines = createInterface({ input: backend.stdout });
  lines.once("line", (line) => {
    const ready = JSON.parse(line);
    const url = `http://${ready.host}:${ready.port}`;
    console.log(`backend ready at ${url} (token kept in memory only)`);
    run(viteScript, [], {
      cwd: join(root, "apps", "dashboard"),
      env: { ...process.env, VITE_TAPNETTRACK_API_URL: url, VITE_TAPNETTRACK_API_TOKEN: token },
    });
    console.log(`open ${VITE_ORIGIN}`);
  });
}
