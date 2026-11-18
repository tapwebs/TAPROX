// Read-only observer: logs the Capture panel text (state, counters, warnings, errors) whenever it changes.
const port = 9444; const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const stamp = () => new Date().toISOString().slice(11, 19);
let targets;
for (let i = 0; i < 120; i++) { try { targets = await (await fetch(`http://127.0.0.1:${port}/json`)).json(); if (targets.some((t) => t.type === "page")) break; } catch {} await sleep(500); }
const page = targets.find((t) => t.type === "page");
const ws = new WebSocket(page.webSocketDebuggerUrl); await new Promise((r) => (ws.onopen = r));
let id = 0; const pending = new Map();
ws.onmessage = (m) => { const d = JSON.parse(m.data); if (d.id && pending.has(d.id)) { pending.get(d.id)(d); pending.delete(d.id); } };
const ev = (expression) => new Promise((res) => { const i = ++id; pending.set(i, res); ws.send(JSON.stringify({ id: i, method: "Runtime.evaluate", params: { expression, returnByValue: true } })); }).then((r) => r.result?.result?.value);
let last = "";
const until = Date.now() + Number(process.argv[2] ?? 240) * 1000;
while (Date.now() < until) {
  try {
    const t = await ev("(() => { const s=[...document.querySelectorAll('section')].find(s=>s.innerText.startsWith('Capture')); if(!s) return 'no capture panel on this page: '+location.hash; const lines=s.innerText.split('\\n').filter(l=>/Capturing|Completed|Failed|Stopping|Preparing|packets|warning|stopped|error|could not|driver|decoder|saved|unsaved/i.test(l)); return location.hash+' :: '+lines.join(' / '); })()");
    const norm = String(t).replace(/\d+ s\b/g, "N s").replace(/[\d,]+ packets/g, "N packets").replace(/[\d.]+ MiB/g, "N MiB");
    if (norm !== last) { console.log(stamp(), String(t).slice(0, 600)); last = norm; }
  } catch (e) { console.log(stamp(), "peek error", String(e).slice(0, 100)); }
  await sleep(2000);
}
process.exit(0);
