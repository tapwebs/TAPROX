// Times Packet Explorer display filters on a capture file, in the REAL desktop window (WebView2 over CDP).
// Args: shotsDir, captureFile, filters (separated by ";;"), desktopPid. Never closes the window.
import { writeFileSync } from "node:fs";

const port = 9444, shots = process.argv[2], file = process.argv[3];
const filters = process.argv[4].split(";;");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const log = (...a) => console.log(...a);
let targets;
for (let i = 0; i < 80; i++) { try { targets = await (await fetch(`http://127.0.0.1:${port}/json`)).json(); if (targets.some((t) => t.type === "page")) break; } catch {} await sleep(500); }
const page = targets.find((t) => t.type === "page");
const ws = new WebSocket(page.webSocketDebuggerUrl); await new Promise((r) => (ws.onopen = r));
let id = 0; const pending = new Map(); const problems = [];
ws.onmessage = (m) => { const d = JSON.parse(m.data); if (d.id && pending.has(d.id)) { pending.get(d.id)(d); pending.delete(d.id); return; }
  if (d.method === "Runtime.exceptionThrown") problems.push("exception " + (d.params.exceptionDetails.exception?.description ?? d.params.exceptionDetails.text));
  if (d.method === "Runtime.consoleAPICalled" && d.params.type === "error") problems.push("console.error " + d.params.args.map((a) => a.value ?? a.description).join(" ").slice(0, 300)); };
const send = (method, params = {}) => new Promise((res) => { const i = ++id; pending.set(i, res); ws.send(JSON.stringify({ id: i, method, params })); });
const ev = async (e) => { const r = (await send("Runtime.evaluate", { expression: e, returnByValue: true, awaitPromise: true })).result; if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description ?? "eval failed: " + e.slice(0, 80)); return r.result.value; };
await send("Runtime.enable");
const until = async (expr, ms = 15000) => { const end = Date.now() + ms; while (Date.now() < end) { if (await ev(`!!(${expr})`)) return true; await sleep(100); } return false; };
const setInput = (label, value) => ev(`(() => { const l=[...document.querySelectorAll('label')].find(x=>x.textContent.trim()===${JSON.stringify(label)}); const i=document.getElementById(l.htmlFor); Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(i,${JSON.stringify(value)}); i.dispatchEvent(new Event('input',{bubbles:true})); return 'ok'; })()`);
const click = (name) => ev(`(() => { const b=[...document.querySelectorAll('button')].find(x=>(x.getAttribute('aria-label')||x.textContent).trim()===${JSON.stringify(name)}); if(!b) return 'no button: '+${JSON.stringify(name)}; b.click(); return 'ok'; })()`);

for (let i = 0; i < 60; i++) { if (/Backend connected|Backend unavailable/.test(await ev("document.body?.innerText ?? ''"))) break; await sleep(500); }
await ev("location.hash = '#/packets'");
if (!(await until("[...document.querySelectorAll('label')].some(x => x.textContent.trim() === 'Open a capture file')", 30000))) log("open box not found; page says:", (await ev("document.body.innerText")).replace(/\n+/g, " | ").slice(0, 600));
log("open:", await setInput("Open a capture file", file), await click("Open file"));
log("loaded:", await until("document.body.innerText.includes('Completed')", 120000));
await until("document.querySelector('table tbody tr')", 30000);
await sleep(1500);

// In-page instrumentation: every /packets and /filter call (duration, response bytes, total), long tasks,
// the longest gap between 50 ms timer ticks (a frozen UI shows as a big gap) and what the filter form shows.
await ev(`(() => {
  const w = window; if (w.__tt) return; w.__tt = { calls: [], long: [], gap: 0, last: performance.now(), seen: [] };
  const f = w.fetch.bind(w);
  w.fetch = async (...a) => { const url = String(a[0]?.url ?? a[0]); const t0 = performance.now(); const rec = { url: url.replace(/^https?:\\/\\/[^/]+/, '').slice(0, 140), t0, ms: null, bytes: 0, total: null, status: null, aborted: false };
    w.__tt.calls.push(rec);
    try { const r = await f(...a); rec.status = r.status; const b = await r.clone().arrayBuffer(); rec.bytes = b.byteLength; try { rec.total = JSON.parse(new TextDecoder().decode(b)).total ?? null; } catch {} rec.ms = performance.now() - t0; return r; }
    catch (e) { rec.aborted = true; rec.ms = performance.now() - t0; throw e; } };
  try { new PerformanceObserver((l) => { for (const e of l.getEntries()) w.__tt.long.push(Math.round(e.duration)); }).observe({ entryTypes: ['longtask'] }); } catch {}
  setInterval(() => { const n = performance.now(); w.__tt.gap = Math.max(w.__tt.gap, n - w.__tt.last - 50); w.__tt.last = n; }, 50);
  setInterval(() => { const s = [...document.querySelectorAll('[role=status],[aria-busy=true]')].map(e => (e.getAttribute('role') || 'busy') + ':' + e.innerText.trim().slice(0, 60)).filter(x => !/Backend|connected/i.test(x)); if (s.length) w.__tt.seen.push([Math.round(performance.now()), s.join(' / ')]); }, 100);
})()`);

const results = [];
for (const flt of filters) {
  await setInput("Display filter", ""); await click("Apply"); await sleep(1500);
  await ev("(() => { const t = window.__tt; t.calls.length = 0; t.long.length = 0; t.gap = 0; t.seen.length = 0; })()");
  const before = await ev("document.querySelector('table tbody tr')?.innerText ?? ''");
  await setInput("Display filter", flt);
  const t0 = Date.now();
  await click("Apply");
  // Done when a /packets call that carries this filter has finished and the table or the empty state has caught up.
  const done = await until(`(() => { const c = window.__tt.calls.filter(x => x.url.includes('display_filter') && x.ms != null && !x.aborted && x.status === 200); return c.length > 0 && document.body.innerText.includes('Showing packets that match') && !document.body.innerText.includes('Loading packets'); })()`, 120000);
  const wall = (Date.now() - t0) / 1000;
  await sleep(1200);
  const r = await ev("({ calls: window.__tt.calls.map(c => ({ url: c.url.replace(/display_filter=[^&]*/, 'display_filter=…'), t: Math.round(c.t0), ms: Math.round(c.ms ?? -1), kb: Math.round(c.bytes / 1024), total: c.total, status: c.status, aborted: c.aborted })), long: window.__tt.long, gap: Math.round(window.__tt.gap), seen: window.__tt.seen.slice(0, 6), first: document.querySelector('table tbody tr')?.innerText.replace(/\\s+/g, ' ').slice(0, 90) ?? '', pager: document.querySelector('[aria-label=\"Packet pages\"]')?.innerText.replace(/\\s+/g, ' ') ?? '', mem: Math.round((performance.memory?.usedJSHeapSize ?? 0) / 1048576) })");
  const pk = r.calls.filter((c) => c.url.includes("/packets"));
  const val = r.calls.filter((c) => c.url.includes("filter/validate"));
  results.push({ flt, done, wall });
  log(`\nfilter "${flt}": finished=${done} wall=${wall.toFixed(2)} s`);
  log(`  validate calls: ${val.map((c) => c.ms + " ms").join(", ") || "none"}`);
  log(`  /packets calls: ${pk.map((c) => `${c.ms} ms ${c.kb} KiB total=${c.total} st=${c.status}${c.aborted ? " ABORTED" : ""}`).join(" | ")}`);
  log(`  UI: longest timer stall ${r.gap} ms; long tasks ${JSON.stringify(r.long)}; busy/status elements seen while waiting: ${r.seen.length ? JSON.stringify(r.seen) : "NONE"}`);
  log(`  first row: ${r.first}; pager: ${r.pager.slice(0, 80)}; JS heap ${r.mem} MB; previous first row kept meanwhile: n/a`);
}
// An invalid filter and the cancel/stale path.
await setInput("Display filter", "tcp.port =="); const te = Date.now(); await click("Apply");
await until("document.body.innerText.toLowerCase().includes('expected') || document.body.innerText.toLowerCase().includes('syntax') || document.body.innerText.toLowerCase().includes('not a valid')", 20000);
log(`\ninvalid filter shows an error after ${((Date.now() - te) / 1000).toFixed(2)} s: ${(await ev("document.querySelector('form')?.innerText.replace(/\\s+/g,' ')")).slice(0, 160)}`);
log("problems:", problems.length ? problems.join(" | ") : "none");
process.exit(0);
