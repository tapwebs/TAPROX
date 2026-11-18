// Drives the REAL desktop window (WebView2 over CDP) through the whole Phase 2 + Phase 3 workflow.
import { writeFileSync, existsSync, unlinkSync } from "node:fs";
import { spawn } from "node:child_process";
import dns from "node:dns/promises";

const port = 9444, shots = process.argv[2], savePath = process.argv[3], minutes = Number(process.argv[4] ?? 10), desktopPid = Number(process.argv[5] ?? 0);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const log = (...a) => console.log(...a);
let targets;
for (let i = 0; i < 80; i++) { try { targets = await (await fetch(`http://127.0.0.1:${port}/json`)).json(); if (targets.some((t) => t.type === "page")) break; } catch {} await sleep(500); }
const page = targets.find((t) => t.type === "page");
const ws = new WebSocket(page.webSocketDebuggerUrl); await new Promise((r) => (ws.onopen = r));
let id = 0; const pending = new Map(); const problems = [];
ws.onmessage = (m) => { const d = JSON.parse(m.data); if (d.id && pending.has(d.id)) { pending.get(d.id)(d); pending.delete(d.id); return; }
  if (d.method === "Runtime.exceptionThrown") problems.push("exception " + (d.params.exceptionDetails.exception?.description ?? d.params.exceptionDetails.text));
  if (d.method === "Runtime.consoleAPICalled" && ["error", "warning"].includes(d.params.type)) problems.push("console." + d.params.type + " " + d.params.args.map((a) => a.value ?? a.description).join(" ").slice(0, 300));
  if (d.method === "Log.entryAdded" && d.params.entry.level === "error") problems.push("log " + d.params.entry.text.slice(0, 300)); };
const send = (method, params = {}) => new Promise((res) => { const i = ++id; pending.set(i, res); ws.send(JSON.stringify({ id: i, method, params })); });
const ev = async (e) => { const r = (await send("Runtime.evaluate", { expression: e, returnByValue: true, awaitPromise: true })).result; if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description ?? "eval failed: " + e.slice(0, 80)); return r.result.value; };
await send("Runtime.enable"); await send("Log.enable");
const until = async (expr, ms = 15000, what = expr) => { const end = Date.now() + ms; while (Date.now() < end) { if (await ev(`!!(${expr})`)) return true; await sleep(250); } log("  TIMEOUT waiting for:", what.slice(0, 120)); log("  page says:", (await ev("document.querySelector('main')?.innerText ?? document.body.innerText")).replace(/\n+/g, " | ").slice(0, 700)); return false; };
const go = async (hash, expr) => { await ev(`location.hash = ${JSON.stringify(hash)}`); return until(expr, 20000, hash + " " + expr); };
const shot = async (name) => { const s = await send("Page.captureScreenshot", { format: "png" }); writeFileSync(`${shots}\\${name}.png`, Buffer.from(s.result.data, "base64")); };
const text = (sel = "main") => ev(`document.querySelector(${JSON.stringify(sel)})?.innerText ?? ""`);

// --- small DOM helpers (React listens to native events, so set values the way a browser does) ---
const setSelect = (label, option) => ev(`(() => { const l=[...document.querySelectorAll('label')].find(x=>x.textContent.trim()===${JSON.stringify(label)}); const s=document.getElementById(l.htmlFor); const o=[...s.options].find(x=>x.textContent.includes(${JSON.stringify(option)})); if(!o) return 'no option: '+[...s.options].map(x=>x.textContent).join('|'); s.value=o.value; s.dispatchEvent(new Event('change',{bubbles:true})); return 'ok'; })()`);
const setInput = (label, value) => ev(`(() => { const l=[...document.querySelectorAll('label')].find(x=>x.textContent.trim()===${JSON.stringify(label)}); const i=document.getElementById(l.htmlFor); Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(i,${JSON.stringify(value)}); i.dispatchEvent(new Event('input',{bubbles:true})); return 'ok'; })()`);
const click = (name) => ev(`(() => { const b=[...document.querySelectorAll('button')].find(x=>(x.getAttribute('aria-label')||x.textContent).trim()===${JSON.stringify(name)}||(x.getAttribute('aria-label')||'').startsWith(${JSON.stringify(name)})); if(!b) return 'no button: '+${JSON.stringify(name)}; b.click(); return 'ok'; })()`);


// Sustained live capture. The script never closes the window itself: the run script does, after this ends.
import { execSync } from "node:child_process";
const alive = (pid) => { try { return execSync(`tasklist /FI "PID eq ${pid}" /NH`, { encoding: "utf8" }).includes(String(pid)); } catch { return false; } };
const stamp = () => new Date().toISOString().slice(11, 19);
let closedAt = null;
ws.addEventListener("close", () => { closedAt = closedAt ?? stamp(); });
for (let i = 0; i < 60; i++) { if (/Backend connected|Backend unavailable/.test(await ev("document.body?.innerText ?? ''"))) break; await sleep(500); }
log(`${stamp()} header:`, await ev("[...document.querySelectorAll('header span')].map(e=>e.textContent.trim()).filter(Boolean).join(' | ')"));
await go("#/packets", "document.querySelector('form select')");
log(`${stamp()} interface choose:`, await setSelect("Interface", "Ethernet"), "| promiscuous ticked:", await ev("document.querySelector('input[type=checkbox]').checked"));
const startedAt = Date.now();
log(`${stamp()} start:`, await click("Start capture"));
log(`${stamp()} capturing:`, await until("document.body.innerText.includes('Capturing')", 60000));

const urls = ["https://www.example.com/", "https://www.wikipedia.org/", "https://www.python.org/", "https://github.com/", "http://neverssl.com/"];
let stopTraffic = false, requests = 0, failures = 0;
const traffic = (async () => {
  let n = 0;
  while (!stopTraffic) {
    await Promise.allSettled(urls.map((u) => fetch(u, { signal: AbortSignal.timeout(8000) }).then((r) => r.arrayBuffer()).then(() => requests++, () => failures++)));
    await dns.lookup(`tapnettrack-soak-${n++}.example.org`).catch(() => {});
    await new Promise((r) => spawn("ping", ["-n", "2", "1.1.1.1"], { stdio: "ignore" }).on("close", r));
    await sleep(4000);
  }
})();

const num = (s) => (s ? Number(String(s).replace(/[,\s]/g, "")) : null);
const pages = ["#/packets", "#/activity", "#/flows", "#/applications"];
const readings = [];
let n = 0, ended = "planned";
while ((Date.now() - startedAt) / 60000 < minutes) {
  if (closedAt) { ended = "window connection closed"; break; }
  if (desktopPid && !alive(desktopPid)) { ended = `desktop process ${desktopPid} is gone`; break; }
  const page = pages[n++ % pages.length];
  const t0 = Date.now();
  let rendered = false;
  try {
    await ev(`location.hash = ${JSON.stringify(page)}`);
    rendered = await until({ "#/packets": "document.querySelector('table tbody tr')", "#/activity": "document.body.innerText.includes('Observed flows')", "#/flows": "document.querySelector('div[aria-label=\"Flow list\"] tbody tr')", "#/applications": "document.body.innerText.includes('Identified') || document.body.innerText.includes('Unclassified')" }[page], 20000, page);
    const renderMs = Date.now() - t0;
    await sleep(1200);
    const body = await ev("document.body.innerText");
    const packets = num((body.match(/([\d,]+) packets ·/) || body.match(/Packets processed\s+([\d,]+)/) || [])[1]);
    const flowsObserved = num((body.match(/Observed flows\s+([\d,]+)/) || [])[1]);
    const state = /Capturing/.test(body) ? "Capturing" : /Completed/.test(body) ? "Completed" : /Failed/.test(body) ? "Failed" : "?";
    const heap = await ev("Math.round((performance.memory?.usedJSHeapSize ?? 0) / 1048576)");
    readings.push({ t: Math.round((Date.now() - startedAt) / 1000), page, renderMs, packets, flowsObserved, state, heap });
    log(`${stamp()} +${String(Math.round((Date.now() - startedAt) / 1000)).padStart(4)}s ${page.padEnd(14)} render ${String(renderMs).padStart(5)} ms  packets=${packets ?? "-"}  flows=${flowsObserved ?? "-"}  state=${state}  jsHeap=${heap} MB  http ok/fail=${requests}/${failures}`);
  } catch (e) {
    log(`${stamp()} reading failed on ${page}: ${String(e).slice(0, 160)}`);
    if (closedAt || (desktopPid && !alive(desktopPid))) { ended = "window or process went away during a reading"; break; }
  }
  await sleep(13000);
}
stopTraffic = true; await traffic;
log(`${stamp()} loop ended: ${ended}; window connection closed at: ${closedAt ?? "no"}; desktop alive: ${desktopPid ? alive(desktopPid) : "n/a"}; elapsed ${((Date.now() - startedAt) / 60000).toFixed(1)} min`);
if (ended !== "planned") { log("problems:", problems.length ? problems.join(" | ") : "none"); process.exit(0); }

const pk = readings.filter((r) => r.packets != null);
const nonDecreasing = pk.filter((r) => r.page === "#/packets" || r.page === "#/activity").every((r, i, a) => i === 0 || r.packets >= a[i - 1].packets - 0);
log(`${stamp()} packet counter readings: first ${pk[0]?.packets}, last ${pk.at(-1)?.packets}; never went backwards: ${nonDecreasing}`);
log(`${stamp()} slowest page render: ${Math.max(...readings.map((r) => r.renderMs))} ms; JS heap first/last: ${readings[0]?.heap}/${readings.at(-1)?.heap} MB`);

await go("#/packets", "document.body.innerText.includes('Stop capture')");
log(`${stamp()} stop:`, await click("Stop capture"), "| completed:", await until("document.body.innerText.includes('Completed')", 30000));
await sleep(2000);
log(`${stamp()} status:`, await ev("[...document.querySelectorAll('section')].find(s=>s.innerText.startsWith('Capture'))?.innerText.split('\\n').filter(l=>/packets/.test(l)).join(' / ')"));
await setInput("Display filter", "dns"); await click("Apply");
{ const t0 = Date.now(); const ok = await until("document.body.innerText.includes('Showing packets that match') && !document.querySelector('[role=status]') && document.querySelectorAll('table tbody tr').length > 0", 60000, 'filter result shown'); log(`${stamp()} display filter dns: rows arrived=${ok} in ${((Date.now() - t0) / 1000).toFixed(1)} s`); }
await setInput("Display filter", ""); await click("Apply"); await sleep(1500);
log(`${stamp()} save:`, await setInput("Save as", savePath), await click("Save capture"), "->", await until("document.body.innerText.includes('Saved ')", 60000), await ev("(document.body.innerText.match(/Saved [^\\n]+/)||[])[0]"));
await go("#/activity", "document.body.innerText.includes('Observed flows')"); await sleep(1500);
log(`${stamp()} activity after stop:`, (await ev("[...document.querySelectorAll('dt')].map(d=>d.textContent.trim()+': '+d.parentElement.innerText.split('\\n').slice(1).join(' ')).join(' | ')")).slice(0, 400));
await go("#/packets", "document.querySelector('form select')");
log(`${stamp()} reopen:`, await setInput("Open a capture file", savePath), await click("Open file"), "->", await until("document.body.innerText.includes('Completed') && /File tt-ui/.test(document.body.innerText)", 120000));
await sleep(3000);
await go("#/activity", "document.body.innerText.includes('Observed flows')"); await sleep(1500);
log(`${stamp()} activity from the reopened file:`, (await ev("[...document.querySelectorAll('dt')].map(d=>d.textContent.trim()+': '+d.parentElement.innerText.split('\\n').slice(1).join(' ')).join(' | ')")).slice(0, 400));
log(`${stamp()} script finished; the run script will now close the window deliberately`);
log("problems:", problems.length ? "\n  " + problems.join("\n  ") : "none");
ws.close();
