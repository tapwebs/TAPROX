// Drives the REAL desktop window (WebView2 over CDP) through the whole Phase 2 + Phase 3 workflow.
import { writeFileSync, existsSync, unlinkSync } from "node:fs";
import { spawn } from "node:child_process";
import dns from "node:dns/promises";

const port = 9444, shots = process.argv[2], savePath = process.argv[3];
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

for (let i = 0; i < 60; i++) { if (/Backend connected|Backend unavailable/.test(await ev("document.body?.innerText ?? ''"))) break; await sleep(500); }
log("header:", await ev("[...document.querySelectorAll('header span')].map(e=>e.textContent.trim()).filter(Boolean).join(' | ')"));

// 1. Phase 1 inventory: a passive scan reads the OS neighbour table (no probes) so devices exist to link to.
log("\n== Device discovery (passive)");
await go("#/discovery", "document.querySelector('select')");
log(" choose interface:", await setSelect("Interface", "Ethernet"));
await sleep(300);
log(" start:", await click("Start scan"));
log(" completed:", await until("document.body.innerText.includes('Completed')", 30000));
log(" ", (await text()).split("\n").filter((l) => /devices|listed/i.test(l)).slice(0, 3).join(" / "));

// 2. Packet Explorer: prerequisites, interface, start.
log("\n== Packet Explorer: start");
await go("#/packets", "document.querySelector('form select')");
// With Npcap in Administrator-only mode Windows asks you to approve each dumpcap start. A prompt left
// unanswered makes the listing fail and the backend waits 30 s before asking again, so retry.
for (let attempt = 1; attempt <= 4 && !(await ev("!!document.querySelector('form select')")); attempt++) {
  log(` waiting for the interface list (attempt ${attempt}); approve the Windows prompt if one is showing`);
  if (await until("document.querySelector('form select')", 20000, 'interface list')) break;
  await sleep(18000); await ev("location.reload()"); await sleep(3000);
  await until("document.body.innerText.includes('Open or save')", 15000, 'packets page');
}
log(' page:', (await text()).replace(/\n+/g, ' | ').slice(0, 300));
await shot("01-packets-idle");
log(" interface options:", await ev("[...document.querySelector('form select').options].map(o=>o.textContent+(o.disabled?' [disabled]':'')).join(' | ')"));
log(" promiscuous ticked by default:", await ev("document.querySelector('input[type=checkbox]').checked"));
log(" choose Ethernet:", await setSelect("Interface", "Ethernet"));
log(" start:", await click("Start capture"));
const live = await until("document.body.innerText.includes('Capturing')", 150000);
log(' page after start:', (await text()).replace(/\n+/g, ' | ').slice(0, 500));
log(" shows Capturing:", live);

// 3. Ordinary traffic for ~32 s, while visiting the Phase 3 screens live.
const urls = ["https://www.example.com/", "https://www.wikipedia.org/", "https://www.python.org/", "https://github.com/", "http://neverssl.com/", "https://www.microsoft.com/", "https://www.mozilla.org/"];
let stopTraffic = false, requests = 0;
const traffic = (async () => {
  let n = 0;
  while (!stopTraffic) {
    await Promise.allSettled(urls.map((u) => fetch(u, { signal: AbortSignal.timeout(8000) }).then((r) => r.arrayBuffer()).then(() => requests++)));
    await dns.lookup(`tapnettrack-test-${n++}.example.org`).catch(() => {});
    await new Promise((r) => spawn("ping", ["-n", "2", "1.1.1.1"], { stdio: "ignore" }).on("close", r));
  }
})();
await sleep(8000);
log("\n   packets after 8 s:", await ev("(document.body.innerText.match(/([\\d,]+) packets/)||[])[1]"));
await shot("02-packets-capturing");

log("\n== Network Activity (live)");
await go("#/activity", "document.body.innerText.includes('Observed flows')");
await sleep(2500);
log(" ", (await text()).split("\n").slice(0, 28).join(" | "));
await shot("03-activity-live");
log(" chart:", await ev("document.querySelector('svg[role=img]')?.getAttribute('aria-label')"));

log("\n== Flow Explorer (live)");
await go("#/flows", "document.querySelector('table')");
await sleep(1500);
const liveFlows = await ev("document.querySelectorAll('table[aria-label], div[aria-label=\"Flow list\"] tbody tr').length");
log(" flow rows visible:", liveFlows, "| pagination:", await ev("(document.body.innerText.match(/Showing [^\\n]+/)||[])[0]"));
await shot("04-flows-live");

await sleep(16000);
stopTraffic = true; await traffic;
log("\n   http requests completed:", requests);

// 4. Stop, then check the Packet Explorer afterwards.
await go("#/packets", "document.body.innerText.includes('Stop capture')");
log("\n== Stop");
log(" stop:", await click("Stop capture"));
log(" completed:", await until("document.body.innerText.includes('Completed')", 20000));
await sleep(1500);
const statusLine = await ev("[...document.querySelectorAll('section')].find(s=>s.innerText.includes('Capture'))?.innerText.split('\\n').filter(l=>/packets/.test(l)).join(' / ')");
log(" status:", statusLine);
await shot("05-packets-completed");
log(" first rows:", await ev("[...document.querySelectorAll('table tbody tr')].slice(0,3).map(r=>[...r.children].map(c=>c.innerText.replace(/\\s+/g,' ').trim()).join(' | ')).join('\\n   ')"));
log(" display filter 'dns':", await setInput("Display filter", "dns"), await click("Apply"));
{ const t0 = Date.now(); const ok = await until("document.body.innerText.includes('Showing packets that match') && !document.querySelector('[role=status]') && document.querySelectorAll('table tbody tr').length > 0", 30000, 'filter result shown'); log("  filtered rows arrived:", ok, ((Date.now() - t0) / 1000).toFixed(1) + " s"); }

log(" dns rows:", await ev("[...document.querySelectorAll('table tbody tr')].slice(0,3).map(r=>[...r.children].map(c=>c.innerText.replace(/\\s+/g,' ').trim()).join(' | ')).join('\\n   ')"));
log(" invalid filter 'nonsense':", await setInput("Display filter", "nonsense"), await click("Apply"));
await sleep(1500);
log("  error shown:", await ev("document.body.innerText.includes('not a valid protocol')"));
await setInput("Display filter", "tcp.port == 443"); await click("Apply"); await sleep(2000);
log(" detail of first packet:", await ev("(() => { const b=document.querySelector('table tbody button'); if(!b) return 'no row'; b.click(); return 'clicked'; })()"));
await until("document.querySelector('aside')", 8000);
await sleep(1500);
log("  layers:", await ev("[...document.querySelectorAll('aside details summary')].map(s=>s.textContent.trim()).join(', ')"), "| hex dump present:", await ev("!!document.querySelector('aside pre')"));
await shot("06-packet-detail");
await setInput("Display filter", ""); await click("Apply");
log(" save:", await setInput("Save as", savePath), await click("Save capture"));
log("  saved message:", await until("document.body.innerText.includes('Saved ')", 20000), await ev("(document.body.innerText.match(/Saved [^\\n]+/)||[])[0]"));

// 5. Phase 3 screens on the finished capture.
log("\n== Network Activity (finished capture)");
await go("#/activity", "document.body.innerText.includes('Observed flows')");
await sleep(1500);
const dash = await ev("[...document.querySelectorAll('dt')].map(d=>d.textContent.trim()+': '+d.parentElement.innerText.split('\\n').slice(1).join(' ')).join(' | ')");
log(" ", dash);
log(" top devices:", await ev("[...document.querySelectorAll('div[aria-label=\"Devices by traffic\"] tbody tr')].slice(0,4).map(r=>[...r.children].map(c=>c.innerText.replace(/\\s+/g,' ').trim()).join(' | ')).join('\\n   ')"));
log(" top destinations:", await ev("[...document.querySelectorAll('div[aria-label=\"Destinations by traffic\"] tbody tr')].slice(0,5).map(r=>[...r.children].map(c=>c.innerText.replace(/\\s+/g,' ').trim()).join(' | ')).join('\\n   ')"));
log(" protocols:", await ev("[...document.querySelectorAll('section')].find(s=>s.innerText.startsWith('Top protocols'))?.innerText.split('\\n').slice(2).join(' / ')"));
await shot("07-activity-final");

log("\n== Flow Explorer (finished capture)");
await go("#/flows", "document.querySelector('div[aria-label=\"Flow list\"] tbody tr')");
await sleep(1000);
log(" pagination:", await ev("(document.body.innerText.match(/Showing [^\\n]+/)||[])[0]"));
log(" sort by bytes:", await click("Bytes")); await sleep(1500);
log(" top rows by bytes:\n   " + await ev("[...document.querySelectorAll('div[aria-label=\"Flow list\"] tbody tr')].slice(0,4).map(r=>[...r.children].map(c=>c.innerText.replace(/\\s+/g,' ').trim()).join(' | ')).join('\\n   ')"));
log(" protocol options:", await ev("[...document.getElementById([...document.querySelectorAll('label')].find(x=>x.textContent.trim()==='Protocol').htmlFor).options].map(o=>o.textContent).join(', ')"));
log(" filter protocol DNS:", await setSelect("Protocol", "DNS")); await sleep(1500);
log("  rows:", await ev("(document.body.innerText.match(/Showing [^\\n]+/)||[])[0]"), await ev("[...document.querySelectorAll('div[aria-label=\"Flow list\"] tbody tr')].slice(0,2).map(r=>[...r.children].map(c=>c.innerText.replace(/\\s+/g,' ').trim()).join(' | ')).join(' // ')"));
await setSelect("Protocol", "All protocols"); await sleep(800);
log(" search 'example':", await setInput("Search", "example")); await sleep(1800);
log("  rows:", await ev("(document.body.innerText.match(/Showing [^\\n]+/)||[])[0] ?? document.body.innerText.includes('No flows match')"));
await setInput("Search", ""); await sleep(1000);
log(" open first flow detail:", await ev("(() => { const b=document.querySelector('div[aria-label=\"Flow list\"] tbody button'); b.click(); return 'clicked'; })()"));
await until("[...document.querySelectorAll('aside')].some(a=>a.innerText.includes('Source chosen by'))", 8000);
log("  detail:\n    " + (await ev("[...document.querySelectorAll('aside')].find(a=>a.innerText.includes('Source chosen by'))?.innerText")).split("\n").slice(0, 60).join("\n    "));
await shot("08-flow-detail");

log("\n== Application Intelligence");
await go("#/applications", "document.body.innerText.includes('Identified') || document.body.innerText.includes('Unclassified')");
await sleep(1500);
log(" ", (await text()).split("\n").slice(0, 70).join(" | "));
await shot("09-applications");

// 6. Reopen the saved file and look at its flows.
log("\n== Open the saved file");
await go("#/packets", "document.querySelector('form select')");
log(" open:", await setInput("Open a capture file", savePath), await click("Open file"));
log(" file loaded:", await until("document.body.innerText.includes('Completed') && document.body.innerText.includes('File tt-ui')", 40000));
await sleep(3000);
await go("#/activity", "document.body.innerText.includes('Observed flows')");
await sleep(1500);
log(" ", await ev("[...document.querySelectorAll('dt')].map(d=>d.textContent.trim()+': '+d.parentElement.innerText.split('\\n').slice(1).join(' ')).join(' | ')"));
await shot("10-activity-from-file");
log("\nproblems:", problems.length ? "\n  " + problems.join("\n  ") : "none");
ws.close();
