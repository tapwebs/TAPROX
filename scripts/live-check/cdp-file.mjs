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
const rowsOf = (sel, n = 4) => ev(`[...document.querySelectorAll(${JSON.stringify(sel)})].slice(0,${n}).map(r=>[...r.children].map(c=>c.innerText.replace(/\\s+/g,' ').trim()).join(' | ')).join('\\n   ')`);
const stats = () => ev("[...document.querySelectorAll('dt')].map(d=>d.textContent.trim()+': '+d.parentElement.innerText.split('\\n').slice(1).join(' ')).join('\\n   ')");

log("\n== Device discovery (passive, reads the OS neighbour table)");
await go("#/discovery", "document.querySelector('select')");
await setSelect("Interface", "Ethernet"); await sleep(300); await click("Start scan");
log(" completed:", await until("document.body.innerText.includes('Completed')", 30000));

log("\n== Packet Explorer, capture tools unavailable to a non-admin user");
await go("#/packets", "document.body.innerText.includes('Open or save')");
await until("document.body.innerText.includes('Packet capture is not available') || document.querySelector('form select')", 30000);
log(" panel:", (await ev("[...document.querySelectorAll('section')].find(s=>s.innerText.startsWith('Capture'))?.innerText")).replace(/\n+/g, " | ").slice(0, 600));
await shot("11-packets-no-capture");

log("\n== Open a real PCAPNG captured from this machine's Ethernet adapter");
log(" open:", await setInput("Open a capture file", savePath), await click("Open file"));
log(" loaded:", await until("document.body.innerText.includes('Completed') && /File real/.test(document.body.innerText)", 60000));
await until("/[1-9][\\d,]* packets/.test(document.body.innerText)", 20000);
await sleep(3000);
log(" status:", await ev("(document.body.innerText.match(/File [^\\n]+\\n[^\\n]*packets[^\\n]*/)||[document.body.innerText.match(/[\\d,]+ packets[^\\n]*/)?.[0]])[0]"));
await until("document.querySelector('table tbody tr')", 20000);
log(" first rows:\n   " + await rowsOf("table tbody tr", 3));
log(" display filter 'dns':", await setInput("Display filter", "dns"), await click("Apply"));
{ const t0 = Date.now(); const ok = await until("document.body.innerText.includes('Showing packets that match') && !document.querySelector('[role=status]') && document.querySelectorAll('table tbody tr').length > 0", 30000, 'filter result shown'); log("  filtered rows arrived:", ok, ((Date.now() - t0) / 1000).toFixed(1) + " s"); }

log(" rows:\n   " + await rowsOf("table tbody tr", 3));
log(" display filter 'nonsense':", await setInput("Display filter", "nonsense"), await click("Apply")); await sleep(2000);
log("  explained:", await ev("[...document.querySelectorAll('p')].map(p=>p.innerText).find(t=>/not a valid protocol|neither a field/.test(t))"));
await setInput("Display filter", "tcp.port == 443"); await click("Apply"); await sleep(3000);
log(" packet detail:", await ev("(() => { const b=document.querySelector('table tbody button'); if(!b) return 'no row'; b.click(); return 'clicked ' + b.getAttribute('aria-label'); })()"));
await until("document.querySelector('aside pre')", 15000); await sleep(1000);
log("  layers:", await ev("[...document.querySelectorAll('aside details summary')].map(s=>s.textContent.trim()).join(', ')"));
log("  hex:", (await ev("document.querySelector('aside pre')?.innerText")).split("\n")[0]);
await shot("12-packet-detail-real");
await setInput("Display filter", ""); await click("Apply"); await sleep(1500);

log("\n== Network Activity (real packets)");
await go("#/activity", "document.body.innerText.includes('Observed flows')"); await sleep(2000);
log(" " + await stats());
log(" session line:", await ev("document.querySelector('main p.text-sm')?.innerText"));
log(" chart label:", await ev("document.querySelector('svg[role=img]')?.getAttribute('aria-label')"));
log(" top devices:\n   " + await rowsOf("div[aria-label='Devices by traffic'] tbody tr", 5));
log(" top destinations:\n   " + await rowsOf("div[aria-label='Destinations by traffic'] tbody tr", 6));
log(" protocols:", await ev("[...document.querySelectorAll('section')].find(s=>s.innerText.startsWith('Top protocols'))?.innerText.split('\\n').slice(2).join(' / ')"));
log(" applications:", await ev("[...document.querySelectorAll('section')].find(s=>s.innerText.startsWith('Application and service'))?.innerText.split('\\n').slice(2).join(' / ')"));
await shot("13-activity-real");

log("\n== Flow Explorer (real packets)");
await go("#/flows", "document.querySelector('div[aria-label=\"Flow list\"] tbody tr')"); await sleep(1500);
log(" pagination:", await ev("(document.body.innerText.match(/Showing [^\\n]+/)||[])[0]"));
await click("Bytes"); await sleep(1500);
log(" biggest flows:\n   " + await rowsOf("div[aria-label='Flow list'] tbody tr", 4));
log(" protocol options:", await ev("[...document.getElementById([...document.querySelectorAll('label')].find(x=>x.textContent.trim()==='Protocol').htmlFor).options].map(o=>o.textContent).join(', ')"));
await setSelect("Protocol", "DNS"); await sleep(1500);
log(" DNS only:", await ev("(document.body.innerText.match(/Showing [^\\n]+/)||[])[0]"), "\n   " + await rowsOf("div[aria-label='Flow list'] tbody tr", 2));
await setSelect("Protocol", "All protocols"); await sleep(800);
await setInput("Search", "example"); await sleep(2000);
log(" search 'example':", await ev("(document.body.innerText.match(/Showing [^\\n]+/)||[])[0] ?? (document.body.innerText.includes('No flows match') ? 'No flows match' : '?')"));
await setInput("Search", ""); await sleep(1200);
await shot("14-flows-real");
log(" open the biggest flow:", await ev("(() => { const b=document.querySelector('div[aria-label=\"Flow list\"] tbody button'); b.click(); return 'ok'; })()"));
await until("[...document.querySelectorAll('aside')].some(a=>a.innerText.includes('Source chosen by'))", 10000);
log("  detail:\n    " + (await ev("[...document.querySelectorAll('aside')].find(a=>a.innerText.includes('Source chosen by'))?.innerText")).split("\n").slice(0, 70).join("\n    "));
await shot("15-flow-detail-real");

log("\n== Application Intelligence (real packets)");
await go("#/applications", "document.body.innerText.includes('Identified') || document.body.innerText.includes('Unclassified')"); await sleep(1500);
log(" " + (await text()).split("\n").slice(0, 90).join(" | "));
await shot("16-applications-real");
log("\nproblems:", problems.length ? "\n  " + problems.join("\n  ") : "none");
ws.close();
