// Drives the REAL debug desktop window (WebView2 over the DevTools protocol) through the Phase 4 screens at three window
// widths and reports layout, console errors and timings. The window is resized with the operating system (SetWindowPos),
// not emulated. usage: node cdp-phase4.mjs <shots dir> <capture file> <app process id> [widths]
import { writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";

const port = 9444;
const [shots, capture, pid, widthsArg] = process.argv.slice(2);
const widths = (widthsArg ?? "900,1024,1440").split(",").map(Number);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const log = (...a) => console.log(...a);
let targets;
for (let i = 0; i < 80; i++) { try { targets = await (await fetch(`http://127.0.0.1:${port}/json`)).json(); if (targets.some((t) => t.type === "page")) break; } catch {} await sleep(500); }
const page = targets.find((t) => t.type === "page");
const ws = new WebSocket(page.webSocketDebuggerUrl); await new Promise((r) => (ws.onopen = r));
let id = 0; const pending = new Map(); let problems = [];
ws.onmessage = (m) => { const d = JSON.parse(m.data); if (d.id && pending.has(d.id)) { pending.get(d.id)(d); pending.delete(d.id); return; }
  if (d.method === "Runtime.exceptionThrown") problems.push("exception " + (d.params.exceptionDetails.exception?.description ?? d.params.exceptionDetails.text));
  if (d.method === "Runtime.consoleAPICalled" && ["error", "warning"].includes(d.params.type)) problems.push("console." + d.params.type + " " + d.params.args.map((a) => a.value ?? a.description).join(" ").slice(0, 300));
  if (d.method === "Log.entryAdded" && ["error", "warning"].includes(d.params.entry.level)) problems.push("log " + d.params.entry.level + " " + d.params.entry.text.slice(0, 300)); };
ws.onclose = () => { console.log("DevTools connection closed"); process.exit(3); };
setInterval(() => {}, 1000); // the web socket alone does not keep node alive while a long call is pending
const send = (method, params = {}) => new Promise((res, rej) => { const i = ++id; const timer = setTimeout(() => rej(new Error('no answer to ' + method + ' within 90 s')), 90000); pending.set(i, (d) => { clearTimeout(timer); res(d); }); ws.send(JSON.stringify({ id: i, method, params })); });
const ev = async (e) => { const r = (await send("Runtime.evaluate", { expression: e, returnByValue: true, awaitPromise: true })).result; if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description ?? "eval failed: " + e.slice(0, 80)); return r.result.value; };
await send("Runtime.enable"); await send("Log.enable");
const until = async (expr, ms = 15000) => { const end = Date.now() + ms; while (Date.now() < end) { if (await ev(`!!(${expr})`)) return true; await sleep(200); } return false; };
const shot = async (name) => { const s = await send("Page.captureScreenshot", { format: "png" }); writeFileSync(`${shots}\\${name}.png`, Buffer.from(s.result.data, "base64")); };
const setInput = (label, value) => ev(`(() => { const l=[...document.querySelectorAll('label')].find(x=>x.textContent.trim()===${JSON.stringify(label)}); const i=document.getElementById(l.htmlFor); Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(i,${JSON.stringify(value)}); i.dispatchEvent(new Event('input',{bubbles:true})); return 'ok'; })()`);
const click = (name) => ev(`(() => { const b=[...document.querySelectorAll('button')].find(x=>(x.getAttribute('aria-label')||x.textContent).trim()===${JSON.stringify(name)}); if(!b) return 'no button: '+${JSON.stringify(name)}; b.click(); return 'ok'; })()`);
const setSelect = (label, option) => ev(`(() => { const l=[...document.querySelectorAll('label')].find(x=>x.textContent.trim()===${JSON.stringify(label)}); const s=document.getElementById(l.htmlFor); const o=[...s.options].find(x=>x.textContent.includes(${JSON.stringify(option)})); if(!o) return 'no option: '+[...s.options].map(x=>x.textContent).join('|'); s.value=o.value; s.dispatchEvent(new Event('change',{bubbles:true})); return 'ok'; })()`);

// --- resize the real window ---
const ps = `
Add-Type @"
using System; using System.Runtime.InteropServices;
public class W { [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr h, IntPtr a, int x, int y, int cx, int cy, uint f);
 [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out R r); [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int c);
 public struct R { public int L, T, Rt, B; } }
"@
$p = Get-Process -Id ${pid}; $h = $p.MainWindowHandle; [W]::ShowWindow($h, 9) | Out-Null
[W]::SetWindowPos($h, [IntPtr]::Zero, 20, 20, [int]$env:TT_W, [int]$env:TT_H, 0x0004) | Out-Null`;
const resize = (w, h) => spawnSync("powershell", ["-NoProfile", "-Command", ps], { env: { ...process.env, TT_W: String(w), TT_H: String(h) } });
const metrics = () => ev("({ inner: innerWidth, innerH: innerHeight, outer: outerWidth, dpr: devicePixelRatio, screen: screen.availWidth })");
async function fit(target) {
  let m = await metrics(); let w = Math.round(target * m.dpr) + 40; let h = 900;
  for (let i = 0; i < 6; i++) {
    resize(w, h); await sleep(700); m = await metrics();
    if (Math.abs(m.inner - target) <= 1) break;
    w += Math.round((target - m.inner) * m.dpr);
  }
  return m;
}

for (let i = 0; i < 60; i++) { if (/Backend connected|Backend unavailable/.test(await ev("document.body?.innerText ?? ''"))) break; await sleep(500); }
log("header:", await ev("[...document.querySelectorAll('header span')].map(e=>e.textContent.trim()).filter(Boolean).join(' | ')"));

// --- data: open the reference capture so alerts, devices and a topology exist ---
await ev("location.hash = '#/packets'"); await until("document.body.innerText.includes('Open or save')", 20000);
log('fit 1440:', JSON.stringify(await fit(1440)));
log("open:", await setInput("Open a capture file", capture), await click("Open file"));
log("capture loaded:", await until("/[1-9][\\d,]* packets/.test(document.body.innerText)", 120000));
await sleep(8000); // the detection run ends a little after the load

const screens = [
  { name: "overview", hash: "#/threats", h1: "Threat Detection", ready: "document.body.innerText.includes('Detection status')" },
  { name: "alerts", hash: "#/alerts", h1: "Security Alerts", ready: "document.querySelector('table') || document.body.innerText.includes('No alerts')" },
  { name: "alert-detail", hash: null, h1: "Security Alerts", ready: "document.body.innerText.includes('What was observed')" },
  { name: "rules", hash: "#/rules", h1: "Detection Rules", ready: "document.body.innerText.includes('Retention, baselines and scoring')" },
  { name: "risk", hash: null, h1: "Device Risk Profile", ready: "document.body.innerText.includes('Alerts that count')" },
  { name: "topology", hash: "#/topology", h1: "Network Topology", ready: "document.querySelector('svg[aria-label^=\"Network graph\"]')" },
  { name: "topology-list", hash: "#/topology", h1: "Network Topology", ready: "document.querySelector('svg[aria-label^=\"Network graph\"]')", list: true },
];
const rows = [];
let failures = 0;
for (const width of widths) {
  const m = await fit(width);
  log(`\n=== window ${width} px: innerWidth ${m.inner}, dpr ${m.dpr}, screen ${m.screen} ===`);
  if (Math.abs(m.inner - width) > 1) { log("  COULD NOT reach this width"); failures++; }
  for (const s of screens) {
    problems = [];
    let hash = s.hash;
    if (s.name === "alert-detail") {
      await ev("location.hash = '#/alerts'"); await until("document.querySelector('table tbody a')", 15000);
      hash = await ev("document.querySelector('table tbody a')?.getAttribute('href') ?? '#/alerts'");
    }
    if (s.name === "risk") { await ev("location.hash = '#/threats'"); await until("document.body.innerText.includes('Devices by risk')", 15000); hash = await ev("document.querySelector('a[href^=\"#/risk/\"]')?.getAttribute('href') ?? '#/risk/1'"); }
    const t0 = Date.now();
    await ev(`location.hash = ${JSON.stringify(hash)}`);
    const ok = await until(`(${s.ready}) && document.querySelector('h1')?.textContent?.trim() === ${JSON.stringify(s.h1)}`, 20000);
    if (s.list) { await click("List"); await until("document.querySelector('[aria-label=\"Relationships\"]')", 8000); }
    const took = Date.now() - t0;
    await sleep(600);
    const info = await ev(`(() => ({ h1: document.querySelector('h1')?.textContent?.trim(), pageOverflow: document.documentElement.scrollWidth - document.documentElement.clientWidth, bodyOverflow: document.body.scrollWidth - document.documentElement.clientWidth,
      mainOverflow: (() => { const m = document.querySelector('main'); return m ? m.scrollWidth - m.clientWidth : 0; })(), tables: document.querySelectorAll('[role=region][aria-label]').length,
      text: document.querySelector('main')?.innerText.replace(/\\s+/g, ' ').slice(0, 160) }))()`);
    const bad = !ok || info.h1 !== s.h1 || info.pageOverflow > 0 || info.mainOverflow > 0 || problems.length > 0;
    if (bad) failures++;
    rows.push({ width, screen: s.name, ok, ms: took, ...info, problems: problems.length });
    log(`  ${bad ? "FAIL" : "ok  "} ${s.name.padEnd(14)} ready=${ok} ${String(took).padStart(5)} ms  h1="${info.h1}" pageOverflow=${info.pageOverflow} mainOverflow=${info.mainOverflow} console=${problems.length}`);
    for (const p of problems.slice(0, 3)) log("       ", p);
    await shot(`${width}-${s.name}`);
  }
  // keyboard on the graph at this width
  problems = [];
  await ev("location.hash = '#/topology'"); await click("Graph"); await until("document.querySelector('svg[aria-label^=\"Network graph\"] [role=button]')", 15000);
  const kb = await ev(`(() => { const nodes=[...document.querySelectorAll('svg [role=button]')]; if(nodes.length<2) return 'only '+nodes.length+' node(s)'; nodes[0].focus(); nodes[0].dispatchEvent(new KeyboardEvent('keydown',{key:'ArrowRight',bubbles:true})); const moved = document.activeElement!==nodes[0]; document.activeElement.dispatchEvent(new KeyboardEvent('keydown',{key:'Enter',bubbles:true})); window.__kb = document.activeElement; return { moved, nodes: nodes.length }; })()`);
  await sleep(300);
  if (typeof kb !== 'string') kb.pressed = await ev("window.__kb?.getAttribute('aria-pressed')");
  log("  graph keyboard:", JSON.stringify(kb));
  if (typeof kb === "string" || !kb.moved || kb.pressed !== "true") failures++;
  await shot(`${width}-topology-selected`);
  // mouse: wheel zoom and drag-pan with real input events in the real window
  await ev("location.hash = '#/topology'"); await until("document.querySelector('svg[aria-label^=\"Network graph\"]')", 15000);
  await click("Fit"); await ev(`document.querySelector('svg[aria-label^="Network graph"]').scrollIntoView({ block: 'center' })`); await sleep(300);
  await ev("document.activeElement?.blur(); document.querySelector('svg [role=button][aria-pressed=true]')?.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape',bubbles:true}))"); await sleep(200);
  const geo = await ev("(() => { const s = document.querySelector('svg[aria-label^=\"Network graph\"]'); const r = s.getBoundingClientRect(); return { x: r.left + r.width / 2, y: r.top + r.height / 2, vb: s.getAttribute('viewBox') }; })()");
  const vbNow = () => ev("document.querySelector('svg[aria-label^=\"Network graph\"]').getAttribute('viewBox')");
  const mouse = (type, x, y, extra = {}) => send("Input.dispatchMouseEvent", { type, x, y, button: "left", buttons: type === "mouseReleased" ? 0 : 1, clickCount: 1, ...extra });
  await send("Input.dispatchMouseEvent", { type: "mouseWheel", x: geo.x, y: geo.y, deltaX: 0, deltaY: -240 }); await sleep(250);
  const zoomed = await vbNow();
  await mouse("mousePressed", geo.x + 200, geo.y + 100); await mouse("mouseMoved", geo.x + 240, geo.y + 120); await mouse("mouseMoved", geo.x + 290, geo.y + 150); await mouse("mouseReleased", geo.x + 290, geo.y + 150); await sleep(250);
  const panned = await vbNow();
  const sel = await ev("document.querySelectorAll('svg [role=button][aria-pressed=true]').length");
  const wOf = (vb) => Number(vb.split(' ')[2]);
  const mouseOk = wOf(zoomed) < wOf(geo.vb) && panned !== zoomed && wOf(panned) === wOf(zoomed) && sel === 0;
  log(`  mouse: wheel ${geo.vb} -> ${zoomed}; drag -> ${panned}; selected after drag: ${sel}  ${mouseOk ? "ok" : "FAIL"}`);
  if (!mouseOk) failures++;
  await shot(`${width}-topology-zoomed`);
  // Overview chart range and the alert's packet filter
  await ev("location.hash = '#/threats'"); await until("document.body.innerText.includes('Alerts over time')", 15000);
  await setSelect("Range", "7 days"); await sleep(1200);
  const chart = await ev("document.querySelector('svg[role=img]')?.getAttribute('aria-label')");
  log("  overview chart:", chart, /last 7 days/.test(chart ?? "") ? "ok" : "FAIL"); if (!/last 7 days/.test(chart ?? "")) failures++;
  await ev("location.hash = '#/alerts'"); await until("document.querySelector('table tbody a')", 15000);
  await ev("location.hash = document.querySelector('table tbody a').getAttribute('href')"); await until("document.body.innerText.includes('Find these packets')", 15000);
  const filter = await ev("document.querySelector('input[readonly]')?.value");
  log("  alert packet filter:", filter, /^ip\.addr == /.test(filter ?? "") ? "ok" : "FAIL"); if (!/^ip\.addr == /.test(filter ?? "")) failures++;
  await shot(`${width}-alert-filter`);

}
log(`\nrows: ${rows.length}, failures: ${failures}`);
writeFileSync(`${shots}\\summary.json`, JSON.stringify(rows, null, 1));
await ev("location.hash = '#/overview'");
process.exit(failures ? 1 : 0);
