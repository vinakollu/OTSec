"""The interactive page: the whole stack drawn while it runs.

:mod:`otguard.live.page` is the narration view — panels of numbers and a feed,
for watching a scripted run go by. This is the other one: a topology with every
component on it, each frame drawn crossing the wire in the colour of the
verdict it got, charts that fill as the plant moves, and controls that drive
the run rather than describe it.

It is one string with no dependencies for the same reason the other page is.
A demonstration happens in a lecture room on whatever network is available,
which is often none, and a page that fetches a charting library from a CDN is a
page that shows a blank rectangle at exactly the wrong moment. Everything here
is drawn on a canvas by hand.

The colours are the ones :mod:`otguard.eval.figstyle` uses for the figures, so
that what an audience sees moving on the screen matches what they later read in
the report.
"""

DEMO_PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OTGuard live</title>
<link rel="icon" href="data:,">
<style>
  :root {
    --surface:#ffffff; --panel:#fbfcfc; --ink:#14202b; --ink2:#54656f; --ink3:#8a99a3;
    --grid:#e6eaec; --rule:#cfd6da;
    --estimate:#1d4ed8; --sensor:#c2410c; --third:#047857; --extra:#6d28d9;
    --safe:#047857; --warn:#a16207; --danger:#b42318; --inert:#94a3b8;
    --sans:"Liberation Sans","Helvetica Neue",Arial,sans-serif;
    --mono:"Liberation Mono","SF Mono",Menlo,Consolas,monospace;
  }
  * { box-sizing:border-box; }
  body {
    margin:0; background:var(--surface); color:var(--ink);
    font-family:var(--sans); font-size:14px; line-height:1.45;
  }
  header {
    display:flex; align-items:baseline; gap:16px; flex-wrap:wrap;
    padding:14px 20px 12px; border-bottom:1px solid var(--rule);
  }
  header h1 { font-size:16px; font-weight:600; margin:0; letter-spacing:-0.01em; }
  header .sub { color:var(--ink2); font-size:12.5px; }
  header .spacer { flex:1 1 auto; }
  .wrap { padding:16px 20px 28px; max-width:1500px; margin:0 auto; }

  .banner {
    display:flex; align-items:center; gap:12px; padding:10px 14px; border-radius:6px;
    border:1px solid var(--rule); background:var(--panel); margin-bottom:14px;
  }
  .banner .dot { width:10px; height:10px; border-radius:50%; background:var(--inert); flex:0 0 auto; }
  .banner .what { font-weight:600; }
  .banner .note { color:var(--ink2); font-size:13px; }
  .banner.safe  { border-color:#b9ddcb; background:#f1f9f5; }
  .banner.safe  .dot { background:var(--safe); }
  .banner.warn  { border-color:#e8d9a8; background:#fdf8ec; }
  .banner.warn  .dot { background:var(--warn); }
  .banner.danger{ border-color:#eec3bd; background:#fdf2f0; }
  .banner.danger .dot { background:var(--danger); }

  .controls { display:flex; gap:8px; align-items:center; flex-wrap:wrap; margin-bottom:16px; }
  select, button {
    font-family:var(--sans); font-size:13px; color:var(--ink);
    background:var(--surface); border:1px solid var(--rule); border-radius:5px;
    padding:7px 11px; cursor:pointer;
  }
  select { max-width:330px; }
  button:hover { border-color:var(--ink3); }
  button.primary { background:var(--ink); color:#fff; border-color:var(--ink); font-weight:600; }
  button.primary:hover { background:#24323f; }
  button.danger { background:var(--danger); color:#fff; border-color:var(--danger); font-weight:600; }
  button.danger:hover { background:#9d2016; }
  .toggle {
    display:inline-flex; align-items:center; gap:9px; padding:6px 12px 6px 10px;
    border:1px solid var(--rule); border-radius:5px; cursor:pointer; user-select:none;
  }
  .toggle .led { width:9px; height:9px; border-radius:50%; background:var(--safe); }
  .toggle.off { border-color:#eec3bd; background:#fdf2f0; }
  .toggle.off .led { background:var(--danger); }
  .toggle .label { font-size:13px; }
  .toggle .label b { font-weight:600; }

  .tiles { display:grid; grid-template-columns:repeat(auto-fit,minmax(132px,1fr)); gap:10px; margin-bottom:16px; }
  .tile { border:1px solid var(--rule); border-radius:6px; padding:9px 11px; background:var(--panel); }
  .tile .k { font-size:11px; color:var(--ink3); text-transform:none; letter-spacing:0.01em; }
  .tile .v { font-family:var(--mono); font-size:19px; font-weight:600; margin-top:1px; }
  .tile .v small { font-size:12px; font-weight:400; color:var(--ink2); }

  .panel { border:1px solid var(--rule); border-radius:6px; background:var(--surface); margin-bottom:16px; }
  .panel > h2 {
    font-size:12.5px; font-weight:600; color:var(--ink2); margin:0;
    padding:9px 13px; border-bottom:1px solid var(--grid);
  }
  .panel > h2 span { font-weight:400; color:var(--ink3); }
  .charts { display:grid; grid-template-columns:repeat(auto-fit,minmax(330px,1fr)); gap:14px; }
  canvas { display:block; width:100%; }
  /* A height in CSS, not only in the attribute. With width:100% and no CSS
     height the element keeps the attribute aspect ratio, and since the
     attribute width is set from the device pixel ratio the box grows to
     several times the height anything is drawn in. */
  #topology { height:400px; }
  #levelChart, #actuatorChart, #decisionChart { height:230px; }

  .log { max-height:230px; overflow-y:auto; font-family:var(--mono); font-size:12px; }
  .log table { width:100%; border-collapse:collapse; }
  .log td { padding:3px 13px; border-bottom:1px solid var(--grid); white-space:nowrap; }
  .log td.detail { white-space:normal; color:var(--ink2); font-family:var(--sans); width:99%; }
  .log td.v { font-weight:600; }
  .log .allow .v { color:var(--ink3); }
  .log .alarm .v { color:var(--warn); }
  .log .block .v { color:var(--danger); }
  .log .trip  .v { color:var(--extra); }
  .log tr.block { background:#fdf5f4; }
  .log tr.trip  { background:#f8f5fd; }
  .legend { display:flex; gap:14px; flex-wrap:wrap; padding:8px 13px; font-size:12px; color:var(--ink2); }
  .legend i { display:inline-block; width:9px; height:9px; border-radius:50%; margin-right:5px; }
  .offline { color:var(--danger); font-weight:600; }
</style>
</head>
<body>
<header>
  <h1>OTGuard live</h1>
  <span class="sub" id="subtitle">connecting…</span>
  <span class="spacer"></span>
  <span class="sub" id="clock"></span>
</header>

<div class="wrap">
  <div class="banner" id="banner">
    <span class="dot"></span>
    <span class="what" id="bannerWhat">starting</span>
    <span class="note" id="bannerNote"></span>
  </div>

  <div class="controls">
    <select id="attackSelect"><option>loading…</option></select>
    <button class="primary" id="launch">Launch attack</button>
    <button id="stopAttack">Stop attack</button>
    <div class="toggle" id="enforceToggle" title="Turn the guard's enforcement off to see the same attack without it">
      <span class="led"></span>
      <span class="label">Guard <b id="enforceLabel">enforcing</b></span>
    </div>
    <div class="toggle" id="linkToggle" title="Close the device's listening socket; the scanner probes it and will notice">
      <span class="led"></span>
      <span class="label">Link to device <b id="linkLabel">up</b></span>
    </div>
    <button id="reset">Reset plant</button>
  </div>

  <div class="tiles" id="tiles"></div>

  <div class="panel">
    <h2>The wire <span>— every frame, where it came from, and what the guard did with it</span></h2>
    <canvas id="topology" height="400"></canvas>
    <div class="legend">
      <span><i style="background:var(--inert)"></i>read</span>
      <span><i style="background:var(--third)"></i>write allowed</span>
      <span><i style="background:var(--warn)"></i>alarmed, still forwarded</span>
      <span><i style="background:var(--danger)"></i>blocked at the guard</span>
      <span><i style="background:var(--extra)"></i>protective trip, written by the guard itself</span>
    </div>
  </div>

  <div class="panel">
    <h2>Devices <span>— what the scanner can reach, probed once a second</span></h2>
    <div class="log"><table id="deviceBody"></table></div>
  </div>

  <div class="charts">
    <div class="panel">
      <h2>Tank level <span>— what the plant is doing, and what the guard believes</span></h2>
      <canvas id="levelChart" height="230"></canvas>
    </div>
    <div class="panel">
      <h2>Actuators <span>— commanded positions reaching the plant</span></h2>
      <canvas id="actuatorChart" height="230"></canvas>
    </div>
    <div class="panel">
      <h2>Guard decisions <span>— frames per second, by verdict</span></h2>
      <canvas id="decisionChart" height="230"></canvas>
    </div>
  </div>

  <div class="panel">
    <h2>Decisions <span>— newest first</span></h2>
    <div class="log"><table id="logBody"></table></div>
  </div>
</div>

<script>
"use strict";
const C = {
  ink:"#14202b", ink2:"#54656f", ink3:"#8a99a3", grid:"#e6eaec", rule:"#cfd6da",
  estimate:"#1d4ed8", sensor:"#c2410c", third:"#047857", extra:"#6d28d9",
  safe:"#047857", warn:"#a16207", danger:"#b42318", inert:"#94a3b8", surface:"#ffffff",
};
const VERDICT = { allow:C.third, alarm:C.warn, block:C.danger, read:C.inert, trip:C.extra };

const state = {
  topo:null, safety:{level_max_m:1.8, level_min_m:0.2, height_m:2.0},
  enforce:true, t:0, speed:1,
  series:[],                 // {t, level, estimate, pump, valve}
  rates:[],                  // {t, allow, alarm, block, read}
  packets:[], trips:0, blocked:0, inspected:0, latencies:[],
  attack:null, damaged:false, connected:false, suspended:[], devices:{}, link:true,
  bucket:{t:0, allow:0, alarm:0, block:0, read:0},
};
const WINDOW_S = 120;

/* ---------------------------------------------------------------- canvas */
function fit(canvas) {
  const dpr = window.devicePixelRatio || 1;
  const w = canvas.clientWidth, h = canvas.clientHeight || canvas.height;
  if (canvas.width !== Math.round(w*dpr) || canvas.height !== Math.round(h*dpr)) {
    canvas.width = Math.round(w*dpr); canvas.height = Math.round(h*dpr);
  }
  const ctx = canvas.getContext("2d");
  ctx.setTransform(dpr,0,0,dpr,0,0);
  return {ctx, w, h};
}
function roundRect(ctx,x,y,w,h,r){
  ctx.beginPath(); ctx.moveTo(x+r,y);
  ctx.arcTo(x+w,y,x+w,y+h,r); ctx.arcTo(x+w,y+h,x,y+h,r);
  ctx.arcTo(x,y+h,x,y,r); ctx.arcTo(x,y,x+w,y,r); ctx.closePath();
}

/* -------------------------------------------------------------- topology */
const topoCanvas = document.getElementById("topology");
let layout = null;

function computeLayout(w,h){
  const masters = state.topo ? state.topo.masters : [];
  const boxW = Math.min(190, Math.max(130, w*0.17));
  const leftX = 14, guardW = Math.min(190, Math.max(140, w*0.16));
  const guardX = Math.max(leftX+boxW+70, w*0.40);
  const devW = Math.min(230, Math.max(150, w*0.20));
  const devX = Math.min(w-devW-14, guardX+guardW+Math.max(70, w*0.10));
  const top = 34, gap = 10;
  const rowH = masters.length ? Math.min(52,(h-top-20-gap*(masters.length-1))/masters.length) : 40;
  const rows = masters.map((m,i)=>({
    name:m.name, address:m.address, description:m.description, read_only:m.read_only,
    x:leftX, y:top+i*(rowH+gap), w:boxW, h:rowH,
  }));
  const guardH = Math.max(120, rows.length? (rows[rows.length-1].y+rowH-top) : 140);
  return {
    rows, boxW,
    guard:{x:guardX, y:top, w:guardW, h:guardH},
    device:{x:devX, y:top+Math.max(0,(guardH-150)/2), w:devW, h:150},
  };
}

function drawTopology(){
  const {ctx,w,h} = fit(topoCanvas);
  ctx.clearRect(0,0,w,h);
  if (!state.topo){ ctx.fillStyle=C.ink3; ctx.font="13px var(--sans)";
    ctx.fillText("waiting for the stack…",16,30); return; }
  layout = computeLayout(w,h);
  const L = layout, g = L.guard, d = L.device;

  ctx.font = "11px system-ui, sans-serif";
  ctx.fillStyle = C.ink3;
  ctx.fillText("MASTERS", L.rows.length?L.rows[0].x:14, 20);
  ctx.fillText("GUARD", g.x, 20);
  ctx.fillText("FIELD DEVICE", d.x, 20);

  // wires
  ctx.strokeStyle = C.grid; ctx.lineWidth = 1.5;
  for (const r of L.rows){
    ctx.beginPath();
    ctx.moveTo(r.x+r.w, r.y+r.h/2);
    ctx.lineTo(g.x, r.y+r.h/2 < g.y+g.h/2 ? g.y+g.h*0.35 : g.y+g.h*0.65);
    ctx.stroke();
  }
  ctx.beginPath(); ctx.moveTo(g.x+g.w, g.y+g.h/2); ctx.lineTo(d.x, d.y+d.h/2); ctx.stroke();

  // master boxes
  for (const r of L.rows){
    const attacking = state.attack && r.name === state.attackSource;
    // A station the attacker is using is not "stood down". The legitimate loop
    // on it has stopped, which is why it is in the suspended set, but the box
    // the audience is looking at is the one the attack is coming from and it
    // has to say so.
    const down = state.suspended.includes(r.name) && !attacking;
    ctx.globalAlpha = down ? 0.42 : 1;
    ctx.fillStyle = attacking ? "#fdf2f0" : "#fbfcfc";
    ctx.strokeStyle = attacking ? C.danger : C.rule;
    ctx.lineWidth = attacking ? 1.6 : 1;
    roundRect(ctx,r.x,r.y,r.w,r.h,5); ctx.fill(); ctx.stroke();
    ctx.fillStyle = C.ink; ctx.font = "600 12px system-ui, sans-serif";
    ctx.fillText(r.name, r.x+9, r.y+17);
    ctx.fillStyle = C.ink3; ctx.font = "10.5px var(--mono), monospace";
    ctx.fillText(r.address, r.x+9, r.y+31);
    ctx.font = "10px system-ui, sans-serif";
    if (attacking){ ctx.fillStyle=C.danger; ctx.fillText("COMPROMISED", r.x+r.w-78, r.y+31); }
    else if (down){ ctx.fillStyle=C.ink3; ctx.fillText("stood down", r.x+r.w-64, r.y+31); }
    else if (r.read_only){ ctx.fillStyle=C.ink3; ctx.fillText("read only", r.x+r.w-56, r.y+31); }
    ctx.globalAlpha = 1;
  }

  // guard box
  const bypass = !state.enforce;
  ctx.fillStyle = bypass ? "#fdf2f0" : "#f1f9f5";
  ctx.strokeStyle = bypass ? "#eec3bd" : "#b9ddcb";
  ctx.lineWidth = 1.5;
  roundRect(ctx,g.x,g.y,g.w,g.h,6); ctx.fill(); ctx.stroke();
  ctx.fillStyle = C.ink; ctx.font = "600 13px system-ui, sans-serif";
  ctx.fillText("OTGuard", g.x+11, g.y+21);
  ctx.fillStyle = bypass ? C.danger : C.safe; ctx.font = "11px system-ui, sans-serif";
  ctx.fillText(bypass ? "watching, powerless" : "enforcing", g.x+11, g.y+37);

  // rule lamps
  const rules = ["R1","R2","R3","R4","R5"];
  const now = performance.now();
  rules.forEach((id,i)=>{
    const y = g.y+58+i*17;
    const lit = state.ruleFlash && state.ruleFlash[id] && now-state.ruleFlash[id] < 1400;
    ctx.beginPath(); ctx.arc(g.x+17, y, 4, 0, Math.PI*2);
    ctx.fillStyle = lit ? C.danger : "#dfe6e9"; ctx.fill();
    ctx.fillStyle = lit ? C.ink : C.ink3;
    ctx.font = (lit?"600 ":"")+"11px var(--mono), monospace";
    ctx.fillText(id, g.x+28, y+4);
  });
  ctx.fillStyle = C.ink3; ctx.font = "10px system-ui, sans-serif";
  ctx.fillText("blocked " + state.blocked, g.x+11, g.y+g.h-10);

  // device box
  ctx.fillStyle = "#fbfcfc"; ctx.strokeStyle = C.rule; ctx.lineWidth = 1;
  roundRect(ctx,d.x,d.y,d.w,d.h,6); ctx.fill(); ctx.stroke();
  ctx.fillStyle = C.ink; ctx.font = "600 13px system-ui, sans-serif";
  ctx.fillText(state.topo.device.name, d.x+11, d.y+21);
  ctx.fillStyle = C.ink3; ctx.font = "10.5px system-ui, sans-serif";
  const units = state.topo.device.units.map(u=>"unit "+u).join(", ");
  ctx.fillText(units, d.x+11, d.y+36);

  // the tank, drawn to scale inside the device
  const last = state.series[state.series.length-1];
  const tx = d.x+13, ty = d.y+48, tw = 46, th = d.h-66;
  ctx.strokeStyle = C.rule; ctx.lineWidth = 1.2;
  ctx.strokeRect(tx,ty,tw,th);
  const H = state.safety.height_m || 2.0;
  const maxY = ty+th*(1-(state.safety.level_max_m/H));
  const minY = ty+th*(1-(state.safety.level_min_m/H));
  ctx.strokeStyle = "rgba(180,35,24,0.45)"; ctx.setLineDash([3,3]); ctx.lineWidth = 1;
  ctx.beginPath(); ctx.moveTo(tx,maxY); ctx.lineTo(tx+tw,maxY); ctx.stroke();
  ctx.beginPath(); ctx.moveTo(tx,minY); ctx.lineTo(tx+tw,minY); ctx.stroke();
  ctx.setLineDash([]);
  if (last){
    const lv = Math.max(0, Math.min(H, last.level));
    const lh = th*(lv/H);
    ctx.fillStyle = state.damaged ? "rgba(180,35,24,0.30)" : "rgba(29,78,216,0.22)";
    ctx.fillRect(tx+1, ty+th-lh, tw-2, lh);
    ctx.fillStyle = C.ink; ctx.font = "600 11px var(--mono), monospace";
    ctx.fillText(last.level.toFixed(2)+" m", tx+tw+10, ty+14);
    ctx.fillStyle = C.ink2; ctx.font = "10.5px system-ui, sans-serif";
    ctx.fillText("pump "+last.pump.toFixed(0)+"%", tx+tw+10, ty+32);
    ctx.fillText("valve "+last.valve.toFixed(0)+"%", tx+tw+10, ty+47);
  }

  drawPackets(ctx, L);
}

const LEG_MS = 620;
function drawPackets(ctx, L){
  const now = performance.now();
  state.packets = state.packets.filter(p => now - p.born < LEG_MS*2 + 500);
  const g = L.guard, d = L.device;
  for (const p of state.packets){
    const age = now - p.born;
    const row = L.rows[p.row] || L.rows[0];
    if (!row) continue;
    const from = {x:row.x+row.w, y:row.y+row.h/2};
    const mid  = {x:g.x, y:row.y+row.h/2 < g.y+g.h/2 ? g.y+g.h*0.35 : g.y+g.h*0.65};
    const to   = {x:d.x, y:d.y+d.h/2};
    let x,y,alpha=1,r=4;
    if (p.kind === "trip"){
      const u = Math.min(1, age/LEG_MS);
      x = g.x+g.w + (to.x-(g.x+g.w))*u; y = (g.y+g.h/2) + (to.y-(g.y+g.h/2))*u;
      r = 5; alpha = 1-0.3*u;
    } else if (age < LEG_MS){
      const u = age/LEG_MS;
      x = from.x + (mid.x-from.x)*u; y = from.y + (mid.y-from.y)*u;
    } else if (p.decision === "block"){
      const u = Math.min(1,(age-LEG_MS)/420);
      x = mid.x; y = mid.y; r = 4+7*u; alpha = 1-u;
    } else {
      const u = Math.min(1,(age-LEG_MS)/LEG_MS);
      x = (g.x+g.w) + (to.x-(g.x+g.w))*u; y = mid.y + (to.y-mid.y)*u;
      alpha = 1-0.15*u;
    }
    ctx.globalAlpha = Math.max(0,alpha);
    ctx.beginPath(); ctx.arc(x,y,r,0,Math.PI*2);
    ctx.fillStyle = VERDICT[p.kind === "trip" ? "trip" : p.decision] || C.inert;
    ctx.fill();
    if (p.decision === "block" && age >= LEG_MS){
      ctx.strokeStyle = C.danger; ctx.lineWidth = 1.4; ctx.stroke();
    }
    ctx.globalAlpha = 1;
  }
}

/* ---------------------------------------------------------------- charts */
function axes(ctx,w,h,pad,yTicks,fmt){
  ctx.clearRect(0,0,w,h);
  ctx.strokeStyle = C.grid; ctx.lineWidth = 1;
  ctx.fillStyle = C.ink3; ctx.font = "10.5px var(--mono), monospace";
  for (const t of yTicks){
    const y = pad.t + (h-pad.t-pad.b)*(1-t.u);
    ctx.beginPath(); ctx.moveTo(pad.l,y); ctx.lineTo(w-pad.r,y); ctx.stroke();
    ctx.fillText(fmt(t.v), 5, y+3.5);
  }
  ctx.strokeStyle = C.rule;
  ctx.beginPath(); ctx.moveTo(pad.l,pad.t); ctx.lineTo(pad.l,h-pad.b); ctx.lineTo(w-pad.r,h-pad.b); ctx.stroke();
}
function windowed(series){
  const tEnd = state.t, tStart = tEnd - WINDOW_S;
  return {rows: series.filter(s=>s.t>=tStart), tStart, tEnd:Math.max(tEnd,tStart+1)};
}
function line(ctx,rows,pad,w,h,tStart,tEnd,get,lo,hi,colour,width){
  ctx.beginPath(); let started=false;
  for (const r of rows){
    const v = get(r); if (v===null||v===undefined||Number.isNaN(v)) continue;
    const x = pad.l + (w-pad.l-pad.r)*((r.t-tStart)/(tEnd-tStart));
    const y = pad.t + (h-pad.t-pad.b)*(1-(v-lo)/(hi-lo));
    if (!started){ ctx.moveTo(x,y); started=true; } else ctx.lineTo(x,y);
  }
  ctx.strokeStyle = colour; ctx.lineWidth = width||1.8;
  ctx.lineJoin="round"; ctx.lineCap="round"; ctx.stroke();
}
function tag(ctx,x,y,text,colour){
  ctx.fillStyle = colour; ctx.font = "600 11px system-ui, sans-serif";
  ctx.fillText(text,x,y);
}

function drawLevel(){
  const {ctx,w,h} = fit(document.getElementById("levelChart"));
  const pad = {l:40,r:76,t:12,b:20};
  const H = state.safety.height_m || 2.0;
  const ticks = [0,0.5,1,1.5,2].filter(v=>v<=H).map(v=>({u:v/H, v}));
  axes(ctx,w,h,pad,ticks,v=>v.toFixed(1));
  const {rows,tStart,tEnd} = windowed(state.series);
  const yOf = v => pad.t+(h-pad.t-pad.b)*(1-v/H);
  // danger bands
  ctx.fillStyle = "rgba(180,35,24,0.055)";
  ctx.fillRect(pad.l, pad.t, w-pad.l-pad.r, yOf(state.safety.level_max_m)-pad.t);
  ctx.fillRect(pad.l, yOf(state.safety.level_min_m), w-pad.l-pad.r, (h-pad.b)-yOf(state.safety.level_min_m));
  ctx.strokeStyle = "rgba(180,35,24,0.5)"; ctx.lineWidth = 1;
  for (const lim of [state.safety.level_max_m, state.safety.level_min_m]){
    ctx.beginPath(); ctx.moveTo(pad.l,yOf(lim)); ctx.lineTo(w-pad.r,yOf(lim)); ctx.stroke();
  }
  if (!rows.length) return;
  line(ctx,rows,pad,w,h,tStart,tEnd,r=>r.estimate,0,H,C.estimate,1.6);
  line(ctx,rows,pad,w,h,tStart,tEnd,r=>r.level,0,H,C.ink,2.1);
  const last = rows[rows.length-1];
  // Nudge apart when the plant and the guard agree, which is most of the time
  // and is exactly when both labels want the same pixel.
  let yTrue = yOf(last.level), yEst = yOf(last.estimate);
  if (Math.abs(yTrue-yEst) < 13){ const d=(13-Math.abs(yTrue-yEst))/2;
    if (yTrue<=yEst){ yTrue-=d; yEst+=d; } else { yTrue+=d; yEst-=d; } }
  tag(ctx,w-pad.r+7,yTrue+4,"true "+last.level.toFixed(2),C.ink);
  tag(ctx,w-pad.r+7,yEst+4,"guard "+last.estimate.toFixed(2),C.estimate);
  ctx.fillStyle = C.ink3; ctx.font="10px system-ui, sans-serif";
  ctx.fillText("metres", 5, 10);
}

function drawActuators(){
  const {ctx,w,h} = fit(document.getElementById("actuatorChart"));
  const pad = {l:40,r:66,t:12,b:20};
  axes(ctx,w,h,pad,[0,25,50,75,100].map(v=>({u:v/100,v})),v=>String(v));
  const {rows,tStart,tEnd} = windowed(state.series);
  if (!rows.length) return;
  line(ctx,rows,pad,w,h,tStart,tEnd,r=>r.valve,0,100,C.third,1.8);
  line(ctx,rows,pad,w,h,tStart,tEnd,r=>r.pump,0,100,C.sensor,1.8);
  const last = rows[rows.length-1];
  const yOf = v => pad.t+(h-pad.t-pad.b)*(1-v/100);
  tag(ctx,w-pad.r+7,yOf(last.pump)+4,"pump "+last.pump.toFixed(0),C.sensor);
  tag(ctx,w-pad.r+7,yOf(last.valve)+4,"valve "+last.valve.toFixed(0),C.third);
  ctx.fillStyle = C.ink3; ctx.font="10px system-ui, sans-serif";
  ctx.fillText("per cent", 5, 10);
}

function drawDecisions(){
  const {ctx,w,h} = fit(document.getElementById("decisionChart"));
  const pad = {l:40,r:66,t:12,b:20};
  const {rows,tStart,tEnd} = windowed(state.rates);
  let peak = 4;
  for (const r of rows) peak = Math.max(peak, r.read+r.allow+r.alarm+r.block);
  const step = peak<=8?2:(peak<=20?5:(peak<=50?10:25));
  const ticks=[]; for(let v=0;v<=peak;v+=step) ticks.push({u:v/peak,v});
  axes(ctx,w,h,pad,ticks,v=>String(v));
  if (!rows.length) return;
  const bw = Math.max(2,(w-pad.l-pad.r)/Math.max(rows.length,WINDOW_S));
  for (const r of rows){
    const x = pad.l + (w-pad.l-pad.r)*((r.t-tStart)/(tEnd-tStart));
    let base = h-pad.b;
    for (const [key,colour] of [["read",C.inert],["allow",C.third],["alarm",C.warn],["block",C.danger]]){
      const v = r[key]; if (!v) continue;
      const hh = (h-pad.t-pad.b)*(v/peak);
      ctx.fillStyle = colour; ctx.fillRect(x-bw/2, base-hh, Math.max(1.5,bw*0.8), hh);
      base -= hh;
    }
  }
  const last = rows[rows.length-1];
  ctx.fillStyle = C.ink2; ctx.font="11px system-ui, sans-serif";
  ctx.fillText("now: "+(last.read+last.allow+last.alarm+last.block)+"/s", w-pad.r+6, pad.t+12);
  ctx.fillStyle = C.ink3; ctx.font="10px system-ui, sans-serif";
  ctx.fillText("frames/s", 5, 10);
}

/* ------------------------------------------------------------------- DOM */
function pct(n,d){ return d? Math.round(100*n/d)+"%" : "—"; }
function quantile(arr,q){
  if(!arr.length) return 0;
  const s=[...arr].sort((a,b)=>a-b);
  return s[Math.min(s.length-1, Math.floor(q*(s.length-1)))];
}
function renderTiles(){
  const last = state.series[state.series.length-1];
  const tiles = [
    ["Frames inspected", String(state.inspected), ""],
    ["Blocked by the guard", String(state.blocked), ""],
    ["Protective trips", String(state.trips), ""],
    ["Write decision, p50", state.latencies.length? Math.round(quantile(state.latencies,0.5)) : "—",
      state.latencies.length? " µs" : ""],
    ["Write decision, p95", state.latencies.length? Math.round(quantile(state.latencies,0.95)) : "—",
      state.latencies.length? " µs" : ""],
    ["Tank", last? last.level.toFixed(2) : "—", last? " m" : ""],
  ];
  document.getElementById("tiles").innerHTML = tiles.map(([k,v,u])=>
    `<div class="tile"><div class="k">${k}</div><div class="v">${v}<small>${u}</small></div></div>`
  ).join("");
}
let logRows = [];
function addLog(row){
  logRows.unshift(row);
  if (logRows.length > 60) logRows.pop();
  document.getElementById("logBody").innerHTML = logRows.map(r=>
    `<tr class="${r.cls}"><td>${r.t}</td><td>${r.who}</td><td>${r.what}</td>`+
    `<td class="v">${r.verdict}</td><td class="detail">${r.detail}</td></tr>`
  ).join("");
}
function setBanner(cls, what, note){
  const b = document.getElementById("banner");
  b.className = "banner " + cls;
  document.getElementById("bannerWhat").textContent = what;
  document.getElementById("bannerNote").textContent = note || "";
}
function refreshBanner(){
  if (!state.connected) return setBanner("danger","disconnected","the demo process is no longer serving this page");
  if (state.damaged) return setBanner("danger","the plant left its safety envelope",
    state.enforce ? "with the guard enforcing" : "the guard was not allowed to act");
  if (!state.link) return setBanner("warn","the link to the device is cut",
    "masters already connected keep driving the plant; the scanner has stopped reaching it");
  if (state.attack && !state.enforce) return setBanner("danger","attack running, guard bypassed", state.attack);
  if (state.attack) return setBanner("warn","attack running, guard enforcing", state.attack);
  if (!state.enforce) return setBanner("warn","guard bypassed","ordinary traffic, nothing being enforced");
  return setBanner("safe","normal operation","ordinary traffic from five masters");
}

/* --------------------------------------------------------------- events */
function rowIndexFor(source){
  if (!state.topo) return 0;
  const i = state.topo.masters.findIndex(m=>m.name===source);
  return i < 0 ? Math.max(0,state.topo.masters.length-1) : i;
}
function bucketTick(t){
  const sec = Math.floor(t);
  if (sec !== state.bucket.t){
    if (state.bucket.t) state.rates.push({...state.bucket});
    if (state.rates.length > 400) state.rates.shift();
    state.bucket = {t:sec, allow:0, alarm:0, block:0, read:0};
  }
}
function onEvent(e){
  state.t = Math.max(state.t, e.t || 0);
  const k = e.kind;

  if (k === "scenario" && e.view === "interactive"){
    state.topo = {masters:e.masters, device:e.device};
    state.safety = e.safety; state.enforce = e.guarded; state.speed = e.speed;
    state.suspended = e.suspended || [];
    document.getElementById("subtitle").textContent =
      `${e.device.name} behind the guard · ${e.masters.length} masters · clock ${e.speed}×`;
    const sel = document.getElementById("attackSelect");
    sel.innerHTML = e.attacks.map(a=>`<option value="${a.name}">${a.name} — ${a.description}</option>`).join("");
    setEnforceUi(e.guarded);
    refreshBanner();

  } else if (k === "state" && e.plant === "tank"){
    state.series.push({t:e.t, level:e.level_m, estimate:e.believed_m,
                       reported:e.reported_m, pump:e.pump_pct, valve:e.valve_pct});
    if (state.series.length > 4000) state.series.shift();
    state.safety = {level_max_m:e.limit_m, level_min_m:e.floor_m, height_m:e.height_m};
    state.damaged = e.overflowed || e.dried_out;
    bucketTick(e.t);
    renderTiles(); refreshBanner();

  } else if (k === "verdict"){
    state.inspected++;
    // Reads cost a few microseconds and writes cost a decision. Averaging the
    // two together produces a headline number that is mostly reads and
    // describes nothing anybody cares about.
    if (e.latency_us && e.point !== "read") {
      state.latencies.push(e.latency_us);
      if (state.latencies.length > 3000) state.latencies.shift();
    }
    if (e.decision === "block") state.blocked++;
    bucketTick(e.t);
    const bucketKey = e.point === "read" ? (e.decision === "block" ? "block" : "read") : e.decision;
    if (state.bucket[bucketKey] !== undefined) state.bucket[bucketKey]++;
    if (state.packets.length < 320){
      state.packets.push({born:performance.now(), row:rowIndexFor(e.source),
                          decision:e.decision, kind:e.point});
    }
    state.ruleFlash = state.ruleFlash || {};
    for (const r of (e.rules||[])) state.ruleFlash[r] = performance.now();
    if (e.point !== "read" || e.decision === "block"){
      const what = e.point === "read" ? "read" :
        `${e.point} = ${e.value}${e.unit||""}`;
      const verdict = e.decision === "block" ? "BLOCKED"
        : e.decision === "alarm" ? "alarm" : "allowed";
      const why = (e.rules && e.rules.length ? e.rules.join(",")+" " : "") + (e.detail||"");
      addLog({cls:e.decision, t:e.t.toFixed(1)+"s", who:e.source, what, verdict, detail:why});
    }

  } else if (k === "trip"){
    state.trips++;
    state.packets.push({born:performance.now(), row:0, decision:"trip", kind:"trip"});
    addLog({cls:"trip", t:e.t.toFixed(1)+"s", who:"OTGuard", what:"protective trip",
            verdict:"TRIP", detail:e.detail||""});

  } else if (k === "device"){
    state.devices[e.name] = e;
    renderDevices();

  } else if (k === "note"){
    if (e.level === "status" && e.status){
      state.enforce = e.status.enforce;
      state.attack = e.status.attack;
      state.attackSource = e.status.source;
      state.suspended = e.status.suspended || [];
      state.damaged = e.status.damaged;
      state.link = e.status.link;
      setEnforceUi(state.enforce);
      setLinkUi(state.link);
      refreshBanner();
    } else if (e.text){
      addLog({cls:e.level === "warn" ? "alarm" : "", t:(e.t||0).toFixed(1)+"s",
              who:"—", what:"", verdict:"", detail:e.text});
    }
  }
}

function renderDevices(){
  const rows = Object.values(state.devices).sort((a,b)=>a.name.localeCompare(b.name));
  document.getElementById("deviceBody").innerHTML = rows.map(d=>{
    const up = d.state === "up";
    const cls = up ? "allow" : (d.state === "down" ? "block" : "");
    const badge = up ? "UP" : (d.state === "down" ? "DOWN" : "unknown");
    const rtt = d.rtt_ms ? d.rtt_ms.toFixed(1)+" ms" : "—";
    const how = d.networked ? "probed" : "model";
    return `<tr class="${cls}"><td>${d.name}</td><td>${d.role||""}</td>`+
           `<td class="v">${badge}</td><td>${rtt}</td><td>${how}</td>`+
           `<td class="detail">${d.detail||""}</td></tr>`;
  }).join("");
}

/* -------------------------------------------------------------- controls */
async function send(action, params){
  const q = new URLSearchParams(params||{}).toString();
  try { await fetch(`/api/${action}${q?"?"+q:""}`); }
  catch (err) { console.error("command failed", err); }
}
function setEnforceUi(on){
  const t = document.getElementById("enforceToggle");
  t.classList.toggle("off", !on);
  document.getElementById("enforceLabel").textContent = on ? "enforcing" : "bypassed";
}
document.getElementById("launch").onclick = () =>
  send("attack", {name: document.getElementById("attackSelect").value});
document.getElementById("stopAttack").onclick = () => send("stop");
document.getElementById("reset").onclick = () => send("reset");
document.getElementById("enforceToggle").onclick = () =>
  send("enforce", {value: state.enforce ? "false" : "true"});
document.getElementById("linkToggle").onclick = () =>
  send("link", {value: state.link ? "false" : "true"});
function setLinkUi(up){
  const t = document.getElementById("linkToggle");
  t.classList.toggle("off", !up);
  document.getElementById("linkLabel").textContent = up ? "up" : "cut";
}

/* ------------------------------------------------------------------ main */
const source = new EventSource("/events");
source.onopen = () => { state.connected = true; refreshBanner(); };
source.onerror = () => { state.connected = false; refreshBanner(); };
source.onmessage = (m) => { try { onEvent(JSON.parse(m.data)); } catch(err){ console.error(err); } };

function frame(){
  drawTopology();
  requestAnimationFrame(frame);
}
requestAnimationFrame(frame);
setInterval(()=>{ drawLevel(); drawActuators(); drawDecisions();
  document.getElementById("clock").textContent = "t = "+state.t.toFixed(1)+" s";
}, 200);
window.addEventListener("resize", ()=>{ drawLevel(); drawActuators(); drawDecisions(); });
renderTiles();
</script>
</body>
</html>
"""
