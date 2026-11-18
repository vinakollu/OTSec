"""The water works on a screen.

Written for somebody who has never seen a treatment plant and is being shown
one for the first time: the schematic carries the process, the meters carry
every number against the limit that applies to it, and the narration column
says in ordinary words what just happened and why. Nothing on the page states
a condition by colour alone.

There is no network dependency. The page is served from loopback by
:mod:`otguard.live.web`, and a demonstration that needs a content delivery
network to draw a chart is a demonstration that fails in the room it matters
in. The charts are drawn on a canvas and the schematic is hand-laid SVG.
"""

WATER_PAGE = r"""<!doctype html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>OTGuard — water treatment works</title>
<style>
/* ------------------------------------------------------------------ *
 * Tokens. The dark series steps are chosen against the dark surface
 * rather than flipped from the light ones, which is why they are not
 * the same hues lightened. Both sets were run through the palette
 * validator in the dataviz skill against their own surface and pass
 * the lightness band, the chroma floor, adjacent-pair separation under
 * simulated colour blindness, the normal-vision floor and contrast.
 * The worst adjacent pair is green against orange: delta E 10.2 under
 * deuteranopia on dark, 9.2 under protanopia on light.
 *
 * Status is a separate reservation. Good, watch and breach never serve
 * as a series colour, and nothing on the page states a condition by
 * colour alone: every one of them carries a glyph and a word.
 * ------------------------------------------------------------------ */
:root{
  --bg:#0a0f15; --surface:#121b24; --surface-2:#18242f; --raised:#1e2c38;
  --line:#243542; --line-soft:#1b2834;
  --ink:#e8eff5; --ink-2:#9db0c0; --ink-3:#8299ac;
  --good:#1fb880; --watch:#d9a21b; --breach:#f0616d; --idle:#5d7183;
  --good-bg:rgba(31,184,128,.13); --watch-bg:rgba(217,162,27,.14);
  --breach-bg:rgba(240,97,109,.14); --idle-bg:rgba(93,113,131,.13);
  --s1:#588ffb; --s2:#d97534; --s3:#00af85; --s4:#9f7aec;
  --water:#2f6fd0; --water-soft:rgba(47,111,208,.22);
  --radius:12px; --radius-s:8px;
  --mono:ui-monospace,"SF Mono",Menlo,Consolas,"Liberation Mono",monospace;
  --sans:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
  --shadow:0 1px 2px rgba(0,0,0,.34),0 8px 24px -12px rgba(0,0,0,.6);
}
:root[data-theme="light"]{
  --bg:#eef2f6; --surface:#ffffff; --surface-2:#f4f7fa; --raised:#eaeff5;
  --line:#d9e1e9; --line-soft:#e7edf3;
  --ink:#0d1b27; --ink-2:#4e5f6e; --ink-3:#5b6b7d;
  --good:#047857; --watch:#a16207; --breach:#b42318; --idle:#94a3b8;
  --good-bg:rgba(4,120,87,.10); --watch-bg:rgba(161,98,7,.11);
  --breach-bg:rgba(180,35,24,.10); --idle-bg:rgba(148,163,184,.14);
  --s1:#1d4ed8; --s2:#c2410c; --s3:#047857; --s4:#6d28d9;
  --water:#1d4ed8; --water-soft:rgba(29,78,216,.16);
  --shadow:0 1px 2px rgba(16,34,51,.06),0 10px 26px -14px rgba(16,34,51,.26);
}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{
  background:var(--bg); color:var(--ink); font-family:var(--sans);
  font-size:14px; line-height:1.5; -webkit-font-smoothing:antialiased;
}
.num{font-family:var(--mono); font-variant-numeric:tabular-nums}
.wrap{max-width:1720px; margin:0 auto; padding:18px 22px 56px}

/* ---------------- header ---------------- */
header.top{
  display:flex; align-items:center; gap:11px; flex-wrap:wrap;
  padding:11px 16px; margin-bottom:16px;
  background:var(--surface); border:1px solid var(--line);
  border-radius:var(--radius); box-shadow:var(--shadow);
  position:sticky; top:0; z-index:40;
}
.brand{display:flex; align-items:baseline; gap:10px; min-width:0;
  flex:1 1 240px; overflow:hidden}
.brand h1{font-size:17px; margin:0; letter-spacing:-.01em; font-weight:650}
.brand .sub{color:var(--ink-3); font-size:12.5px; white-space:nowrap;
  overflow:hidden; text-overflow:ellipsis}
.spacer{flex:0 1 0}
.clock{font-family:var(--mono); font-size:13px; color:var(--ink-2);
  background:var(--surface-2); border:1px solid var(--line);
  padding:5px 10px; border-radius:999px; white-space:nowrap}
.chip{
  display:inline-flex; align-items:center; gap:7px; padding:5px 12px 5px 9px;
  border-radius:999px; font-size:12.5px; font-weight:600; white-space:nowrap;
  border:1px solid transparent;
}
.chip .glyph{font-family:var(--mono); font-size:12px; line-height:1}
.chip.good{background:var(--good-bg); color:var(--good); border-color:var(--good)}
.chip.watch{background:var(--watch-bg); color:var(--watch); border-color:var(--watch)}
.chip.breach{background:var(--breach-bg); color:var(--breach); border-color:var(--breach)}
.chip.idle{background:var(--idle-bg); color:var(--ink-2); border-color:var(--line)}
button{
  font:inherit; font-size:12.5px; white-space:nowrap; font-weight:560; color:var(--ink);
  background:var(--surface-2); border:1px solid var(--line);
  border-radius:var(--radius-s); padding:6px 11px; cursor:pointer;
  transition:background .12s ease, border-color .12s ease, transform .06s ease;
}
button:hover{background:var(--raised); border-color:var(--ink-3)}
button:active{transform:translateY(1px)}
button:focus-visible{outline:2px solid var(--s1); outline-offset:2px}
button[disabled]{opacity:.45; cursor:not-allowed}
button.primary{background:var(--s1); border-color:var(--s1); color:#fff}
:root[data-theme="light"] button.primary{color:#fff}
button.primary:hover{filter:brightness(1.08)}
button.danger{color:var(--breach); border-color:var(--breach)}
button.danger:hover{background:var(--breach-bg)}
.seg{display:inline-flex; border:1px solid var(--line); border-radius:var(--radius-s);
  overflow:hidden; background:var(--surface-2)}
.seg button{border:0; border-radius:0; background:transparent; padding:6px 12px}
.seg button[aria-pressed="true"]{background:var(--s1); color:#fff}

/* ---------------- panels ---------------- */
.panel{
  background:var(--surface); border:1px solid var(--line);
  border-radius:var(--radius); box-shadow:var(--shadow); overflow:hidden;
}
.panel > h2{
  margin:0; padding:13px 18px 11px; font-size:12px; font-weight:700;
  letter-spacing:.08em; text-transform:uppercase; color:var(--ink-3);
  border-bottom:1px solid var(--line-soft);
  display:flex; align-items:center; gap:10px;
}
.panel > h2 .note{text-transform:none; letter-spacing:0; font-weight:450;
  font-size:12px; color:var(--ink-3)}
.panel .body{padding:16px 18px}
.grid{display:grid; gap:16px; margin-bottom:16px}
.g-hero{grid-template-columns:repeat(3,1fr)}
.g-main{grid-template-columns:minmax(0,2.05fr) minmax(330px,1fr)}
.g-split{grid-template-columns:minmax(0,1fr) minmax(0,1fr)}

/* ---------------- stat tiles ---------------- */
.tile{
  background:var(--surface); border:1px solid var(--line); border-radius:var(--radius);
  padding:14px 16px 13px; box-shadow:var(--shadow); position:relative; overflow:hidden;
}
.tile::before{content:""; position:absolute; left:0; top:0; bottom:0; width:3px;
  background:var(--idle)}
.tile[data-health="good"]::before{background:var(--good)}
.tile[data-health="watch"]::before{background:var(--watch)}
.tile[data-health="breach"]::before{background:var(--breach)}
.tile .cap{font-size:12px; color:var(--ink-3); margin-bottom:6px}
.tile .val{display:flex; align-items:baseline; gap:6px}
.tile .val b{font-family:var(--mono); font-variant-numeric:tabular-nums;
  font-size:30px; font-weight:600; letter-spacing:-.02em; line-height:1.05}
.tile .val span{font-size:13px; color:var(--ink-2)}
.tile .foot{margin-top:7px; font-size:12px; color:var(--ink-2);
  display:flex; align-items:center; gap:6px}
.dot{width:8px; height:8px; border-radius:50%; background:var(--idle); flex:none}
.dot.good{background:var(--good)} .dot.watch{background:var(--watch)}
.dot.breach{background:var(--breach)}
</style>
<style>
/* ---------------- schematic ---------------- */
#flow{width:100%; height:auto; display:block}
#flow text{font-family:var(--sans); fill:var(--ink)}
.sv-box{fill:var(--surface-2); stroke:var(--line); stroke-width:1}
.sv-stage{fill:var(--raised); stroke:var(--line); stroke-width:1}
.sv-stage.alert{stroke:var(--breach); stroke-width:1.6}
.sv-stage.warn{stroke:var(--watch); stroke-width:1.6}
.sv-title{font-size:12.5px; font-weight:640; fill:var(--ink)}
.sv-sub{font-size:10.5px; fill:var(--ink-3)}
.sv-k{font-size:10.5px; fill:var(--ink-3)}
.sv-v{font-size:12px; font-weight:600; fill:var(--ink);
  font-family:var(--mono); font-variant-numeric:tabular-nums}
.sv-pipe{stroke:var(--water-soft); stroke-width:9; fill:none; stroke-linecap:round}
.sv-flow{stroke:var(--water); stroke-width:2.4; fill:none; stroke-linecap:round;
  stroke-dasharray:7 13; animation:drift 1.5s linear infinite}
@keyframes drift{to{stroke-dashoffset:-20}}
.sv-wire{stroke:var(--line); stroke-width:1.2; fill:none}
.sv-guard{fill:var(--good-bg); stroke:var(--good); stroke-width:1.4}
.sv-guard.off{fill:var(--watch-bg); stroke:var(--watch); stroke-dasharray:5 4}
.sv-guard-t{font-size:12.5px; font-weight:700; fill:var(--good)}
.sv-guard.off + .sv-guard-t, .sv-guard-t.off{fill:var(--watch)}
.sv-legend{font-size:10.5px; fill:var(--ink-3)}
@media (prefers-reduced-motion:reduce){ .sv-flow{animation:none} }

/* ---------------- meter list ---------------- */
.meters{display:flex; flex-direction:column}
.meter{display:grid; grid-template-columns:minmax(150px,1.25fr) minmax(130px,2fr) 96px 74px;
  gap:12px; align-items:center; padding:9px 18px; border-bottom:1px solid var(--line-soft)}
.meter:last-child{border-bottom:0}
.meter:hover{background:var(--surface-2)}
.meter .nm{font-size:13px; min-width:0}
.meter .nm b{font-weight:550; display:block; overflow:hidden;
  text-overflow:ellipsis; white-space:nowrap}
.meter .nm i{font-style:normal; color:var(--ink-3); font-size:11.5px;
  display:block; overflow:hidden; text-overflow:ellipsis; white-space:nowrap}
.track{position:relative; height:9px; border-radius:5px; background:var(--surface-2);
  border:1px solid var(--line-soft); overflow:visible}
.track .fill{position:absolute; inset:0 auto 0 0; border-radius:4px; background:var(--idle);
  transition:width .35s cubic-bezier(.4,0,.2,1), background .25s linear}
.track .fill.good{background:var(--good)} .track .fill.watch{background:var(--watch)}
.track .fill.breach{background:var(--breach)}
.track .mk{position:absolute; top:-3px; bottom:-3px; width:2px; background:var(--ink-3);
  opacity:.65; border-radius:1px}
.track .mk.hard{background:var(--breach); opacity:.9}
.meter .fig{text-align:right; font-family:var(--mono);
  font-variant-numeric:tabular-nums; font-size:13.5px; font-weight:600;
  white-space:nowrap}
.meter .fig em{font-style:normal; font-weight:400; color:var(--ink-3);
  font-size:11px; margin-left:3px}
.meter .st{justify-self:end}
.meter .st .chip{padding:3px 9px; font-size:11px}

/* ---------------- charts ---------------- */
.charts{display:grid; grid-template-columns:1fr; gap:15px; padding:16px 18px}
.chart{min-width:0}
.chart .hd{display:flex; align-items:baseline; justify-content:space-between;
  gap:8px; margin-bottom:5px}
.chart .hd b{font-size:12.5px; font-weight:600}
.chart .hd span{font-family:var(--mono); font-variant-numeric:tabular-nums;
  font-size:12.5px; color:var(--ink-2)}
.chart canvas{width:100%; height:128px; display:block}
.chart .lg{margin-top:4px; font-size:11px; color:var(--ink-3)}

/* ---------------- narration ---------------- */
#feed{overflow-y:auto; padding:6px 0}
.ln{display:grid; grid-template-columns:20px 1fr; gap:10px;
  padding:9px 18px 10px; border-bottom:1px solid var(--line-soft)}
.ln:last-child{border-bottom:0}
.ln .ic{width:20px; height:20px; border-radius:6px; display:grid; place-items:center;
  font-family:var(--mono); font-size:11px; font-weight:700; margin-top:1px;
  background:var(--idle-bg); color:var(--ink-2); border:1px solid var(--line)}
.ln.good .ic{background:var(--good-bg); color:var(--good); border-color:var(--good)}
.ln.watch .ic{background:var(--watch-bg); color:var(--watch); border-color:var(--watch)}
.ln.breach .ic{background:var(--breach-bg); color:var(--breach); border-color:var(--breach)}
.ln h4{margin:0 0 2px; font-size:13px; font-weight:600; line-height:1.4}
.ln p{margin:0; font-size:12.5px; color:var(--ink-2); line-height:1.5}
.ln.pass{padding-top:6px; padding-bottom:7px}
.ln.pass h4{font-weight:450; font-size:12.5px; color:var(--ink-2)}
.ln.pass .ic{background:transparent; border-color:var(--line-soft); color:var(--ink-3)}
.ln time{display:block; margin-top:4px; font-family:var(--mono); font-size:10.5px;
  color:var(--ink-3)}
.ln.fresh{animation:slide .3s ease both}
@keyframes slide{from{opacity:0; transform:translateY(-5px)}}
@media (prefers-reduced-motion:reduce){ .ln.fresh{animation:none} }

/* ---------------- attacks ---------------- */
.atk{display:grid; grid-template-columns:repeat(auto-fill,minmax(282px,1fr));
  gap:12px; padding:16px 18px}
.card{background:var(--surface-2); border:1px solid var(--line);
  border-radius:var(--radius-s); padding:13px 14px; display:flex;
  flex-direction:column; gap:8px}
.card.live{border-color:var(--breach); background:var(--breach-bg)}
.card h3{margin:0; font-size:13.5px; font-weight:640}
.card p{margin:0; font-size:12px; color:var(--ink-2); line-height:1.5; flex:1}
.card .from{font-size:11px; color:var(--ink-3); font-family:var(--mono)}
.card button{align-self:flex-start}

/* ---------------- network ---------------- */
.zones{display:grid; grid-template-columns:repeat(auto-fill,minmax(236px,1fr));
  gap:12px; padding:16px 18px}
.zone{border:1px solid var(--line); border-radius:var(--radius-s);
  background:var(--surface-2); padding:11px 13px}
.zone h4{margin:0 0 2px; font-size:12.5px; font-weight:640;
  display:flex; justify-content:space-between; gap:8px; align-items:baseline}
.zone h4 em{font-style:normal; font-family:var(--mono); font-size:10.5px;
  color:var(--ink-3)}
.zone > p{margin:0 0 8px; font-size:11.5px; color:var(--ink-3); line-height:1.45}
.dev{display:flex; align-items:center; gap:7px; padding:3px 0; font-size:11.5px}
.dev code{font-family:var(--mono); font-size:11px; color:var(--ink-2)}
.dev .role{color:var(--ink-3); margin-left:auto; font-size:10.5px}
.conduits{padding:0 18px 16px; display:flex; flex-direction:column; gap:6px}
.cd{display:flex; align-items:center; gap:9px; font-size:12px;
  padding:7px 11px; border-radius:var(--radius-s); background:var(--surface-2);
  border:1px solid var(--line)}
.cd.guarded{border-color:var(--good); background:var(--good-bg)}
.cd code{font-family:var(--mono); font-size:11px}
.cd .why{color:var(--ink-3); font-size:11.5px; margin-left:auto; text-align:right}

.foot-note{margin-top:14px; font-size:11.5px; color:var(--ink-3); line-height:1.6;
  max-width:92ch}
.counts{display:flex; gap:26px; flex-wrap:wrap; padding:13px 18px 15px;
  border-top:1px solid var(--line-soft); margin-top:auto}
.counts div{font-size:12px; color:var(--ink-3)}
.counts b{display:block; font-family:var(--mono); font-size:19px; font-weight:600;
  color:var(--ink); line-height:1.25}
@media (max-width:1180px){
  .g-hero{grid-template-columns:repeat(2,1fr)}
  .g-main,.g-split{grid-template-columns:1fr}
  .charts{grid-template-columns:1fr}
}
@media (max-width:640px){
  .wrap{padding:12px 14px 40px}
  .g-hero{grid-template-columns:1fr}
  .meter{grid-template-columns:1fr 70px; row-gap:6px}
  .meter .track{grid-column:1/-1}
}
</style>
</head>
<body>
<div class="wrap">

<header class="top">
  <div class="brand">
    <h1>Riverside water treatment works</h1>
    <span class="sub" id="site-sub">river intake to the mains, guarded by OTGuard</span>
  </div>
  <div class="spacer"></div>
  <span class="chip idle" id="plant-chip"><span class="glyph">&#9679;</span><span id="plant-chip-t">starting</span></span>
  <span class="clock" id="clock">00:00</span>
  <span class="clock" id="speed">&times;1</span>
  <div class="seg" role="group" aria-label="Guard mode">
    <button id="mode-on" aria-pressed="true">Enforcing</button>
    <button id="mode-off" aria-pressed="false">Watch only</button>
  </div>
  <button id="ack">Acknowledge</button>
  <button id="theme" title="Switch between the dark and light screen">Light</button>
  <button id="reset" class="danger">Reset works</button>
</header>

<p id="summary" style="margin:0 0 16px; font-size:14.5px; color:var(--ink-2); line-height:1.55"></p>

<div class="grid g-hero" id="hero"></div>

<div class="grid g-main">
  <section class="panel" style="display:flex; flex-direction:column">
    <h2>The process <span class="note">water left to right; commands come down from the top and cross the guard</span></h2>
    <div class="body" style="padding:10px 14px 4px">
      <svg id="flow" viewBox="0 0 1400 440" role="img"
           aria-label="Schematic of the treatment works with live values at each stage"></svg>
    </div>
    <div class="counts" id="counts"></div>
  </section>
  <section class="panel" style="display:flex; flex-direction:column">
    <h2>What is happening <span class="note">newest first</span></h2>
    <div id="feed" style="flex:1 1 0; min-height:280px"></div>
  </section>
</div>

<div class="grid g-split">
  <section class="panel">
    <h2>Every measurement, against its own limit</h2>
    <div class="meters" id="meters"></div>
  </section>
  <section class="panel">
    <h2>Recent history <span class="note">shaded band is the allowed range</span></h2>
    <div class="charts" id="charts"></div>
  </section>
</div>

<section class="panel" style="margin-bottom:16px">
  <h2>Interfere with the plant
      <span class="note">each one is a real incident's shape; the guard is on
      unless you switch it off</span></h2>
  <div class="atk" id="attacks"></div>
</section>

<section class="panel">
  <h2>The network <span class="note">zones and conduits, Purdue levels in the corner</span></h2>
  <div class="zones" id="zones"></div>
  <div class="conduits" id="conduits"></div>
</section>

<p class="foot-note" id="honesty"></p>
</div>
<script>
"use strict";
/* ================================================================== *
 * State
 * ================================================================== */
var SCEN = null, METRICS = {}, LASTSEQ = 0, ENFORCING = true;
var HIST = {}, HIST_MAX = 150;
var STAGE_AT = {};          /* stage -> {x, y, w, h} in SVG units          */
var SRC_AT = {};            /* source key -> {x, y}                        */
var GUARD_Y = 115;
var CHART_KEYS = ["chlorine_residual", "filtered_turbidity",
                  "clearwell_level", "pressure"];
var GLYPH = {good:"✓", watch:"!", breach:"✕", info:"·"};

var $ = function (id) { return document.getElementById(id); };
function el(tag, cls, text) {
  var n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined && text !== null) n.textContent = text;
  return n;
}
function svg(tag, attrs) {
  var n = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (var k in attrs) { if (attrs[k] !== undefined) n.setAttribute(k, attrs[k]); }
  return n;
}
function clock(t) {
  var s = Math.max(0, Math.floor(t));
  var h = Math.floor(s / 3600), m = Math.floor(s / 60) % 60;
  var ss = ("0" + (s % 60)).slice(-2);
  return (h ? h + ":" + ("0" + m).slice(-2) : m) + ":" + ss;
}

/* ================================================================== *
 * Controls
 * ================================================================== */
function send(action, params) {
  var q = "";
  for (var k in params) {
    q += (q ? "&" : "?") + encodeURIComponent(k) + "=" + encodeURIComponent(params[k]);
  }
  return fetch("/api/" + action + q).then(function (r) { return r.json(); })
    .catch(function () { return {ok: false}; });
}
function wireControls() {
  $("mode-on").onclick = function () { send("enforce", {value: "true"}); };
  $("mode-off").onclick = function () { send("enforce", {value: "false"}); };
  $("ack").onclick = function () { send("ack", {}); };
  $("reset").onclick = function () { HIST = {}; send("reset", {}); };
  $("theme").onclick = function () {
    var r = document.documentElement;
    var next = r.getAttribute("data-theme") === "dark" ? "light" : "dark";
    r.setAttribute("data-theme", next);
    $("theme").textContent = next === "dark" ? "Light" : "Dark";
    try { localStorage.setItem("otguard-theme", next); } catch (e) {}
    drawCharts();
  };
  try {
    var saved = localStorage.getItem("otguard-theme");
    if (saved) {
      document.documentElement.setAttribute("data-theme", saved);
      $("theme").textContent = saved === "dark" ? "Light" : "Dark";
    }
  } catch (e) {}
}
function setMode(on) {
  ENFORCING = on;
  $("mode-on").setAttribute("aria-pressed", on ? "true" : "false");
  $("mode-off").setAttribute("aria-pressed", on ? "false" : "true");
}

/* ================================================================== *
 * The schematic
 * ================================================================== */
var SUPERVISORY = [
  {key: "scada",       label: "SCADA-01", sub: "control room"},
  {key: "hmi",         label: "HMI-01",   sub: "operator screen"},
  {key: "engineering", label: "ENG-01",   sub: "engineering laptop"},
  {key: "historian",   label: "HIST-01",  sub: "historian, reads only"}
];
var CONTROLLERS = [
  {name: "PLC-INTAKE",    from: 0, to: 0},
  {name: "PLC-CHEM",      from: 1, to: 2},
  {name: "PLC-FILTER",    from: 3, to: 4},
  {name: "PLC-DISINFECT", from: 5, to: 6},
  {name: "PLC-DIST",      from: 7, to: 7}
];

function buildFlow(stages) {
  var s = $("flow");
  while (s.firstChild) { s.removeChild(s.firstChild); }
  var L = 20, R = 1380, W = R - L, n = stages.length;
  var gap = 10, bw = (W - gap * (n - 1)) / n;
  var stageY = 238, stageH = 174;

  /* supervisory row */
  var sw = 150, sx = L;
  SUPERVISORY.forEach(function (d) {
    s.appendChild(svg("rect", {x: sx, y: 14, width: sw, height: 44, rx: 7, "class": "sv-box"}));
    s.appendChild(text(sx + 11, 33, d.label, "sv-title"));
    s.appendChild(text(sx + 11, 48, d.sub, "sv-sub"));
    SRC_AT[d.key] = {x: sx + sw / 2, y: 58};
    s.appendChild(svg("path", {
      d: "M" + (sx + sw / 2) + " 58 V" + (d.reads ? 80 : 92),
      "class": "sv-wire",
      "stroke-dasharray": d.reads ? "4 4" : undefined
    }));
    if (d.reads) {
      s.appendChild(text(sx + sw / 2, 89, "reads, never writes", "sv-legend", "middle"));
    }
    sx += sw + 10;
  });
  /* the one box that is outside the plant's own network */
  var jx = R - 212;
  s.appendChild(svg("rect", {x: jx, y: 14, width: 212, height: 44, rx: 7, "class": "sv-box",
                             "stroke-dasharray": "5 4"}));
  s.appendChild(text(jx + 11, 33, "JUMP-01", "sv-title"));
  s.appendChild(text(jx + 11, 48, "vendor support, enterprise network", "sv-sub"));
  SRC_AT.vendor = {x: jx + 106, y: 58};
  s.appendChild(svg("path", {d: "M" + (jx + 106) + " 58 V92", "class": "sv-wire",
                             "stroke-dasharray": "5 4"}));

  /* the guard */
  var g = svg("rect", {x: L, y: 92, width: W, height: 46, rx: 9, "class": "sv-guard", id: "guard-bar"});
  s.appendChild(g);
  var gt = text(L + 16, 113, "OTGuard", "sv-guard-t"); gt.setAttribute("id", "guard-t");
  s.appendChild(gt);
  var gs = text(L + 16, 128, "every command below this line is checked against the physics",
                "sv-sub"); gs.setAttribute("id", "guard-s");
  s.appendChild(gs);
  s.appendChild(svg("g", {id: "fly"}));

  /* controllers */
  CONTROLLERS.forEach(function (c) {
    var x0 = L + c.from * (bw + gap);
    var x1 = L + c.to * (bw + gap) + bw;
    var cw = x1 - x0;
    s.appendChild(svg("rect", {x: x0, y: 170, width: cw, height: 40, rx: 7, "class": "sv-box"}));
    s.appendChild(text(x0 + cw / 2, 189, c.name, "sv-title", "middle"));
    s.appendChild(text(x0 + cw / 2, 203, "controller", "sv-sub", "middle"));
    s.appendChild(svg("path", {d: "M" + (x0 + cw / 2) + " 138 V170", "class": "sv-wire"}));
    s.appendChild(svg("path", {d: "M" + (x0 + cw / 2) + " 210 V" + stageY, "class": "sv-wire"}));
  });

  /* stages, and the water between them */
  stages.forEach(function (st, i) {
    var x = L + i * (bw + gap);
    if (i > 0) {
      s.appendChild(svg("path", {d: "M" + (x - gap - 1) + " 325 h" + (gap + 2), "class": "sv-pipe"}));
      s.appendChild(svg("path", {d: "M" + (x - gap - 1) + " 325 h" + (gap + 2), "class": "sv-flow"}));
    }
    var r = svg("rect", {x: x, y: stageY, width: bw, height: stageH, rx: 9,
                         "class": "sv-stage", id: "stg-" + st.stage});
    s.appendChild(r);
    s.appendChild(text(x + 11, stageY + 21, String(i + 1) + ". " + st.label, "sv-title"));
    var vals = svg("g", {id: "sv-" + st.stage});
    s.appendChild(vals);
    STAGE_AT[st.stage] = {x: x, y: stageY, w: bw, h: stageH};
  });

  /* water in and water out */
  s.appendChild(svg("path", {d: "M2 325 h20", "class": "sv-pipe"}));
  s.appendChild(svg("path", {d: "M" + R + " 325 h20", "class": "sv-pipe"}));
  s.appendChild(text(L, 432, "▸ river", "sv-legend"));
  s.appendChild(text(R, 432, "to the town ▸", "sv-legend", "end"));
}
function text(x, y, str, cls, anchor) {
  var t = svg("text", {x: x, y: y, "class": cls, "text-anchor": anchor});
  t.textContent = str;
  return t;
}
/* ================================================================== *
 * Scenario: everything the page only needs told once
 * ================================================================== */
function renderScenario(p) {
  SCEN = p;
  METRICS = {};
  p.metrics.forEach(function (m) { METRICS[m.key] = m; });
  $("site-sub").textContent = p.summary;
  $("speed").textContent = "×" + p.speed;
  buildFlow(p.stages);
  buildHero(p);
  buildMeters(p);
  buildCharts(p);
  buildAttacks(p);
  buildNetwork(p.topology);
  $("honesty").textContent =
    "The twenty-two devices, six zones and six conduits above are a model of the "
    + "works' network, not twenty-two listening servers; the tank demonstration is "
    + "the one that runs real Modbus over real sockets. What is not modelled is the "
    + "guard. Every verdict on this page is the rule set reaching a decision about "
    + "the water the simulation is actually moving, and the time on the clock runs "
    + "at ×" + p.speed + " so that a contact tank that takes forty minutes to "
    + "fill can be watched.";
}

function buildHero(p) {
  var box = $("hero"); box.innerHTML = "";
  p.metrics.filter(function (m) { return m.headline; }).forEach(function (m) {
    var t = el("div", "tile"); t.id = "tile-" + m.key;
    t.setAttribute("data-health", "idle");
    t.appendChild(el("div", "cap", m.label));
    var v = el("div", "val");
    var b = el("b", null, "—"); b.id = "tv-" + m.key;
    v.appendChild(b); v.appendChild(el("span", null, m.unit));
    t.appendChild(v);
    var f = el("div", "foot");
    var d = el("span", "dot"); d.id = "td-" + m.key;
    var s = el("span", null, "waiting"); s.id = "ts-" + m.key;
    f.appendChild(d); f.appendChild(s);
    t.appendChild(f);
    t.title = m.plain + " " + m.why;
    box.appendChild(t);
  });
}

function buildMeters(p) {
  var box = $("meters"); box.innerHTML = "";
  p.metrics.forEach(function (m) {
    var row = el("div", "meter"); row.id = "mr-" + m.key;
    var nm = el("div", "nm");
    nm.appendChild(el("b", null, m.label));
    nm.appendChild(el("i", null, m.plain));
    row.appendChild(nm);
    var tr = el("div", "track");
    var fl = el("div", "fill"); fl.id = "mf-" + m.key;
    tr.appendChild(fl);
    row.appendChild(tr);
    var fig = el("div", "fig");
    var fv = el("span", null, "—"); fv.id = "mv-" + m.key;
    fig.appendChild(fv); fig.appendChild(el("em", null, m.unit));
    row.appendChild(fig);
    var st = el("div", "st");
    var chip = el("span", "chip idle"); chip.id = "mc-" + m.key;
    chip.appendChild(el("span", "glyph", "·"));
    chip.appendChild(el("span", null, "—"));
    st.appendChild(chip);
    row.appendChild(st);
    row.title = m.why;
    box.appendChild(row);
  });
}

function buildCharts(p) {
  var box = $("charts"); box.innerHTML = "";
  CHART_KEYS.forEach(function (key) {
    var m = METRICS[key]; if (!m) { return; }
    var c = el("div", "chart");
    var hd = el("div", "hd");
    hd.appendChild(el("b", null, m.label));
    var cur = el("span", null, "—"); cur.id = "cv-" + key;
    hd.appendChild(cur);
    c.appendChild(hd);
    var cv = document.createElement("canvas"); cv.id = "cc-" + key;
    c.appendChild(cv);
    var low = m.limit_low, high = m.limit_high, note;
    if (low !== null && high !== null) { note = "allowed " + low + " to " + high + " " + m.unit; }
    else if (high !== null) { note = "must stay under " + high + " " + m.unit; }
    else if (low !== null) { note = "must stay above " + low + " " + m.unit; }
    else { note = m.unit; }
    c.appendChild(el("div", "lg", note));
    box.appendChild(c);
  });
}

function buildAttacks(p) {
  var box = $("attacks"); box.innerHTML = "";
  p.attacks.forEach(function (a) {
    var c = el("div", "card"); c.id = "atk-" + a.name;
    c.appendChild(el("h3", null, a.title));
    c.appendChild(el("p", null, a.story));
    c.appendChild(el("div", "from", "from " + a.source + " — " + a.zone + " zone"));
    var b = el("button", "primary", "Run this");
    b.onclick = function () { send("attack", {name: a.name}); };
    c.appendChild(b);
    box.appendChild(c);
  });
  var stop = el("div", "card");
  stop.appendChild(el("h3", null, "Stop"));
  stop.appendChild(el("p", null,
    "Halt whatever is running and give the plant's own control back. The works "
    + "recovers on its own if nothing was permanently moved."));
  var sb = el("button", null, "Stop the attack");
  sb.onclick = function () { send("stop", {}); };
  stop.appendChild(sb);
  box.appendChild(stop);
}

function buildNetwork(topo) {
  var zb = $("zones"); zb.innerHTML = "";
  topo.zones.forEach(function (z) {
    var d = el("div", "zone");
    var h = el("h4", null, z.name);
    h.appendChild(el("em", null, z.level));
    d.appendChild(h);
    d.appendChild(el("p", null, z.purpose));
    topo.devices.filter(function (v) { return v.zone === z.name; }).forEach(function (v) {
      var r = el("div", "dev");
      var dot = el("span", "dot " + (v.critical ? "good" : ""));
      r.appendChild(dot);
      r.appendChild(el("code", null, v.name));
      r.appendChild(el("span", "role", v.kind));
      r.title = v.description + " (" + v.address + ", " + v.protocol + ")";
      d.appendChild(r);
    });
    zb.appendChild(d);
  });
  var cb = $("conduits"); cb.innerHTML = "";
  topo.conduits.forEach(function (c) {
    var r = el("div", "cd" + (c.guarded ? " guarded" : ""));
    r.appendChild(el("span", "glyph", c.guarded ? "✓" : "·"));
    r.appendChild(el("code", null, c.source + " → " + c.target));
    r.appendChild(el("span", null, c.protocol));
    r.appendChild(el("span", "why", c.guarded ? "OTGuard sits here" : c.note));
    cb.appendChild(r);
  });
}
/* ================================================================== *
 * State: the part that changes every second
 * ================================================================== */
function renderState(p) {
  setMode(p.enforcing);
  $("summary").textContent = p.summary;

  var bar = $("guard-bar"), gt = $("guard-t"), gs = $("guard-s");
  if (bar) {
    bar.setAttribute("class", "sv-guard" + (p.enforcing ? "" : " off"));
    gt.setAttribute("class", "sv-guard-t" + (p.enforcing ? "" : " off"));
    gs.textContent = p.enforcing
      ? "every command below this line is checked against the physics"
      : "watching only — commands are judged and let through anyway";
  }

  var worst = "good", any = false;
  p.metrics.forEach(function (m) {
    paintMetric(m);
    if (m.health === "breach") { worst = "breach"; }
    else if (m.health === "watch" && worst !== "breach") { worst = "watch"; }
    any = true;
    if (CHART_KEYS.indexOf(m.key) >= 0) { push(m.key, p.t, m.value); }
  });
  if (p.harms && p.harms.length) { worst = "breach"; }
  if (any) { setChip($("plant-chip"), worst, plantWord(worst, p)); }
  $("clock").textContent = clock(p.t);

  (p.stages || []).forEach(paintStage);
  drawCharts();
  paintCounts(p.counters, p);
  (p.attack ? markAttack(p.attack) : markAttack(null));
}

function plantWord(worst, p) {
  if (p.harms && p.harms.length) { return "water leaving is not safe"; }
  if (worst === "breach") { return "a limit is broken"; }
  if (worst === "watch") { return "drifting"; }
  return p.enforcing ? "compliant, guard enforcing" : "compliant, guard watching only";
}
function setChip(node, health, word) {
  node.className = "chip " + health;
  node.firstChild.textContent = GLYPH[health] || GLYPH.info;
  node.lastChild.textContent = word;
}

function paintMetric(m) {
  var tv = $("tv-" + m.key);
  if (tv) {
    tv.textContent = m.shown;
    $("tile-" + m.key).setAttribute("data-health", m.health);
    $("td-" + m.key).className = "dot " + m.health;
    $("ts-" + m.key).textContent = m.health_label;
  }
  var fill = $("mf-" + m.key);
  if (!fill) { return; }
  fill.className = "fill " + m.health;
  fill.style.width = Math.max(1.2, Math.min(100, m.fraction * 100)).toFixed(1) + "%";
  $("mv-" + m.key).textContent = m.shown;
  var chip = $("mc-" + m.key);
  setChip(chip, m.health, m.health_label);
  var track = fill.parentNode;
  if (!track.dataset.marked) {
    track.dataset.marked = "1";
    (m.marks || []).forEach(function (mk) {
      var hard = mk.name === "min" || mk.name === "max";
      var d = el("div", "mk" + (hard ? " hard" : ""));
      d.style.left = Math.max(0, Math.min(100, mk.at * 100)).toFixed(2) + "%";
      d.title = mk.name + " " + m.unit;
      track.appendChild(d);
    });
  }
}

function paintStage(s) {
  var g = $("sv-" + s.stage), geo = STAGE_AT[s.stage];
  if (!g || !geo) { return; }
  while (g.firstChild) { g.removeChild(g.firstChild); }
  var y = geo.y + 48;
  (s.values || []).forEach(function (v) {
    g.appendChild(text(geo.x + 11, y, v.name, "sv-k"));
    g.appendChild(text(geo.x + 11, y + 17, v.shown, "sv-v"));
    y += 40;
  });
  if (s.controller) {
    g.appendChild(text(geo.x + 11, geo.y + geo.h - 10, s.controller, "sv-legend"));
  }
}

function paintCounts(c, p) {
  if (!c) { return; }
  var box = $("counts"); box.innerHTML = "";
  [["Commands checked", c.inspected],
   ["Refused", c.blocked],
   ["Protective actions", c.trips],
   ["Attacks run", c.attacks]].forEach(function (pair) {
    var d = el("div");
    d.appendChild(el("b", null, String(pair[1])));
    d.appendChild(document.createTextNode(pair[0]));
    box.appendChild(d);
  });
}

function markAttack(name) {
  var cards = document.querySelectorAll(".card");
  for (var i = 0; i < cards.length; i++) {
    cards[i].className = "card" + (cards[i].id === "atk-" + name ? " live" : "");
  }
}

/* ================================================================== *
 * Charts
 * ================================================================== */
function push(key, t, v) {
  var a = HIST[key] || (HIST[key] = []);
  a.push([t, v]);
  if (a.length > HIST_MAX) { a.shift(); }
}
function css(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}
function drawCharts() {
  CHART_KEYS.forEach(function (key) { drawChart(key); });
}
function drawChart(key) {
  var cv = $("cc-" + key), m = METRICS[key], data = HIST[key];
  if (!cv || !m || !data || data.length < 2) { return; }
  var dpr = window.devicePixelRatio || 1;
  var w = cv.clientWidth, h = cv.clientHeight;
  if (!w || !h) { return; }
  if (cv.width !== Math.round(w * dpr)) {
    cv.width = Math.round(w * dpr); cv.height = Math.round(h * dpr);
  }
  var g = cv.getContext("2d");
  g.setTransform(dpr, 0, 0, dpr, 0, 0);
  g.clearRect(0, 0, w, h);

  /* Scale to the data, then reach out to a limit only when it is close
     enough to be worth seeing. Forcing both limits into view flattens a
     steady trace onto the floor of its own band, which is the one shape a
     process chart must not have: it reads as a plant doing nothing when it
     is a plant holding its value. The caption under each chart states the
     range in full, so an out-of-view limit is never unstated. */
  var vals = data.map(function (d) { return d[1]; });
  var dmin = Math.min.apply(null, vals), dmax = Math.max.apply(null, vals);
  var span = dmax - dmin;
  var pad = span > 1e-9 ? span * 0.45 : (Math.abs(dmax) * 0.12 || 0.5);
  var lo = dmin - pad, hi = dmax + pad;
  var reach = Math.max(pad * 2.2, span * 1.6);
  if (m.limit_low !== null && m.limit_low > lo - reach) {
    lo = Math.min(lo, m.limit_low - pad * 0.35);
  }
  if (m.limit_high !== null && m.limit_high < hi + reach) {
    hi = Math.max(hi, m.limit_high + pad * 0.35);
  }
  lo = Math.max(lo, m.scale_min); hi = Math.min(hi, m.scale_max);
  if (hi - lo < 1e-9) { hi = lo + Math.abs(lo || 1) * 0.2 + 0.1; }

  var PAD = 4, iw = w - PAD * 2, ih = h - PAD * 2;
  function Y(v) { return PAD + ih - ((v - lo) / (hi - lo)) * ih; }
  function X(i) { return PAD + (i / (data.length - 1)) * iw; }

  /* the allowed band, drawn first so the line sits on top of it */
  var lowOn = m.limit_low !== null && m.limit_low > lo && m.limit_low < hi;
  var highOn = m.limit_high !== null && m.limit_high > lo && m.limit_high < hi;
  if (lowOn || highOn) {
    var bl = lowOn ? m.limit_low : lo, bh = highOn ? m.limit_high : hi;
    g.fillStyle = css("--good-bg");
    g.fillRect(PAD, Y(bh), iw, Y(bl) - Y(bh));
  }
  [[m.limit_low, "low"], [m.limit_high, "high"]].forEach(function (pair) {
    if (pair[0] === null || pair[0] < lo || pair[0] > hi) { return; }
    g.strokeStyle = css("--breach"); g.lineWidth = 1;
    g.setLineDash([3, 3]); g.globalAlpha = 0.75;
    g.beginPath(); g.moveTo(PAD, Y(pair[0])); g.lineTo(w - PAD, Y(pair[0])); g.stroke();
    g.setLineDash([]); g.globalAlpha = 1;
  });

  g.strokeStyle = css("--s1"); g.lineWidth = 2;
  g.lineJoin = "round"; g.lineCap = "round";
  g.beginPath();
  data.forEach(function (d, i) {
    var x = X(i), y = Y(d[1]);
    if (i === 0) { g.moveTo(x, y); } else { g.lineTo(x, y); }
  });
  g.stroke();

  var last = data[data.length - 1];
  g.fillStyle = css("--s1");
  g.strokeStyle = css("--surface"); g.lineWidth = 2;
  g.beginPath(); g.arc(X(data.length - 1), Y(last[1]), 4.5, 0, 6.2832);
  g.fill(); g.stroke();
  $("cv-" + key).textContent = fmt(last[1], m);
}
function fmt(v, m) {
  var span = (m.scale_max - m.scale_min);
  var dp = span >= 500 ? 0 : span >= 20 ? 1 : 2;
  return v.toFixed(dp) + " " + m.unit;
}
/* ================================================================== *
 * The narration column
 * ================================================================== */
var FEED_MAX = 90;
function addLine(p, t, quiet) {
  var feed = $("feed");
  var sev = p.severity || "info";
  var row = el("div", "ln " + sev + (quiet ? " pass" : "") + " fresh");
  var ic = el("div", "ic", GLYPH[sev] || GLYPH.info);
  row.appendChild(ic);
  var body = el("div");
  body.appendChild(el("h4", null, p.headline || ""));
  if (p.detail && !quiet) { body.appendChild(el("p", null, p.detail)); }
  var tm = el("time", null, clock(t));
  if (p.tag) { tm.textContent = clock(t) + "  ·  " + p.tag; }
  body.appendChild(tm);
  row.appendChild(body);
  feed.insertBefore(row, feed.firstChild);
  while (feed.childNodes.length > FEED_MAX) { feed.removeChild(feed.lastChild); }
  setTimeout(function () { row.classList.remove("fresh"); }, 320);
}

/* ================================================================== *
 * A command crossing the guard, drawn
 * ================================================================== */
function flyCommand(p) {
  var layer = $("fly");
  var from = SRC_AT[p.source] || SRC_AT.scada;
  var to = STAGE_AT[p.stage];
  if (!layer || !from || !to) { return; }
  var blocked = p.decision === "block";
  var colour = blocked ? css("--breach") : (p.decision === "alarm" ? css("--watch") : css("--s1"));
  var midX = to.x + to.w / 2;

  var dot = svg("circle", {r: 5, cx: from.x, cy: from.y, fill: colour,
                           stroke: css("--surface"), "stroke-width": 1.5});
  layer.appendChild(dot);

  /* Three legs: down to the guard, along it, then down into the stage.
     A refused command never gets past the second leg, which is the whole
     point of drawing it this way. */
  var legs = blocked
    ? [[from.x, from.y, from.x, GUARD_Y]]
    : [[from.x, from.y, from.x, GUARD_Y],
       [from.x, GUARD_Y, midX, GUARD_Y],
       [midX, GUARD_Y, midX, to.y]];
  var total = legs.reduce(function (a, l) {
    return a + Math.hypot(l[2] - l[0], l[3] - l[1]);
  }, 0);
  var speed = 460;                       /* svg units per second */
  var started = null;

  function frame(ts) {
    if (started === null) { started = ts; }
    var travelled = (ts - started) / 1000 * speed;
    if (travelled >= total) { return finish(); }
    var left = travelled;
    for (var i = 0; i < legs.length; i++) {
      var l = legs[i], len = Math.hypot(l[2] - l[0], l[3] - l[1]);
      if (left <= len) {
        var k = len ? left / len : 1;
        dot.setAttribute("cx", l[0] + (l[2] - l[0]) * k);
        dot.setAttribute("cy", l[1] + (l[3] - l[1]) * k);
        break;
      }
      left -= len;
    }
    requestAnimationFrame(frame);
  }
  function finish() {
    if (blocked) {
      dot.setAttribute("cx", from.x); dot.setAttribute("cy", GUARD_Y);
      var x = svg("path", {d: "M" + (from.x - 6) + " " + (GUARD_Y - 6)
                              + " l12 12 M" + (from.x + 6) + " " + (GUARD_Y - 6) + " l-12 12",
                           stroke: css("--breach"), "stroke-width": 2.4,
                           "stroke-linecap": "round", fill: "none"});
      layer.appendChild(x);
      setTimeout(function () { fade(x); }, 620);
    } else {
      pulse(to);
    }
    fade(dot);
  }
  function fade(node) {
    var o = 1;
    (function step() {
      o -= 0.09;
      if (o <= 0) { if (node.parentNode) { node.parentNode.removeChild(node); } return; }
      node.setAttribute("opacity", o.toFixed(2));
      requestAnimationFrame(step);
    })();
  }
  function pulse(geo) {
    var r = svg("rect", {x: geo.x, y: geo.y, width: geo.w, height: geo.h, rx: 9,
                         fill: "none", stroke: colour, "stroke-width": 2});
    layer.appendChild(r);
    setTimeout(function () { fade(r); }, 220);
  }
  if (window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    finish();
  } else {
    requestAnimationFrame(frame);
  }
}

/* ================================================================== *
 * The stream
 * ================================================================== */
function connect() {
  var src = new EventSource("/events?after=" + LASTSEQ);
  src.onmessage = function (ev) {
    var p;
    try { p = JSON.parse(ev.data); } catch (e) { return; }
    LASTSEQ = p.seq || LASTSEQ;
    if (p.kind === "scenario") { renderScenario(p); }
    else if (p.kind === "state") { renderState(p); }
    else if (p.kind === "note") { addLine(p, p.t); }
    else if (p.kind === "trip") { addLine(p, p.t); }
    else if (p.kind === "verdict") {
      flyCommand(p);
      addLine(p, p.t, p.decision === "allow");
    }
  };
  src.onerror = function () {
    src.close();
    setTimeout(connect, 1200);
  };
}

wireControls();
connect();
window.addEventListener("resize", drawCharts);
</script>
</body>
</html>
"""
