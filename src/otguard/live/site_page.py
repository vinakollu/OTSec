"""The storage site on a screen.

The works page draws a process: water entering at one end and leaving at the
other, with a stage for each thing done to it. This one draws a yard. Sixteen
battery units, a collection bus, a transformer, a breaker and a grid
connection, with the three instruments that each measure the same power drawn
where they actually sit in the circuit.

The instruments are the reason this page looks the way it does. On a real site
nobody can see what they are each reporting side by side, which is exactly how
two frozen readings come to outvote a live one. Here they are three boxes in a
row, each showing its own number, whether its link is still up, and whether
the guard has named it as the one that is lying.

Everything around the yard is shared with the works page through
:mod:`otguard.live.ui`, so the two cannot drift apart. No network dependency.
"""

from __future__ import annotations

from .ui import BUILD_JS, CHART_JS, CORE_CSS, HEAD_JS, PARTS_CSS, TAIL_JS

SITE_PAGE = (
    r"""<!doctype html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>OTGuard, grid storage site</title>
"""
    + CORE_CSS
    + r"""
<style>
/* ---------------- the yard ---------------- */
#yard{width:100%; height:auto; display:block}
#yard text{font-family:var(--sans); fill:var(--ink)}
.sv-box{fill:var(--surface-2); stroke:var(--line); stroke-width:1}
.sv-title{font-size:12.5px; font-weight:640; fill:var(--ink)}
.sv-sub{font-size:10.5px; fill:var(--ink-3)}
.sv-v{font-size:11.5px; font-weight:600; fill:var(--ink);
  font-family:var(--mono); font-variant-numeric:tabular-nums}
.sv-k{font-size:10px; fill:var(--ink-3)}
.sv-legend{font-size:10.5px; fill:var(--ink-3)}
.sv-wire{stroke:var(--line); stroke-width:1.2; fill:none}
.sv-guard{fill:var(--good-bg); stroke:var(--good); stroke-width:1.4}
.sv-guard.off{fill:var(--watch-bg); stroke:var(--watch); stroke-dasharray:5 4}
.sv-guard-t{font-size:12.5px; font-weight:700; fill:var(--good)}
.sv-guard-t.off{fill:var(--watch)}

/* one Megapack */
.pk{fill:var(--raised); stroke:var(--line); stroke-width:1}
.pk.good{stroke:var(--good)}
.pk.watch{stroke:var(--watch); stroke-width:1.6}
.pk.breach{stroke:var(--breach); stroke-width:2}
.pk-name{font-size:10.5px; font-weight:700; fill:var(--ink-2);
  font-family:var(--mono)}
.pk-soc-bg{fill:var(--surface)}
.pk-soc{fill:var(--s1)}
.pk-p{font-size:12px; font-weight:650; fill:var(--ink);
  font-family:var(--mono); font-variant-numeric:tabular-nums}
.pk-t{font-size:10px; fill:var(--ink-3); font-family:var(--mono)}
.pk-flag{font-size:10px; font-weight:700; font-family:var(--mono)}
.pk-flag.cold{fill:var(--watch)} .pk-flag.off{fill:var(--idle)}
.pk-flag.hot{fill:var(--breach)}

/* power path */
.bus{stroke:var(--s1); stroke-width:3; fill:none; stroke-linecap:round;
  opacity:.65}
.bus-flow{stroke:var(--s1); stroke-width:2; fill:none; stroke-dasharray:6 12;
  animation:drift 1.4s linear infinite}
@keyframes drift{to{stroke-dashoffset:-18}}
@media (prefers-reduced-motion:reduce){ .bus-flow{animation:none} }
.xfmr{fill:none; stroke:var(--ink-3); stroke-width:1.6}
.poi-box{fill:var(--surface-2); stroke:var(--line); stroke-width:1.2}
.poi-box.over{stroke:var(--breach); stroke-width:2; fill:var(--breach-bg)}
.brk{stroke:var(--ink-2); stroke-width:2.4; stroke-linecap:round}
.brk.open{stroke:var(--watch)}

/* the three instruments */
.inst{fill:var(--surface-2); stroke:var(--line); stroke-width:1.2}
.inst.live{stroke:var(--good)}
.inst.dead{stroke:var(--breach); stroke-dasharray:4 4}
.inst.suspect{stroke:var(--watch); stroke-width:1.8}
.inst-t{font-size:11px; font-weight:620; fill:var(--ink)}
.inst-v{font-size:13px; font-weight:700; fill:var(--ink);
  font-family:var(--mono); font-variant-numeric:tabular-nums}
.inst-s{font-size:10px; fill:var(--ink-3)}
</style>
"""
    + PARTS_CSS
    + r"""
</head>
<body>
<div class="wrap">

<header class="top">
  <div class="brand">
    <h1>Fern Hollow storage site</h1>
    <span class="sub" id="site-sub">sixteen battery units behind one grid connection</span>
  </div>
  <div class="spacer"></div>
  <span class="chip idle" id="plant-chip"><span class="glyph">&#9679;</span><span id="plant-chip-t">starting</span></span>
  <span class="clock" id="clock">00:00</span>
  <span class="clock" id="speed">&times;1</span>
  <div class="seg" role="group" aria-label="Guard mode">
    <button id="mode-on" aria-pressed="true">Enforcing</button>
    <button id="mode-off" aria-pressed="false">Watch only</button>
  </div>
  <div class="seg" role="group" aria-label="Dispatch">
    <button data-mw="-12">Charge</button>
    <button data-mw="0">Idle</button>
    <button data-mw="8" aria-pressed="true">Export 8</button>
    <button data-mw="18">Export 18</button>
  </div>
  <button id="theme" title="Switch between the dark and light screen">Light</button>
  <button id="reset" class="danger">Reset site</button>
</header>

<p id="summary" style="margin:0 0 16px; font-size:14.5px; color:var(--ink-2); line-height:1.55"></p>

<div class="grid g-hero" id="hero"></div>

<div class="grid g-main">
  <section class="panel" style="display:flex; flex-direction:column">
    <h2>The site
      <span class="note">power flows up from the batteries to the grid; commands
      come down from the top and cross the guard</span></h2>
    <div class="body" style="padding:10px 14px 4px">
      <svg id="yard" viewBox="0 0 1400 596" role="img"
           aria-label="Schematic of the storage site: sixteen battery units, the
                       transformer, the grid connection and the three instruments
                       measuring it"></svg>
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
  <h2>Interfere with the site
    <span class="note">two of these the guard does not win, and they say so</span></h2>
  <div class="atk" id="attacks"></div>
</section>

<p class="foot-note" id="honesty"></p>
</div>
"""
    + HEAD_JS
    + r"""
CHART_KEYS = ["p_poi", "apparent", "hottest", "measurement_spread"];
"""
    + BUILD_JS
    + r"""
/* ================================================================== *
 * The yard
 * ================================================================== */
var UNIT_AT = {};        /* device -> {x, y, w, h}                     */
var AREA_AT = {};        /* area key -> {x, y, w, h} for command dots  */
var N_PACKS = 16, PACK_MW = 1.927;

var SUPERVISORY = [
  {key: "scada",       label: "SCADA-01", sub: "site controller"},
  {key: "hmi",         label: "HMI-01",   sub: "operator screen"},
  {key: "engineering", label: "ENG-01",   sub: "engineering, via the jump server"},
  {key: "enterprise",  label: "CORP-01",  sub: "corporate network", outside: true}
];

function buildYard(p) {
  var s = $("yard");
  while (s.firstChild) { s.removeChild(s.firstChild); }
  N_PACKS = p.n_packs || 16;
  PACK_MW = p.pack_mw || 1.927;
  var L = 20, R = 1380, W = R - L;

  /* who can write, and the one that should not be able to */
  var sw = 190, sx = L;
  SUPERVISORY.forEach(function (d) {
    var x = d.outside ? R - sw : sx;
    s.appendChild(svg("rect", {x: x, y: 14, width: sw, height: 44, rx: 7,
                               "class": "sv-box",
                               "stroke-dasharray": d.outside ? "5 4" : undefined}));
    s.appendChild(text(x + 11, 33, d.label, "sv-title"));
    s.appendChild(text(x + 11, 48, d.sub, "sv-sub"));
    SRC_AT[d.key] = {x: x + sw / 2, y: 58};
    s.appendChild(svg("path", {d: "M" + (x + sw / 2) + " 58 V92", "class": "sv-wire",
                               "stroke-dasharray": d.outside ? "5 4" : undefined}));
    if (!d.outside) { sx += sw + 10; }
  });

  /* the guard */
  s.appendChild(svg("rect", {x: L, y: 92, width: W, height: 46, rx: 9,
                             "class": "sv-guard", id: "guard-bar"}));
  var gt = text(L + 16, 113, "OTGuard", "sv-guard-t"); gt.setAttribute("id", "guard-t");
  s.appendChild(gt);
  var gs = text(L + 16, 128,
                "every command below this line is checked against the physics",
                "sv-sub");
  gs.setAttribute("id", "guard-s");
  s.appendChild(gs);
  s.appendChild(svg("g", {id: "fly"}));

  /* the yard: sixteen units in two rows */
  s.appendChild(text(L, 168, N_PACKS + " battery units · "
                     + PACK_MW.toFixed(2) + " MW each", "sv-legend"));
  var cols = 8, gap = 8;
  var cw = (W - gap * (cols - 1)) / cols, ch = 84;
  for (var i = 0; i < N_PACKS; i++) {
    var col = i % cols, row = Math.floor(i / cols);
    var x = L + col * (cw + gap), y = 182 + row * (ch + 10);
    var id = "MP" + ("0" + (i + 1)).slice(-2);
    var g = svg("g", {id: "pk-" + id});
    s.appendChild(g);
    UNIT_AT[id] = {x: x, y: y, w: cw, h: ch};
  }
  AREA_AT.fleet = {x: L, y: 182, w: W, h: ch * 2 + 10};

  /* collection bus under the yard, then the transformer and the grid */
  var busY = 300 + ch;
  for (var c = 0; c < cols; c++) {
    var sx2 = L + c * (cw + gap) + cw / 2;
    s.appendChild(svg("path", {d: "M" + sx2 + " " + (182 + ch + 10 + ch)
                               + " V" + busY, "class": "bus"}));
  }
  s.appendChild(svg("path", {d: "M" + L + " " + busY + " H" + R, "class": "bus"}));
  s.appendChild(svg("path", {d: "M" + L + " " + busY + " H" + R, "class": "bus-flow"}));
  s.appendChild(text(L, busY - 8, "collection bus", "sv-legend"));
  AREA_AT.collection = {x: L, y: busY - 14, w: W, h: 28};

  /* transformer */
  var tx = 520, ty = busY + 14;
  s.appendChild(svg("path", {d: "M700 " + busY + " V" + ty, "class": "bus"}));
  s.appendChild(svg("circle", {cx: 690, cy: ty + 26, r: 20, "class": "xfmr"}));
  s.appendChild(svg("circle", {cx: 714, cy: ty + 26, r: 20, "class": "xfmr"}));
  s.appendChild(text(tx + 220, ty + 70, "transformer", "sv-legend", "middle"));
  var tl = text(tx + 220, ty + 16, "", "sv-v", "middle");
  tl.setAttribute("id", "xfmr-load");
  s.appendChild(tl);
  AREA_AT.transformer = {x: 650, y: ty, w: 110, h: 60};

  /* breaker and the grid connection */
  var py = ty + 52;
  s.appendChild(svg("path", {d: "M724 " + (ty + 26) + " H840", "class": "bus"}));
  var brk = svg("path", {d: "M856 " + (ty + 26) + " l26 -14", "class": "brk",
                         id: "brk"});
  s.appendChild(svg("circle", {cx: 850, cy: ty + 26, r: 4, fill: "var(--ink-3)"}));
  s.appendChild(svg("circle", {cx: 888, cy: ty + 26, r: 4, fill: "var(--ink-3)"}));
  s.appendChild(brk);
  var bl = text(872, ty + 62, "breaker", "sv-legend", "middle");
  bl.setAttribute("id", "brk-label");
  s.appendChild(bl);
  s.appendChild(svg("path", {d: "M892 " + (ty + 26) + " H1010", "class": "bus"}));

  var poi = svg("rect", {x: 1010, y: py - 34, width: 290, height: 72, rx: 9,
                         "class": "poi-box", id: "poi-box"});
  s.appendChild(poi);
  s.appendChild(text(1024, py - 14, "To the grid", "sv-title"));
  var pv = text(1024, py + 10, "", "inst-v"); pv.setAttribute("id", "poi-mw");
  s.appendChild(pv);
  var pl = text(1024, py + 26, "", "sv-sub"); pl.setAttribute("id", "poi-limit");
  s.appendChild(pl);
  AREA_AT.poi = {x: 1010, y: py - 34, w: 290, h: 72};

  /* the three instruments, drawn where each one actually measures */
  var iy = busY + 108, iw = 300, ig = 28;
  ["telemetry", "relay", "poi_meter"].forEach(function (key, n) {
    var x = L + n * (iw + ig);
    var g = svg("g", {id: "inst-" + key});
    s.appendChild(g);
    AREA_AT["inst_" + key] = {x: x, y: iy, w: iw, h: 60};
  });
  s.appendChild(text(R, iy + 78,
    "three instruments, three routes, one quantity", "sv-legend", "end"));
  AREA_AT.measurement = {x: L, y: iy, w: W, h: 60};
}

function text(x, y, str, cls, anchor) {
  var t = svg("text", {x: x, y: y, "class": cls, "text-anchor": anchor});
  t.textContent = str;
  return t;
}

/* ================================================================== *
 * Scenario
 * ================================================================== */
function renderScenario(p) {
  SCEN = p;
  METRICS = {};
  p.metrics.forEach(function (m) { METRICS[m.key] = m; });
  $("site-sub").textContent = p.summary;
  $("speed").textContent = "×" + p.speed;
  buildYard(p);
  buildHero(p);
  buildMeters(p);
  buildCharts(p);
  buildAttacks(p);
  $("honesty").textContent =
    "The site's network is a model rather than a rack of listening servers, and "
    + "the DNP3 and GOOSE frames the protocols are built from run in process "
    + "rather than over real layer 2. What is not modelled is the guard: every "
    + "verdict here is the B1 to B8 rule set deciding about the power the "
    + "simulation is actually moving. The clock runs at ×" + p.speed
    + ", which is why a battery warms up in a minute rather than an hour. Two of "
    + "the attacks on this page defeat the guard, and they are on it for that "
    + "reason.";
}

/* ================================================================== *
 * State
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
      : "watching only, commands are judged and let through anyway";
  }

  var worst = "good";
  p.metrics.forEach(function (m) {
    paintMetric(m);
    if (m.health === "breach") { worst = "breach"; }
    else if (m.health === "watch" && worst !== "breach") { worst = "watch"; }
    if (CHART_KEYS.indexOf(m.key) >= 0) { push(m.key, p.t, m.value); }
  });
  if (p.harms && p.harms.length) { worst = "breach"; }
  setChip($("plant-chip"), worst, siteWord(worst, p));
  $("clock").textContent = clock(p.t);

  (p.units || []).forEach(paintUnit);
  paintGrid(p);
  drawCharts();
  paintCounts(p.counters);
  markAttack(p.attack);
}

function siteWord(worst, p) {
  if (p.harms && p.harms.length) { return "equipment damaged"; }
  if (worst === "breach") { return "a limit is broken"; }
  if (worst === "watch") { return "drifting"; }
  return p.enforcing ? "normal, guard enforcing" : "normal, guard watching only";
}

function paintUnit(u) {
  var g = $("pk-" + u.device), geo = UNIT_AT[u.device];
  if (!g || !geo) { return; }
  while (g.firstChild) { g.removeChild(g.firstChild); }
  g.appendChild(svg("rect", {x: geo.x, y: geo.y, width: geo.w, height: geo.h,
                             rx: 8, "class": "pk " + u.health}));
  g.appendChild(text(geo.x + 9, geo.y + 17, u.device, "pk-name"));

  /* charge: a bar, because a number alone does not show how close to empty */
  var bw = geo.w - 18, by = geo.y + 24;
  g.appendChild(svg("rect", {x: geo.x + 9, y: by, width: bw, height: 7, rx: 3.5,
                             "class": "pk-soc-bg"}));
  g.appendChild(svg("rect", {x: geo.x + 9, y: by, rx: 3.5, height: 7,
                             width: Math.max(1, bw * u.soc / 100), "class": "pk-soc"}));
  var sign = u.p_mw > 0.005 ? "▲" : (u.p_mw < -0.005 ? "▼" : "·");
  g.appendChild(text(geo.x + 9, geo.y + 52,
                     sign + " " + Math.abs(u.p_mw).toFixed(2) + " MW", "pk-p"));
  g.appendChild(text(geo.x + 9, geo.y + 68,
                     u.soc.toFixed(0) + "%  " + u.temp_c.toFixed(0) + "°C",
                     "pk-t"));
  var flag = "";
  if (!u.online) { flag = "OFF"; }
  else if (u.damaged && u.damaged.length) { flag = "DAMAGED"; }
  else if (!u.cooling) { flag = "NO COOL"; }
  if (flag) {
    var cls = flag === "OFF" ? "off" : (flag === "DAMAGED" ? "hot" : "cold");
    g.appendChild(text(geo.x + geo.w - 9, geo.y + 17, flag, "pk-flag " + cls, "end"));
  }
  g.appendChild(svg("title", {})).textContent =
    u.device + ": " + u.p_mw.toFixed(3) + " MW, " + u.soc.toFixed(1) + "% charged, "
    + u.temp_c.toFixed(1) + " °C"
    + (u.online ? "" : ", offline") + (u.cooling ? "" : ", cooling off")
    + (u.damaged && u.damaged.length ? ", " + u.damaged.join(" and ") : "");
}

function paintGrid(p) {
  var poi = null, mva = null;
  p.metrics.forEach(function (m) {
    if (m.key === "p_poi") { poi = m; }
    if (m.key === "apparent") { mva = m; }
  });
  if (poi) {
    $("poi-mw").textContent = poi.shown + " MW";
    $("poi-limit").textContent = "limit " + p.poi_limit_mw.toFixed(0) + " MW";
    $("poi-box").setAttribute("class",
      "poi-box" + (poi.health === "breach" ? " over" : ""));
  }
  if (mva) { $("xfmr-load").textContent = mva.shown + " MVA"; }

  var open = p.breaker !== "closed";
  var brk = $("brk");
  if (brk) {
    brk.setAttribute("class", "brk" + (open ? " open" : ""));
    brk.setAttribute("d", open ? "M856 {Y} l26 -16".replace("{Y}", brkY())
                                : "M856 {Y} l32 0".replace("{Y}", brkY()));
    $("brk-label").textContent = open ? "breaker OPEN" : "breaker";
  }
  (p.sources || []).forEach(paintInstrument);
}
function brkY() {
  var g = AREA_AT.transformer;
  return g ? (g.y + 26) : 0;
}

function paintInstrument(src) {
  var g = $("inst-" + src.key), geo = AREA_AT["inst_" + src.key];
  if (!g || !geo) { return; }
  while (g.firstChild) { g.removeChild(g.firstChild); }
  var state = !src.live ? "dead" : (src.health === "watch" ? "suspect" : "live");
  g.appendChild(svg("rect", {x: geo.x, y: geo.y, width: geo.w, height: geo.h,
                             rx: 8, "class": "inst " + state}));
  g.appendChild(text(geo.x + 12, geo.y + 20, src.label, "inst-t"));
  g.appendChild(text(geo.x + 12, geo.y + 42, src.mw.toFixed(2) + " MW", "inst-v"));
  var says = !src.live ? "link down, frozen at its last reading"
           : (src.named ? "named by the guard as the one that is wrong"
                        : "live");
  g.appendChild(text(geo.x + geo.w - 12, geo.y + 42, says, "inst-s", "end"));
}

function paintCounts(c) {
  if (!c) { return; }
  var box = $("counts"); box.innerHTML = "";
  [["Commands checked", c.inspected], ["Refused", c.blocked],
   ["Protective actions", c.trips], ["Attacks run", c.attacks]].forEach(function (pr) {
    var d = el("div");
    d.appendChild(el("b", null, String(pr[1])));
    d.appendChild(document.createTextNode(pr[0]));
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
 * A command crossing the guard
 * ================================================================== */
function flyCommand(p) {
  var layer = $("fly");
  var from = SRC_AT[p.source] || SRC_AT.scada;
  var to = UNIT_AT[p.device] || AREA_AT[p.area] || AREA_AT.fleet;
  if (!layer || !from || !to) { return; }
  var blocked = p.decision === "block";
  var colour = blocked ? css("--breach")
             : (p.decision === "alarm" ? css("--watch") : css("--s1"));
  var midX = to.x + to.w / 2;
  var dot = svg("circle", {r: 5, cx: from.x, cy: from.y, fill: colour,
                           stroke: css("--surface"), "stroke-width": 1.5});
  layer.appendChild(dot);

  var legs = blocked
    ? [[from.x, from.y, from.x, GUARD_Y]]
    : [[from.x, from.y, from.x, GUARD_Y],
       [from.x, GUARD_Y, midX, GUARD_Y],
       [midX, GUARD_Y, midX, to.y]];
  var total = legs.reduce(function (a, l) {
    return a + Math.hypot(l[2] - l[0], l[3] - l[1]);
  }, 0);
  var started = null, speed = 620;

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
                              + " l12 12 M" + (from.x + 6) + " " + (GUARD_Y - 6)
                              + " l-12 12",
                           stroke: css("--breach"), "stroke-width": 2.4,
                           "stroke-linecap": "round", fill: "none"});
      layer.appendChild(x);
      setTimeout(function () { fade(x); }, 620);
    } else {
      var r = svg("rect", {x: to.x, y: to.y, width: to.w, height: to.h, rx: 8,
                           fill: "none", stroke: colour, "stroke-width": 2});
      layer.appendChild(r);
      setTimeout(function () { fade(r); }, 220);
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
  if (window.matchMedia
      && window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    finish();
  } else {
    requestAnimationFrame(frame);
  }
}
"""
    + CHART_JS
    + TAIL_JS
)
