"""The water works on a screen.

Written for somebody who has never seen a treatment plant and is being shown
one for the first time: the schematic carries the process, the meters carry
every number against the limit that applies to it, and the narration column
says in ordinary words what just happened and why. Nothing on the page states
a condition by colour alone.

Everything that is not the plant itself comes from :mod:`otguard.live.ui`,
which the storage site's page draws from too. What is here is the works: eight
stages in a row, the controllers above them, and the guard on the line
between.

There is no network dependency. The page is served from loopback by
:mod:`otguard.live.web`, and a demonstration that needs a content delivery
network to draw a chart is a demonstration that fails in the room it matters
in. The charts are drawn on a canvas and the schematic is hand-laid SVG.
"""

from __future__ import annotations

from .ui import BUILD_JS, CHART_JS, CORE_CSS, HEAD_JS, PARTS_CSS, TAIL_JS

WATER_PAGE = (
    r"""<!doctype html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>OTGuard, water treatment works</title>
"""
    + CORE_CSS
    + r"""
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
.sv-guard.off + .sv-guard-t.sv-guard-t.off{fill:var(--watch)}
.sv-legend{font-size:10.5px; fill:var(--ink-3)}
@media (prefers-reduced-motion:reduce){ .sv-flow{animation:none} }
</style>
"""
    + PARTS_CSS
    + r"""
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
    <h2>The process <span class="note">water left to right, commands down from the top and across the guard</span></h2>
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
"""
    + HEAD_JS
    + r"""
CHART_KEYS = ["chlorine_residual", "filtered_turbidity", "clearwell_level", "pressure"];
"""
    + BUILD_JS
    + r"""
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
    + "works' network, not twenty-two listening servers. What is not modelled is "
    + "the guard. Every verdict on this page is the rule set reaching a decision "
    + "about the water the simulation is actually moving, and the time on the "
    + "clock runs at ×" + p.speed + " so that a clearwell taking forty minutes "
    + "to fill can be watched.";
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
"""
    + CHART_JS
    + TAIL_JS
)
