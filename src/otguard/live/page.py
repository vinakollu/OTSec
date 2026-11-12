"""The browser view, as one self-contained page.

Held in a Python string rather than a static file so that running the demo
needs nothing installed and nothing served from anywhere else. There are no
external stylesheets, no fonts and no script tags pointing at a CDN: a control
display that goes blank because a network is unavailable would be a poor
advertisement for a project about operational technology, and the machines this
would run near often have no route to the internet at all.

It reads the same event stream the terminal view reads, through server-sent
events, and it computes nothing the stream did not carry. ``EventSource``
handles reconnection by itself and sends the last id it saw, which the server
turns into a replay of what the page missed.
"""

from __future__ import annotations

PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OTGuard live</title>
<style>
  :root {
    --bg: #0e1116; --panel: #161b22; --line: #263040; --text: #d7dee8;
    --dim: #7d8899; --ok: #3fb950; --warn: #d29922; --bad: #f85149;
    --accent: #58a6ff; --fill: #1f6feb;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; background: var(--bg); color: var(--text);
    font: 14px/1.5 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  }
  header {
    display: flex; flex-wrap: wrap; gap: 8px 18px; align-items: baseline;
    padding: 14px 18px; border-bottom: 1px solid var(--line); background: var(--panel);
    position: sticky; top: 0;
  }
  header h1 { font-size: 15px; margin: 0; letter-spacing: .04em; }
  .tag {
    font-size: 12px; padding: 2px 8px; border: 1px solid var(--line); border-radius: 10px;
    color: var(--dim);
  }
  .tag.on { color: var(--ok); border-color: var(--ok); }
  .tag.off { color: var(--warn); border-color: var(--warn); }
  #clock { margin-left: auto; color: var(--accent); }
  main {
    display: grid; gap: 14px; padding: 14px 18px;
    grid-template-columns: minmax(320px, 1.4fr) minmax(280px, 1fr);
  }
  @media (max-width: 820px) { main { grid-template-columns: 1fr; } }
  section {
    background: var(--panel); border: 1px solid var(--line); border-radius: 8px;
    padding: 12px 14px; min-width: 0;
  }
  section h2 {
    font-size: 11px; text-transform: uppercase; letter-spacing: .1em;
    color: var(--dim); margin: 0 0 10px; font-weight: 600;
  }
  .wide { grid-column: 1 / -1; }

  /* the tank */
  .tankwrap { display: flex; gap: 18px; align-items: flex-end; }
  .tank {
    position: relative; width: 150px; height: 240px; border: 2px solid var(--line);
    border-top: none; border-radius: 0 0 6px 6px; background: #0b0e13; overflow: hidden;
  }
  .water {
    position: absolute; left: 0; right: 0; bottom: 0; background: var(--fill);
    transition: height .18s linear, background .2s;
  }
  .mark { position: absolute; left: 0; right: 0; border-top: 1px dashed var(--warn); }
  .mark.floor { border-top-color: var(--accent); }
  /* Below the line, not above it: the overflow mark sits near the top of a
     tank with overflow:hidden, and a label above it gets cut off. */
  .mark span {
    position: absolute; right: 3px; top: 2px; font-size: 10px; color: var(--dim);
    text-shadow: 0 0 3px var(--bg), 0 0 3px var(--bg);
  }
  .readouts { flex: 1; min-width: 0; }
  .big { font-size: 26px; }
  .big.ok { color: var(--ok); } .big.warn { color: var(--warn); } .big.bad { color: var(--bad); }

  /* bars */
  .row { display: flex; align-items: center; gap: 10px; margin: 6px 0; }
  .row .label { width: 92px; color: var(--dim); flex: none; }
  .row .value { width: 86px; text-align: right; flex: none; }
  .track {
    flex: 1; height: 10px; background: #0b0e13; border: 1px solid var(--line);
    border-radius: 5px; overflow: hidden; position: relative; min-width: 60px;
  }
  .track i { display: block; height: 100%; background: var(--fill); transition: width .18s linear; }
  .track .limit { position: absolute; top: 0; bottom: 0; width: 2px; background: var(--warn); }

  /* measurements */
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: 4px 6px; border-bottom: 1px solid var(--line); }
  th { color: var(--dim); font-weight: 500; font-size: 11px; text-transform: uppercase; }
  td.num { text-align: right; font-variant-numeric: tabular-nums; }
  .pill {
    font-size: 11px; padding: 1px 7px; border-radius: 9px; border: 1px solid;
    white-space: nowrap;
  }
  .pill.counted { color: var(--ok); border-color: var(--ok); }
  .pill.stale { color: var(--bad); border-color: var(--bad); }
  .pill.lying { color: var(--warn); border-color: var(--warn); }
  .banner {
    margin-top: 10px; padding: 8px 10px; border-radius: 6px; font-size: 13px;
    border: 1px solid var(--warn); color: var(--warn); background: rgba(210,153,34,.08);
  }
  .banner.bad { border-color: var(--bad); color: var(--bad); background: rgba(248,81,73,.08); }

  /* packs */
  .packs { display: grid; grid-template-columns: repeat(8, 1fr); gap: 5px; }
  .pack {
    border: 1px solid var(--line); border-radius: 4px; padding: 4px; text-align: center;
    font-size: 10px; color: var(--dim); background: #0b0e13;
  }
  .pack b { display: block; color: var(--text); font-size: 11px; font-weight: 500; }
  /* display:block, or the span ignores its height and the inner bar escapes
     the card it is supposed to sit in. */
  .pack .soc {
    display: block; height: 4px; margin-top: 3px; background: #1b2230; border-radius: 2px;
  }
  .pack .soc i { display: block; height: 100%; background: var(--ok); border-radius: 2px; }
  .pack.off { border-color: var(--bad); color: var(--bad); }

  /* devices */
  .devs { display: grid; grid-template-columns: repeat(auto-fill, minmax(118px, 1fr)); gap: 6px; }
  .dev {
    display: flex; align-items: center; gap: 6px; padding: 5px 7px; font-size: 12px;
    border: 1px solid var(--line); border-radius: 5px; background: #0b0e13; min-width: 0;
  }
  .dot { width: 8px; height: 8px; border-radius: 50%; background: var(--dim); flex: none; }
  .dev.up .dot { background: var(--ok); }
  .dev.down .dot { background: var(--bad); }
  .dev.down { border-color: var(--bad); }
  .dev .nm { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .dev .mdl { color: var(--dim); font-size: 10px; margin-left: auto; flex: none; }

  /* feed */
  #feed { max-height: 320px; overflow-y: auto; }
  .ev { display: flex; gap: 8px; padding: 2px 0; border-bottom: 1px solid rgba(38,48,64,.5); }
  .ev .t { color: var(--dim); flex: none; width: 62px; text-align: right; }
  .ev .w { flex: none; width: 54px; font-weight: 600; }
  .ev .d { min-width: 0; overflow-wrap: anywhere; }
  .ev.block .w { color: var(--bad); } .ev.alarm .w { color: var(--warn); }
  .ev.allow .w { color: var(--ok); } .ev.trip .w { color: var(--warn); }
  .ev.down .w { color: var(--bad); } .ev.up .w { color: var(--ok); }
  .ev .why { color: var(--dim); }
  footer { padding: 6px 18px 20px; color: var(--dim); font-size: 12px; }
</style>
</head>
<body>
<header>
  <h1>OTGuard live</h1>
  <span class="tag" id="plant">waiting</span>
  <span class="tag" id="scenario"></span>
  <span class="tag" id="mode"></span>
  <span id="clock">t = 0.0 s</span>
</header>

<main>
  <section id="plantpanel"><h2>plant</h2><div id="plantbody"></div></section>
  <section><h2>devices</h2><div id="devsum" style="color:var(--dim);margin-bottom:8px"></div>
    <div class="devs" id="devs"></div></section>
  <section class="wide"><h2>commands and verdicts</h2><div id="feed"></div></section>
</main>
<footer id="foot">connecting&hellip;</footer>

<script>
(function () {
  "use strict";
  var el = function (id) { return document.getElementById(id); };
  var state = null, devices = {}, scenario = null, lastSeq = 0, clock = 0, dropped = 0;

  function fmt(v, dp) { return (v >= 0 ? "+" : "") + v.toFixed(dp === undefined ? 3 : dp); }
  function esc(s) {
    return String(s === undefined || s === null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  // ---- plant -------------------------------------------------------
  function drawTank(s) {
    var h = s.height_m || 2, pct = Math.max(0, Math.min(1, s.level_m / h)) * 100;
    var tone = (s.overflowed || s.dried_out) ? "bad"
             : (s.level_m > s.limit_m - 0.15 || s.level_m < s.floor_m + 0.1) ? "warn" : "ok";
    var hurt = s.overflowed ? "the tank has overflowed"
             : s.dried_out ? "the pump has run dry" : "";
    return ''
      + '<div class="tankwrap">'
      +   '<div class="tank">'
      +     '<div class="water" style="height:' + pct.toFixed(1) + '%;background:'
      +       (tone === "bad" ? "var(--bad)" : tone === "warn" ? "var(--warn)" : "var(--fill)")
      +     '"></div>'
      +     '<div class="mark" style="bottom:' + (s.limit_m / h * 100).toFixed(1)
      +       '%"><span>' + s.limit_m + ' m overflow</span></div>'
      +     '<div class="mark floor" style="bottom:' + (s.floor_m / h * 100).toFixed(1)
      +       '%"><span>' + s.floor_m + ' m dry</span></div>'
      +   '</div>'
      +   '<div class="readouts">'
      +     '<div class="big ' + tone + '">' + s.level_m.toFixed(3) + ' m</div>'
      +     '<div style="color:var(--dim);margin-bottom:8px">sensor says '
      +       s.reported_m.toFixed(3) + ' m &middot; guard believes '
      +       s.believed_m.toFixed(3) + ' m</div>'
      +     bar("pump", s.pump_pct, 100, "%", 1)
      +     bar("valve", s.valve_pct, 100, "%", 1)
      +   '</div>'
      + '</div>'
      + (hurt ? '<div class="banner bad">' + hurt + '</div>' : '');
  }

  // signed is for quantities where the direction is the story (export vs
  // import); a pump at "+12 %" just reads oddly.
  function bar(label, value, full, unit, dp, limit, signed) {
    var pct = Math.max(0, Math.min(1, Math.abs(value) / full)) * 100;
    return '<div class="row"><span class="label">' + label + '</span>'
      + '<span class="track"><i style="width:' + pct.toFixed(1) + '%"></i>'
      + (limit === undefined ? ''
         : '<span class="limit" style="left:' + (limit / full * 100).toFixed(1) + '%"></span>')
      + '</span>'
      + '<span class="value">' + (signed ? fmt(value, dp) : value.toFixed(dp))
      + ' ' + unit + '</span></div>';
  }

  function drawSite(s) {
    var counted = {}, i;
    for (i = 0; i < s.counted.length; i++) { counted[s.counted[i]] = 1; }
    var rows = "", n = 0, name;
    for (name in s.measurements) {
      if (!Object.prototype.hasOwnProperty.call(s.measurements, name)) { continue; }
      n++;
      var isCounted = counted[name], accused = s.lying_source === name;
      rows += '<tr><td>' + esc(name) + '</td>'
        + '<td class="num">' + fmt(s.measurements[name]) + ' MW</td>'
        + '<td><span class="pill ' + (isCounted ? "counted" : "stale") + '">'
        + (isCounted ? "counted" : "stale, not counted") + '</span>'
        + (accused ? ' <span class="pill lying">named as lying</span>' : '')
        + '</td></tr>';
    }
    var short = s.counted.length < 3;
    var warn = short
      ? (s.counted.length >= 2
          ? "quorum lost: two measurements can show a disagreement and can no longer say "
            + "which of them is wrong"
          : s.counted.length === 1
            ? "one measurement left: no cross-check at all, and a bias on it is undetectable"
            : "no measurement of site power is arriving")
      : "";
    var packs = "";
    for (i = 0; i < s.packs.length; i++) {
      var p = s.packs[i], soc = Math.max(0, Math.min(1, p.soc)) * 100;
      packs += '<div class="pack' + (p.online ? '' : ' off') + '">'
        + '<b>' + esc(p.device || ('MP' + (i + 1))) + '</b>'
        + (p.online ? fmt(p.p_mw, 2) : 'offline')
        + '<span class="soc"><i style="width:' + soc.toFixed(0) + '%"></i></span></div>';
    }
    var over = Math.abs(s.poi_mw) > s.limit_mw;
    return ''
      + '<div class="big ' + (Math.abs(s.poi_mw) > s.rating_mw ? "bad" : over ? "warn" : "ok")
      +   '">' + fmt(s.poi_mw) + ' MW</div>'
      + '<div style="color:var(--dim);margin-bottom:8px">guard believes '
      +   fmt(s.believed_mw) + ' MW &middot; limit ' + s.limit_mw
      +   ' MW &middot; transformer ' + s.rating_mw + ' MVA</div>'
      + bar("export", s.poi_mw, s.rating_mw, "MW", 3, s.limit_mw, true)
      + '<table><thead><tr><th>measurement</th><th class="num">reads</th><th>in the vote</th>'
      +   '</tr></thead><tbody>' + rows + '</tbody></table>'
      + (warn ? '<div class="banner">' + warn + '</div>' : '')
      + (s.damaged ? '<div class="banner bad">the site has been damaged</div>' : '')
      + '<h2 style="margin-top:12px">' + s.packs.length + ' units</h2>'
      + '<div class="packs">' + packs + '</div>';
  }

  function drawPlant() {
    if (!state) { el("plantbody").innerHTML =
      '<div style="color:var(--dim)">waiting for the plant to report</div>'; return; }
    el("plantbody").innerHTML = state.plant === "tank" ? drawTank(state) : drawSite(state);
  }

  // ---- devices -----------------------------------------------------
  function drawDevices() {
    var names = Object.keys(devices).sort(function (a, b) {
      var da = devices[a], db = devices[b];
      if ((da.state === "down") !== (db.state === "down")) { return da.state === "down" ? -1 : 1; }
      if (da.critical !== db.critical) { return da.critical ? -1 : 1; }
      return a < b ? -1 : 1;
    });
    var html = "", up = 0, down = 0, modelled = 0, i;
    for (i = 0; i < names.length; i++) {
      var d = devices[names[i]];
      if (d.state === "up") { up++; } else if (d.state === "down") { down++; }
      if (!d.networked) { modelled++; }
      html += '<div class="dev ' + d.state + '" title="' + esc(d.detail) + '">'
        + '<span class="dot"></span><span class="nm">' + esc(d.name) + '</span>'
        + (d.networked ? (d.state === "up" && d.rtt_ms
            ? '<span class="mdl">' + d.rtt_ms.toFixed(1) + 'ms</span>' : '')
           : '<span class="mdl">model</span>')
        + '</div>';
    }
    el("devs").innerHTML = html;
    el("devsum").innerHTML = names.length
      ? up + ' answering' + (down ? ', <span style="color:var(--bad)">' + down
          + ' not</span>' : '')
        + ' &middot; ' + modelled + ' of ' + names.length
        + ' read from the model rather than probed over a socket'
      : 'no devices being scanned';
  }

  // ---- feed --------------------------------------------------------
  function push(cls, word, detail, why) {
    var feed = el("feed");
    var atEnd = feed.scrollTop + feed.clientHeight >= feed.scrollHeight - 24;
    var div = document.createElement("div");
    div.className = "ev " + cls;
    div.innerHTML = '<span class="t">' + clock.toFixed(1) + 's</span>'
      + '<span class="w">' + esc(word) + '</span>'
      + '<span class="d">' + esc(detail)
      + (why ? ' <span class="why">' + esc(why) + '</span>' : '') + '</span>';
    feed.appendChild(div);
    while (feed.childNodes.length > 300) { feed.removeChild(feed.firstChild); }
    if (atEnd) { feed.scrollTop = feed.scrollHeight; }
  }

  // ---- events ------------------------------------------------------
  function apply(e) {
    lastSeq = e.seq;
    if (typeof e.t === "number") { clock = Math.max(clock, e.t); }
    el("clock").textContent = "t = " + clock.toFixed(1) + " s";

    if (e.kind === "scenario") {
      scenario = e; state = null; devices = {};
      el("feed").innerHTML = "";
      el("plant").textContent = e.plant;
      el("scenario").textContent = e.name;
      el("mode").textContent = e.guarded ? "guard enforcing" : "guard powerless";
      el("mode").className = "tag " + (e.guarded ? "on" : "off");
      push("", "run", e.name + " on the " + e.plant, e.summary);
      drawPlant(); drawDevices();
    } else if (e.kind === "state") {
      state = e; drawPlant();
    } else if (e.kind === "device") {
      devices[e.name] = e;
      if (e.state === "down") { push("down", "DOWN", e.name + " stopped answering", e.detail); }
      else if (e.previous === "down") { push("up", "UP", e.name + " is back", e.detail); }
      drawDevices();
    } else if (e.kind === "command") {
      push("", "->", e.source + (e.device ? " " + e.device : "") + " "
        + e.point + "=" + e.value + e.unit);
    } else if (e.kind === "verdict") {
      push(e.decision, e.decision.toUpperCase(),
        e.source + (e.device ? " " + e.device : "") + " "
          + e.point + "=" + e.value + e.unit,
        (e.rules.length ? "[" + e.rules.join(",") + "] " : "") + e.detail);
    } else if (e.kind === "trip") {
      push("trip", "GUARD", e.detail, "[" + e.rules.join(",") + "]");
    } else if (e.kind === "note") {
      push(e.level === "warn" ? "alarm" : e.level === "bad" ? "block" : "", "note", e.text);
    } else if (e.kind === "done") {
      push("", "result", e.outcome, e.lines.join("  "));
    }
  }

  function connect() {
    var src = new EventSource("/events" + (lastSeq ? "?after=" + lastSeq : ""));
    src.onmessage = function (m) {
      try { apply(JSON.parse(m.data)); } catch (err) { /* a bad frame is not fatal */ }
    };
    src.onopen = function () { el("foot").textContent = "connected"; };
    src.onerror = function () {
      el("foot").textContent = "reconnecting\\u2026";
      // EventSource retries on its own; resuming from lastSeq is what stops a
      // reconnection replaying the whole run.
    };
  }
  connect();
})();
</script>
</body>
</html>
"""
