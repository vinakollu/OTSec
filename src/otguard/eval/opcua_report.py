"""Tables and figures for the OPC UA security-mode experiment.

Two numbers carry the result and they belong in different forms.

How much of the traffic the guard could read is a quantity, and a quantity with
a floor that is not zero: an encrypted channel still shows a guard sixteen
bytes per message. Those sixteen bytes are worth drawing, because they are
exactly what the blind rate detector has to work with and they explain why it
is so much looser than the rule it replaces.

What the guard managed to do about each attack is not a quantity. It is one of
four outcomes, and putting four outcomes on a numeric axis is how a chart ends
up implying that "refused" is twice as good as "recovered". It gets a grid of
labelled cells instead.
"""

from __future__ import annotations

import json
import statistics
import textwrap
from pathlib import Path

from ..opcua.framing import SecurityMode
from . import figstyle as fs
from .opcua_experiment import MODES, CellResult, Pair, latency_summary

#: What each outcome means, and the colour it is drawn in.
OUTCOMES = {
    "no attack": ("ordinary traffic only; the false-alarm baseline", fs.STATUS["inert"]),
    "refused": ("the command never reached the device", fs.STATUS["safe"]),
    "recovered": ("it reached the device; the guard tripped the plant back", fs.STATUS["warn"]),
    "damaged": ("it reached the device and the consequence stood", fs.STATUS["danger"]),
    "alarmed": ("objected to, nothing to prevent in this model", fs.SERIES["estimate"]),
    "ignored": ("reads only; correctly forwarded and nothing claimed", fs.STATUS["inert"]),
    "false alarm": ("reads only, and the guard objected anyway", fs.SERIES["extra"]),
    "missed": ("the guard never objected to anything", fs.STATUS["inert"]),
}


def load_pairs(path: Path) -> list[Pair]:
    """Rebuild the pairs from a saved ``opcua_metrics.json``.

    The episodes are the expensive part and the tables are not, so a change to
    how a result is worded should not cost another run of the experiment.
    """
    payload = json.loads(path.read_text())
    guarded: dict[tuple[str, str], CellResult] = {}
    powerless: dict[tuple[str, str], CellResult] = {}
    for row in payload.get("cells", []):
        cell = CellResult.from_dict(row)
        (guarded if cell.enforced else powerless)[cell.key] = cell
    pairs = []
    for key, cell in guarded.items():
        other = powerless.get(key)
        if other is not None:
            pairs.append(Pair(guarded=cell, unguarded=other))
    return pairs


def _by_mode(pairs: list[Pair]) -> dict[SecurityMode, list[Pair]]:
    out: dict[SecurityMode, list[Pair]] = {m: [] for m in MODES}
    for pair in pairs:
        out.setdefault(pair.mode, []).append(pair)
    return out


def format_visibility(pairs: list[Pair]) -> str:
    lines = [
        "What the guard could read",
        "=" * 96,
        f"{'security mode':<18}{'messages':>10}{'bytes':>10}{'legible':>10}"
        f"{'legible %':>11}{'bodies read':>13}{'opaque':>9}",
        "-" * 96,
    ]
    for mode, group in _by_mode(pairs).items():
        if not group:
            continue
        messages = total = legible = decoded = opaque = 0
        for pair in group:
            v = pair.guarded.visibility
            messages += v.get("messages", 0)
            total += v.get("msg_total_bytes", 0)
            legible += v.get("msg_legible_bytes", 0)
            decoded += v.get("bodies_decoded", 0)
            opaque += v.get("bodies_opaque", 0)
        share = 100.0 * legible / total if total else 0.0
        lines.append(
            f"{mode.value:<18}{messages:>10}{total:>10}{legible:>10}{share:>10.1f}%"
            f"{decoded:>13}{opaque:>9}"
        )
    lines += [
        "",
        "Request and response chunks only; the handshake is cleartext in every mode and",
        "counting it would flatter the encrypted case. Sixteen bytes of every message stay",
        "legible whatever the mode: the type, the length, the channel and the key. None of",
        "them say which node is being written, or to what.",
    ]
    return "\n".join(lines)


def format_outcomes(pairs: list[Pair]) -> str:
    scenarios = sorted({p.scenario for p in pairs})
    modes = [m for m in MODES if any(p.mode is m for p in pairs)]
    width = 18
    lines = [
        "",
        "What the guard did about each attack",
        "-" * 96,
        "scenario".ljust(20) + "".join(m.value.ljust(width) for m in modes),
        "-" * 96,
    ]
    index = {(p.scenario, p.mode): p for p in pairs}
    for scenario in scenarios:
        row = scenario.ljust(20)
        for mode in modes:
            pair = index.get((scenario, mode))
            row += (pair.outcome if pair else "-").ljust(width)
        lines.append(row)
    lines.append("")
    lines.append("  * refused by the wire policy rather than by a physics rule.")
    lines.append("")
    for name, (meaning, _) in OUTCOMES.items():
        lines.append(f"  {name:<13}{meaning}")
    return "\n".join(lines)


def format_detail(pairs: list[Pair]) -> str:
    lines = [
        "",
        "Every cell",
        "-" * 128,
        f"{'scenario':<18}{'mode':<17}{'outcome':<13}{'rules':<26}"
        f"{'blocked':>8}{'trips':>7}{'blind':>7}{'severed':>9}"
        f"{'peak m':>8}{'unguard':>9}  {'operator'}",
        "-" * 128,
    ]
    for pair in sorted(pairs, key=lambda p: (p.scenario, p.mode.value)):
        g, u = pair.guarded, pair.unguarded
        # Wire refusals are shown beside the rules rather than only when no
        # rule fired, or a cell where the policy did the stopping and a rule
        # also fired reads as though the rule did all of it.
        parts = list(g.rules_fired) + [f"{w}*" for w in g.wire_reasons]
        rules = ",".join(parts) or "-"
        severed = f"{g.severed_at:.0f}s" if g.severed_at is not None else "-"
        if g.recovery.attempted == 0:
            operator = "no recovery writes"
        elif g.recovery_blocked:
            operator = f"locked out ({g.recovery.attempted} writes lost)"
        else:
            operator = f"{g.recovery.accepted}/{g.recovery.attempted} recovery writes"
        lines.append(
            f"{pair.scenario:<18}{pair.mode.value:<17}{pair.outcome:<13}{rules:<26}"
            f"{g.writes_blocked + g.wire_blocked:>8}{g.trips:>7}{g.blind_trips:>7}"
            f"{severed:>9}{g.peak_level_m:>8.2f}{u.peak_level_m:>9.2f}  {operator}"
        )
    return "\n".join(lines)


def format_false_alarms(pairs: list[Pair]) -> str:
    benign = [p for p in pairs if not p.guarded.is_attack]
    lines = ["", "Ordinary traffic, no attack", "-" * 96]
    if not benign:
        lines.append("  not run")
        return "\n".join(lines)
    lines.append(f"{'mode':<18}{'writes':>8}{'refused':>9}{'objections':>12}{'trips':>7}")
    lines.append("-" * 96)
    for pair in sorted(benign, key=lambda p: p.mode.value):
        g = pair.guarded
        total = g.honest.attempted + g.recovery.attempted
        refused = g.honest.refused + g.recovery.refused
        lines.append(
            f"{pair.mode.value:<18}{total:>8}{refused:>9}"
            f"{g.writes_blocked + g.wire_blocked + g.alarms:>12}{g.trips + g.blind_trips:>7}"
        )
    return "\n".join(lines)


def format_summary(pairs: list[Pair]) -> str:
    lat = latency_summary(pairs)
    attacks = [p for p in pairs if p.guarded.is_attack and not p.guarded.read_only]
    lines = ["", "Reading the three modes against each other", "-" * 96]
    for mode in MODES:
        group = [p for p in attacks if p.mode is mode]
        if not group:
            continue
        refused = sum(1 for p in group if p.outcome == "refused")
        recovered = sum(1 for p in group if p.outcome == "recovered")
        damaged = sum(1 for p in group if p.outcome == "damaged")
        missed = sum(1 for p in group if p.outcome == "missed")
        to_prevent = sum(1 for p in group if p.damage_to_prevent)
        prevented = sum(1 for p in group if p.damage_prevented)
        severed = sum(1 for p in group if p.guarded.severed_at is not None)
        locked = sum(1 for p in group if p.guarded.recovery_blocked)
        leads = [p.guarded.first_detection_t for p in group
                 if p.guarded.first_detection_t is not None]
        lines.append(f"  {mode.value}")
        lines.append(
            f"    refused {refused}, tripped back {recovered}, damaged {damaged}, "
            f"not objected to {missed}  (of {len(group)})"
        )
        lines.append(
            f"    damage prevented {prevented}/{to_prevent}; "
            f"channels cut {severed}; operator locked out of recovery {locked}"
        )
        if leads:
            lines.append(
                f"    first objection: median {statistics.median(leads):.1f}s "
                f"after the episode began, earliest {min(leads):.1f}s"
            )
    if lat.get("count"):
        lines.append("")
        lines.append(
            f"  Decision cost on readable channels: p50 {lat['p50']:.0f} us, "
            f"p95 {lat['p95']:.0f} us, p99 {lat['p99']:.0f} us (n={lat['count']})"
        )
    lines += [
        "",
        "  Read the rows in order. A refusal keeps the command off the device. A trip",
        "  lets it land and pulls the plant back, which needs the process to have moved",
        "  far enough to notice. Nothing in the third column is a tuning failure: on an",
        "  encrypted channel the guard has no command to refuse and no command to",
        "  attribute, and the only mechanism left reads the level and waits.",
    ]
    return "\n".join(lines)


def render(pairs: list[Pair]) -> str:
    return "\n".join([
        format_visibility(pairs),
        format_outcomes(pairs),
        format_detail(pairs),
        format_false_alarms(pairs),
        format_summary(pairs),
    ])


# ----------------------------------------------------------------------
# Figure
# ----------------------------------------------------------------------
def plot_experiment(pairs: list[Pair], path: Path) -> Path:
    import matplotlib.pyplot as plt

    fs.apply()
    modes = [m for m in MODES if any(p.mode is m for p in pairs)]
    scenarios = sorted({p.scenario for p in pairs if p.guarded.is_attack})
    index = {(p.scenario, p.mode): p for p in pairs}

    fig, (left, right) = plt.subplots(
        1, 2, figsize=(11.0, 1.4 + 0.46 * max(len(scenarios), 3)),
        gridspec_kw={"width_ratios": [1.0, 1.5], "wspace": 0.42},
    )

    # --- what the guard could read ---
    shares, labels = [], []
    for mode in modes:
        total = legible = 0
        for pair in pairs:
            if pair.mode is not mode:
                continue
            v = pair.guarded.visibility
            total += v.get("msg_total_bytes", 0)
            legible += v.get("msg_legible_bytes", 0)
        shares.append(100.0 * legible / total if total else 0.0)
        labels.append(mode.value)
    # Spread three bars over the same row grid the six-row panel beside them
    # uses, so the two halves share a rhythm instead of one having bars three
    # times the thickness of the other's cells.
    rows = max(len(scenarios), len(modes))
    step = rows / len(modes)
    ys = [(i + 0.5) * step - 0.5 for i in range(len(modes))]
    fs.style(left, xlabel="per cent of request and response bytes", grid="x")
    left.barh(ys, shares, height=0.5,
              color=[fs.SERIES["estimate"] if s > 50 else fs.STATUS["danger"] for s in shares],
              zorder=2)
    left.set_yticks(ys)
    left.set_yticklabels(labels)
    left.set_ylim(rows - 0.5, -0.5)
    left.set_xlim(0, 118)
    for y, share in zip(ys, shares):
        fs.value(left, share, y, f"{share:.0f}%", offset=(6, -3), ha="left")
    left.set_title("What the guard can read", loc="left",
                   fontsize=fs.TYPE.subtitle, color=fs.INK, pad=6)

    # --- what it managed to do ---
    fs.style(right, grid="")
    for side in ("left", "bottom"):
        right.spines[side].set_visible(False)
    right.set_xlim(-0.5, len(modes) - 0.5)
    right.set_ylim(len(scenarios) - 0.5, -0.5)
    right.set_xticks(range(len(modes)))
    right.set_xticklabels([m.value for m in modes])
    right.set_yticks(range(len(scenarios)))
    right.set_yticklabels(scenarios)
    right.tick_params(length=0)
    right.xaxis.set_ticks_position("top")

    seen: list[str] = []
    for row, scenario in enumerate(scenarios):
        for col, mode in enumerate(modes):
            pair = index.get((scenario, mode))
            if pair is None:
                continue
            outcome = pair.outcome
            colour = OUTCOMES.get(outcome, ("", fs.STATUS["inert"]))[1]
            right.add_patch(plt.Rectangle(
                (col - 0.44, row - 0.34), 0.88, 0.68,
                facecolor=colour, alpha=0.16, edgecolor=colour, lw=0.9, zorder=1,
            ))
            right.annotate(outcome, xy=(col, row), ha="center", va="center",
                           fontsize=fs.TYPE.label, color=colour, zorder=3)
            if outcome not in seen:
                seen.append(outcome)
    right.set_title("What it managed to do about the attack", loc="left",
                    fontsize=fs.TYPE.subtitle, color=fs.INK, pad=22)

    fs.titles(
        fig,
        "One guard, one attack set, three OPC UA security modes",
        "Encryption does not weaken the rules. It removes the traffic they run on.",
    )
    # Built from the outcomes actually on the chart, so a cell can never carry
    # a word the key below does not explain. Wrapped, because matplotlib fits
    # the saved image around its contents and one long line of key drags the
    # figure out to twice the width of the charts it belongs to.
    key = "  ".join(
        f"{name}: {OUTCOMES[name][0]}." for name in OUTCOMES if name in seen
    )
    fs.footnote(fig, "\n".join(textwrap.wrap(key, width=120)))
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path)
    plt.close(fig)
    return path


def write_report(pairs: list[Pair], out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    cells = []
    for pair in pairs:
        for cell in (pair.guarded, pair.unguarded):
            row = cell.as_dict()
            row["outcome"] = pair.outcome if cell.enforced else ""
            row["damaged_unguarded"] = pair.unguarded.damaged
            cells.append(row)
    payload = {
        "cells": cells,
        "latency_us": latency_summary(pairs),
        "modes": [m.value for m in MODES],
    }
    path = out_dir / "opcua_metrics.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True))
    return path
