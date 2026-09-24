"""Rendering: console tables, a JSON record, and per-scenario trace plots.

The JSON is the artefact that matters — it is what a progress report quotes and
what a later run gets diffed against. The plots exist because the interesting
claims in this project are about *trajectories* (where the level went, and when
the guard objected), and a table cannot show that a trip landed 40 seconds
before the tank would have topped out.
"""

from __future__ import annotations

import json
from pathlib import Path

from .harness import RunResult
from .metrics import Report

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from . import figstyle  # noqa: E402

_BAR = "=" * 78


def render_console(report: Report) -> str:
    """Human-readable summary for the terminal."""
    lines: list[str] = []
    s, c, b, lat = report.scenarios, report.commands, report.benign_traffic, report.latency

    lines.append(_BAR)
    lines.append("OTGuard evaluation")
    lines.append(_BAR)
    lines.append("")
    lines.append("Per-scenario outcomes")
    lines.append("-" * 78)
    header = (
        f"{'scenario':<18}{'kind':<8}{'detect':<8}{'damage':<8}"
        f"{'no-guard':<10}{'rules':<14}{'trips':<6}"
    )
    lines.append(header)
    for entry in report.per_scenario:
        unguarded = entry.get("unguarded_damaged")
        unguarded_text = {True: "damaged", False: "safe", None: "-"}[unguarded]
        lines.append(
            f"{entry['name']:<18}{entry['category']:<8}"
            f"{_yn(entry['detected']):<8}{_yn(entry['damaged']):<8}"
            f"{unguarded_text:<10}{','.join(entry['rules_fired']) or '-':<14}"
            f"{entry['supervision_trips']:<6}"
        )

    lines.append("")
    lines.append("Headline metrics")
    lines.append("-" * 78)
    lines.append(
        f"  Detection rate           {s.detection_rate:6.1%}   "
        f"({s.attacks_detected}/{s.attacks_total} attack scenarios flagged)"
    )
    lines.append(
        f"  Damage avoidance         {s.damage_avoidance_rate:6.1%}   "
        f"({s.damage_avoided}/{s.attacks_damaging_unguarded} attacks that caused "
        f"damage without the guard)"
    )
    lines.append(
        f"  False-alarm rate         {s.false_alarm_rate:6.1%}   "
        f"({s.normal_with_false_alarm}/{s.normal_total} benign scenarios raised any alarm)"
    )
    lines.append(
        f"  Benign writes blocked    {b.benign_blocked:6d}   "
        f"of {b.benign_total} in benign scenarios ({b.false_positive_rate:.2%} flagged)"
    )
    lines.append(
        f"  Malicious write recall   {c.recall:6.1%}   "
        f"({c.malicious_flagged}/{c.malicious_total}); precision {c.precision:.1%}"
    )
    lines.append("")
    lines.append(
        f"  Added latency            p50 {lat.p50_us:.1f} us | p95 {lat.p95_us:.1f} us | "
        f"p99 {lat.p99_us:.1f} us | max {lat.max_us:.1f} us  (n={lat.count})"
    )
    lines.append("")
    return "\n".join(lines)


def write_json(report: Report, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report.as_dict(), indent=2, sort_keys=True))
    return path


def plot_run(
    run: RunResult,
    safety,
    path: str | Path,
    unguarded: RunResult | None = None,
    cusum_threshold: float = 30.0,
) -> Path:
    """One scenario: what the tank did, what the guard was told, what it did.

    The detector panel is drawn only when the detector actually moves. On most
    scenarios the CUSUM sits in a noise band two orders of magnitude below its
    threshold, and a panel showing that is a panel saying nothing at the same
    size as the panel saying everything.
    """
    figstyle.apply()

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    t = [s.t for s in run.samples]
    true = [s.true_level_m for s in run.samples]
    reported = [s.reported_level_m for s in run.samples]
    estimate = [s.estimated_level_m for s in run.samples]
    cusum = [s.cusum for s in run.samples]

    # Whether the operator is being lied to is a property of the scenario, not
    # something to infer from the trace: the transmitter has millimetres of
    # noise on it, so any tolerance small enough to catch a real bias also
    # catches ordinary noise and labels every honest run as spoofed.
    spoofed = run.scenario.sensor_attack is not None
    show_detector = max(cusum, default=0.0) > cusum_threshold * 0.25

    if show_detector:
        fig, (ax, ax2) = plt.subplots(
            2, 1, figsize=(9.5, 5.6), sharex=True, height_ratios=[3.2, 1],
            gridspec_kw={"hspace": 0.18},
        )
    else:
        fig, ax = plt.subplots(figsize=(9.5, 4.4))
        ax2 = None

    # --- the process ---
    if unguarded is not None:
        ax.plot([s.t for s in unguarded.samples],
                [s.true_level_m for s in unguarded.samples],
                lw=1.5, ls=(0, (5, 3)), color=figstyle.COUNTERFACTUAL, zorder=2)
    ax.plot(t, true, lw=2.0, color=figstyle.TRUTH, zorder=5)
    if spoofed:
        ax.plot(t, reported, lw=1.4, ls=(0, (1.5, 1.5)),
                color=figstyle.SERIES["sensor"], zorder=4)
    ax.plot(t, estimate, lw=1.2, color=figstyle.SERIES["estimate"], alpha=0.9, zorder=3)

    # Fit the axis to what happened, and admit a safety limit only when the
    # process came near it. Reserving room for a dry-out limit the level never
    # approached spends half the panel on empty space and flattens the part of
    # the trace the figure exists to show.
    traces = [*true, *estimate]
    if unguarded is not None:
        traces += [s.true_level_m for s in unguarded.samples]
    lo, hi = min(traces), max(traces)
    reach = max(hi - lo, 0.1) * 0.4
    show_high = hi + reach >= safety.level_max_m
    show_low = lo - reach <= safety.level_min_m
    if show_high:
        hi = max(hi, safety.level_max_m)
    if show_low:
        lo = min(lo, safety.level_min_m)
    pad = max((hi - lo) * 0.16, 0.05)
    ax.set_ylim(lo - pad, hi + pad)

    if show_high:
        figstyle.danger_band(ax, safety.level_max_m, above=True, label="overflow")
    if show_low:
        figstyle.danger_band(ax, safety.level_min_m, above=False, label="dry-out")

    # An attack window that covers the whole episode is not a window. When the
    # attack runs to the end, mark where it starts instead of tinting the page.
    if run.scenario.attack_window is not None:
        start, end = run.scenario.attack_window
        end = min(end, t[-1])
        covers_everything = (end - start) > 0.7 * (t[-1] - t[0])
        if covers_everything:
            ax.axvline(start, color=figstyle.STATUS["danger"], lw=0.9, alpha=0.45)
            ax.annotate("attack begins", xy=(start, 1.0),
                        xycoords=("data", "axes fraction"),
                        xytext=(4, 4), textcoords="offset points",
                        ha="left", va="bottom", fontsize=figstyle.TYPE.note,
                        color=figstyle.STATUS["danger"])
        else:
            figstyle.span(ax, start, end, label="attack", alpha=0.07)

    # Refused writes are a rug along the bottom, not full-height rules: they
    # are events on the command channel, not events in the tank.
    refused = [v.command.t for v, _ in run.verdicts if not v.allowed]
    if refused:
        y0 = ax.get_ylim()[0]
        ax.plot(refused, [y0] * len(refused), marker="|", ls="none", ms=7,
                mew=1.1, color=figstyle.SERIES["extra"], alpha=0.75, zorder=6,
                clip_on=False)

    trips = [e.t for e in run.supervision_events if e.action is not None]
    for i, trip in enumerate(trips):
        ax.axvline(trip, color=figstyle.SERIES["extra"], lw=1.2, alpha=0.8, zorder=4)
        if i == 0:
            figstyle.callout(
                ax, (trip, ax.get_ylim()[1]),
                f"guard trips the pump  t={trip:.0f}s",
                offset=(8, -16), colour=figstyle.SERIES["extra"],
            )

    labels = [(true[-1], "true level", figstyle.TRUTH),
              (estimate[-1], "guard estimate", figstyle.SERIES["estimate"])]
    if spoofed:
        labels.append((reported[-1], "shown to operator", figstyle.SERIES["sensor"]))
    if unguarded is not None:
        labels.append((unguarded.samples[-1].true_level_m, "no guard",
                       figstyle.COUNTERFACTUAL))
    figstyle.direct_labels(ax, labels)

    figstyle.style(ax, ylabel="level (m)")
    if ax2 is None:
        ax.set_xlabel("time (s)")

    # --- the detector, when it has something to say ---
    if ax2 is not None:
        ax2.fill_between(t, 0, cusum, color=figstyle.SERIES["sensor"],
                         alpha=0.18, lw=0, zorder=2)
        ax2.plot(t, cusum, lw=1.2, color=figstyle.SERIES["sensor"], zorder=3)
        ax2.axhline(cusum_threshold, color=figstyle.STATUS["danger"],
                    lw=0.9, alpha=0.6, zorder=1)
        ax2.annotate(f"R4 alarms above {cusum_threshold:g}", xy=(0.0, cusum_threshold),
                     xycoords=("axes fraction", "data"),
                     xytext=(2, 3), textcoords="offset points",
                     fontsize=figstyle.TYPE.note, color=figstyle.STATUS["danger"])
        ax2.set_ylim(0, max(max(cusum) * 1.25, cusum_threshold * 1.35))
        figstyle.style(ax2, xlabel="time (s)", ylabel="R4 statistic")

    outcome = _outcome_note(run, unguarded, safety)
    figstyle.titles(fig, run.scenario.name, run.scenario.description)
    if outcome:
        figstyle.footnote(fig, outcome)

    fig.savefig(path)
    plt.close(fig)
    return path


def _outcome_note(run: RunResult, unguarded: RunResult | None, safety) -> str:
    """The sentence a reader should leave the figure with."""
    peak = max((s.true_level_m for s in run.samples), default=0.0)
    if unguarded is None:
        return f"peak level {peak:.2f} m"
    upeak = max((s.true_level_m for s in unguarded.samples), default=0.0)
    damaged = run.damaged
    udamaged = unguarded.damaged
    if udamaged and not damaged:
        return (f"guarded peak {peak:.2f} m against the {safety.level_max_m:.2f} m limit; "
                f"the same attack reaches {upeak:.2f} m with the guard removed")
    if udamaged and damaged:
        return (f"the attack succeeds either way: {peak:.2f} m guarded, "
                f"{upeak:.2f} m unguarded")
    return f"no damage in either run; guarded peak {peak:.2f} m, unguarded {upeak:.2f} m"


def plot_stealth_sweep(rows: list[dict], path: str | Path) -> Path:
    """Where a patient attacker wins, drawn so the band is visible.

    The previous version of this figure plotted "never detected" as a detection
    delay of zero, which reads as instant detection: exactly backwards, and on
    the one figure whose job is to show the defence failing. Detection outcome
    is categorical, so it is drawn as a category strip under the damage curve
    rather than forced onto a numeric axis it does not belong on.
    """
    figstyle.apply()

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    rows = sorted(rows, key=lambda r: r["rate_mm_s"])
    rates = [r["rate_mm_s"] for r in rows]
    limit = rows[0]["level_max_m"]
    guarded = [r["guarded_max_level_m"] for r in rows]
    unguarded = [r["unguarded_max_level_m"] for r in rows]

    def state(row: dict) -> str:
        detected = row["detection_delay_s"] is not None
        damaged = row["guarded_max_level_m"] >= limit - 1e-6
        if damaged and not detected:
            return "wins"
        if damaged:
            return "late"
        if not detected:
            return "harmless"
        return "stopped"

    states = [state(r) for r in rows]
    colours = {"wins": figstyle.STATUS["danger"], "late": figstyle.STATUS["warn"],
               "harmless": figstyle.STATUS["inert"], "stopped": figstyle.STATUS["safe"]}
    captions = {"wins": "not detected,\ndamage", "late": "detected,\ntoo late",
                "harmless": "not detected,\ntoo slow to matter",
                "stopped": "detected,\nprevented"}

    fig, (ax, ax2) = plt.subplots(
        2, 1, figsize=(9.5, 5.4), sharex=True, height_ratios=[4, 1],
        gridspec_kw={"hspace": 0.12},
    )

    # The unguarded run is drawn as a wide soft stroke underneath, because for
    # the slow rates it lies exactly under the guarded one. A same-width line
    # would vanish there and the reader would think the counterfactual only
    # starts where the two separate.
    ax.plot(rates, unguarded, lw=5.0, color=figstyle.COUNTERFACTUAL,
            alpha=0.35, solid_capstyle="round", zorder=2)
    ax.plot(rates, unguarded, lw=1.3, ls=(0, (4, 3)), marker="s", ms=4.5,
            color=figstyle.COUNTERFACTUAL, zorder=3)
    ax.plot(rates, guarded, lw=2.0, marker="o", ms=6, color=figstyle.TRUTH, zorder=5)
    ax.set_xscale("log")
    ax.set_ylim(min(guarded) - 0.08, max(unguarded) + 0.14)

    # Only one thing on this figure is shaded, and it is the finding. The
    # overflow limit gets a ruled line and a word; shading it too would put two
    # different meanings in the same pink.
    ax.axhline(limit, color=figstyle.STATUS["danger"], lw=0.9, alpha=0.5, zorder=1)
    ax.annotate("overflow", xy=(0.0, limit), xycoords=("axes fraction", "data"),
                xytext=(2, 3), textcoords="offset points",
                fontsize=figstyle.TYPE.note, color=figstyle.STATUS["danger"])

    losing = [r for r, s in zip(rates, states) if s in ("wins", "late")]
    if losing:
        figstyle.span(ax, min(losing) * 0.78, max(losing) * 1.28,
                      label="the attack wins here", alpha=0.09)

    figstyle.direct_labels(ax, [
        (guarded[-1], "with the guard", figstyle.TRUTH),
        (unguarded[-1], "guard removed", figstyle.COUNTERFACTUAL),
    ])
    figstyle.style(ax, ylabel="peak level reached (m)")

    # --- outcome strip ---
    # Markers on the shared x axis, and the key on its own row inside the same
    # axes. Hanging the key off the figure in offset points put it through the
    # axis label, then through the footnote; giving it space in the strip means
    # nothing else can move into it.
    for rate, st in zip(rates, states):
        ax2.plot([rate], [0.55], marker="o", ms=11, color=colours[st],
                 markeredgecolor=figstyle.SURFACE, markeredgewidth=1.6, zorder=3)
    ax2.set_ylim(-1.15, 1.0)
    ax2.set_yticks([])
    ax2.set_xscale("log")
    figstyle.style(ax2, xlabel="false-data ramp rate (mm/s, log scale)", grid="none")
    ax2.spines["left"].set_visible(False)

    order = [s for s in ("wins", "late", "harmless", "stopped") if s in states]
    for i, st in enumerate(order):
        x = (i + 0.5) / len(order)
        ax2.annotate(
            "\u25cf  " + captions[st].replace("\n", " "),
            xy=(x, -0.62), xycoords=("axes fraction", "data"),
            ha="center", va="center", fontsize=figstyle.TYPE.note, color=colours[st],
        )

    figstyle.titles(
        fig,
        "The band where a patient attacker wins",
        "Same attack, slower. Each point is one ramp rate; the strip below says "
        "what the guard managed.",
    )
    worst = [r for r, s in zip(rates, states) if s == "wins"]
    if worst:
        figstyle.footnote(
            fig,
            f"at {min(worst):g} mm/s the bias is never detected and the tank still "
            f"overflows; tightening R4 to catch it trades against the false-alarm rate",
        )
    fig.savefig(path)
    plt.close(fig)
    return path


def _yn(value: bool) -> str:
    return "yes" if value else "no"
