"""Text tables and figures for the storage-site evaluation."""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from . import figstyle  # noqa: E402
from .site_harness import SiteRunResult  # noqa: E402
from .site_metrics import SiteReport  # noqa: E402
from .site_sweeps import SweepPoint  # noqa: E402

# One colour per measurement source, used consistently across every figure so
# that the reader learns the mapping once. These are the project's categorical
# slots, so the tank figures and the site figures agree on what blue means.
SOURCE_COLOURS = {
    "poi_meter": figstyle.SERIES["sensor"],
    "telemetry": figstyle.SERIES["estimate"],
    "relay": figstyle.SERIES["third"],
}


def format_summary(report: SiteReport) -> str:
    """The headline table."""
    s = report.scenarios
    c = report.commands
    b = report.benign_traffic
    lat = report.latency.as_dict()

    lines = [
        "Storage-site evaluation",
        "=" * 78,
        f"  Attacks detected            {s.attacks_detected}/{s.attacks}"
        f"  ({s.detection_rate * 100:.1f}%)",
        f"  Damage avoidance            {s.attacks_damage_avoided}/"
        f"{s.attacks_damaging_unguarded}"
        f"  ({s.damage_avoidance * 100:.1f}% of attacks that damaged the site unguarded)",
        f"  Benign scenarios clean      {s.benign - s.benign_with_any_flag}/{s.benign}",
        f"  Benign writes flagged       {b.benign_flagged}/{b.benign_total}"
        f"  ({b.false_positive_rate * 100:.2f}%)",
        f"  Whole-suite benign writes   {c.benign_flagged}/{c.benign_total}"
        f"  ({c.false_positive_rate * 100:.2f}%)",
    ]
    if s.source_attributions:
        lines.append(
            f"  Lying source named right    {s.source_attributions_correct}/"
            f"{s.source_attributions}"
        )
    lines += [
        f"  Decision latency            p50 {lat['p50_us']:.0f} us,"
        f" p95 {lat['p95_us']:.0f} us, p99 {lat['p99_us']:.0f} us"
        f"  (n={lat['count']})",
        "",
    ]
    return "\n".join(lines)


def format_scenarios(report: SiteReport) -> str:
    """Per-scenario detail, attacks first."""
    header = (
        f"{'scenario':<28}{'detect':>9}{'damage':>9}{'unguard':>9}"
        f"{'peak POI':>10}{'unguard':>9}  rules"
    )
    lines = [header, "-" * len(header) + "------"]

    for row in report.per_scenario:
        if row["category"] != "attack":
            continue
        detect = f"{row['first_detection_s']:.0f}s" if row["detected"] else "MISSED"
        lines.append(
            f"{row['name']:<28}{detect:>9}"
            f"{('yes' if row['damaged'] else 'no'):>9}"
            f"{('yes' if row.get('unguarded_damaged') else 'no'):>9}"
            f"{row['peak_poi_mw']:>10.1f}"
            f"{row.get('unguarded_peak_poi_mw', 0.0):>9.1f}"
            f"  {','.join(row['rules_fired'])}"
        )

    lines += ["", f"{'benign scenario':<28}{'writes':>9}{'flagged':>9}{'blocked':>9}  rules"]
    lines.append("-" * len(header) + "------")
    for row in report.per_scenario:
        if row["category"] == "attack":
            continue
        lines.append(
            f"{row['name']:<28}{row['commands']:>9}"
            f"{row['supervision_events']:>9}{row['blocked']:>9}"
            f"  {','.join(row['rules_fired'])}"
        )
    return "\n".join(lines) + "\n"


def format_sweep_bias(points: list[SweepPoint], control: list[SweepPoint] | None = None) -> str:
    """The cross-source result, formatted to make the claim checkable."""
    lines = [
        "Cross-source voting against a biased revenue meter",
        "-" * 78,
        "The column that matters is displacement, not time: if voting bounds how far",
        "an attacker can move a measurement rather than how fast, it stays roughly",
        "flat as the ramp rate changes by orders of magnitude.",
        "",
        f"{'ramp (mW/s)':>13}{'detected':>12}{'bias then':>13}  named source",
    ]
    for p in points:
        detected = f"{p.detected_at_s:.0f}s" if p.detected else "never"
        bias = f"{p.displacement_at_detection * 1000:.0f} kW" if p.detected else "-"
        lines.append(f"{p.parameter * 1000:>13.2f}{detected:>12}{bias:>13}  {p.named_source or '-'}")

    if control:
        lines += ["", "Control — the same attack with voting disabled:"]
        for p in control:
            lines.append(
                f"{p.parameter * 1000:>13.2f}"
                f"{('detected' if p.detected else 'never'):>12}"
            )
    return "\n".join(lines) + "\n"


def format_sweep_creep(points: list[SweepPoint]) -> str:
    lines = [
        "Dispatch creep against B3's incremental test",
        "-" * 78,
        "B3 objects only when a command makes an existing excursion worse, which is",
        "what stops it blocking a recovery. That is also an escape hatch, and this is",
        "where it opens.",
        "",
        f"{'step MW/unit':>14}{'detected':>11}{'peak MW over limit':>21}  rules",
    ]
    for p in points:
        detected = f"{p.detected_at_s:.0f}s" if p.detected else "never"
        lines.append(
            f"{p.parameter:>14.3f}{detected:>11}{p.peak_excursion:>21.2f}"
            f"  {','.join(p.rules) or '-'}"
        )
    return "\n".join(lines) + "\n"


def format_sweep_soc(held: list[SweepPoint], transient: list[SweepPoint]) -> str:
    lines = [
        "B2: a battery-management re-anchor against a sustained spoof",
        "-" * 78,
        "Both are a step followed by an offset. What separates them is persistence,",
        "not size — the CUSUM only accumulates while the disagreement continues.",
        "",
        f"{'offset':>9}{'held (spoof)':>16}{'one sample (re-anchor)':>26}",
    ]
    for h, t in zip(held, transient):
        lines.append(
            f"{h.parameter * 100:>8.0f}%"
            f"{(f'latch @{h.detected_at_s:.0f}s' if h.detected else 'missed'):>16}"
            f"{('latched (false alarm)' if t.detected else 'clean'):>26}"
        )
    return "\n".join(lines) + "\n"


# ----------------------------------------------------------------------
# Figures
# ----------------------------------------------------------------------


def _style(ax, title: str, xlabel: str, ylabel: str) -> None:
    if title:
        ax.set_title(title, fontsize=figstyle.TYPE.subtitle, loc="left",
                     color=figstyle.INK, pad=6)
    figstyle.style(ax, xlabel=xlabel, ylabel=ylabel)


def plot_scenario(run: SiteRunResult, path: Path) -> None:
    """Three stacked panels: the three power measurements, charge, temperature."""
    if not run.samples:
        return
    figstyle.apply()

    t = [s.t for s in run.samples]
    fig, axes = plt.subplots(3, 1, figsize=(9.5, 7.4), sharex=True,
                             height_ratios=[2.2, 1, 1],
                             gridspec_kw={"hspace": 0.28})

    # --- the three measurements of the same power ---
    ax = axes[0]
    ax.plot(t, [s.p_poi_true_mw for s in run.samples],
            color=figstyle.TRUTH, linewidth=2.0, zorder=5)
    ax.plot(t, [s.p_poi_reported_mw for s in run.samples],
            color=SOURCE_COLOURS["poi_meter"], linewidth=1.3,
            linestyle=(0, (1.5, 1.5)), zorder=4)
    ax.plot(t, [s.p_relay_mw for s in run.samples],
            color=SOURCE_COLOURS["relay"], linewidth=1.2,
            linestyle=(0, (4, 2)), zorder=3)
    ax.plot(t, [s.p_telemetry_mw for s in run.samples],
            color=SOURCE_COLOURS["telemetry"], linewidth=1.2, alpha=0.85, zorder=3)
    _style(ax, "Site power, as each instrument sees it", "", "MW")
    figstyle.direct_labels(ax, [
        (run.samples[-1].p_poi_true_mw, "true", figstyle.TRUTH),
        (run.samples[-1].p_poi_reported_mw, "revenue meter", SOURCE_COLOURS["poi_meter"]),
        (run.samples[-1].p_relay_mw, "relay CT", SOURCE_COLOURS["relay"]),
        (run.samples[-1].p_telemetry_mw, "telemetry sum", SOURCE_COLOURS["telemetry"]),
    ])
    if run.first_detection_t is not None:
        ax.axvline(run.first_detection_t, color=figstyle.STATUS["danger"],
                   linewidth=1.0, alpha=0.7, zorder=2)
        # Inside the axes, not above them: the panel title already owns the
        # strip of space directly over the frame.
        ax.annotate("guard objects", xy=(run.first_detection_t, 0.97),
                    xycoords=("data", "axes fraction"),
                    xytext=(4, 0), textcoords="offset points",
                    fontsize=figstyle.TYPE.note, color=figstyle.STATUS["danger"],
                    ha="left", va="top")

    ax = axes[1]
    ax.plot(t, [s.min_soc * 100 for s in run.samples],
            color=figstyle.SERIES["estimate"], linewidth=1.6)
    _style(ax, "Lowest state of charge in the fleet", "", "%")

    ax = axes[2]
    temps = [s.max_temp_c for s in run.samples]
    ax.plot(t, temps, color=figstyle.SERIES["sensor"], linewidth=1.6)
    _style(ax, "Hottest unit", "time (s)", "\u00b0C")

    figstyle.titles(fig, run.scenario.name, run.scenario.description)
    fig.savefig(path)
    plt.close(fig)


def plot_bias_sweep(points: list[SweepPoint], path: Path,
                    control: list[SweepPoint] | None = None) -> None:
    """How far a biased meter gets before the vote objects.

    The previous version of this figure carried the caption "flat across two
    orders of magnitude" over a curve that climbs from 262 to 725 kW, which is
    a 2.8-fold rise and visibly not flat. The claim it was reaching for is
    about the *ratio*: the attacker's rate changes by 250x and the distance
    they achieve changes by 2.8x, so the vote bounds displacement rather than
    speed. That is a comparison between two spans, so the figure now draws
    both spans instead of asserting one in a footnote.
    """
    detected = [p for p in points if p.detected]
    if not detected:
        return
    figstyle.apply()

    rates = [p.parameter * 1000 for p in detected]
    bias = [p.displacement_at_detection * 1000 for p in detected]
    rate_ratio = max(rates) / min(rates)
    bias_ratio = max(bias) / min(bias)

    fig, ax = plt.subplots(figsize=(9.0, 4.8))
    ax.semilogx(rates, bias, marker="o", color=figstyle.SERIES["sensor"],
                linewidth=2.0, markersize=6, zorder=4)

    # The bound itself, drawn as the band the whole curve lives inside.
    ax.axhspan(min(bias), max(bias), color=figstyle.SERIES["sensor"],
               alpha=0.07, zorder=0, lw=0)
    for edge in (min(bias), max(bias)):
        ax.axhline(edge, color=figstyle.SERIES["sensor"], lw=0.8,
                   alpha=0.45, zorder=1)

    ax.set_ylim(0, max(bias) * 1.32)
    _style(ax, "", "meter bias ramp rate (mW/s, log scale)", "bias at detection (kW)")

    figstyle.callout(
        ax, (rates[len(rates) // 2], max(bias)),
        f"every attack is caught inside {min(bias):.0f}\u2013{max(bias):.0f} kW",
        offset=(-10, 34), colour=figstyle.SERIES["sensor"],
    )
    ax.annotate(
        f"rate varies {rate_ratio:.0f}\u00d7   \u2192   displacement varies {bias_ratio:.1f}\u00d7",
        xy=(0.02, 0.06), xycoords="axes fraction",
        fontsize=figstyle.TYPE.note, color=figstyle.INK_2, family=figstyle.MONO,
    )

    if control:
        missed = [p for p in control if not p.detected]
        if missed:
            ax.annotate(
                f"with voting disabled the same attack is never detected "
                f"({len(missed)} of {len(control)} rates tried)",
                xy=(0.02, 0.155), xycoords="axes fraction",
                fontsize=figstyle.TYPE.note, color=figstyle.STATUS["danger"],
            )

    figstyle.titles(
        fig,
        "Cross-source voting bounds how far a meter can drift",
        "Bias accumulated by the time three independent measurements disagree "
        "enough to object.",
    )
    fig.savefig(path)
    plt.close(fig)


def plot_creep_sweep(points: list[SweepPoint], path: Path) -> None:
    """The escape hatch in B3's incremental test, with the sizes named."""
    figstyle.apply()
    fig, ax = plt.subplots(figsize=(9.0, 4.6))

    labels = [f"{p.parameter:g}" for p in points]
    peaks = [p.peak_excursion for p in points]
    colours = [figstyle.STATUS["danger"] if not p.detected else figstyle.SERIES["estimate"]
               for p in points]
    ax.bar(labels, peaks, color=colours, width=0.62, zorder=3)

    for label, peak, point in zip(labels, peaks, points):
        figstyle.value(ax, label, peak, f"{peak:.2f}",
                       colour=figstyle.STATUS["danger"] if not point.detected
                       else figstyle.INK_2)
    ax.set_ylim(0, max(peaks) * 1.22 if max(peaks) else 1.0)
    _style(ax, "", "step size (MW per unit per 20 s)", "peak MW over the export limit")

    # A two-entry key, each dot in its own colour. A single-colour footnote
    # cannot carry a colour key, which is what the previous line tried to do.
    for i, (colour, text) in enumerate((
        (figstyle.STATUS["danger"], "never detected"),
        (figstyle.SERIES["estimate"], "detected"),
    )):
        ax.annotate(f"\u25cf  {text}", xy=(0.0 + i * 0.16, 1.02),
                    xycoords="axes fraction", fontsize=figstyle.TYPE.note,
                    color=colour, ha="left", va="bottom")

    worst = [p for p in points if not p.detected and p.peak_excursion > 0.1]
    if worst:
        figstyle.footnote(
            fig,
            f"the worst undetected case leaves the site "
            f"{max(p.peak_excursion for p in worst):.2f} MW over its export limit",
        )
    figstyle.titles(
        fig,
        "A slow enough ramp walks past the incremental test",
        "B3 objects only when a command makes an existing excursion worse, which "
        "is what stops it blocking a recovery.",
    )
    fig.savefig(path)
    plt.close(fig)


def write_report(
    report: SiteReport,
    runs: list[SiteRunResult],
    out_dir: Path,
    sweeps: dict | None = None,
) -> None:
    """Write metrics JSON and every figure."""
    out_dir.mkdir(parents=True, exist_ok=True)
    plots = out_dir / "plots"
    plots.mkdir(exist_ok=True)

    payload = report.as_dict()
    if sweeps:
        payload["sweeps"] = sweeps
    (out_dir / "site_metrics.json").write_text(json.dumps(payload, indent=2, sort_keys=True))

    for run in runs:
        plot_scenario(run, plots / f"site_{run.scenario.name}.png")
