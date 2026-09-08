"""Text tables and figures for the storage-site evaluation."""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from .site_harness import SiteRunResult  # noqa: E402
from .site_metrics import SiteReport  # noqa: E402
from .site_sweeps import SweepPoint  # noqa: E402

# One colour per measurement source, used consistently across every figure so
# that the reader learns the mapping once.
SOURCE_COLOURS = {
    "poi_meter": "#c2410c",
    "telemetry": "#1d4ed8",
    "relay": "#047857",
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
    ax.set_title(title, fontsize=11, loc="left")
    ax.set_xlabel(xlabel, fontsize=9)
    ax.set_ylabel(ylabel, fontsize=9)
    ax.grid(True, alpha=0.25, linewidth=0.6)
    ax.tick_params(labelsize=8)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)


def plot_scenario(run: SiteRunResult, path: Path) -> None:
    """Three stacked panels: the three power measurements, SoC, temperature."""
    if not run.samples:
        return
    t = [s.t for s in run.samples]
    fig, axes = plt.subplots(3, 1, figsize=(9, 8), sharex=True)

    ax = axes[0]
    ax.plot(t, [s.p_poi_true_mw for s in run.samples], color="#111827",
            linewidth=1.6, label="true POI power")
    ax.plot(t, [s.p_poi_reported_mw for s in run.samples],
            color=SOURCE_COLOURS["poi_meter"], linewidth=1.0, linestyle="--",
            label="revenue meter")
    ax.plot(t, [s.p_relay_mw for s in run.samples],
            color=SOURCE_COLOURS["relay"], linewidth=1.0, linestyle=":", label="relay CT")
    ax.plot(t, [s.p_telemetry_mw for s in run.samples],
            color=SOURCE_COLOURS["telemetry"], linewidth=1.0, alpha=0.7,
            label="telemetry sum (LV bus)")
    if run.first_detection_t is not None:
        ax.axvline(run.first_detection_t, color="#b91c1c", linewidth=1.0)
        ax.annotate("first objection", (run.first_detection_t, ax.get_ylim()[1]),
                    fontsize=8, color="#b91c1c", ha="left", va="top",
                    xytext=(4, -4), textcoords="offset points")
    _style(ax, f"{run.scenario.name} — site power", "", "MW")
    ax.legend(fontsize=7, frameon=False, ncol=2)

    ax = axes[1]
    ax.plot(t, [s.min_soc * 100 for s in run.samples], color="#1d4ed8", linewidth=1.4)
    _style(ax, "Lowest state of charge in the fleet", "", "%")

    ax = axes[2]
    ax.plot(t, [s.max_temp_c for s in run.samples], color="#c2410c", linewidth=1.4)
    _style(ax, "Hottest unit", "time (s)", "deg C")

    fig.tight_layout()
    fig.savefig(path, dpi=130)
    plt.close(fig)


def plot_bias_sweep(points: list[SweepPoint], path: Path) -> None:
    """Displacement at detection against ramp rate — the headline figure."""
    detected = [p for p in points if p.detected]
    if not detected:
        return
    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.semilogx(
        [p.parameter * 1000 for p in detected],
        [p.displacement_at_detection * 1000 for p in detected],
        marker="o", color="#c2410c", linewidth=1.6, markersize=5,
    )
    _style(
        ax,
        "Bias accumulated before the vote objects",
        "meter bias ramp rate (mW/s, log scale)",
        "bias at detection (kW)",
    )
    ax.set_ylim(bottom=0)
    ax.annotate(
        "flat across two orders of magnitude:\nvoting bounds displacement, not rate",
        xy=(0.5, 0.15), xycoords="axes fraction", fontsize=8, color="#374151",
    )
    fig.tight_layout()
    fig.savefig(path, dpi=130)
    plt.close(fig)


def plot_creep_sweep(points: list[SweepPoint], path: Path) -> None:
    fig, ax = plt.subplots(figsize=(8, 4.5))
    colours = ["#b91c1c" if not p.detected else "#1d4ed8" for p in points]
    ax.bar([f"{p.parameter:g}" for p in points],
           [p.peak_excursion for p in points], color=colours, width=0.6)
    _style(
        ax,
        "How far over the export limit a creeping attack gets (red = never detected)",
        "step size (MW per unit per 20 s)",
        "peak MW over export limit",
    )
    fig.tight_layout()
    fig.savefig(path, dpi=130)
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
