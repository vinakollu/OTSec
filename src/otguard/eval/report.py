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
    """Draw one scenario's level trace, sensor view, and guard interventions."""
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    t = [s.t for s in run.samples]
    fig, (ax, ax2) = plt.subplots(
        2, 1, figsize=(10, 6.5), sharex=True, height_ratios=[3, 1]
    )

    # --- level traces ---
    ax.plot(t, [s.true_level_m for s in run.samples], label="true level", lw=2, color="#1f77b4")
    reported = [s.reported_level_m for s in run.samples]
    if any(abs(a - b.true_level_m) > 1e-6 for a, b in zip(reported, run.samples)):
        ax.plot(t, reported, label="reported to HMI", lw=1.4, ls="--", color="#d62728")
    ax.plot(
        t,
        [s.estimated_level_m for s in run.samples],
        label="guard estimate",
        lw=1.2,
        ls=":",
        color="#2ca02c",
    )
    if unguarded is not None:
        ax.plot(
            [s.t for s in unguarded.samples],
            [s.true_level_m for s in unguarded.samples],
            label="true level, guard disabled",
            lw=1.4,
            ls="-.",
            color="#7f7f7f",
            alpha=0.85,
        )

    ax.axhline(safety.level_max_m, color="k", ls="--", lw=1, alpha=0.6)
    ax.axhline(safety.level_min_m, color="k", ls="--", lw=1, alpha=0.6)
    ax.text(t[0], safety.level_max_m, " overflow limit", va="bottom", fontsize=8, alpha=0.7)
    ax.text(t[0], safety.level_min_m, " dry-out limit", va="top", fontsize=8, alpha=0.7)

    if run.scenario.attack_window is not None:
        start, end = run.scenario.attack_window
        ax.axvspan(start, min(end, t[-1]), color="#d62728", alpha=0.07, label="attack window")

    for verdict, _ in run.verdicts:
        if not verdict.allowed:
            ax.axvline(verdict.command.t, color="#ff7f0e", alpha=0.35, lw=0.8)
    for event in run.supervision_events:
        if event.action is not None:
            ax.axvline(event.t, color="#9467bd", lw=1.6, ls="-")
            ax.plot([event.t], [safety.level_max_m], marker="v", color="#9467bd", ms=8)

    ax.set_ylabel("level (m)")
    ax.set_title(f"{run.scenario.name} — {run.scenario.description}", fontsize=10)
    ax.legend(loc="best", fontsize=8, ncol=2)
    ax.grid(alpha=0.25)

    # --- detector statistic ---
    ax2.plot(t, [s.cusum for s in run.samples], color="#8c564b", lw=1.2)
    ax2.axhline(cusum_threshold, color="k", ls="--", lw=1, alpha=0.5)
    ax2.set_ylabel("R4 CUSUM")
    ax2.set_xlabel("time (s)")
    ax2.set_yscale("symlog", linthresh=10)
    ax2.grid(alpha=0.25)

    fig.tight_layout()
    fig.savefig(path, dpi=130)
    plt.close(fig)
    return path


def plot_stealth_sweep(rows: list[dict], path: str | Path) -> Path:
    """Attacker ramp rate vs. detection delay and peak level reached."""
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    rates = [r["rate_mm_s"] for r in rows]
    fig, (ax, ax2) = plt.subplots(1, 2, figsize=(11, 4.2))

    detected = [r["detection_delay_s"] for r in rows]
    ax.plot(rates, [d if d is not None else float("nan") for d in detected], "o-", color="#1f77b4")
    for r, d in zip(rates, detected):
        if d is None:
            ax.plot([r], [0], marker="x", ms=10, color="#d62728")
    ax.set_xscale("log")
    ax.set_xlabel("bias ramp rate (mm/s)")
    ax.set_ylabel("detection delay (s)")
    ax.set_title("R4 detection delay\n(x = never detected)", fontsize=10)
    ax.grid(alpha=0.3)

    ax2.plot(rates, [r["guarded_max_level_m"] for r in rows], "o-", label="with guard", color="#2ca02c")
    ax2.plot(rates, [r["unguarded_max_level_m"] for r in rows], "s--", label="no guard", color="#7f7f7f")
    ax2.axhline(rows[0]["level_max_m"], color="k", ls="--", lw=1, alpha=0.6)
    ax2.set_xscale("log")
    ax2.set_xlabel("bias ramp rate (mm/s)")
    ax2.set_ylabel("peak true level (m)")
    ax2.set_title("Damage reached\n(above the dashed line = overflow)", fontsize=10)
    ax2.legend(fontsize=8)
    ax2.grid(alpha=0.3)

    fig.tight_layout()
    fig.savefig(path, dpi=130)
    plt.close(fig)
    return path


def _yn(value: bool) -> str:
    return "yes" if value else "no"
