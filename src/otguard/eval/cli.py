"""``otguard-eval`` — run the scenario suite and emit the results.

Every scenario is replayed twice: once with the guard enforcing, and once with
it watching but powerless. The second run is what makes "no overflow occurred"
mean something.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ..config import load_config
from ..scenarios import all_scenarios, by_name
from ..scenarios.attacks import stealthy_bias
from .harness import run_scenario
from .metrics import score
from .report import plot_run, plot_stealth_sweep, render_console, write_json

DEFAULT_OUT = Path("results")
SWEEP_RATES_MM_S = [0.2, 0.5, 1.0, 2.0, 3.0, 5.0, 10.0, 20.0, 50.0]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="otguard-eval",
        description="Evaluate the physics-plausibility guard against the scenario suite.",
    )
    parser.add_argument("--config", type=Path, default=None, help="path to a YAML config")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="output directory")
    parser.add_argument(
        "--scenario",
        action="append",
        default=None,
        help="run only this scenario (repeatable)",
    )
    parser.add_argument("--no-plots", action="store_true", help="skip figure generation")
    parser.add_argument(
        "--stealth-sweep",
        action="store_true",
        help="also sweep the stealthy-bias ramp rate to map the detector's blind band",
    )
    parser.add_argument("--quiet", action="store_true", help="only print the JSON path")
    args = parser.parse_args(argv)

    config = load_config(args.config)
    scenarios = (
        [by_name(name) for name in args.scenario] if args.scenario else all_scenarios()
    )

    guarded = [run_scenario(s, config, enforce=True) for s in scenarios]
    unguarded = [run_scenario(s, config, enforce=False) for s in scenarios]
    report = score(guarded, unguarded)

    args.out.mkdir(parents=True, exist_ok=True)
    json_path = write_json(report, args.out / "metrics.json")

    if not args.quiet:
        print(render_console(report))

    if not args.no_plots:
        plots = args.out / "plots"
        by_scenario = {r.scenario.name: r for r in unguarded}
        for run in guarded:
            plot_run(
                run,
                config.safety,
                plots / f"{run.scenario.name}.png",
                unguarded=by_scenario.get(run.scenario.name),
                cusum_threshold=config.guard.consistency.cusum_threshold,
            )
        if not args.quiet:
            print(f"  Plots written to {plots}/")

    if args.stealth_sweep:
        rows = run_stealth_sweep(config)
        (args.out / "stealth_sweep.json").write_text(json.dumps(rows, indent=2))
        if not args.no_plots:
            plot_stealth_sweep(rows, args.out / "plots" / "stealth_sweep.png")
        if not args.quiet:
            print(_render_sweep(rows))

    if not args.quiet:
        print(f"  Metrics written to {json_path}")
    else:
        print(json_path)
    return 0


def run_stealth_sweep(config, rates_mm_s: list[float] | None = None) -> list[dict]:
    """Map ramp rate against detection delay and damage.

    The shape this produces is the point: fast ramps are caught, slow ones are
    harmless, and there is a band in between where the attack both evades R4 and
    does real damage. Quantifying that band is more useful than a single
    detection number, because it tells an asset owner what the guard does and
    does not buy them.
    """
    rows: list[dict] = []
    for rate_mm in rates_mm_s or SWEEP_RATES_MM_S:
        scenario = stealthy_bias(rate_mm / 1000.0)
        g = run_scenario(scenario, config, enforce=True)
        u = run_scenario(scenario, config, enforce=False)
        delay = None
        if g.first_detection_t is not None and scenario.attack_window is not None:
            delay = round(g.first_detection_t - scenario.attack_window[0], 2)
        rows.append(
            {
                "rate_mm_s": rate_mm,
                "detection_delay_s": delay,
                "guarded_max_level_m": round(g.max_level_m, 4),
                "unguarded_max_level_m": round(u.max_level_m, 4),
                "guarded_damaged": g.damaged,
                "unguarded_damaged": u.damaged,
                "level_max_m": config.safety.level_max_m,
            }
        )
    return rows


def _render_sweep(rows: list[dict]) -> str:
    lines = ["", "Stealthy-bias sweep (R4 blind band)", "-" * 78]
    lines.append(
        f"{'rate mm/s':<12}{'detected after':<17}{'peak w/ guard':<16}"
        f"{'peak no guard':<16}{'outcome'}"
    )
    for row in rows:
        delay = "never" if row["detection_delay_s"] is None else f"{row['detection_delay_s']:.1f} s"
        if row["guarded_damaged"]:
            outcome = "ATTACK SUCCEEDS"
        elif row["unguarded_damaged"]:
            outcome = "prevented"
        else:
            outcome = "harmless anyway"
        lines.append(
            f"{row['rate_mm_s']:<12.1f}{delay:<17}{row['guarded_max_level_m']:<16.3f}"
            f"{row['unguarded_max_level_m']:<16.3f}{outcome}"
        )
    lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
