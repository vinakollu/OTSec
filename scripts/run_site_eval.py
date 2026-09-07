#!/usr/bin/env python3
"""Run the storage-site evaluation and write the numbers and figures.

    python scripts/run_site_eval.py                 # the suite
    python scripts/run_site_eval.py --sweeps        # + the boundary experiments
    python scripts/run_site_eval.py --scenario soc_spoof --verbose

Every scenario runs twice, enforcing and not, so the results table can say what
would have happened without the guard. That column is the difference between a
result and an assertion.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from otguard.config import load_config  # noqa: E402
from otguard.eval.site_harness import run_site_scenario  # noqa: E402
from otguard.eval.site_metrics import score_site  # noqa: E402
from otguard.eval.site_report import (  # noqa: E402
    format_scenarios,
    format_summary,
    format_sweep_bias,
    format_sweep_creep,
    format_sweep_soc,
    plot_bias_sweep,
    plot_creep_sweep,
    write_report,
)
from otguard.eval.site_sweeps import (  # noqa: E402
    sweep_dispatch_creep,
    sweep_meter_bias,
    sweep_soc_offset,
)
from otguard.scenarios.bess_attacks import all_attacks  # noqa: E402
from otguard.scenarios.bess_normal import all_normal  # noqa: E402

BIAS_RATES = [0.0002, 0.0005, 0.001, 0.002, 0.005, 0.01, 0.05]
CREEP_STEPS = [0.002, 0.005, 0.01, 0.02, 0.05, 0.10, 0.20]
SOC_OFFSETS = [0.02, 0.04, 0.06, 0.10, 0.15, 0.25]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=None)
    parser.add_argument("--out", type=Path, default=REPO_ROOT / "results")
    parser.add_argument("--scenario", action="append", default=None,
                        help="run only these scenarios (repeatable)")
    parser.add_argument("--sweeps", action="store_true",
                        help="also run the boundary experiments")
    parser.add_argument("--no-figures", action="store_true")
    parser.add_argument("--verbose", action="store_true",
                        help="print every finding, not just the tables")
    args = parser.parse_args()

    config = load_config(args.config)
    scenarios = all_attacks() + all_normal()
    if args.scenario:
        wanted = set(args.scenario)
        scenarios = [s for s in scenarios if s.name in wanted]
        missing = wanted - {s.name for s in scenarios}
        if missing:
            parser.error(f"unknown scenario(s): {', '.join(sorted(missing))}")

    guarded, unguarded = [], []
    for scenario in scenarios:
        guarded.append(run_site_scenario(scenario, config, enforce=True))
        unguarded.append(run_site_scenario(scenario, config, enforce=False))

    report = score_site(guarded, unguarded)
    print(format_summary(report))
    print(format_scenarios(report))

    if args.verbose:
        for run in guarded:
            findings = [
                (v.command, f)
                for v, _ in run.verdicts
                for f in v.findings
            ] + [
                (None, f) for e in run.supervision_events for f in e.findings
            ]
            if not findings:
                continue
            print(f"--- {run.scenario.name} ---")
            for command, finding in findings[:8]:
                where = str(command) if command is not None else "(supervision)"
                print(f"  {where}\n      {finding}")
            print()

    sweeps = None
    if args.sweeps:
        bias = sweep_meter_bias(config, BIAS_RATES)
        control = sweep_meter_bias(config, [0.001, 0.002], voting=False)
        creep = sweep_dispatch_creep(config, CREEP_STEPS)
        held = sweep_soc_offset(config, SOC_OFFSETS, transient=False)
        transient = sweep_soc_offset(config, SOC_OFFSETS, transient=True)

        print(format_sweep_bias(bias, control))
        print(format_sweep_creep(creep))
        print(format_sweep_soc(held, transient))

        sweeps = {
            "meter_bias": [vars(p) for p in bias],
            "meter_bias_no_voting": [vars(p) for p in control],
            "dispatch_creep": [vars(p) for p in creep],
            "soc_offset_held": [vars(p) for p in held],
            "soc_offset_transient": [vars(p) for p in transient],
        }
        if not args.no_figures:
            plots = args.out / "plots"
            plots.mkdir(parents=True, exist_ok=True)
            plot_bias_sweep(bias, plots / "site_bias_sweep.png")
            plot_creep_sweep(creep, plots / "site_creep_sweep.png")

    write_report(
        report,
        [] if args.no_figures else guarded,
        args.out,
        sweeps=sweeps,
    )
    print(f"wrote {args.out / 'site_metrics.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
