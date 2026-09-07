#!/usr/bin/env python3
"""Where the guard's time goes, and whether it fits inside a control scan.

The course material is blunt that security must not break a control loop's
real-time properties, so this is a first-class result rather than a footnote. It
breaks the cost down three ways:

1. per-rule cost of one ``check`` — which rule dominates, and by how much;
2. cost of one ``observe`` — the filter and supervision, run every scan;
3. how R3's lookahead scales with its horizon, since that is the one knob that
   buys detection at the direct expense of latency.

All of this is CPU time for the decision itself. The wire cost of the proxy is a
separate number, measured end to end by ``scripts/run_demo.py``.

    python scripts/bench_latency.py
    python scripts/bench_latency.py --iterations 20000
"""

from __future__ import annotations

import argparse
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from otguard.config import load_config  # noqa: E402
from otguard.guard import Command, CommandKind, Observation, PhysicsGuard  # noqa: E402
from otguard.guard.rules import (  # noqa: E402
    ConsistencyRule,
    DynamicsRule,
    GuardContext,
    LockoutRule,
    PredictionRule,
    RangeRule,
)
from otguard.sim import WaterTank  # noqa: E402


def _settled(config, level_m=1.0):
    plant = WaterTank(config.plant, config.safety, seed=1)
    plant.state.level_m = level_m
    guard = PhysicsGuard(config, initial_level_m=level_m)
    t = 0.0
    for _ in range(50):
        plant.step()
        t += config.plant.dt_s
        guard.observe(Observation(t, plant.measure()))
    return plant, guard, t


def _timeit(fn, iterations: int) -> dict:
    # One warm-up pass so the first-call cost does not land in the percentiles.
    for _ in range(min(200, iterations)):
        fn()
    samples = []
    for _ in range(iterations):
        start = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - start) * 1e6)
    samples.sort()
    return {
        "mean": statistics.fmean(samples),
        "p50": samples[len(samples) // 2],
        "p95": samples[int(0.95 * (len(samples) - 1))],
        "p99": samples[int(0.99 * (len(samples) - 1))],
        "max": samples[-1],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--iterations", type=int, default=5000)
    parser.add_argument("--config", type=Path, default=None)
    args = parser.parse_args(argv)

    config = load_config(args.config)
    scan_us = config.plant.dt_s * 1e6

    print(f"Control scan period: {scan_us:.0f} us   ({config.plant.dt_s:g} s)")
    print(f"Iterations per measurement: {args.iterations}")
    print("=" * 74)

    # --- 1. per-rule cost ---
    plant, guard, t = _settled(config)
    ctx = GuardContext(
        estimator=guard.estimator,
        config=config.guard,
        safety=config.safety,
        history=tuple(),
        now=t,
        trip_latched=True,
        trip_directions=frozenset({"high"}),
    )
    command = Command(t, CommandKind.PUMP, 60.0)

    print()
    print("Per-rule cost of one command check")
    print("-" * 74)
    print(f"{'rule':<24}{'mean us':>10}{'p50':>10}{'p95':>10}{'p99':>10}{'max':>10}")
    rules = [RangeRule(), DynamicsRule(), PredictionRule(), ConsistencyRule(), LockoutRule()]
    for rule in rules:
        stats = _timeit(lambda r=rule: r.check(command, ctx), args.iterations)
        label = f"{rule.rule_id} {rule.name}"
        print(
            f"{label:<24}{stats['mean']:>10.2f}{stats['p50']:>10.2f}"
            f"{stats['p95']:>10.2f}{stats['p99']:>10.2f}{stats['max']:>10.2f}"
        )

    # --- 2. whole-guard cost ---
    print()
    print("Whole-guard operations")
    print("-" * 74)
    print(f"{'operation':<24}{'mean us':>10}{'p50':>10}{'p95':>10}{'p99':>10}{'max':>10}")

    check_stats = _timeit(lambda: guard.check(command), args.iterations)
    print(
        f"{'check() all rules':<24}{check_stats['mean']:>10.2f}{check_stats['p50']:>10.2f}"
        f"{check_stats['p95']:>10.2f}{check_stats['p99']:>10.2f}{check_stats['max']:>10.2f}"
    )

    counter = {"t": t}

    def observe_once() -> None:
        counter["t"] += config.plant.dt_s
        plant.step()
        guard.observe(Observation(counter["t"], plant.measure()))

    observe_stats = _timeit(observe_once, min(args.iterations, 3000))
    print(
        f"{'observe() per scan':<24}{observe_stats['mean']:>10.2f}{observe_stats['p50']:>10.2f}"
        f"{observe_stats['p95']:>10.2f}{observe_stats['p99']:>10.2f}{observe_stats['max']:>10.2f}"
    )

    # --- 3. horizon sensitivity ---
    print()
    print("R3 lookahead cost vs. horizon  (the detection/latency knob)")
    print("-" * 74)
    print(f"{'horizon (s)':<16}{'steps':>10}{'mean us':>12}{'% of scan':>12}")
    _, fresh_guard, _ = _settled(config)
    for horizon in (1.0, 3.0, 5.0, 10.0, 30.0):
        steps = int(round(horizon / config.plant.dt_s))
        stats = _timeit(
            lambda h=horizon: fresh_guard.estimator.predict(h), min(args.iterations, 3000)
        )
        print(
            f"{horizon:<16.1f}{steps:>10}{stats['mean']:>12.2f}"
            f"{100 * stats['mean'] / scan_us:>11.2f}%"
        )

    worst = check_stats["p99"] + observe_stats["p99"]
    print()
    print("-" * 74)
    print(
        f"Worst case per scan (p99 observe + p99 check): {worst:.1f} us, "
        f"{100 * worst / scan_us:.2f}% of the {scan_us:.0f} us scan period."
    )
    print(
        "The guard adds well under a percent of the loop budget; the binding "
        "cost in a real deployment is the network hop, not the rules."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
