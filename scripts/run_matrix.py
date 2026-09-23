#!/usr/bin/env python3
"""Run every attack from every sender against every receiver.

    python scripts/run_matrix.py                    # the whole matrix
    python scripts/run_matrix.py --ablation         # + wire policy on/off
    python scripts/run_matrix.py --scenario overflow --verbose

Every pair runs twice, with the guard enforcing and with it watching but
powerless, so the results can say what would have happened without it.
Episodes run over real TCP sockets on a clock faster than the wall; decision
latency is still measured in wall-clock microseconds.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from otguard.config import load_config  # noqa: E402
from otguard.eval.matrix import (  # noqa: E402
    all_scenarios,
    benign_scenarios,
    run_matrix,
)
from otguard.eval.matrix_report import (  # noqa: E402
    format_ablation,
    format_benign,
    format_matrix,
    format_pairs,
    format_summary,
    write_report,
)
from otguard.modbus.inventory import PERMISSIVE_POLICY  # noqa: E402


async def main_async(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    only = set(args.scenario) if args.scenario else None

    scenarios = all_scenarios()
    if only:
        known = {s.name for s in scenarios}
        missing = only - known
        if missing:
            print(f"unknown scenario(s): {', '.join(sorted(missing))}", file=sys.stderr)
            return 2

    results = await run_matrix(scenarios, config, speed=args.speed, only=only)
    benign = await run_matrix(benign_scenarios(), config, speed=args.speed)

    print(format_summary(results))
    print(format_matrix(results))
    if args.verbose or only:
        print(format_pairs(results))
    print(format_benign(benign))

    ablation = None
    if args.ablation:
        ablation = await run_matrix(
            scenarios, config, policy=PERMISSIVE_POLICY, speed=args.speed, only=only
        )
        print(format_ablation(results, ablation))

    path = write_report(results, benign, args.out, ablation)
    print(f"\nwrote {path}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--config", type=Path, default=None)
    parser.add_argument("--out", type=Path, default=REPO_ROOT / "results")
    parser.add_argument("--scenario", action="append", default=None,
                        help="run only these scenarios (repeatable)")
    parser.add_argument("--ablation", action="store_true",
                        help="also run with the wire policy disabled")
    parser.add_argument("--speed", type=float, default=20.0,
                        help="simulated seconds per wall second")
    parser.add_argument("--verbose", action="store_true",
                        help="print every pair, not just the matrix")
    args = parser.parse_args()
    logging.basicConfig(level=logging.ERROR, format="  %(message)s")
    return asyncio.run(main_async(args))


if __name__ == "__main__":
    raise SystemExit(main())
