#!/usr/bin/env python3
"""Run the incident catalogue and write the coverage report.

    python scripts/run_incidents.py                 # tank and site evidence only
    python scripts/run_incidents.py --matrix        # also the device-matrix pairs
    python scripts/run_incidents.py --only oldsmar triton

The matrix pairs run over real TCP sockets, so they take a few seconds each and
are off by default. The OPC UA cells are read from ``results/opcua_metrics.json``
if ``scripts/run_opcua.py`` has been run; otherwise those rows say so rather
than reading as misses.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from otguard.config import load_config                        # noqa: E402
from otguard.eval.incident_report import plot_coverage, render  # noqa: E402
from otguard.eval.incidents import run_incidents, write_report  # noqa: E402
from otguard.scenarios.incidents import INCIDENTS              # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=None)
    parser.add_argument("--out", type=Path, default=Path("results/incidents"))
    parser.add_argument("--matrix", action="store_true",
                        help="also run the device-matrix pairs (slower, real sockets)")
    parser.add_argument("--opcua-metrics", type=Path,
                        default=Path("results/opcua/opcua_metrics.json"))
    parser.add_argument("--only", nargs="+", default=None,
                        help="incident keys to run")
    parser.add_argument("--no-figure", action="store_true")
    args = parser.parse_args(argv)

    config = load_config(args.config) if args.config else load_config()
    incidents = INCIDENTS
    if args.only:
        wanted = set(args.only)
        incidents = tuple(i for i in INCIDENTS if i.key in wanted)
        missing = wanted - {i.key for i in incidents}
        if missing:
            parser.error(f"unknown incident keys: {', '.join(sorted(missing))}")

    results = asyncio.run(run_incidents(
        config,
        incidents,
        include_matrix=args.matrix,
        opcua_metrics_path=args.opcua_metrics,
    ))

    print(render(results))
    path = write_report(results, args.out)
    print(f"\nwrote {path}")
    if not args.no_figure:
        figure = plot_coverage(results, args.out / "incident_coverage.png")
        print(f"wrote {figure}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
