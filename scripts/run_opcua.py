#!/usr/bin/env python3
"""Run the OPC UA security-mode experiment.

    python scripts/run_opcua.py
    python scripts/run_opcua.py --modes None SignAndEncrypt
    python scripts/run_opcua.py --scenarios none overflow setpoint_jump

Each cell runs a real OPC UA session over a loopback socket, through the guard,
with a secure-channel handshake per episode. The full set is forty-two episodes
and takes several minutes; ``--scenarios`` and ``--modes`` cut it down.

Unlike the in-process evaluation this is not reproducible to the sample. It
runs over real sockets at a scaled clock, so the number of writes an episode
produces moves by a few either way between runs, exactly as the device matrix
does. The outcomes are stable; the counts are not.

Certificates are generated on first use into ``--cert-dir`` and reused after
that. They are self-signed test fixtures and nothing validates a chain.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from otguard.config import load_config                              # noqa: E402
from otguard.eval.opcua_experiment import MODES, SCENARIOS, run_experiment  # noqa: E402
from otguard.eval.opcua_report import (                                  # noqa: E402
    load_pairs, plot_experiment, render, write_report,
)
from otguard.opcua.framing import SecurityMode                      # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=None)
    parser.add_argument("--out", type=Path, default=Path("results/opcua"))
    parser.add_argument("--cert-dir", type=Path, default=Path("results/opcua/certs"))
    parser.add_argument("--scenarios", nargs="+", default=list(SCENARIOS))
    parser.add_argument("--modes", nargs="+", default=[m.value for m in MODES],
                        choices=[m.value for m in SecurityMode])
    parser.add_argument("--speed", type=float, default=20.0,
                        help="simulated seconds per wall second")
    parser.add_argument("--no-figure", action="store_true")
    parser.add_argument("--from-metrics", type=Path, default=None,
                        help="redraw the tables and figure from a saved run "
                             "instead of running the episodes again")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO if args.verbose else logging.ERROR)
    if not args.verbose:
        # Cutting a channel is one of the refusals under test, and a client
        # whose channel has just been cut cannot close its session politely.
        # asyncua logs the resulting timeout with a full traceback, once per
        # severed episode, which buries the report under expected noise.
        logging.getLogger("asyncua.client.client").setLevel(logging.CRITICAL)
    unknown = set(args.scenarios) - set(SCENARIOS)
    if unknown:
        parser.error(f"unknown scenarios: {', '.join(sorted(unknown))}")

    if args.from_metrics is not None:
        if not args.from_metrics.exists():
            parser.error(f"no saved run at {args.from_metrics}")
        pairs = load_pairs(args.from_metrics)
        print(render(pairs))
        if not args.no_figure:
            print(f"\nwrote {plot_experiment(pairs, args.out / 'opcua_modes.png')}")
        return 0

    config = load_config(args.config) if args.config else load_config()
    modes = tuple(SecurityMode(m) for m in args.modes)

    pairs = asyncio.run(run_experiment(
        config, args.cert_dir,
        scenarios=tuple(args.scenarios),
        modes=modes,
        speed=args.speed,
    ))

    failures = [c for p in pairs for c in (p.guarded, p.unguarded) if c.error]
    print(render(pairs))
    if failures:
        print("\nEpisodes that failed to run")
        print("-" * 96)
        for cell in failures:
            print(f"  {cell.scenario}/{cell.mode.value}/"
                  f"{'enforcing' if cell.enforced else 'powerless'}: {cell.error}")

    path = write_report(pairs, args.out)
    print(f"\nwrote {path}")
    if not args.no_figure:
        figure = plot_experiment(pairs, args.out / "opcua_modes.png")
        print(f"wrote {figure}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
