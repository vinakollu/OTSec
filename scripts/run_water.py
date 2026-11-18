#!/usr/bin/env python3
"""Run the water treatment works, live, in a browser.

    python3 scripts/run_water.py

This is the water site and nothing else. The storage tank has its own command
(``scripts/run_live_demo.py``) and the two are deliberately not combined: they
are different plants on different timescales, and one page trying to be both
tells you less about either.

The works starts compliant and running itself. Every command its own control
issues crosses the guard, which is the traffic that matters most — a guard
that objects to a plant operating normally is of no use whatever it catches.
From the page you can run any of nine attacks, each the shape of a real
incident, switch the guard between enforcing and watching, and put the works
back where it started.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging
import sys
import webbrowser
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from otguard.live.bus import EventBus                      # noqa: E402
from otguard.live.water_demo import WaterDemo              # noqa: E402
from otguard.live.water_page import WATER_PAGE             # noqa: E402
from otguard.live.web import LiveServer                    # noqa: E402


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--host", default="127.0.0.1",
                   help="interface to bind (default: loopback only)")
    p.add_argument("--port", type=int, default=8701)
    p.add_argument("--speed", type=float, default=30.0,
                   help="simulated seconds per real second (default: 30)")
    p.add_argument("--watch-only", action="store_true",
                   help="start with the guard watching instead of enforcing")
    p.add_argument("--no-browser", action="store_true")
    p.add_argument("--verbose", action="store_true")
    return p.parse_args(argv)


async def run(args: argparse.Namespace) -> int:
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s  %(message)s",
    )
    bus = EventBus()
    demo = WaterDemo(bus, speed=args.speed, enforce=not args.watch_only)
    server = LiveServer(
        bus, host=args.host, port=args.port,
        page=WATER_PAGE, on_command=demo.command,
    )
    await server.start()
    url = f"http://{args.host}:{args.port}/"
    print(f"\n  Riverside water treatment works is live at {url}")
    print("  Nine attacks are on the page. Ctrl-C stops the run.\n")
    if not args.no_browser:
        with contextlib.suppress(Exception):
            webbrowser.open(url)
    await demo.start()
    try:
        await asyncio.Event().wait()
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        await demo.stop()
        await server.stop()
    return 0


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        return asyncio.run(run(args))
    except KeyboardInterrupt:
        print("\n  stopped")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
