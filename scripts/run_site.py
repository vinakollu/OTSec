#!/usr/bin/env python3
"""Run the grid storage site, live, in a browser.

    python3 scripts/run_site.py

This is the storage site and nothing else. The treatment works has its own
command (``scripts/run_water.py``) and the two are deliberately not combined:
they are different plants on different timescales, and one page trying to be
both tells you less about either.

The site starts dispatched at about 8 MW with all sixteen units online, three
measurements arriving and the guard enforcing. Every command the site
controller issues crosses the guard, which is the traffic that matters most.
From the page you can change the dispatch, run any of ten attacks, switch the
guard between enforcing and watching, and put the site back where it started.

Two of the ten attacks defeat the guard and say so on their own card. Leaving
them off would make the demonstration a sales pitch.
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
from otguard.live.site_demo import SiteDemo                # noqa: E402
from otguard.live.site_page import SITE_PAGE               # noqa: E402
from otguard.live.web import LiveServer                    # noqa: E402


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--host", default="127.0.0.1",
                   help="interface to bind (default: loopback only)")
    p.add_argument("--port", type=int, default=8702)
    p.add_argument("--speed", type=float, default=10.0,
                   help="simulated seconds per real second (default: 10)")
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
    demo = SiteDemo(bus, speed=args.speed, enforce=not args.watch_only)
    server = LiveServer(bus, host=args.host, port=args.port,
                        page=SITE_PAGE, on_command=demo.command)
    await server.start()
    url = f"http://{args.host}:{args.port}/"
    print(f"\n  Fern Hollow storage site is live at {url}")
    print("  Ten attacks are on the page. Ctrl-C stops the run.\n")
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
