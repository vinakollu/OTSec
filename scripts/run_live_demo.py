#!/usr/bin/env python3
"""The interactive live demonstration, in a browser, driven by you.

    python scripts/run_live_demo.py
    python scripts/run_live_demo.py --device drives
    python scripts/run_live_demo.py --speed 2 --port 9000

``run_live.py`` plays two scripted scenarios and narrates them. This one stands
the stack up and leaves it running with ordinary traffic flowing, and waits.
An attack happens when you launch one, the guard stops enforcing when you say
so, and the link to the device goes down when you cut it.

What runs is the stack the device matrix measures: a simulated field device,
the guard in front of it, and five masters speaking Modbus over loopback.
Nothing is mocked and nothing is pre-recorded. The scanner probes the device
and the guard throughout, so the page can say whether each is answering.

The page draws the topology, animates every frame across the wire in the
colour of the verdict it got, and fills three charts as the plant moves.

It binds loopback and has no authentication, and anything the page can ask for
changes the plant it is showing. Present from it; do not expose it.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from otguard.config import load_config                 # noqa: E402
from otguard.live import EventBus, LiveServer          # noqa: E402
from otguard.live.demo import InteractiveDemo          # noqa: E402
from otguard.live.demo_page import DEMO_PAGE           # noqa: E402
from otguard.modbus.field_devices import EXECUTORS     # noqa: E402


async def serve(args: argparse.Namespace) -> int:
    config = load_config(args.config) if args.config else load_config()
    bus = EventBus()
    demo = InteractiveDemo(
        config, bus,
        executor=args.device,
        speed=args.speed,
        initial_level_m=args.level,
        enforce=not args.start_unguarded,
    )
    server = LiveServer(bus, host=args.host, port=args.port,
                        page=DEMO_PAGE, on_command=demo.command)

    await demo.start()
    await server.start()
    print(f"\n  OTGuard live demo   {server.url}")
    print(f"  device {args.device} · clock {args.speed:g}x · "
          f"{'enforcing' if not args.start_unguarded else 'NOT enforcing'}")
    print("  Launch an attack from the page. Ctrl-C to stop.\n")

    try:
        await asyncio.Event().wait()
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        await server.stop()
        await demo.stop()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device", choices=sorted(EXECUTORS), default="plc",
                        help="which field device sits behind the guard")
    parser.add_argument("--speed", type=float, default=1.0,
                        help="simulated seconds per wall second")
    parser.add_argument("--level", type=float, default=1.30,
                        help="starting tank level in metres")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765, help="0 picks a free port")
    parser.add_argument("--start-unguarded", action="store_true",
                        help="begin with the guard watching but powerless")
    parser.add_argument("--config", type=Path, default=None)
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING,
                        format="%(levelname)-8s %(message)s")
    try:
        return asyncio.run(serve(args))
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
