#!/usr/bin/env python3
"""End-to-end demo: a real attack over real Modbus TCP, through the guard.

Stands up the full stack in one process — simulated PLC, guard proxy, and an
attacker driving a stock ``pymodbus`` client — and runs one attack to
completion, twice: once through the guard and once straight at the PLC. The
second run is the control. Without it, "the tank did not overflow" is not
evidence of anything.

    python scripts/run_demo.py                    # overflow attack
    python scripts/run_demo.py --attack out_of_envelope
    python scripts/run_demo.py --attack water_hammer --verbose

This is also where the *network* cost of the guard is measured. The evaluation
harness reports the rule-evaluation time in isolation; the number that matters
to a plant is the added round-trip on the wire, which is what ``--attack``
prints as "added latency" here.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pymodbus.client import AsyncModbusTcpClient  # noqa: E402

from otguard.config import load_config  # noqa: E402
from otguard.modbus import GuardedModbusProxy, SimulatedPLC  # noqa: E402
from otguard.modbus.registers import (  # noqa: E402
    HR_PUMP_CMD,
    HR_VALVE_CMD,
    IR_LEVEL,
    LEVEL_SCALE,
    PCT_SCALE,
)

ATTACKS = ("overflow", "out_of_envelope", "water_hammer", "dryout")


async def drive_attack(client: AsyncModbusTcpClient, attack: str, duration_s: float) -> None:
    """Play one attack at whatever endpoint the client is pointed at."""
    if attack == "overflow":
        # Individually legal commands; only the consequence is an attack.
        await client.write_register(HR_VALVE_CMD, int(0 * PCT_SCALE))
        await client.write_register(HR_PUMP_CMD, int(100 * PCT_SCALE))
        await asyncio.sleep(duration_s)

    elif attack == "dryout":
        await client.write_register(HR_PUMP_CMD, 0)
        await client.write_register(HR_VALVE_CMD, int(100 * PCT_SCALE))
        await asyncio.sleep(duration_s)

    elif attack == "out_of_envelope":
        for value in (2500, 1800, 0xFF38):  # 250 %, 180 %, and -20 % as a signed word
            await client.write_register(HR_VALVE_CMD, value)
            await asyncio.sleep(0.5)
        await asyncio.sleep(min(duration_s, 5.0))

    elif attack == "water_hammer":
        deadline = asyncio.get_event_loop().time() + min(duration_s, 20.0)
        state = True
        while asyncio.get_event_loop().time() < deadline:
            await client.write_register(HR_VALVE_CMD, int((100 if state else 0) * PCT_SCALE))
            state = not state
            await asyncio.sleep(0.2)

    else:  # pragma: no cover - argparse restricts this
        raise ValueError(f"unknown attack {attack!r}")


async def run_once(
    config,
    attack: str,
    duration_s: float,
    guarded: bool,
) -> dict:
    """Run the attack against the PLC, with or without the guard in the path."""
    plc = SimulatedPLC(config, port=0)
    await plc.start()
    plc.tank.state.level_m = 0.95

    proxy = None
    target_port = plc.port
    if guarded:
        proxy = GuardedModbusProxy(
            config, plc_host="127.0.0.1", plc_port=plc.port, listen_port=0
        )
        await proxy.start()
        target_port = proxy.listen_port

    client = AsyncModbusTcpClient("127.0.0.1", port=target_port)
    await client.connect()
    if not client.connected:
        raise RuntimeError("attacker client could not connect")

    refused = 0
    try:
        await drive_attack(client, attack, duration_s)
    finally:
        # Count how many writes the endpoint refused, as the HMI would see it.
        reading = await client.read_input_registers(IR_LEVEL, count=1)
        final_level = reading.registers[0] / LEVEL_SCALE if not reading.isError() else float("nan")
        client.close()

    result = {
        "guarded": guarded,
        "final_level_m": final_level,
        "true_level_m": plc.tank.state.level_m,
        "overflowed": plc.tank.state.overflowed,
        "dried_out": plc.tank.state.dried_out,
        "scans": plc.scans,
    }
    if proxy is not None:
        result.update(
            blocked=proxy.stats.writes_blocked,
            inspected=proxy.stats.writes_inspected,
            trips=proxy.stats.trips_issued,
            polls=proxy.stats.polls,
            latency_us=list(proxy.stats.wire_latency_us),
        )
        await proxy.stop()
    await plc.stop()
    return result


async def main_async(args: argparse.Namespace) -> int:
    config = load_config(args.config)

    print(f"Attack: {args.attack}   (duration {args.duration:g}s per run)")
    print("=" * 70)

    unguarded = await run_once(config, args.attack, args.duration, guarded=False)
    guarded = await run_once(config, args.attack, args.duration, guarded=True)

    print(f"{'':22}{'no guard':>16}{'through guard':>18}")
    print("-" * 70)
    print(f"{'final true level (m)':22}{unguarded['true_level_m']:>16.3f}"
          f"{guarded['true_level_m']:>18.3f}")
    print(f"{'overflowed':22}{str(unguarded['overflowed']):>16}"
          f"{str(guarded['overflowed']):>18}")
    print(f"{'dried out':22}{str(unguarded['dried_out']):>16}"
          f"{str(guarded['dried_out']):>18}")
    print(f"{'writes blocked':22}{'-':>16}{guarded.get('blocked', 0):>18}")
    print(f"{'protective trips':22}{'-':>16}{guarded.get('trips', 0):>18}")

    latencies = guarded.get("latency_us") or []
    if latencies:
        ordered = sorted(latencies)
        p95 = ordered[min(len(ordered) - 1, int(0.95 * (len(ordered) - 1)))]
        print()
        print(
            f"Added round-trip through the guard: "
            f"median {statistics.median(ordered):.0f} us, "
            f"p95 {p95:.0f} us, max {ordered[-1]:.0f} us "
            f"over {len(ordered)} transactions"
        )

    print()
    damage_stopped = (unguarded["overflowed"] or unguarded["dried_out"]) and not (
        guarded["overflowed"] or guarded["dried_out"]
    )
    print("Result:", "damage prevented" if damage_stopped else
          ("no damage in either run" if not (unguarded["overflowed"] or unguarded["dried_out"])
           else "ATTACK SUCCEEDED THROUGH THE GUARD"))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--attack", choices=ATTACKS, default="overflow")
    parser.add_argument("--duration", type=float, default=40.0, help="seconds to hold the attack")
    parser.add_argument("--config", type=Path, default=None)
    parser.add_argument("--verbose", "-v", action="store_true", help="show guard decisions")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.WARNING if args.verbose else logging.ERROR,
        format="  %(message)s",
    )
    return asyncio.run(main_async(args))


if __name__ == "__main__":
    raise SystemExit(main())
