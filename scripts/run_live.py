#!/usr/bin/env python3
"""Watch the guard work, rather than read about it afterwards.

``run_demo.py`` runs an attack to completion in silence and prints a table. It
is the right shape for a result and the wrong shape for understanding what
happened, because everything interesting — the level climbing, the write
arriving, the rule objecting, the guard taking the valve — happens in the
minute you spent looking at a blank terminal.

This runs the same stack and narrates it as it goes, to a terminal that
redraws in place and to a browser page, both fed from one event stream so they
cannot disagree. The device scanner runs alongside, and on the site half its
output is wired into the guard's cross-source vote, which is where it stops
being decoration.

    python scripts/run_live.py                  # tank, then the battery site
    python scripts/run_live.py --only tank
    python scripts/run_live.py --only site
    python scripts/run_live.py --no-web         # terminal only
    python scripts/run_live.py --port 9000

Two scenarios run, in order.

**The tank.** The real stack over real sockets: a simulated controller, the
guard proxy in front of it, and an attacker driving a stock ``pymodbus``
client. Individually legal commands that together fill the tank. The scanner
probes the controller and the guard by reading a register off each.

**The battery site.** Sixteen units, three independent measurements of the
same power, and two of the three measurement links cut while the site ramps
down. It runs twice: once with the scanner telling the guard which
measurements are still arriving, and once without. The second run is the
control, and it is the interesting one — two stale readings agree with each
other, so the majority vote names the one honest instrument as the liar.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pymodbus.client import AsyncModbusTcpClient  # noqa: E402

from otguard.bess.site import BessSite  # noqa: E402
from otguard.bess.types import MeasurementSource  # noqa: E402
from otguard.config import Config, load_config  # noqa: E402
from otguard.guard.site_guard import SiteGuard  # noqa: E402
from otguard.live import EventBus, LiveServer, TerminalView  # noqa: E402
from otguard.live import events as ev  # noqa: E402
from otguard.modbus import GuardedModbusProxy, SimulatedPLC  # noqa: E402
from otguard.modbus.registers import (  # noqa: E402
    HR_PUMP_CMD,
    HR_VALVE_CMD,
    IR_LEVEL,
    LEVEL_SCALE,
    PCT_SCALE,
)
from otguard.scan import Scanner, site_targets, tank_targets  # noqa: E402

ATTACKS = ("overflow", "dryout", "out_of_envelope", "water_hammer")

#: How often the display is refreshed with the plant's state. Fast enough that
#: a tank filling looks like it is filling, slow enough that the feed is
#: readable.
_FRAME_S = 0.2


class Live:
    """The bus, the renderers and the config, carried between scenarios."""

    def __init__(self, config: Config, bus: EventBus, view: TerminalView) -> None:
        self.config = config
        self.bus = bus
        self.view = view

    def emit(self, event) -> None:
        self.bus.publish(event)

    def device_event(self, t: float, status) -> None:
        """Publish one device row out of a scanner status."""
        target = status.target
        self.emit(ev.device(
            t,
            name=status.name,
            state=status.state.value,
            role=target.role,
            zone=target.zone,
            evidence=status.evidence.value,
            networked=target.networked,
            detail=status.detail,
            measurement_source=(
                target.measurement_source.label if target.measurement_source else None
            ),
            critical=target.critical,
            rtt_ms=status.last_rtt_ms,
        ))


# ----------------------------------------------------------------------
# The water tank, over real sockets
# ----------------------------------------------------------------------
async def _drive_attack(client: AsyncModbusTcpClient, attack: str, duration_s: float) -> None:
    """The same attacks ``run_demo.py`` plays, at the same endpoint."""
    if attack == "overflow":
        await client.write_register(HR_VALVE_CMD, 0)
        await client.write_register(HR_PUMP_CMD, int(100 * PCT_SCALE))
        await asyncio.sleep(duration_s)
    elif attack == "dryout":
        await client.write_register(HR_PUMP_CMD, 0)
        await client.write_register(HR_VALVE_CMD, int(100 * PCT_SCALE))
        await asyncio.sleep(duration_s)
    elif attack == "out_of_envelope":
        for value in (2500, 1800, 0xFF38):  # 250 %, 180 %, and -20 % as a signed word
            await client.write_register(HR_VALVE_CMD, value)
            await asyncio.sleep(1.0)
        await asyncio.sleep(min(duration_s, 6.0))
    elif attack == "water_hammer":
        loop = asyncio.get_event_loop()
        deadline = loop.time() + min(duration_s, 20.0)
        state = True
        while loop.time() < deadline:
            await client.write_register(HR_VALVE_CMD, int((100 if state else 0) * PCT_SCALE))
            state = not state
            await asyncio.sleep(0.4)
    else:  # pragma: no cover - argparse restricts this
        raise ValueError(f"unknown attack {attack!r}")


async def tank_scenario(live: Live, attack: str, duration_s: float) -> dict:
    """Stand up the tank stack, run one attack through the guard, narrate it."""
    config = live.config
    plc = SimulatedPLC(config, port=0, initial_level_m=0.95)
    await plc.start()
    proxy = GuardedModbusProxy(config, plc_host="127.0.0.1", plc_port=plc.port, listen_port=0)
    await proxy.start()

    scanner = Scanner(config.scan, targets=tank_targets(
        plc_port=plc.port, proxy_port=proxy.listen_port, timeout_s=config.scan.timeout_s
    ))

    live.emit(ev.scenario(
        0.0, plant="tank", name=attack, guarded=True,
        summary={
            "overflow": "valve shut and pump full: two legal commands that fill the tank",
            "dryout": "pump off and valve open: the tank drains until the pump runs dry",
            "out_of_envelope": "valve positions the equipment cannot physically take",
            "water_hammer": "the valve slammed open and shut until the pipe splits",
        }[attack],
    ))

    stop = asyncio.Event()
    painter = asyncio.create_task(_tank_painter(live, plc, proxy, scanner, stop))

    client = AsyncModbusTcpClient("127.0.0.1", port=proxy.listen_port)
    await client.connect()
    if not client.connected:
        raise RuntimeError("the attacker's client could not reach the guard")
    try:
        await _drive_attack(client, attack, duration_s)
    finally:
        client.close()
        stop.set()
        await painter

    state = plc.tank.state
    damaged = state.overflowed or state.dried_out
    outcome = "the tank was damaged" if damaged else "the tank is intact"
    lines = [
        f"final level {state.level_m:.3f} m",
        f"{proxy.stats.writes_blocked} writes blocked, "
        f"{proxy.stats.trips_issued} protective trips",
        f"{proxy.stats.writes_inspected} writes inspected over "
        f"{proxy.stats.frames_forwarded} frames",
    ]
    live.emit(ev.done(_now(proxy), plant="tank", name=attack, outcome=outcome, lines=lines))

    # The proxy holds a persistent poll connection to the controller, and on
    # 3.12 and later a server's wait_closed() waits for its clients, so the
    # order here is not cosmetic: stopping the controller first hangs.
    await proxy.stop()
    await plc.stop()
    return {"damaged": damaged, "level_m": state.level_m,
            "blocked": proxy.stats.writes_blocked, "trips": proxy.stats.trips_issued}


def _now(proxy: GuardedModbusProxy) -> float:
    return proxy._now()


def _reported_level(plc: SimulatedPLC) -> float:
    """The level as the HMI would read it, noise and all.

    Taken from the input register rather than by calling ``tank.measure()``,
    which would draw fresh noise and show a number nobody on the wire ever saw.
    """
    raw = plc.input[IR_LEVEL]
    if raw >= 0x8000:
        raw -= 0x10000
    return raw / LEVEL_SCALE


async def _tank_painter(
    live: Live, plc: SimulatedPLC, proxy: GuardedModbusProxy, scanner: Scanner,
    stop: asyncio.Event,
) -> None:
    """Sample the plant, drain the guard's new verdicts, sweep the scanner."""
    seen_verdicts = 0
    seen_events = 0
    sweep_due = 0.0
    guard = proxy.guard

    while not stop.is_set():
        t = proxy._now()

        # Verdicts the proxy has recorded since the last frame. Reading its
        # lists rather than installing callbacks keeps the proxy untouched.
        while seen_verdicts < len(proxy.verdicts):
            verdict = proxy.verdicts[seen_verdicts]
            seen_verdicts += 1
            live.emit(ev.command(
                verdict.command.t, source="hmi01", kind=verdict.command.kind.value,
                value=verdict.command.value, unit=verdict.command.kind.unit,
            ))
            live.emit(ev.verdict(
                verdict.command.t,
                decision=verdict.decision.value,
                source="hmi01",
                point=verdict.command.kind.value,
                value=verdict.command.value,
                unit=verdict.command.kind.unit,
                rules=verdict.rule_ids,
                detail="; ".join(f.detail for f in verdict.findings),
                latency_us=verdict.latency_us,
            ))

        while seen_events < len(proxy.events):
            event = proxy.events[seen_events]
            seen_events += 1
            live.emit(ev.trip(
                event.t if hasattr(event, "t") else t,
                direction=getattr(event, "direction", "") or "supervision",
                rules=[f.rule_id for f in event.findings],
                detail="; ".join(f.detail for f in event.findings) or str(event.action),
            ))

        if t >= sweep_due:
            sweep_due = t + live.config.scan.interval_s
            await _sweep(live, scanner, t)

        state = plc.tank.state
        live.emit(ev.tank_state(
            t,
            level_m=state.level_m,
            reported_m=_reported_level(plc),
            believed_m=guard.estimator.state.level_m,
            pump_pct=state.pump_pos_pct,
            valve_pct=state.valve_pos_pct,
            limit_m=live.config.safety.level_max_m,
            floor_m=live.config.safety.level_min_m,
            height_m=live.config.plant.height_m,
            overflowed=state.overflowed,
            dried_out=state.dried_out,
        ))
        await asyncio.sleep(_FRAME_S)


# ----------------------------------------------------------------------
# The battery site
# ----------------------------------------------------------------------
async def site_scenario(live: Live, inform_guard: bool, speed: float = 10.0) -> dict:
    """Ramp the fleet, cut two measurement links, and see who the vote blames.

    With ``inform_guard`` the scanner's findings reach the cross-source vote
    and the stale readings stop counting. Without it the guard behaves as it
    did before the scanner existed, which is the comparison worth having.
    """
    config = live.config
    site = BessSite(config.bess.site, config.bess.safety, config.bess.pack, seed=7)
    guard = SiteGuard(config)
    targets, _network = site_targets(site)
    scanner = Scanner(config.scan, targets=targets)

    name = "stale_measurements" if inform_guard else "stale_measurements (control)"
    live.emit(ev.scenario(
        0.0, plant="site", name=name, guarded=True,
        summary=(
            "two of three measurement links cut while the site ramps down, "
            + ("with the scanner telling the guard" if inform_guard
               else "with the scanner not telling the guard")
        ),
    ))

    for unit in site.packs:
        unit.set_power(1.2)

    dt = config.bess.site.dt_s
    t = 0.0
    sweep_due = 0.0
    frame_due = 0.0
    # The site is a pure in-process loop, so it is paced here rather than by a
    # socket. Stepping a batch between sleeps keeps the display smooth without
    # making the run take its simulated length in real minutes.
    steps_per_frame = max(1, int(_FRAME_S * speed / dt))
    script = {
        60.0: ("the fleet is exporting; all three measurements agree", "info"),
        120.0: ("cutting the revenue meter's link: its reading freezes", "warn"),
        260.0: ("cutting the protection relay's link: two readings now frozen", "warn"),
        300.0: ("the site ramps down, and the two frozen readings do not", "warn"),
    }
    fired: set[float] = set()

    while t < 520.0:
        t = _advance_site(site, t, dt, steps_per_frame)

        for when, (text, level) in script.items():
            if t >= when and when not in fired:
                fired.add(when)
                live.emit(ev.note(t, text, level=level))

        if t >= sweep_due:
            sweep_due = t + config.scan.interval_s * 10.0
            await _sweep(live, scanner, t)
            if inform_guard:
                guard.set_live_sources(scanner.live_sources())

        observation = site.observe(t)
        event = guard.observe(observation)
        if event is not None and event.findings:
            live.emit(ev.trip(
                t,
                direction=getattr(event, "direction", "") or "supervision",
                rules=sorted({f.rule_id for f in event.findings}),
                detail="; ".join(f.detail for f in event.findings)[:200],
            ))

        if t >= frame_due:
            frame_due = t + _FRAME_S * speed
            _emit_site_state(live, site, guard, observation, t)
        await asyncio.sleep(_FRAME_S)

    truth = site.state.p_poi_mw
    error = guard.site_power_mw - truth
    accused = guard.voter.alarm.label if guard.voter.alarm else "none"
    outcome = (
        f"the guard is out by {error:+.3f} MW"
        if abs(error) > 1.0 else "the guard tracked the site"
    )
    lines = [
        f"true export {truth:+.3f} MW, guard believes {guard.site_power_mw:+.3f} MW",
        f"measurements counted: {len(guard.voter.counted)} of 3",
        f"source named as lying: {accused}",
    ]
    live.emit(ev.done(t, plant="site", name=name, outcome=outcome, lines=lines))
    return {"truth_mw": truth, "believed_mw": guard.site_power_mw, "error_mw": error,
            "accused": accused, "counted": len(guard.voter.counted)}


def _advance_site(site: BessSite, t: float, dt: float, steps: int) -> float:
    """Step the site a batch, cutting links and ramping on the way through.

    The script is in here rather than in the loop above so that the loop reads
    as what it is: step, narrate, scan, observe, draw.
    """
    for _ in range(steps):
        site.step(dt, t)
        t += dt
        if t >= 120.0 and site.link_up(MeasurementSource.POI_METER):
            site.set_link(MeasurementSource.POI_METER, False)
        if t >= 260.0 and site.link_up(MeasurementSource.RELAY):
            site.set_link(MeasurementSource.RELAY, False)
        if 300.0 <= t < 300.0 + dt * steps:
            for unit in site.packs:
                unit.set_power(0.05)
    return t


async def _sweep(live: Live, scanner: Scanner, t: float) -> None:
    """One scanner sweep, publishing whatever changed.

    The whole table goes out after the first sweep, because until then every
    device is UNKNOWN and a display with no rows in it looks broken rather
    than new.
    """
    for change in await scanner.scan_once():
        status = scanner.status(change.name)
        if status is not None:
            live.device_event(t, status)
    if scanner.sweeps <= 1:
        for status in scanner.snapshot():
            live.device_event(t, status)


def _emit_site_state(live: Live, site: BessSite, guard: SiteGuard, observation, t: float) -> None:
    referred = guard.voter.referred(observation)
    live.emit(ev.site_state(
        t,
        poi_mw=site.state.p_poi_mw,
        believed_mw=guard.site_power_mw,
        limit_mw=guard.poi_limit_mw,
        rating_mw=config_rating(guard),
        measurements={src.label: value for src, value in referred.items()},
        counted=[src.label for src in guard.voter.counted],
        packs=[
            {"device": unit.state.device, "online": unit.state.online,
             "p_mw": unit.state.p_mw, "soc": unit.state.soc}
            for unit in site.packs
        ],
        lying_source=guard.voter.alarm.label if guard.voter.alarm else None,
        damaged=site.damaged,
    ))


def config_rating(guard: SiteGuard) -> float:
    return guard.bess.site.poi_rating_mw


# ----------------------------------------------------------------------
# Driving it
# ----------------------------------------------------------------------
async def main_async(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    bus = EventBus()
    view = TerminalView()
    bus.on(view.on_event)

    server: LiveServer | None = None
    if not args.no_web:
        server = LiveServer(bus, host=args.host, port=args.port)
        await server.start()

    results: dict[str, dict] = {}
    with view:
        if server is not None and not view.tty:
            print(f"live view at {server.url}")
        live = Live(config, bus, view)
        if args.only in ("tank", "both"):
            results["tank"] = await tank_scenario(live, args.attack, args.duration)
            await asyncio.sleep(args.pause)
        if args.only in ("site", "both"):
            results["site_informed"] = await site_scenario(live, inform_guard=True,
                                                           speed=args.speed)
            await asyncio.sleep(args.pause)
            results["site_control"] = await site_scenario(live, inform_guard=False,
                                                          speed=args.speed)

    if server is not None:
        if args.hold:
            print(f"\nholding the live view open at {server.url} — ctrl-c to stop")
            with contextlib.suppress(asyncio.CancelledError, KeyboardInterrupt):
                await asyncio.sleep(args.hold)
        await server.stop()

    _summarise(results)
    return 0


def _summarise(results: dict[str, dict]) -> None:
    if not results:
        return
    print()
    tank = results.get("tank")
    if tank:
        print(f"tank: {'damaged' if tank['damaged'] else 'intact'} at "
              f"{tank['level_m']:.3f} m, {tank['blocked']} writes blocked, "
              f"{tank['trips']} trips")
    informed, control = results.get("site_informed"), results.get("site_control")
    if informed and control:
        print()
        print(f"{'site, two measurements gone stale':36}"
              f"{'told':>10}{'not told':>26}")
        print("-" * 72)
        label = "error in the guard's belief (MW)"
        print(f"{label:36}"
              f"{informed['error_mw']:>10.3f}{control['error_mw']:>26.3f}")
        print(f"{'measurements counted':36}"
              f"{informed['counted']:>10}{control['counted']:>26}")
        print(f"{'source named as lying':36}"
              f"{informed['accused']:>10}{control['accused']:>26}")
        print()
        print("The control run is the point: two frozen readings agree with each")
        print("other, so the majority vote names the one honest instrument.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--only", choices=("tank", "site", "both"), default="both")
    parser.add_argument("--attack", choices=ATTACKS, default="overflow")
    parser.add_argument("--duration", type=float, default=30.0,
                        help="seconds to hold the tank attack (it needs ~20 to do damage)")
    parser.add_argument("--speed", type=float, default=10.0,
                        help="how much faster than real time the site scenario runs")
    parser.add_argument("--pause", type=float, default=2.0,
                        help="seconds between scenarios, so the result stays on screen")
    parser.add_argument("--hold", type=float, default=0.0,
                        help="seconds to keep the web view up after the run")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--no-web", action="store_true", help="terminal only")
    parser.add_argument("--config", type=Path, default=None)
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args(argv)

    # The live view is the output. Anything the logger writes lands in the
    # middle of a frame and corrupts it, so it is quiet unless asked.
    logging.basicConfig(
        level=logging.WARNING if args.verbose else logging.CRITICAL,
        format="  %(message)s",
    )
    try:
        return asyncio.run(main_async(args))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
