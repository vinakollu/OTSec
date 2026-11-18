"""An interactive live demonstration: the stack runs, and you drive it.

``run_live.py`` plays two scripted scenarios and narrates them. This is the
other shape. Nothing happens on a timer: the stack stands up with ordinary
traffic flowing and stays there, and an attack, a bypass, a severed link or a
reset happen when somebody asks for one. That is what a demonstration in front
of an audience needs, because the interesting question is always "what if" and
the answer should arrive while the question is still in the room.

What runs is the same stack the device matrix measures: a simulated field
device, the guard proxy in front of it, and five masters speaking Modbus over
loopback sockets. The scanner from :mod:`otguard.scan` probes the device and
the guard the whole time, so the picture includes whether each is answering.

Three controls carry the argument.

Launching an attack runs one of the matrix's attack coroutines, from the
source address that attack is defined to come from. The masters that write
stand down while it runs, which is how the matrix runs them, and for the same
reason: leave the supervisory loop writing and it overwrites the attacker's
set-point, the attack never reaches the plant, and the guard gets credit for a
save its victim had already made.

Bypassing the guard leaves it watching and powerless. Showing the same attack
twice, a minute apart, with and without enforcement, is the whole of this
project's method compressed into one gesture.

Cutting the link to the device closes its listening socket. The plant keeps
running and masters already connected keep driving it, but nothing new can
reach it, and the scanner notices and says so. It is a real probe failing, not
a flag being set.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import Any

from ..clock import SimClock
from ..config import Config
from ..eval.matrix import SOURCE_ADDRESSES, MatrixScenario, all_scenarios
from ..modbus.deviceproxy import DeviceGuardProxy
from ..modbus.field_devices import EXECUTORS
from ..modbus.inventory import Inventory, SourceClass, SourceDevice, WirePolicy
from ..modbus.masters import MASTERS, AttackResult, Master
from ..scan import Scanner, tank_targets
from ..scan.scanner import ScanTransition
from . import events as ev
from .bus import EventBus
from .events import Kind, LiveEvent

log = logging.getLogger(__name__)

#: Masters running ordinary traffic for the whole session.
BACKGROUND = ("hmi", "scada", "peer_controller", "historian", "engineering")


def topology(t: float, **payload: Any) -> LiveEvent:
    """The one-off description of what the page is about to draw."""
    return LiveEvent(Kind.SCENARIO, t, {"plant": "tank", "view": "interactive", **payload})


class InteractiveDemo:
    def __init__(
        self,
        config: Config,
        bus: EventBus,
        executor: str = "plc",
        speed: float = 1.0,
        initial_level_m: float = 1.30,
        enforce: bool = True,
        policy: WirePolicy | None = None,
    ) -> None:
        if executor not in EXECUTORS:
            raise ValueError(f"unknown device {executor!r}; have {', '.join(EXECUTORS)}")
        self.config = config
        self.bus = bus
        self.executor = executor
        self.initial_level_m = initial_level_m
        self.clock = SimClock(speed=speed)

        device_cls, map_fn = EXECUTORS[executor]
        self.map = map_fn()
        self.device = device_cls(
            config, port=0, clock=self.clock, initial_level_m=initial_level_m
        )
        self.inventory = Inventory()
        self.proxy = DeviceGuardProxy(
            config, self.map, target_port=0, listen_port=0,
            inventory=self.inventory, policy=policy or WirePolicy(),
            clock=self.clock, enforce=enforce, initial_level_m=initial_level_m,
            listener=self._on_frame,
        )
        self.scanner: Scanner | None = None
        self.masters: dict[str, Master] = {}
        self._master_tasks: dict[str, asyncio.Task] = {}
        self.suspended: set[str] = set()
        self._tasks: list[asyncio.Task] = []
        self._attack_task: asyncio.Task | None = None
        self._attacker: Master | None = None
        self.attack_name: str | None = None
        self.attack_source: str | None = None
        self.attack_result = AttackResult()
        self._scenarios = {s.name: s for s in all_scenarios()}

    def _now(self) -> float:
        return self.clock.now()

    # ------------------------------------------------------------------
    # The guard's tap
    # ------------------------------------------------------------------
    def _on_frame(self, frame: dict) -> None:
        """Turn one proxy decision into an event the page can draw."""
        if frame.get("type") == "trip":
            self.bus.publish(ev.trip(
                frame.get("t", self._now()),
                direction="high" if frame.get("pump") is not None else "low",
                rules=["R3"], detail=frame.get("reason", ""),
            ))
            return
        if frame.get("type") != "frame":
            return
        point = frame.get("kind") or f"fc{frame.get('fc')}"
        value = frame.get("value")
        self.bus.publish(ev.verdict(
            frame.get("t", self._now()),
            decision=frame.get("decision", "allow"),
            source=frame.get("source", "?"),
            point=point,
            value=float(value) if isinstance(value, (int, float)) else 0.0,
            unit="%" if point in ("pump", "valve") else ("m" if point == "setpoint" else ""),
            device=self.map.name,
            rules=list(frame.get("rules") or []),
            detail=frame.get("detail") or (frame.get("wire") or ""),
            latency_us=float(frame.get("latency_us") or 0.0),
        ))

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    async def start(self) -> None:
        await self.device.start()
        self.proxy.target_port = self.device.port
        await self.proxy.start()

        # The scanner reads a register off the guard to prove the whole path
        # is alive, so the guard has to know who it is. An asset scanner is a
        # documented, read-only device on a plant network; leaving it out of
        # the inventory means the guard refuses its probe as an unknown source,
        # and the device table fills with "alive, and our address is wrong".
        self.inventory.add(SourceDevice(
            name="scanner",
            source_class=SourceClass.HISTORIAN,
            description="asset scanner, reads only",
            read_only=True,
        ))
        self.inventory.bind("127.0.0.1", "scanner")

        self.scanner = Scanner(
            cfg=self.config.scan,
            clock=self.clock,
            targets=tank_targets(
                plc_port=self.device.port, proxy_port=self.proxy.listen_port
            ),
        )
        self._tasks.append(self.scanner.start(self._on_scan_change))

        for name in BACKGROUND:
            master = self._build(name, SOURCE_ADDRESSES[name])
            await master.connect()
            self.masters[name] = master
            self._master_tasks[name] = asyncio.create_task(self._run_master(master))

        self._tasks.append(asyncio.create_task(self._telemetry_loop()))
        self._tasks.append(asyncio.create_task(self._device_loop()))
        self.bus.publish(self.describe())
        self._note("the plant is running normally")

    def _build(self, name: str, address: str) -> Master:
        master = MASTERS[name](
            name, self.map, "127.0.0.1", self.proxy.listen_port, address, self.clock
        )
        self.inventory.add(master.as_source_device())
        self.inventory.bind(address, name)
        return master

    async def _run_master(self, master: Master) -> None:
        try:
            await master.run()
        except asyncio.CancelledError:
            raise
        except Exception:  # pragma: no cover - one dead master must not stop the rest
            log.exception("master %s stopped", master.name)

    async def stop(self) -> None:
        if self.scanner is not None:
            with contextlib.suppress(Exception):
                await self.scanner.stop()
        for task in list(self._tasks) + list(self._master_tasks.values()):
            task.cancel()
        for task in list(self._tasks) + list(self._master_tasks.values()):
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        self._tasks.clear()
        self._master_tasks.clear()
        await self._cancel_attack()
        for master in self.masters.values():
            with contextlib.suppress(Exception):
                await master.close()
        self.masters.clear()
        with contextlib.suppress(Exception):
            await self.proxy.stop()
        with contextlib.suppress(Exception):
            await self.device.stop()

    # ------------------------------------------------------------------
    # What the page draws once
    # ------------------------------------------------------------------
    def describe(self) -> LiveEvent:
        return topology(
            self._now(),
            name="interactive",
            summary=f"{self.map.name} behind the guard, five masters sending",
            guarded=self.proxy.enforce,
            device={
                "name": self.map.name,
                "units": sorted({p.unit_id for p in self.map.points}),
                "points": [
                    {"name": p.name, "unit": p.unit_id, "role": p.role.value,
                     "kind": p.kind.value if p.kind else None}
                    for p in self.map.points
                ],
            },
            masters=[
                {"name": n, "address": SOURCE_ADDRESSES[n],
                 "description": MASTERS[n].description,
                 "read_only": MASTERS[n].read_only}
                for n in BACKGROUND
            ],
            attacks=[
                {"name": s.name, "description": s.description}
                for s in self._scenarios.values() if self.executor in s.executors
            ],
            safety={
                "level_max_m": self.config.safety.level_max_m,
                "level_min_m": self.config.safety.level_min_m,
                "height_m": self.config.plant.height_m,
            },
            suspended=sorted(self.suspended),
            speed=self.clock.speed,
        )

    # ------------------------------------------------------------------
    # Telemetry and the scanner
    # ------------------------------------------------------------------
    async def _telemetry_loop(self) -> None:
        period = self.config.plant.dt_s
        try:
            while True:
                state = self.device.tank.state
                self.bus.publish(ev.tank_state(
                    self._now(),
                    level_m=state.level_m,
                    reported_m=self.device.tank.measure(),
                    believed_m=self.proxy.guard.estimated_level_m,
                    pump_pct=state.pump_pos_pct,
                    valve_pct=state.valve_pos_pct,
                    limit_m=self.config.safety.level_max_m,
                    floor_m=self.config.safety.level_min_m,
                    height_m=self.config.plant.height_m,
                    overflowed=state.overflowed,
                    dried_out=state.dried_out,
                ))
                await self.clock.sleep(period)
        except asyncio.CancelledError:
            raise

    def _on_scan_change(self, transition: ScanTransition) -> None:
        """The scanner only reports changes, so this is where a link dying lands."""
        self._publish_device(transition.name, previous=transition.previous.value)
        self._note(
            f"{transition.name} {'went down' if transition.lost else 'is ' + transition.current.label}"
            f": {transition.detail}",
            level="warn" if transition.lost else "info",
        )
        self._publish_status()

    def _publish_device(self, name: str, previous: str = "") -> None:
        if self.scanner is None:
            return
        status = self.scanner.status(name)
        if status is None:
            return
        self.bus.publish(ev.device(
            self._now(),
            name=status.name,
            state=status.state.value,
            previous=previous,
            role=status.target.role,
            zone=status.target.zone,
            evidence=status.evidence.value,
            networked=status.target.networked,
            detail=status.detail,
            critical=status.target.critical,
            rtt_ms=status.last_rtt_ms,
        ))

    async def _device_loop(self) -> None:
        """Republish every device row on a slow cycle.

        The scanner reports transitions, which is the right thing for a log and
        not enough for a table: a page that opened after the last change would
        have no rows at all. This repeats the current picture often enough that
        a browser joining late sees one, and rarely enough to stay out of the
        way of the traffic it is describing.
        """
        try:
            while True:
                await self.clock.sleep(2.0)
                if self.scanner is None:
                    continue
                for status in self.scanner.snapshot():
                    self._publish_device(status.name)
        except asyncio.CancelledError:
            raise

    def _note(self, text: str, level: str = "info") -> None:
        self.bus.publish(ev.note(self._now(), text, level=level))

    def _publish_status(self) -> None:
        """A compact state line the page keeps in its banner."""
        state = self.device.tank.state
        self.bus.publish(LiveEvent(Kind.NOTE, self._now(), {
            "text": "", "level": "status", "status": {
                "enforce": self.proxy.enforce,
                "attack": self.attack_name,
                "source": self.attack_source,
                "suspended": sorted(self.suspended),
                "damaged": state.overflowed or state.dried_out,
                "link": self.device.reachable,
            },
        }))

    # ------------------------------------------------------------------
    # Standing the legitimate masters down
    # ------------------------------------------------------------------
    async def _suspend_masters(self, keep: tuple[str, ...]) -> None:
        for name, task in list(self._master_tasks.items()):
            if name in keep:
                continue
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
            del self._master_tasks[name]
            master = self.masters.get(name)
            if master is not None:
                with contextlib.suppress(Exception):
                    await master.close()
            self.suspended.add(name)
        if self.suspended:
            self._note(
                ", ".join(sorted(self.suspended))
                + " stopped writing: the attacker has the station, so the "
                  "legitimate loop is not also using it",
            )
        self._publish_status()

    async def _resume_masters(self) -> None:
        for name in sorted(self.suspended):
            master = self._build(name, SOURCE_ADDRESSES[name])
            with contextlib.suppress(Exception):
                await master.connect()
                self.masters[name] = master
                self._master_tasks[name] = asyncio.create_task(self._run_master(master))
        self.suspended.clear()
        self._publish_status()

    # ------------------------------------------------------------------
    # Controls
    # ------------------------------------------------------------------
    async def launch_attack(self, name: str) -> dict:
        scenario = self._scenarios.get(name)
        if scenario is None:
            return {"ok": False, "error": f"no attack called {name!r}"}
        if self.executor not in scenario.executors:
            return {"ok": False, "error": f"{name} does not apply to a {self.executor}"}
        await self._cancel_attack()

        source = "hmi" if "hmi" in scenario.sources else scenario.sources[0]
        address = (SOURCE_ADDRESSES["rogue"] if scenario.unknown_source
                   else SOURCE_ADDRESSES[source])
        attacker = MASTERS[source](
            source, self.map, "127.0.0.1", self.proxy.listen_port, address, self.clock
        )
        if not scenario.unknown_source:
            self.inventory.add(attacker.as_source_device())
            self.inventory.bind(address, source)
        await attacker.connect()
        # The attacker is a separate connection and never in this set, so an
        # attack whose sender is the historian still has its historian.
        await self._suspend_masters(tuple(scenario.background))

        self._attacker = attacker
        self.attack_name = name
        self.attack_source = source
        self.attack_result = AttackResult()
        self._attack_task = asyncio.create_task(
            self._run_attack(scenario, attacker, self.attack_result)
        )
        self._note(
            f"{name} launched from {source}"
            + (" at an address the guard has never seen" if scenario.unknown_source else ""),
            level="warn",
        )
        self._publish_status()
        return {"ok": True, "attack": name, "source": source, "address": address}

    async def _run_attack(self, scenario: MatrixScenario, attacker: Master,
                          result: AttackResult) -> None:
        try:
            await scenario.attack(attacker, result, scenario.hold_s)
            self._note(f"{scenario.name} finished")
        except asyncio.CancelledError:
            raise
        except Exception:  # pragma: no cover
            log.exception("attack %s failed", scenario.name)
            self._note(f"{scenario.name} stopped early", level="warn")
        self.attack_name = None
        self.attack_source = None
        await self._resume_masters()
        self._note("ordinary traffic resumed")

    async def _cancel_attack(self) -> None:
        if self._attack_task is not None:
            self._attack_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._attack_task
            self._attack_task = None
        if self._attacker is not None:
            with contextlib.suppress(Exception):
                await self._attacker.close()
            self._attacker = None
        self.attack_name = None
        self.attack_source = None

    async def set_enforce(self, enforce: bool) -> dict:
        self.proxy.enforce = enforce
        self._note(
            "the guard is enforcing" if enforce
            else "the guard is watching, and powerless",
            level="info" if enforce else "warn",
        )
        self._publish_status()
        return {"ok": True, "enforce": enforce}

    async def set_link(self, up: bool) -> dict:
        await self.device.set_reachable(up)
        self._note(
            f"the link to {self.map.name} is " + ("back" if up else "cut")
            + ("" if up else "; the scanner will notice within three sweeps"),
            level="info" if up else "warn",
        )
        self._publish_status()
        return {"ok": True, "link": up}

    async def reset(self) -> dict:
        await self._cancel_attack()
        await self._resume_masters()
        await self.device.set_reachable(True)
        tank = self.device.tank
        tank.state.level_m = self.initial_level_m
        tank.state.overflowed = False
        tank.state.dried_out = False
        tank.set_pump(0.0)
        tank.set_valve(0.0)
        self.proxy.guard.acknowledge()
        self.proxy.guard.reset_log()
        self._note("reset to the starting level")
        self._publish_status()
        return {"ok": True}

    async def command(self, action: str, query: dict[str, str]) -> dict:
        if action == "attack":
            return await self.launch_attack(query.get("name", ""))
        if action == "stop":
            await self._cancel_attack()
            await self._resume_masters()
            self._note("attack stopped, ordinary traffic resumed")
            self._publish_status()
            return {"ok": True}
        if action == "enforce":
            return await self.set_enforce(query.get("value", "true") == "true")
        if action == "link":
            return await self.set_link(query.get("value", "true") == "true")
        if action == "reset":
            return await self.reset()
        return {"ok": False, "error": f"unknown command {action!r}"}
