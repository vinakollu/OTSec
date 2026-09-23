"""Running every attack from every sender against every receiver.

The question this answers is the one a reviewer asks after seeing the guard
stop an overflow: does that hold when something other than an operator station
is sending, and something other than a PLC is obeying? The matrix is the
answer, and it is run over real TCP sockets rather than in-process, because
half the differences between device classes only exist on the wire.

Each episode stands up:

* one executor (PLC, drive gateway or RTU) with the tank behind it,
* the guard proxy in front of it, configured with that executor's device map,
* the benign masters for the scenario, each on its own source address,
* the attacking master, which is one of those same devices turned hostile.

and runs it twice: once with the guard enforcing and once with the guard
watching but powerless. Without the second run, "the tank did not overflow"
says nothing, because it may never have been going to.

A scenario declares which sources and executors it applies to. Not every
attack makes sense everywhere: a drive parameter attack needs a drive, and an
interlock cannot be disabled on a device that has none. Pairs a scenario does
not apply to are reported as not applicable rather than silently counted as
successes, because a defence credited for attacks that could not happen is not
a defence.
"""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass, field
from typing import Awaitable, Callable

from ..clock import SimClock
from ..config import Config
from ..modbus import EXECUTORS, DeviceGuardProxy, Inventory, WirePolicy
from ..modbus.inventory import PERMISSIVE_POLICY
from ..modbus.masters import (
    MASTERS,
    AttackResult,
    Master,
    attack_coil_sweep,
    attack_historian_write,
    attack_interlock_disable,
    attack_mask_write,
    attack_overflow,
    attack_parameter_overspeed,
    attack_ramp_tamper,
    attack_readwrite_sneak,
    attack_valve_hammer,
    attack_write_flood,
)

#: Each master gets its own loopback address so the guard identifies it the way
#: it would in a plant, where devices sit at different addresses.
SOURCE_ADDRESSES = {
    "hmi": "127.0.0.11",
    "scada": "127.0.0.12",
    "peer_controller": "127.0.0.13",
    "historian": "127.0.0.14",
    "engineering": "127.0.0.15",
    "rogue": "127.0.0.99",
}

AttackFn = Callable[[Master, AttackResult, float], Awaitable[None]]


@dataclass(frozen=True)
class MatrixScenario:
    """One attack, and the sender/receiver pairs it can be run against."""

    name: str
    description: str
    attack: AttackFn
    sources: tuple[str, ...]
    executors: tuple[str, ...]
    duration_s: float = 40.0
    hold_s: float = 30.0
    initial_level_m: float = 1.30
    #: Benign masters running alongside, to keep the link realistic.
    background: tuple[str, ...] = ()
    #: Attacker connects from an address the inventory does not know.
    unknown_source: bool = False
    expected: str = ""


@dataclass
class EpisodeResult:
    scenario: str
    source: str
    executor: str
    enforced: bool
    overflowed: bool = False
    dried_out: bool = False
    peak_level_m: float = 0.0
    final_level_m: float = 0.0
    attack: AttackResult = field(default_factory=AttackResult)
    rules_fired: tuple[str, ...] = ()
    wire_reasons: tuple[str, ...] = ()
    trips: int = 0
    polls: int = 0
    benign_writes: int = 0
    benign_refused: int = 0
    latency_us: list[float] = field(default_factory=list)
    interlock_trips: int = 0

    @property
    def damaged(self) -> bool:
        return self.overflowed or self.dried_out

    @property
    def detected(self) -> bool:
        return bool(self.rules_fired or self.wire_reasons)


@dataclass
class PairResult:
    """One scenario on one sender/receiver pair, guarded and unguarded."""

    scenario: str
    source: str
    executor: str
    guarded: EpisodeResult
    unguarded: EpisodeResult

    @property
    def damage_prevented(self) -> bool:
        return self.unguarded.damaged and not self.guarded.damaged

    @property
    def stopped_at_wire(self) -> bool:
        return bool(self.guarded.wire_reasons) and not self.guarded.rules_fired


async def _run_episode(
    scenario: MatrixScenario,
    source_name: str,
    executor_name: str,
    config: Config,
    enforce: bool,
    policy: WirePolicy | None = None,
    speed: float = 20.0,
) -> EpisodeResult:
    """Stand the stack up, run one episode, tear it down."""
    clock = SimClock(speed=speed)
    device_cls, map_fn = EXECUTORS[executor_name]
    device_map = map_fn()

    device = device_cls(config, port=0, clock=clock, initial_level_m=scenario.initial_level_m)
    await device.start()

    inventory = Inventory()
    proxy = DeviceGuardProxy(
        config,
        device_map,
        target_port=device.port,
        listen_port=0,
        inventory=inventory,
        policy=policy or WirePolicy(),
        clock=clock,
        enforce=enforce,
        initial_level_m=scenario.initial_level_m,
    )
    await proxy.start()

    def build(name: str, address: str) -> Master:
        master = MASTERS[name](
            name, device_map, "127.0.0.1", proxy.listen_port, address, clock
        )
        inventory.add(master.as_source_device())
        inventory.bind(address, name)
        return master

    background = [build(n, SOURCE_ADDRESSES[n]) for n in scenario.background if n != source_name]

    attacker = MASTERS[source_name](
        source_name,
        device_map,
        "127.0.0.1",
        proxy.listen_port,
        SOURCE_ADDRESSES["rogue"] if scenario.unknown_source else SOURCE_ADDRESSES[source_name],
        clock,
    )
    if not scenario.unknown_source:
        inventory.add(attacker.as_source_device())
        inventory.bind(SOURCE_ADDRESSES[source_name], source_name)

    tasks: list[asyncio.Task] = []
    result = EpisodeResult(scenario.name, source_name, executor_name, enforce)
    peak = scenario.initial_level_m

    try:
        for master in background:
            await master.connect()
            tasks.append(asyncio.create_task(master.run()))
        await attacker.connect()

        # Let the estimator settle against the plant before anything happens.
        await clock.sleep(4.0)
        proxy.guard.acknowledge()

        attack_task = asyncio.create_task(
            scenario.attack(attacker, result.attack, scenario.hold_s)
        )

        deadline = clock.now() + scenario.duration_s
        while clock.now() < deadline:
            peak = max(peak, device.tank.state.level_m)
            if device.tank.state.overflowed or device.tank.state.dried_out:
                break
            await clock.sleep(0.2)
        attack_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await attack_task
    finally:
        for task in tasks:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        for master in background:
            await master.close()
        await attacker.close()
        await proxy.stop()
        await device.stop()

    state = device.tank.state
    result.overflowed = state.overflowed
    result.dried_out = state.dried_out
    result.peak_level_m = max(peak, state.level_m)
    result.final_level_m = state.level_m
    result.rules_fired = tuple(sorted({r for f in proxy.frames for r in f.rule_ids}
                                      | {f.rule_id for e in proxy.events for f in e.findings}))
    result.wire_reasons = tuple(sorted(proxy.stats.wire_reasons))
    result.trips = proxy.stats.trips_issued
    result.polls = proxy.stats.polls
    result.benign_writes = sum(m.stats.writes_sent for m in background)
    result.benign_refused = sum(m.stats.writes_refused for m in background)
    result.latency_us = list(proxy.stats.wire_latency_us)
    result.interlock_trips = getattr(device, "interlock_trips", 0)
    return result


async def run_pair(
    scenario: MatrixScenario,
    source: str,
    executor: str,
    config: Config,
    policy: WirePolicy | None = None,
    speed: float = 20.0,
) -> PairResult:
    """Run one scenario on one pair, with the guard enforcing and without."""
    guarded = await _run_episode(scenario, source, executor, config, True, policy, speed)
    unguarded = await _run_episode(scenario, source, executor, config, False, policy, speed)
    return PairResult(scenario.name, source, executor, guarded, unguarded)


async def run_matrix(
    scenarios: list[MatrixScenario],
    config: Config,
    policy: WirePolicy | None = None,
    speed: float = 20.0,
    only: set[str] | None = None,
) -> list[PairResult]:
    results: list[PairResult] = []
    for scenario in scenarios:
        if only and scenario.name not in only:
            continue
        for source in scenario.sources:
            for executor in scenario.executors:
                results.append(
                    await run_pair(scenario, source, executor, config, policy, speed)
                )
    return results


# ----------------------------------------------------------------------
# The scenario suite
# ----------------------------------------------------------------------
ALL_SOURCES = ("hmi", "scada", "peer_controller", "engineering")
ALL_EXECUTORS = ("plc", "drives", "rtu")


def all_scenarios() -> list[MatrixScenario]:
    """Attacks spanning the matrix, plus the ones only some devices allow."""
    return [
        MatrixScenario(
            name="overflow",
            description="Shut the outlet and run the inlet flat out. Every write is "
                        "individually legal; only the consequence is an attack.",
            attack=attack_overflow,
            sources=ALL_SOURCES,
            executors=ALL_EXECUTORS,
            background=("historian",),
            expected="R3 refuses the pump command, or supervision trips",
        ),
        MatrixScenario(
            name="valve_hammer",
            description="Slam the outlet open and shut. A pressure transient, not a "
                        "level excursion, so no lookahead rule sees it coming.",
            attack=attack_valve_hammer,
            sources=ALL_SOURCES,
            executors=ALL_EXECUTORS,
            hold_s=20.0,
            background=("historian",),
            expected="R2 reversal count",
        ),
        MatrixScenario(
            name="write_flood",
            description="Hammer the command path. What counts as a flood depends on "
                        "which device is sending.",
            attack=attack_write_flood,
            sources=ALL_SOURCES,
            executors=ALL_EXECUTORS,
            hold_s=20.0,
            background=("historian",),
            expected="R2 rate against this source's budget",
        ),
        MatrixScenario(
            name="parameter_overspeed",
            description="Raise the drive's maximum frequency, then command 100 %. The "
                        "speed reference stays in range; its meaning changed.",
            attack=attack_parameter_overspeed,
            sources=("engineering", "hmi", "scada"),
            executors=("drives",),
            background=("historian",),
            expected="wire policy refuses the parameter write",
        ),
        MatrixScenario(
            name="ramp_tamper",
            description="Shorten the drive's acceleration ramp so the pump steps "
                        "instead of ramping, outrunning the guard's model of it.",
            attack=attack_ramp_tamper,
            sources=("engineering", "hmi"),
            executors=("drives",),
            background=("historian",),
            expected="wire policy refuses the parameter write",
        ),
        MatrixScenario(
            name="interlock_disable",
            description="Switch off the RTU's own high-level interlock, then fill. The "
                        "case where the executor was protecting itself.",
            attack=attack_interlock_disable,
            sources=("engineering", "hmi", "scada"),
            executors=("rtu",),
            background=("historian",),
            expected="wire policy refuses the interlock write",
        ),
        MatrixScenario(
            name="coil_sweep",
            description="Start the pump and clear the interlock in one FC15 frame.",
            attack=attack_coil_sweep,
            sources=("hmi", "scada"),
            executors=("rtu",),
            background=("historian",),
            expected="the multi-coil write is parsed, not skipped",
        ),
        MatrixScenario(
            name="mask_write",
            description="Drive the pump with a mask write. Same effect on the device, "
                        "a function code a narrow parser skips.",
            attack=attack_mask_write,
            sources=("hmi", "scada"),
            executors=("plc", "drives"),
            background=("historian",),
            expected="FC22 refused as unjudgeable",
        ),
        MatrixScenario(
            name="readwrite_sneak",
            description="Hide the pump command in the write half of an FC23 frame.",
            attack=attack_readwrite_sneak,
            sources=("hmi", "scada"),
            executors=("plc", "drives"),
            background=("historian",),
            expected="FC23's write half is parsed and judged",
        ),
        MatrixScenario(
            name="historian_write",
            description="A read-only device starts issuing commands.",
            attack=attack_historian_write,
            sources=("historian",),
            executors=ALL_EXECUTORS,
            expected="wire policy refuses a write from a read-only source",
        ),
        MatrixScenario(
            name="unknown_source",
            description="A device not in the inventory writes to the controller.",
            attack=attack_overflow,
            sources=("hmi",),
            executors=ALL_EXECUTORS,
            unknown_source=True,
            background=("historian",),
            expected="wire policy refuses an unknown source, then R3",
        ),
    ]


def benign_scenarios() -> list[MatrixScenario]:
    """Ordinary traffic from every source, with no attack at all.

    The false-alarm measurement for the matrix. ``attack`` does nothing, so
    anything the guard refuses here is a refusal of legitimate work.
    """
    async def quiet(master: Master, result: AttackResult, hold_s: float) -> None:
        await master.clock.sleep(hold_s)

    return [
        MatrixScenario(
            name="normal_traffic",
            description="Every benign master running at once against each executor.",
            attack=quiet,
            sources=("hmi",),
            executors=ALL_EXECUTORS,
            duration_s=45.0,
            hold_s=40.0,
            initial_level_m=0.90,
            background=("scada", "peer_controller", "historian"),
            expected="nothing flagged",
        ),
    ]


ABLATIONS = {
    "policy_off": PERMISSIVE_POLICY,
    "policy_on": WirePolicy(),
}
