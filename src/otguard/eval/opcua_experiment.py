"""The OPC UA security-mode experiment.

One question, asked three times: how much of the guard survives when the
protocol encrypts itself?

Each cell of the experiment runs the identical device, the identical guard and
the identical attack over a real TCP connection, changing only the security
mode the device and its client negotiated. Every cell also runs a second time
with the guard watching but powerless, because "the tank did not overflow" is
not a result on its own.

The attack is issued through the operator station's own session rather than
from a separate connection. That is this project's threat model — the attacker
has the operator station, not a foothold beside it — and it is also what makes
the cost of the guard's last resort measurable. On a signed channel the guard
cannot refuse one write and keep the session, so the only refusal available is
to cut the channel, and the channel it cuts is the one the operator is watching
the plant through. The honest writes lost to that are counted.

Ports are picked from the operating system rather than fixed, because a cell
that reuses a port a previous cell left in TIME_WAIT fails for a reason that
has nothing to do with the experiment.
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
import statistics
from dataclasses import dataclass, field
from pathlib import Path

from ..clock import SimClock
from ..config import Config
from ..opcua.certs import CertSet, ensure_certs
from ..opcua.device import SimulatedOpcUaDevice, endpoint_url
from ..opcua.framing import SecurityMode
from ..opcua.masters import READ_ONLY, SPECS, MasterStats, namespace_index, open_client, operator
from ..opcua.proxy import OpcUaGuardProxy

WARMUP_S = 10.0
ATTACK_START_S = 30.0
DEFAULT_DURATION_S = 150.0
DEFAULT_SPEED = 20.0
#: The same starting level, holding commands and attack timing as the
#: in-process ``overflow`` scenario, so the two sets of numbers can be read
#: against each other rather than only against themselves.
DEFAULT_INITIAL_LEVEL_M = 0.95

#: The order the report presents them in: readable and rewritable, readable
#: only, neither.
MODES = (SecurityMode.NONE, SecurityMode.SIGN, SecurityMode.SIGN_AND_ENCRYPT)

#: ``none`` is the no-attack episode. It carries the false-alarm number, and
#: without it a suite of attacks says nothing about what the guard costs.
SCENARIOS = ("none",) + tuple(SPECS)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


async def _bounded(awaitable, timeout: float = 10.0) -> None:
    """Await something that might never finish, and carry on when it does not."""
    if awaitable is None:
        return
    try:
        await asyncio.wait_for(awaitable, timeout)
    except Exception:
        pass
    except asyncio.CancelledError:
        pass


def _since(t: float | None, t0: float) -> float | None:
    """Re-express a clock reading as seconds since the episode started."""
    return None if t is None else round(t - t0, 2)


def _reset(device: SimulatedOpcUaDevice, proxy: OpcUaGuardProxy, clock: SimClock,
           initial_level_m: float, *, place_plant: bool = True) -> float:
    """Put the plant and the scoring back to zero, and return the new time origin.

    Called twice: once after the session is up, to undo the drain that happened
    while the handshake was running, and once after warm-up, to start counting.

    It deliberately does not rewind the clock. Everything in the experiment
    shares one :class:`~otguard.clock.SimClock`, and the device's scan loop
    tracks plant time against it; winding the clock back to zero leaves that
    loop waiting for a moment that has already passed, and the plant simply
    stops. The symptom is a tank whose level never changes and an episode that
    looks like it ran. So the clock runs on and the episode carries an origin.
    """
    if place_plant:
        device.tank.state.level_m = initial_level_m
    device.tank.state.overflowed = False
    device.tank.state.dried_out = False
    device.peak_level_m = device.tank.state.level_m
    device.min_level_m = device.tank.state.level_m
    proxy.reset_scoring()
    return clock.now()


@dataclass
class CellResult:
    """One (attack, security mode, enforcing) episode."""

    scenario: str
    mode: SecurityMode
    enforced: bool
    t0: float = 0.0          # clock reading where scoring began
    detected: bool = False
    first_detection_t: float | None = None
    damaged: bool = False
    peak_level_m: float = 0.0
    min_level_m: float = 0.0
    honest: MasterStats = field(default_factory=MasterStats)
    recovery: MasterStats = field(default_factory=MasterStats)
    attack: MasterStats = field(default_factory=MasterStats)
    writes_decoded: int = 0
    writes_blocked: int = 0
    wire_blocked: int = 0
    alarms: int = 0
    trips: int = 0
    blind_trips: int = 0
    integrity_alarm_t: float | None = None
    polls: int = 0
    severed_at: float | None = None
    sever_reason: str = ""
    rules_fired: tuple[str, ...] = ()
    wire_reasons: tuple[str, ...] = ()
    visibility: dict = field(default_factory=dict)
    latency_us: list[float] = field(default_factory=list)
    error: str = ""

    @property
    def key(self) -> tuple[str, str]:
        return (self.scenario, self.mode.value)

    @property
    def is_attack(self) -> bool:
        return self.scenario != "none"

    @property
    def read_only(self) -> bool:
        return self.scenario in READ_ONLY

    @property
    def honest_writes_lost(self) -> int:
        """Ordinary writes refused before the attack began: the false-alarm cost."""
        return self.honest.refused

    @property
    def recovery_blocked(self) -> bool:
        """Could the operator still reach the plant after the attack?

        A guard that refused by cutting the channel has cut the way back in
        too. On a signed channel that is the only refusal available, so this is
        a cost of the security mode and not of the rules.
        """
        return self.recovery.attempted > 0 and self.recovery.accepted == 0

    @property
    def stopped_before_the_device(self) -> bool:
        """Was the attack refused at the wire, rather than cleaned up after?"""
        return self.writes_blocked > 0 or self.wire_blocked > 0

    def as_dict(self) -> dict:
        return {
            "scenario": self.scenario,
            "mode": self.mode.value,
            "enforced": self.enforced,
            "detected": self.detected,
            "first_detection_t": self.first_detection_t,
            "damaged": self.damaged,
            "peak_level_m": round(self.peak_level_m, 3),
            "min_level_m": round(self.min_level_m, 3),
            "honest_writes": self.honest.attempted,
            "honest_writes_accepted": self.honest.accepted,
            "recovery_writes": self.recovery.attempted,
            "recovery_writes_accepted": self.recovery.accepted,
            "attack_writes": self.attack.attempted,
            "attack_writes_accepted": self.attack.accepted,
            "writes_decoded": self.writes_decoded,
            "writes_blocked": self.writes_blocked,
            "wire_blocked": self.wire_blocked,
            "alarms": self.alarms,
            "trips": self.trips,
            "blind_trips": self.blind_trips,
            "integrity_alarm_t": self.integrity_alarm_t,
            "polls": self.polls,
            "severed_at": self.severed_at,
            "sever_reason": self.sever_reason,
            "rules_fired": list(self.rules_fired),
            "wire_reasons": list(self.wire_reasons),
            "visibility": self.visibility,
            "latency_us": self.latency_us,
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, row: dict) -> "CellResult":
        """Rebuild a cell from what ``as_dict`` wrote.

        This exists so a table or a figure can be redrawn from a saved run
        instead of paying for forty-two secure-channel handshakes again. It
        lives next to ``as_dict`` so the two stay in step; a round trip is
        tested.
        """
        cell = cls(
            scenario=row["scenario"],
            mode=SecurityMode(row["mode"]),
            enforced=bool(row["enforced"]),
            t0=0.0,
            detected=bool(row["detected"]),
            first_detection_t=row.get("first_detection_t"),
            damaged=bool(row["damaged"]),
            peak_level_m=float(row.get("peak_level_m", 0.0)),
            min_level_m=float(row.get("min_level_m", 0.0)),
            writes_decoded=int(row.get("writes_decoded", 0)),
            writes_blocked=int(row.get("writes_blocked", 0)),
            wire_blocked=int(row.get("wire_blocked", 0)),
            alarms=int(row.get("alarms", 0)),
            trips=int(row.get("trips", 0)),
            blind_trips=int(row.get("blind_trips", 0)),
            integrity_alarm_t=row.get("integrity_alarm_t"),
            polls=int(row.get("polls", 0)),
            severed_at=row.get("severed_at"),
            sever_reason=row.get("sever_reason", ""),
            rules_fired=tuple(row.get("rules_fired", ())),
            wire_reasons=tuple(row.get("wire_reasons", ())),
            visibility=dict(row.get("visibility", {})),
            latency_us=list(row.get("latency_us", ())),
            error=row.get("error", ""),
        )
        cell.honest = MasterStats(
            attempted=int(row.get("honest_writes", 0)),
            accepted=int(row.get("honest_writes_accepted", 0)),
        )
        cell.recovery = MasterStats(
            attempted=int(row.get("recovery_writes", 0)),
            accepted=int(row.get("recovery_writes_accepted", 0)),
        )
        cell.attack = MasterStats(
            attempted=int(row.get("attack_writes", 0)),
            accepted=int(row.get("attack_writes_accepted", 0)),
        )
        return cell


async def run_cell(
    scenario: str,
    mode: SecurityMode,
    config: Config,
    certs: CertSet,
    *,
    enforce: bool = True,
    speed: float = DEFAULT_SPEED,
    duration_s: float = DEFAULT_DURATION_S,
    initial_level_m: float = DEFAULT_INITIAL_LEVEL_M,
) -> CellResult:
    """Run one episode and return everything it produced."""
    result = CellResult(scenario=scenario, mode=mode, enforced=enforce)
    clock = SimClock(speed)
    device_port = _free_port()
    proxy_port = _free_port()

    device = SimulatedOpcUaDevice(
        config, port=device_port, mode=mode, certs=certs,
        clock=clock, initial_level_m=initial_level_m,
    )
    proxy = OpcUaGuardProxy(
        config, mode, target_port=device_port, listen_port=proxy_port,
        certs=certs, clock=clock, enforce=enforce, initial_level_m=initial_level_m,
    )
    client = None
    try:
        await device.start()
        await proxy.start()

        # Open the session *before* the scored window. Establishing a secure
        # channel costs real time, and on a clock running twenty times faster
        # than the wall that is tens of simulated seconds — more of them under
        # SignAndEncrypt than under None, because of the asymmetric
        # cryptography in the handshake. Scoring from the moment the proxy
        # starts would hand the three modes three different plants to guard and
        # call the difference a result.
        client = await open_client(endpoint_url("127.0.0.1", proxy_port), mode, certs)
        ns = await namespace_index(client)
        _reset(device, proxy, clock, initial_level_m)

        # Now let the estimator lock on to a quiet plant, the same warm-up the
        # in-process harness uses, and only then start counting.
        await clock.sleep(WARMUP_S)
        t0 = _reset(device, proxy, clock, initial_level_m, place_plant=False)
        result.t0 = t0
        device.run_until = t0 + duration_s

        spec = SPECS.get(scenario)
        stand_down = None
        recovery_from = None
        if spec is not None:
            recovery_from = ATTACK_START_S + spec.span_s
            if spec.operator_stands_down:
                stand_down = (ATTACK_START_S, recovery_from)

        tasks = [
            asyncio.create_task(
                operator(
                    client, clock, result.honest, duration_s, ns,
                    stand_down=stand_down, recovery_from=recovery_from,
                    recovery_stats=result.recovery,
                )
            )
        ]
        if spec is not None:
            async def attacker() -> None:
                await clock.sleep(ATTACK_START_S)
                with contextlib.suppress(Exception):
                    await spec.run(client, clock, result.attack, ns)

            tasks.append(asyncio.create_task(attacker()))

        done_by = duration_s / speed + 20.0
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), done_by)
        for task in tasks:
            task.cancel()

        # Read the outcome here, before anything is torn down. The clock is
        # shared and keeps running, and the device's scan loop keeps stepping
        # the plant, so waiting out a disconnection on a channel the guard has
        # already cut hands the episode up to another two hundred simulated
        # seconds. The tank then drains to 0.00 m with nobody driving it, long
        # after the episode ended, and the cell is scored as a dry-out that
        # never happened inside the window.
        _collect(result, device, proxy)
    except Exception as exc:  # pragma: no cover - reported, not swallowed
        result.error = f"{type(exc).__name__}: {exc}"
    finally:
        # Every step of the teardown is bounded. Disconnecting a client whose
        # channel the guard has already cut can wait on a socket that is never
        # going to answer, and one hung cell stalls the whole run.
        await _bounded(client.disconnect() if client is not None else None)
        await _bounded(proxy.stop())
        await _bounded(device.stop())

    return result


def _collect(result: CellResult, device: SimulatedOpcUaDevice,
             proxy: OpcUaGuardProxy) -> CellResult:
    """Copy the episode's outcome out of the live objects."""
    stats = proxy.stats
    result.detected = proxy.detected
    result.first_detection_t = _since(proxy.first_detection_t, result.t0)
    result.damaged = device.damaged
    result.peak_level_m = device.peak_level_m
    result.min_level_m = device.min_level_m
    result.writes_decoded = stats.writes_decoded
    result.writes_blocked = stats.writes_blocked
    result.wire_blocked = stats.wire_blocked
    result.alarms = stats.writes_alarmed
    result.trips = stats.trips_issued
    result.blind_trips = stats.blind_trips
    result.integrity_alarm_t = _since(stats.integrity_alarm_t, result.t0)
    result.polls = stats.polls
    result.severed_at = _since(stats.severed_at, result.t0)
    result.sever_reason = stats.sever_reason
    result.rules_fired = tuple(sorted({r for w in proxy.writes for r in w.rule_ids}
                                      | {f.rule_id for e in proxy.events for f in e.findings}))
    result.wire_reasons = tuple(sorted(stats.wire_reasons))
    result.visibility = proxy.visibility.as_dict()
    result.latency_us = list(stats.decision_latency_us)
    return result


@dataclass
class Pair:
    """One scenario and mode, run enforcing and run powerless."""

    guarded: CellResult
    unguarded: CellResult

    @property
    def scenario(self) -> str:
        return self.guarded.scenario

    @property
    def mode(self) -> SecurityMode:
        return self.guarded.mode

    @property
    def damage_to_prevent(self) -> bool:
        return self.unguarded.damaged

    @property
    def damage_prevented(self) -> bool:
        return self.unguarded.damaged and not self.guarded.damaged

    @property
    def outcome(self) -> str:
        """The four-way answer the experiment is actually about.

        ``refused``   the command never reached the device
        ``recovered`` it did, and the guard tripped the plant back afterwards
        ``damaged``   it did, and the guard did not stop the consequence
        ``missed``    the guard never objected to anything

        The no-attack episode gets its own word. Calling a clean benign run a
        miss puts the false-alarm baseline in the same column as a failure.

        So does the reconnaissance episode, for the opposite reason. It issues
        no commands, so there is nothing for the guard to catch and "missed" is
        the wrong word for doing the right thing. An objection to it is not a
        partial success either: it is a false alarm, and on an encrypted
        channel the only way the guard has to act on one is to cut the
        operator's session.
        """
        g = self.guarded
        if not g.is_attack:
            return "no attack"
        if g.read_only:
            return "false alarm" if g.detected else "ignored"
        if not g.detected:
            return "missed"
        if g.stopped_before_the_device:
            return "refused"
        if self.unguarded.damaged and not g.damaged:
            return "recovered"
        if g.damaged:
            return "damaged"
        return "alarmed"


async def run_experiment(
    config: Config,
    cert_dir: Path,
    scenarios: tuple[str, ...] = SCENARIOS,
    modes: tuple[SecurityMode, ...] = MODES,
    **kwargs,
) -> list[Pair]:
    """Every scenario against every mode, each enforcing and powerless."""
    certs = await ensure_certs(cert_dir)
    pairs: list[Pair] = []
    for scenario in scenarios:
        for mode in modes:
            guarded = await run_cell(scenario, mode, config, certs, enforce=True, **kwargs)
            unguarded = await run_cell(scenario, mode, config, certs, enforce=False, **kwargs)
            pairs.append(Pair(guarded=guarded, unguarded=unguarded))
    return pairs


def latency_summary(pairs: list[Pair]) -> dict:
    values = [v for p in pairs for v in p.guarded.latency_us]
    if not values:
        return {"count": 0}
    ordered = sorted(values)
    return {
        "count": len(ordered),
        "p50": statistics.median(ordered),
        "p95": ordered[int(0.95 * (len(ordered) - 1))],
        "p99": ordered[int(0.99 * (len(ordered) - 1))],
    }
