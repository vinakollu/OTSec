"""Clients in front of the guard: one honest, five not.

Every one of these connects to the proxy rather than to the device, so each
request crosses the guard on its way in. They all read time from the shared
:class:`~otguard.clock.SimClock`, so "writes every second" means a simulated
second however fast the episode is actually running.

The attacks are chosen to separate two things the three security modes affect
differently: whether the guard can *read* a command, and whether the command
moves the process. An attack that does both is the easy case — even a blind
guard sees the level go wrong. The interesting cells are the attacks that move
nothing measurable, because those are the ones that disappear completely when
the channel is encrypted.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass

from asyncua import Client, ua

from ..clock import SimClock
from ..guard.types import CommandKind
from ..scenarios.base import LevelController
from .certs import MASTER_URI, CertSet
from .framing import SecurityMode
from .nodes import NAMESPACE_URI


async def open_client(url: str, mode: SecurityMode, certs: CertSet | None,
                      application_uri: str = MASTER_URI) -> Client:
    """Connect a client at the given security mode, through whatever is listening."""
    # Three seconds, not ten. When the guard refuses by cutting the channel the
    # client's next request has nowhere to go, and a long timeout turns an
    # attack of two hundred writes into a very long wait on sockets that are
    # already closed.
    client = Client(url, timeout=3)
    client.application_uri = application_uri
    if mode is not SecurityMode.NONE:
        from asyncua.crypto.security_policies import SecurityPolicyBasic256Sha256

        if certs is None:
            raise ValueError(f"security mode {mode.value} needs certificates")
        await client.set_security(
            SecurityPolicyBasic256Sha256,
            certificate=certs.master.cert_str,
            private_key=certs.master.key_str,
            server_certificate=certs.device.cert_str,
            mode=(
                ua.MessageSecurityMode.Sign
                if mode is SecurityMode.SIGN
                else ua.MessageSecurityMode.SignAndEncrypt
            ),
        )
    await client.connect()
    return client


#: Which node each writable process variable lives on.
NODE_FOR_KIND = {
    CommandKind.PUMP: "Tank.PumpCommand",
    CommandKind.VALVE: "Tank.ValveCommand",
    CommandKind.SETPOINT: "Tank.LevelSetpoint",
}


def _node(client: Client, identifier: str, namespace_index: int = 2):
    return client.get_node(ua.NodeId(identifier, namespace_index))


async def _write(client: Client, identifier: str, value: float,
                 namespace_index: int = 2) -> bool:
    """Write one node. False when the guard, or the device, said no."""
    try:
        await _node(client, identifier, namespace_index).write_value(
            ua.DataValue(ua.Variant(float(value), ua.VariantType.Double))
        )
        return True
    except Exception:
        return False


#: Consecutive failed writes after which a looping attack gives up.
#:
#: Once the guard has cut the channel every further request waits out the
#: client timeout and returns nothing. A real attacker would reconnect and try
#: again; modelling that retry storm is not what any of these episodes measure,
#: and without a limit a single severed channel costs the run ten minutes of
#: waiting for sockets that are gone.
GIVE_UP_AFTER = 3


@dataclass
class MasterStats:
    """What the client itself saw, which is not what the guard saw."""

    attempted: int = 0
    accepted: int = 0

    @property
    def refused(self) -> int:
        return self.attempted - self.accepted


async def namespace_index(client: Client) -> int:
    """Resolve the device's namespace rather than assuming index 2."""
    with contextlib.suppress(Exception):
        uris = await client.get_namespace_array()
        if NAMESPACE_URI in uris:
            return uris.index(NAMESPACE_URI)
    return 2


# ----------------------------------------------------------------------
# The honest client
# ----------------------------------------------------------------------
async def operator(client: Client, clock: SimClock, stats: MasterStats,
                   duration_s: float, ns: int = 2,
                   valve_pct: float = 30.0, period_s: float = 2.0,
                   stand_down: tuple[float, float] | None = None,
                   recovery_from: float | None = None,
                   recovery_stats: MasterStats | None = None) -> None:
    """An operator station holding a level, the way a supervisory loop does.

    Three things here are load-bearing.

    It closes the loop. An earlier version held a fixed pump command, which is
    not a steady state — the tank filled from 0.95 m to 1.65 m over the episode
    and the guard was right to object. Measuring that as a false alarm would
    have been measuring a bad client.

    It reads its target off the device rather than holding it internally, so a
    write to the set-point node changes what this loop aims at. That is what
    makes a set-point attack an attack: the damage is done by the plant's own
    control, working correctly, against a target it was handed.

    It stands down during ``stand_down``. Under this project's threat model the
    attacker has the operator station, so the legitimate loop is not also using
    it. Leaving it running means the honest loop fights the attack for the same
    actuator and neutralises it — the attack is then stopped by its victim
    rather than by the guard, which flatters the guard without anyone noticing.
    The loop comes back when the window closes, and whether it can still write
    at that point is the measurement: a guard that refused by cutting the
    channel has also cut the operator's way back in.
    """
    controller = LevelController(
        setpoint_m=0.95, valve_pct=valve_pct, write_period_s=period_s
    )
    controller.reset()
    # Both windows are offsets from the moment this client starts, not clock
    # readings. The clock has already been running for the handshake and the
    # warm-up by the time the episode begins, so comparing against it directly
    # puts the whole episode inside the stand-down window and the operator
    # never writes at all.
    start = clock.now()
    end = start + duration_s
    while clock.now() < end:
        now = clock.now() - start
        if stand_down is not None and stand_down[0] <= now <= stand_down[1]:
            await clock.sleep(period_s)
            continue
        level = setpoint = None
        try:
            level = float(await _node(client, "Tank.Level", ns).read_value())
            setpoint = float(await _node(client, "Tank.LevelSetpoint", ns).read_value())
        except Exception:
            pass
        # After the attack window the operator is trying to get the plant back.
        # Whether those writes land is counted separately, because it is a
        # different question from whether ordinary traffic is refused.
        into = stats
        if (recovery_stats is not None and recovery_from is not None
                and now >= recovery_from):
            into = recovery_stats
        if level is not None:
            if setpoint is not None:
                controller.set_setpoint(setpoint)
            for scheduled in controller.update(clock.now(), level):
                identifier = NODE_FOR_KIND.get(scheduled.kind)
                if identifier is None or scheduled.kind is CommandKind.SETPOINT:
                    continue
                into.attempted += 1
                if await _write(client, identifier, scheduled.value, ns):
                    into.accepted += 1
        await clock.sleep(period_s)


# ----------------------------------------------------------------------
# The attacks
# ----------------------------------------------------------------------
async def overflow(client: Client, clock: SimClock, stats: MasterStats,
                   ns: int = 2, hold_s: float = 70.0) -> None:
    """Shut the outlet, run the inlet flat out, wait.

    Both values are inside the equipment rating and nothing about either write
    is anomalous. Only the consequence is, which is the argument for physics
    rules in the first place, and it is also the one attack a blind guard can
    still catch — because the consequence is in the level it polls itself.
    """
    for identifier, value in (("Tank.ValveCommand", 0.0), ("Tank.PumpCommand", 100.0)):
        stats.attempted += 1
        if await _write(client, identifier, value, ns):
            stats.accepted += 1
    await clock.sleep(hold_s)


async def setpoint_jump(client: Client, clock: SimClock, stats: MasterStats,
                        ns: int = 2, hold_s: float = 70.0) -> None:
    """Raise the level set-point above the tank, the way Oldsmar raised a dose.

    The write is one number to one node and it moves no actuator by itself: it
    changes what the control loop will aim for. A readable channel makes this a
    range check. An encrypted one makes it invisible, and process supervision
    cannot recover it, because nothing has happened yet.
    """
    stats.attempted += 1
    if await _write(client, "Tank.LevelSetpoint", 1.95, ns):
        stats.accepted += 1
    await clock.sleep(hold_s)


async def write_flood(client: Client, clock: SimClock, stats: MasterStats,
                      ns: int = 2, writes: int = 200, period_s: float = 0.05) -> None:
    """Hammer the command node far faster than any operator station writes.

    The only attack here whose signature survives encryption, because the
    signature is the arrival rate and no security mode hides that.
    """
    misses = 0
    for i in range(writes):
        stats.attempted += 1
        if await _write(client, "Tank.PumpCommand", 50.0 + (i % 5), ns):
            stats.accepted += 1
            misses = 0
        else:
            misses += 1
            if misses >= GIVE_UP_AFTER:
                break
        await clock.sleep(period_s)


async def valve_hammer(client: Client, clock: SimClock, stats: MasterStats,
                       ns: int = 2, cycles: int = 40, period_s: float = 0.2) -> None:
    """Cycle the outlet valve to generate pressure transients.

    Every value is in range and the level barely moves. This tank models level
    and not pressure, so there is no damage flag to raise either — the pairs it
    produces are evidence about detection and none about damage, exactly as in
    the Modbus matrix. Its purpose here is to be the attack that a guard with
    no view of the commands cannot see at all.
    """
    misses = 0
    for i in range(cycles):
        stats.attempted += 1
        if await _write(client, "Tank.ValveCommand", 100.0 if i % 2 == 0 else 0.0, ns):
            stats.accepted += 1
            misses = 0
        else:
            misses += 1
            if misses >= GIVE_UP_AFTER:
                break
        await clock.sleep(period_s)


async def parameter_tamper(client: Client, clock: SimClock, stats: MasterStats,
                           ns: int = 2, hold_s: float = 70.0) -> None:
    """Raise the pump's maximum-speed parameter, then command a legal speed.

    The speed reference never leaves its range. What changed is what the range
    means, which is the drive-gateway attack from the Modbus matrix carried over
    to a node that announces its own engineering unit and is no safer for it.
    """
    stats.attempted += 1
    if await _write(client, "Tank.PumpMaxSpeed", 180.0, ns):
        stats.accepted += 1
    for identifier, value in (("Tank.ValveCommand", 0.0), ("Tank.PumpCommand", 95.0)):
        stats.attempted += 1
        if await _write(client, identifier, value, ns):
            stats.accepted += 1
    await clock.sleep(hold_s)


async def recon_browse(client: Client, clock: SimClock, stats: MasterStats,
                       ns: int = 2, passes: int = 6, period_s: float = 1.0) -> None:
    """Enumerate the address space and read everything. Write nothing.

    This is the Havex shape: the 2014 Dragonfly campaign's OPC scanning module
    inventoried what was on the network and sent it home. OPC UA makes this
    easier than OPC DA did, because the address space is self-describing by
    design.

    There is no command to judge here, so a plausibility guard contributes
    nothing against it. The scenario is in the suite to be scored as a
    false-alarm case and to make that gap explicit rather than leave it to be
    noticed later.
    """
    for _ in range(passes):
        with contextlib.suppress(Exception):
            objects = client.nodes.objects
            for child in await objects.get_children():
                for leaf in await child.get_children():
                    with contextlib.suppress(Exception):
                        await leaf.read_value()
                        await leaf.read_browse_name()
                    stats.attempted += 1
                    stats.accepted += 1
        await clock.sleep(period_s)


#: How long the attacker holds the station, and whether the honest loop has to
#: get out of the way while they do.
#:
#: The split is not a convenience. An attack that writes the same actuator the
#: operator's loop is regulating needs the loop to stand down, or the two fight
#: and the attack fails for the wrong reason. An attack that works *through*
#: the loop — tampering with the target it aims at, or only reading — needs the
#: loop running, because the loop is the mechanism.
@dataclass(frozen=True)
class AttackSpec:
    run: object
    span_s: float
    operator_stands_down: bool
    note: str = ""


SPECS: dict[str, AttackSpec] = {
    "overflow": AttackSpec(overflow, 70.0, True, "contends for the pump and the valve"),
    "setpoint_jump": AttackSpec(setpoint_jump, 70.0, False,
                                "the loop has to obey the tampered target"),
    "write_flood": AttackSpec(write_flood, 70.0, True, "contends for the pump"),
    "valve_hammer": AttackSpec(valve_hammer, 70.0, True, "contends for the valve"),
    "parameter_tamper": AttackSpec(parameter_tamper, 70.0, True,
                                   "contends for the pump, through its scaling"),
    "recon_browse": AttackSpec(recon_browse, 70.0, False, "reads only; nothing to contend for"),
}

#: Kept for callers that only want the coroutines.
ATTACKS = {name: spec.run for name, spec in SPECS.items()}

#: Attacks that only read. Scored as traffic the guard must not refuse.
READ_ONLY = frozenset({"recon_browse"})
