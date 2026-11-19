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
from ..bess.types import SiteCommandKind
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
    SiteCommandKind.SITE_POWER: "Site.DispatchSetpoint",
    SiteCommandKind.POI_LIMIT: "Site.ExportLimit",
    SiteCommandKind.BREAKER: "Site.Breaker",
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
                   fraction: float = 0.45, period_s: float = 2.0,
                   ramp_mw_s: float = 0.8,
                   stand_down: tuple[float, float] | None = None,
                   recovery_from: float | None = None,
                   recovery_stats: MasterStats | None = None) -> None:
    """A site controller dispatching against the connection agreement.

    Three things here are load-bearing.

    It dispatches to a fraction of the export limit rather than to a fixed
    number of megawatts, which is what a site controller does: the limit is
    the contract and the schedule is written against it.

    It reads that limit off the device rather than holding it internally, so a
    write to the limit node changes what this loop aims at. That is what makes
    a limit attack an attack: the damage is done by the site's own control,
    working correctly, against a figure it was handed. Oldsmar's shape, on a
    battery.

    It stands down during ``stand_down``. Under this project's threat model
    the attacker has the station, so the legitimate loop is not also using it.
    Leaving it running means the honest loop fights the attack for the same
    set-point and neutralises it — the attack is then stopped by its victim
    rather than by the guard, which flatters the guard without anyone
    noticing. The loop comes back when the window closes, and whether it can
    still write at that point is the measurement: a guard that refused by
    cutting the channel has also cut the operator's way back in.
    """
    # Both windows are offsets from the moment this client starts, not clock
    # readings. The clock has already been running for the handshake and the
    # warm-up by the time the episode begins, so comparing against it directly
    # puts the whole episode inside the stand-down window and the operator
    # never writes at all.
    start = clock.now()
    end = start + duration_s
    held = 0.0
    with contextlib.suppress(Exception):
        held = float(await _node(client, "Site.DispatchSetpoint", ns).read_value())
    while clock.now() < end:
        now = clock.now() - start
        if stand_down is not None and stand_down[0] <= now <= stand_down[1]:
            await clock.sleep(period_s)
            continue
        limit = None
        with contextlib.suppress(Exception):
            limit = float(await _node(client, "Site.ExportLimit", ns).read_value())
        # After the attack window the operator is trying to get the site back.
        # Whether those writes land is counted separately, because it is a
        # different question from whether ordinary traffic is refused.
        into = stats
        if (recovery_stats is not None and recovery_from is not None
                and now >= recovery_from):
            into = recovery_stats
        if limit is not None:
            target = limit * fraction
            # Walk toward the target at a rate the grid code allows rather
            # than stepping to it. A site controller ramps; one that writes
            # its whole schedule in a single set-point is asking for a jump
            # of several megawatts in one scan, and a rule that let that
            # through would have nothing to say about the attack that does
            # the same thing on purpose.
            step = ramp_mw_s * period_s
            held = max(held - step, min(held + step, target))
            into.attempted += 1
            if await _write(client, "Site.DispatchSetpoint", held, ns):
                into.accepted += 1
        await clock.sleep(period_s)


# ----------------------------------------------------------------------
# The attacks
# ----------------------------------------------------------------------
async def export_over_limit(client: Client, clock: SimClock, stats: MasterStats,
                            ns: int = 2, hold_s: float = 70.0) -> None:
    """Dispatch the fleet past the grid connection, and wait.

    The value is inside what the batteries can produce and nothing about the
    write is anomalous. Only the consequence is, which is the argument for
    physics rules in the first place, and it is also the one attack a blind
    guard can still catch — because the consequence is in the power it polls
    itself.
    """
    stats.attempted += 1
    if await _write(client, "Site.DispatchSetpoint", 30.0, ns):
        stats.accepted += 1
    await clock.sleep(hold_s)


async def limit_tamper(client: Client, clock: SimClock, stats: MasterStats,
                       ns: int = 2, hold_s: float = 70.0) -> None:
    """Raise the export limit, the way Oldsmar's set-point was raised.

    The write is one number to one node and it moves no megawatt by itself: it
    changes what the site controller will aim for, and the controller does the
    rest correctly. A readable channel makes this a range check against the
    transformer. An encrypted one makes it invisible, and process supervision
    cannot recover it, because nothing has happened yet.
    """
    stats.attempted += 1
    if await _write(client, "Site.ExportLimit", 45.0, ns):
        stats.accepted += 1
    await clock.sleep(hold_s)


async def write_flood(client: Client, clock: SimClock, stats: MasterStats,
                      ns: int = 2, writes: int = 200, period_s: float = 0.05) -> None:
    """Hammer the dispatch node far faster than any site controller writes.

    The only attack here whose signature survives encryption, because the
    signature is the arrival rate and no security mode hides that.
    """
    misses = 0
    for i in range(writes):
        stats.attempted += 1
        if await _write(client, "Site.DispatchSetpoint", 8.0 + (i % 5), ns):
            stats.accepted += 1
            misses = 0
        else:
            misses += 1
            if misses >= GIVE_UP_AFTER:
                break
        await clock.sleep(period_s)


async def breaker_hammer(client: Client, clock: SimClock, stats: MasterStats,
                         ns: int = 2, cycles: int = 40, period_s: float = 0.2) -> None:
    """Cycle the main breaker.

    Every value is legal and the power barely moves, because this model only
    damages switchgear on a close that is out of synchronism and the grid does
    not drift inside an episode. The pairs it produces are evidence about
    detection and none about damage, exactly as the valve attack was. Its
    purpose here is to be the attack a guard with no view of the commands
    cannot see at all.
    """
    misses = 0
    for i in range(cycles):
        stats.attempted += 1
        if await _write(client, "Site.Breaker", 0.0 if i % 2 == 0 else 1.0, ns):
            stats.accepted += 1
            misses = 0
        else:
            misses += 1
            if misses >= GIVE_UP_AFTER:
                break
        await clock.sleep(period_s)


async def parameter_tamper(client: Client, clock: SimClock, stats: MasterStats,
                           ns: int = 2, hold_s: float = 70.0) -> None:
    """Raise the ramp limit, then dispatch a figure that is in range.

    The set-point never leaves its range. What changed is how fast the site is
    allowed to get there, and a site that slams its output around moves the
    frequency for everybody connected nearby. It is a write to a node that
    announces its own engineering unit and is no safer for it.
    """
    stats.attempted += 1
    if await _write(client, "Site.RampLimit", 40.0, ns):
        stats.accepted += 1
    stats.attempted += 1
    if await _write(client, "Site.DispatchSetpoint", 19.0, ns):
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
    "export_over_limit": AttackSpec(export_over_limit, 70.0, True,
                                    "contends for the dispatch set-point"),
    "limit_tamper": AttackSpec(limit_tamper, 70.0, False,
                               "the loop has to obey the tampered limit"),
    "write_flood": AttackSpec(write_flood, 70.0, True,
                              "contends for the dispatch set-point"),
    "breaker_hammer": AttackSpec(breaker_hammer, 70.0, True,
                                 "contends for the breaker"),
    "parameter_tamper": AttackSpec(parameter_tamper, 70.0, True,
                                   "contends for the dispatch, through its ramp"),
    "recon_browse": AttackSpec(recon_browse, 70.0, False,
                               "reads only; nothing to contend for"),
}

#: Kept for callers that only want the coroutines.
ATTACKS = {name: spec.run for name, spec in SPECS.items()}

#: Attacks that only read. Scored as traffic the guard must not refuse.
READ_ONLY = frozenset({"recon_browse"})
