"""Who is allowed to talk, and what the guard does with frames it cannot judge.

Two things live here, and they are deliberately separate from the physics
rules.

An :class:`Inventory` names the devices that send commands. The guard learns a
sender's identity from the only thing a transparent bump-in-the-wire actually
has: the TCP peer it accepted the connection from. That is weak evidence. It
survives nothing but the honest case — an attacker on the operator station's
own host inherits that station's identity, and a spoofed source address defeats
it outright. It is recorded as a configured fact rather than a verified one,
and every result that leans on it says so.

A :class:`WirePolicy` says what to do with a write the rules cannot evaluate:
an unknown function code, a write to an address the device map does not
describe, a parameter write, a sender not in the inventory. None of these are
physics questions, so none of them belong in R1..R5. They are the guard
answering "can I judge this at all?" before it asks "is this physically sane?".

Defaults refuse. A guard that forwards what it does not understand is a guard
whose coverage is the list of attacks its author happened to think of.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class SourceClass(str, Enum):
    """What kind of device is sending, which sets its expected traffic shape."""

    HMI = "hmi"
    SCADA = "scada"
    ENGINEERING = "engineering"
    PEER_CONTROLLER = "peer_controller"
    HISTORIAN = "historian"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class SourceDevice:
    """One configured command source.

    ``writes`` is what this device is expected to write, as a set of point
    names from the device map. An empty set means "reads only": a historian
    that polls has no business writing a setpoint, and saying so costs nothing
    and catches the case where its credentials are reused.
    """

    name: str
    source_class: SourceClass
    description: str = ""
    writes: frozenset[str] = frozenset()
    read_only: bool = False

    def may_write(self, point_name: str) -> bool:
        if self.read_only:
            return False
        return not self.writes or point_name in self.writes


@dataclass
class Inventory:
    """The configured command sources, looked up by TCP peer address."""

    devices: dict[str, SourceDevice] = field(default_factory=dict)
    _by_peer: dict[str, str] = field(default_factory=dict, repr=False)

    def add(self, device: SourceDevice) -> SourceDevice:
        self.devices[device.name] = device
        return device

    def bind(self, address: str, name: str) -> None:
        """Associate a source address with a configured device name.

        Addresses are hosts, not host-and-port pairs. A client's source port is
        assigned by its kernel and changes every reconnection, so it identifies
        nothing; what a plant's documentation records is that the operator
        station lives at one address and the historian at another.
        """
        self._by_peer[address] = name

    def identify(self, peer: tuple[str, int] | str | None) -> SourceDevice:
        """Name the sender behind a connection, or return the unknown device."""
        if peer is None:
            return UNKNOWN_SOURCE
        host = peer if isinstance(peer, str) else peer[0]
        name = self._by_peer.get(host)
        if name is None:
            return UNKNOWN_SOURCE
        return self.devices.get(name, UNKNOWN_SOURCE)


UNKNOWN_SOURCE = SourceDevice(
    name="unknown",
    source_class=SourceClass.UNKNOWN,
    description="a connection from an address not in the inventory",
)


class WireDecision(str, Enum):
    """Why a frame was stopped before the physics rules ever ran."""

    UNKNOWN_FUNCTION = "unknown_function"
    UNPARSEABLE = "unparseable"
    UNMAPPED_POINT = "unmapped_point"
    PARAMETER_WRITE = "parameter_write"
    UNAUTHORISED_SOURCE = "unauthorised_source"
    UNAUTHORISED_POINT = "unauthorised_point"


@dataclass(frozen=True)
class WirePolicy:
    """What to do with writes the physics rules cannot evaluate.

    Every flag defaults to refusing. ``allow_unknown_sources`` is the one worth
    arguing about: refusing it turns the guard into an access-control device as
    well as a physics one, which is a different claim than the project makes
    elsewhere. It is reported as its own column in the results so its
    contribution can be told apart from the rules'.
    """

    refuse_unknown_functions: bool = True
    refuse_unmapped_points: bool = True
    refuse_parameter_writes: bool = True
    enforce_source_scope: bool = True
    allow_unknown_sources: bool = False

    def permits(self, decision: WireDecision) -> bool:
        """True when the policy lets a frame with this defect through anyway."""
        return {
            WireDecision.UNKNOWN_FUNCTION: not self.refuse_unknown_functions,
            WireDecision.UNPARSEABLE: False,
            WireDecision.UNMAPPED_POINT: not self.refuse_unmapped_points,
            WireDecision.PARAMETER_WRITE: not self.refuse_parameter_writes,
            WireDecision.UNAUTHORISED_SOURCE: self.allow_unknown_sources,
            WireDecision.UNAUTHORISED_POINT: not self.enforce_source_scope,
        }[decision]


#: Everything forwarded that the rules cannot judge. The ablation baseline:
#: it isolates what the physics rules catch on their own.
PERMISSIVE_POLICY = WirePolicy(
    refuse_unknown_functions=False,
    refuse_unmapped_points=False,
    refuse_parameter_writes=False,
    enforce_source_scope=False,
    allow_unknown_sources=True,
)
