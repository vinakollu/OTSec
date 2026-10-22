"""The device's address space, and the guard's map of it.

One list serves both. The simulated device builds its nodes from it, and the
guard reads the same list as its configured description of what each node means
physically. That is the OPC UA equivalent of
:mod:`otguard.modbus.devicemap`, and the roles are the same three.

Node identifiers are strings fixed here rather than numbers the server hands
out at start-up. A guard whose map depends on whatever identifiers a server
assigned at boot is not configurable; a plant's documentation records
``ns=2;s=Tank.PumpCommand``, and that is what the guard is given.

The useful difference from Modbus is that OPC UA nodes carry their own type and
engineering unit, so none of the scaling and live-zero arithmetic that the
Modbus device maps need applies. A pump command is a Double in per cent and the
server will reject a string. That removes one class of guard bug and removes
none of the rest: a Double of 100.0 in per cent is still a perfectly legal
value for a command that is about to overflow the tank.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..guard.types import CommandKind
from ..modbus.devicemap import PointRole

NAMESPACE_URI = "http://otguard.gatech.edu/tank"
ENDPOINT_PATH = "/otguard/tank/"


@dataclass(frozen=True)
class OpcPoint:
    """One node, and what writing to it does to the plant."""

    identifier: str                 # the string part of ns=2;s=<identifier>
    browse_name: str
    role: PointRole
    kind: CommandKind | None = None
    unit: str = ""
    writable: bool = False
    initial: float = 0.0

    def node_id_string(self, namespace_index: int) -> str:
        return f"ns={namespace_index};s={self.identifier}"


#: The tank as an OPC UA server exposes it. Four writable nodes, three of them
#: commands the physics rules understand and one a parameter they do not.
TANK_POINTS: tuple[OpcPoint, ...] = (
    OpcPoint("Tank.PumpCommand", "PumpCommand", PointRole.COMMAND,
             CommandKind.PUMP, "%", writable=True),
    # Both actuators start shut, which is what the guard assumes about a plant
    # it has just been inserted in front of. A device that boots with its outlet
    # already 30 % open hands the guard a falling level it has no command to
    # explain, and the consistency rule reaches the conclusion its premise
    # allows: the transmitter must be lying. Matching the two is not a trick to
    # make the numbers work — it is the cold-start problem, and a deployment
    # solves it by reading the actuator feedback before enforcing, which this
    # proxy does not model.
    OpcPoint("Tank.ValveCommand", "ValveCommand", PointRole.COMMAND,
             CommandKind.VALVE, "%", writable=True, initial=0.0),
    # The operator station reads this back and aims at it, so tampering with it
    # makes the plant's own control loop do the damage. A set-point node nobody
    # reads is a number in a register, and a scenario built on one measures a
    # write that nothing obeyed.
    OpcPoint("Tank.LevelSetpoint", "LevelSetpoint", PointRole.COMMAND,
             CommandKind.SETPOINT, "m", writable=True, initial=0.95),
    # A commissioning parameter: writing it changes how the actuator responds,
    # which invalidates the model every physics rule reasons about. There is no
    # rule that can judge it, so the wire policy decides, exactly as on the
    # drive gateway in the Modbus matrix.
    OpcPoint("Tank.PumpMaxSpeed", "PumpMaxSpeed", PointRole.PARAMETER,
             None, "%", writable=True, initial=100.0),
    OpcPoint("Tank.Level", "Level", PointRole.PASSTHROUGH, None, "m"),
    OpcPoint("Tank.PumpFeedback", "PumpFeedback", PointRole.PASSTHROUGH, None, "%"),
    OpcPoint("Tank.ValveFeedback", "ValveFeedback", PointRole.PASSTHROUGH, None, "%"),
)

LEVEL_POINT = "Tank.Level"


class NodeMap:
    """Looks a node identifier up and says what it means."""

    def __init__(self, points: tuple[OpcPoint, ...] = TANK_POINTS,
                 namespace_index: int = 2) -> None:
        self.namespace_index = namespace_index
        self.points = points
        self._by_identifier = {p.identifier: p for p in points}

    def __iter__(self):
        return iter(self.points)

    def writable(self) -> list[OpcPoint]:
        return [p for p in self.points if p.writable]

    def lookup(self, node_id) -> OpcPoint | None:
        """Resolve an :class:`asyncua.ua.NodeId` against the configured map.

        Returns ``None`` for a node the map does not describe, which the wire
        policy treats the same way it treats an unmapped Modbus register: a
        write whose meaning the guard does not know.
        """
        identifier = getattr(node_id, "Identifier", None)
        if not isinstance(identifier, str):
            return None
        if getattr(node_id, "NamespaceIndex", self.namespace_index) != self.namespace_index:
            return None
        return self._by_identifier.get(identifier)
