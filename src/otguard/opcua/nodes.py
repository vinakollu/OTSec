"""The device's address space, and the guard's map of it.

One list serves both. The simulated device builds its nodes from it, and the
guard reads the same list as its configured description of what each node
means physically. That is the OPC UA equivalent of a Modbus device map, and
the roles are the same three.

Node identifiers are strings fixed here rather than numbers the server hands
out at start-up. A guard whose map depends on whatever identifiers a server
assigned at boot is not configurable; a plant's documentation records
``ns=2;s=Site.DispatchSetpoint``, and that is what the guard is given.

The useful difference from Modbus is that OPC UA nodes carry their own type
and engineering unit, so none of the scaling and live-zero arithmetic a Modbus
map needs applies. A dispatch set-point is a Double in megawatts and the
server will reject a string. That removes one class of guard bug and removes
none of the rest: a Double of 30.0 in megawatts is still a perfectly legal
value for a command that is about to push a site past its grid connection.

Four writable nodes, and the four of them are chosen to cover the four cases
the guard has to tell apart.

``Site.DispatchSetpoint``  a command the rules understand and can judge.
``Site.ExportLimit``       the contractual limit, writable, which is what
                           makes the limit something an attacker can move
                           before dispatching against it rather than a
                           physical impossibility.
``Site.Breaker``           an interlock question rather than a magnitude one.
``Site.RampLimit``         a commissioning parameter. Writing it changes what
                           every later command means, so no rule that reasons
                           about where the power ends up can judge it, and the
                           wire policy has to answer instead.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..bess.types import SiteCommandKind
from ..guard.wire import PointRole

NAMESPACE_URI = "http://otguard.gatech.edu/site"
ENDPOINT_PATH = "/otguard/site/"


@dataclass(frozen=True)
class OpcPoint:
    """One node, and what writing to it does to the plant."""

    identifier: str                 # the string part of ns=2;s=<identifier>
    browse_name: str
    role: PointRole
    kind: SiteCommandKind | None = None
    unit: str = ""
    writable: bool = False
    initial: float = 0.0

    def node_id_string(self, namespace_index: int) -> str:
        return f"ns={namespace_index};s={self.identifier}"


#: The storage site as an OPC UA server exposes it.
SITE_POINTS: tuple[OpcPoint, ...] = (
    # What the site is being asked to deliver, in megawatts at the grid
    # connection. The device shares it across the units that are online, which
    # is what a site controller does with a fleet set-point.
    OpcPoint("Site.DispatchSetpoint", "DispatchSetpoint", PointRole.COMMAND,
             SiteCommandKind.SITE_POWER, "MW", writable=True, initial=0.0),
    # The connection agreement. An engineer is supposed to be able to change
    # it, which is exactly why an attacker raises it first and dispatches
    # against the new figure afterwards. A guard that reads this register as
    # its constraint is checking the attacker's own work, so the rules judge a
    # proposed limit against the transformer instead, which nobody can write.
    OpcPoint("Site.ExportLimit", "ExportLimit", PointRole.COMMAND,
             SiteCommandKind.POI_LIMIT, "MW", writable=True, initial=20.0),
    # Closing onto a grid the site does not match destroys switchgear in a
    # single cycle. It is not a magnitude question, which is why a rule about
    # where the power ends up cannot answer it.
    OpcPoint("Site.Breaker", "Breaker", PointRole.COMMAND,
             SiteCommandKind.BREAKER, "", writable=True, initial=1.0),
    # A commissioning parameter: writing it changes how fast the site is
    # allowed to move, which invalidates the model every physics rule reasons
    # about. There is no rule that can judge it, so the wire policy decides.
    OpcPoint("Site.RampLimit", "RampLimit", PointRole.PARAMETER,
             None, "MW/s", writable=True, initial=2.0),
    # Read back by the operator station, and by the guard's blind supervisor
    # when the channel is encrypted and there is nothing else left to read.
    OpcPoint("Site.PoiPowerMw", "PoiPowerMw", PointRole.PASSTHROUGH, None, "MW"),
    OpcPoint("Site.FleetSoc", "FleetSoc", PointRole.PASSTHROUGH, None, "%"),
    OpcPoint("Site.HottestTempC", "HottestTempC", PointRole.PASSTHROUGH, None, "degC"),
    OpcPoint("Site.TransformerMva", "TransformerMva", PointRole.PASSTHROUGH, None, "MVA"),
)

#: The measurement the blind supervisor falls back on. On an encrypted channel
#: the guard cannot read a single command, so the only thing it has left is
#: the quantity the plant publishes about itself.
POWER_POINT = "Site.PoiPowerMw"
LIMIT_POINT = "Site.ExportLimit"


class NodeMap:
    """Looks a node identifier up and says what it means."""

    def __init__(self, points: tuple[OpcPoint, ...] = SITE_POINTS,
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
