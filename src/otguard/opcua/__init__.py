"""OPC UA: the same guard, on a protocol that can encrypt itself.

Everything else in this project guards a protocol with no security at all, and
the guard's access to the traffic is simply assumed. OPC UA is the protocol a
plant replaces Modbus *with*, and it changes that assumption: the device and
its client negotiate a security mode, and that negotiation decides how much of
the conversation a bump-in-the-wire can see.

The question the package exists to answer is what the guard is worth in each
mode, measured rather than argued. ``docs/opcua.md`` has the numbers.

Importing this package needs ``asyncua``, which is an optional dependency.
:mod:`otguard.opcua.framing` and :mod:`otguard.opcua.nodes` do not.
"""

from .framing import SecurityMode, Visibility
from .nodes import TANK_POINTS, NodeMap, OpcPoint

__all__ = ["SecurityMode", "Visibility", "TANK_POINTS", "NodeMap", "OpcPoint"]
