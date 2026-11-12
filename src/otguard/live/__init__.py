"""The live view: one event stream, a terminal renderer and a browser renderer.

The stream is the single source of truth. Neither renderer reads the plant, so
every number on either display arrived as an event and a disagreement between
the two is a rendering bug rather than two opinions about the same tank.
"""

from .bus import EventBus, Subscription
from .events import Kind, LiveEvent
from .terminal import TerminalView
from .web import LiveServer

__all__ = [
    "EventBus",
    "Kind",
    "LiveEvent",
    "LiveServer",
    "Subscription",
    "TerminalView",
]
