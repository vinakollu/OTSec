"""The live view: one event stream, a terminal renderer and a browser renderer.

The stream is the single source of truth. Neither renderer reads the plant, so
every number on either display arrived as an event and a disagreement between
the two is a rendering bug rather than two opinions about the same tank.
"""

from .bus import EventBus, Subscription
from .demo import InteractiveDemo
from .demo_page import DEMO_PAGE
from .events import Kind, LiveEvent
from .terminal import TerminalView
from .web import LiveServer

__all__ = [
    "DEMO_PAGE",
    "EventBus",
    "InteractiveDemo",
    "Kind",
    "LiveEvent",
    "LiveServer",
    "Subscription",
    "TerminalView",
]
