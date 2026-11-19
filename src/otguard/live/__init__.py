"""The live view: one event stream, a terminal renderer and browser renderers.

The stream is the single source of truth. No renderer reads a plant, so every
number on every display arrived as an event, and a disagreement between two of
them is a rendering bug rather than two opinions about the same site.
"""

from .bus import EventBus, Subscription
from .events import Kind, LiveEvent
from .site_demo import SiteDemo
from .site_page import SITE_PAGE
from .terminal import TerminalView
from .water_demo import WaterDemo
from .water_page import WATER_PAGE
from .web import LiveServer

__all__ = [
    "SITE_PAGE",
    "WATER_PAGE",
    "EventBus",
    "Kind",
    "LiveEvent",
    "LiveServer",
    "SiteDemo",
    "Subscription",
    "TerminalView",
    "WaterDemo",
]
