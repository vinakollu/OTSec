"""Protocol layers for a storage site: DNP3, GOOSE, PRP and REST.

The Modbus TCP implementation lives in :mod:`otguard.modbus`, where the
water-tank work left it; these are the additional protocols a Megapack-class
site speaks. All four expose the same shape — encode, decode, and a state
machine that can object — so the site guard can consume them uniformly.
"""

from . import dnp3, goose, prp, rest

__all__ = ["dnp3", "goose", "prp", "rest"]
