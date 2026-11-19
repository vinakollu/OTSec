"""Modbus TCP framing.

What is left here is the wire format and nothing else. The device scanner
reads a register off a site controller to establish that something is
answering, and that read has to be a real Modbus frame, so the framing stays.
Everything that used to sit on top of it, the simulated controller, the
device maps, the sender inventory and the guard proxies, belonged to the
storage tank and went with it.
"""

from .protocol import Frame, Space, decode_frame, encode_frame, parse_read, parse_write

__all__ = [
    "Frame",
    "Space",
    "decode_frame",
    "encode_frame",
    "parse_read",
    "parse_write",
]
