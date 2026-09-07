"""Minimal Modbus TCP framing: MBAP header plus the function codes we need.

Written out rather than pulled from a library for two reasons. The proxy has to
parse and rebuild frames itself in order to inspect writes, so this code has to
exist somewhere regardless. And the one dependency that could have supplied it
is mid-migration to a new datastore API that changes again in its next major
version — pinning the core of the project to that is a poor trade for a protocol
that fits on a page.

The independent check comes from the other direction instead: the demo drives
this code with ``pymodbus``' client, so a real, widely used stack has to be
satisfied by what these functions produce.

Frame layout (Modbus TCP, MBAP + PDU)::

    +----------------+----------------+----------------+---------+---------+
    | transaction(2) | protocol(2)=0  | length(2)      | unit(1) | PDU     |
    +----------------+----------------+----------------+---------+---------+

``length`` counts the unit byte plus the PDU, which is the off-by-one every
hand-rolled Modbus implementation gets wrong at least once.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

MBAP_SIZE = 7
PROTOCOL_ID = 0

# --- function codes ---
FC_READ_COILS = 0x01
FC_READ_DISCRETE_INPUTS = 0x02
FC_READ_HOLDING_REGISTERS = 0x03
FC_READ_INPUT_REGISTERS = 0x04
FC_WRITE_SINGLE_COIL = 0x05
FC_WRITE_SINGLE_REGISTER = 0x06
FC_WRITE_MULTIPLE_REGISTERS = 0x10

WRITE_FUNCTION_CODES = frozenset(
    {FC_WRITE_SINGLE_COIL, FC_WRITE_SINGLE_REGISTER, FC_WRITE_MULTIPLE_REGISTERS}
)

# --- exception codes ---
EX_ILLEGAL_FUNCTION = 0x01
EX_ILLEGAL_DATA_ADDRESS = 0x02
EX_ILLEGAL_DATA_VALUE = 0x03
EX_SERVER_FAILURE = 0x04

MAX_REGISTERS_PER_READ = 125
MAX_REGISTERS_PER_WRITE = 123


@dataclass(frozen=True)
class Frame:
    """One decoded Modbus TCP application data unit."""

    transaction_id: int
    unit_id: int
    pdu: bytes

    @property
    def function_code(self) -> int:
        return self.pdu[0] if self.pdu else 0

    @property
    def is_write(self) -> bool:
        return self.function_code in WRITE_FUNCTION_CODES

    def encode(self) -> bytes:
        return encode_frame(self.transaction_id, self.unit_id, self.pdu)


def encode_frame(transaction_id: int, unit_id: int, pdu: bytes) -> bytes:
    """Wrap a PDU in an MBAP header."""
    return struct.pack(">HHHB", transaction_id, PROTOCOL_ID, len(pdu) + 1, unit_id) + pdu


def decode_frame(buffer: bytes) -> tuple[Frame | None, bytes]:
    """Pull one complete frame off the front of ``buffer``.

    Returns ``(frame, remainder)``, with ``frame`` set to ``None`` when more
    bytes are needed. TCP is a stream: frames arrive split and coalesced, and a
    parser that assumes one read equals one frame works right up until it meets
    a busy link.
    """
    if len(buffer) < MBAP_SIZE:
        return None, buffer
    transaction_id, protocol_id, length, unit_id = struct.unpack(">HHHB", buffer[:MBAP_SIZE])
    if protocol_id != PROTOCOL_ID:
        raise ValueError(f"not a Modbus/TCP frame: protocol id {protocol_id}")
    if length < 1:
        raise ValueError(f"invalid MBAP length {length}")
    total = MBAP_SIZE + length - 1  # length includes the unit byte
    if len(buffer) < total:
        return None, buffer
    return Frame(transaction_id, unit_id, buffer[MBAP_SIZE:total]), buffer[total:]


def exception_pdu(function_code: int, code: int) -> bytes:
    """Build an exception response PDU for a request."""
    return struct.pack(">BB", function_code | 0x80, code)


def is_exception(pdu: bytes) -> bool:
    return bool(pdu) and bool(pdu[0] & 0x80)


# ----------------------------------------------------------------------
# Request parsing
# ----------------------------------------------------------------------
@dataclass(frozen=True)
class WriteRequest:
    """A decoded register/coil write: which addresses, and what values."""

    function_code: int
    address: int
    values: list[int]

    @property
    def is_coil(self) -> bool:
        return self.function_code == FC_WRITE_SINGLE_COIL


def parse_write(pdu: bytes) -> WriteRequest | None:
    """Decode a write PDU into addresses and values, or ``None`` if malformed.

    Returning ``None`` rather than raising keeps the proxy's decision simple: a
    frame it cannot understand is a frame it must not vouch for.
    """
    if not pdu:
        return None
    fc = pdu[0]

    if fc == FC_WRITE_SINGLE_REGISTER:
        if len(pdu) != 5:
            return None
        address, value = struct.unpack(">HH", pdu[1:5])
        return WriteRequest(fc, address, [value])

    if fc == FC_WRITE_SINGLE_COIL:
        if len(pdu) != 5:
            return None
        address, value = struct.unpack(">HH", pdu[1:5])
        # Modbus encodes coil states as 0xFF00 (on) and 0x0000 (off).
        if value not in (0x0000, 0xFF00):
            return None
        return WriteRequest(fc, address, [1 if value else 0])

    if fc == FC_WRITE_MULTIPLE_REGISTERS:
        if len(pdu) < 6:
            return None
        address, count, byte_count = struct.unpack(">HHB", pdu[1:6])
        body = pdu[6:]
        if count == 0 or count > MAX_REGISTERS_PER_WRITE:
            return None
        if byte_count != count * 2 or len(body) != byte_count:
            return None
        values = list(struct.unpack(f">{count}H", body))
        return WriteRequest(fc, address, values)

    return None


@dataclass(frozen=True)
class ReadRequest:
    function_code: int
    address: int
    count: int


def parse_read(pdu: bytes) -> ReadRequest | None:
    if len(pdu) != 5:
        return None
    fc = pdu[0]
    if fc not in (
        FC_READ_COILS,
        FC_READ_DISCRETE_INPUTS,
        FC_READ_HOLDING_REGISTERS,
        FC_READ_INPUT_REGISTERS,
    ):
        return None
    address, count = struct.unpack(">HH", pdu[1:5])
    return ReadRequest(fc, address, count)


# ----------------------------------------------------------------------
# Response building
# ----------------------------------------------------------------------
def read_registers_response(function_code: int, values: list[int]) -> bytes:
    body = struct.pack(f">{len(values)}H", *[v & 0xFFFF for v in values])
    return struct.pack(">BB", function_code, len(body)) + body


def write_single_response(function_code: int, address: int, value: int) -> bytes:
    return struct.pack(">BHH", function_code, address, value & 0xFFFF)


def write_multiple_response(address: int, count: int) -> bytes:
    return struct.pack(">BHH", FC_WRITE_MULTIPLE_REGISTERS, address, count)
