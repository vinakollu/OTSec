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
from enum import Enum

MBAP_SIZE = 7
PROTOCOL_ID = 0

# --- function codes ---
FC_READ_COILS = 0x01
FC_READ_DISCRETE_INPUTS = 0x02
FC_READ_HOLDING_REGISTERS = 0x03
FC_READ_INPUT_REGISTERS = 0x04
FC_WRITE_SINGLE_COIL = 0x05
FC_WRITE_SINGLE_REGISTER = 0x06
FC_WRITE_MULTIPLE_COILS = 0x0F
FC_WRITE_MULTIPLE_REGISTERS = 0x10
FC_MASK_WRITE_REGISTER = 0x16
FC_READ_WRITE_MULTIPLE_REGISTERS = 0x17

# Every public function code that can change a device's state. A guard that
# inspects only some of these is not inspecting writes; it is inspecting the
# writes its authors happened to test with, and the rest walk straight past.
WRITE_FUNCTION_CODES = frozenset(
    {
        FC_WRITE_SINGLE_COIL,
        FC_WRITE_SINGLE_REGISTER,
        FC_WRITE_MULTIPLE_COILS,
        FC_WRITE_MULTIPLE_REGISTERS,
        FC_MASK_WRITE_REGISTER,
        FC_READ_WRITE_MULTIPLE_REGISTERS,
    }
)
READ_FUNCTION_CODES = frozenset(
    {
        FC_READ_COILS,
        FC_READ_DISCRETE_INPUTS,
        FC_READ_HOLDING_REGISTERS,
        FC_READ_INPUT_REGISTERS,
    }
)

# --- exception codes ---
EX_ILLEGAL_FUNCTION = 0x01
EX_ILLEGAL_DATA_ADDRESS = 0x02
EX_ILLEGAL_DATA_VALUE = 0x03
EX_SERVER_FAILURE = 0x04
EX_GATEWAY_TARGET_FAILED = 0x0B

MAX_REGISTERS_PER_READ = 125
MAX_REGISTERS_PER_WRITE = 123
MAX_COILS_PER_READ = 2000
MAX_COILS_PER_WRITE = 1968
MAX_REGISTERS_PER_READWRITE = 121


class Space(str, Enum):
    """The four Modbus data tables.

    Coils and holding registers are separate address spaces: coil 0 and holding
    register 0 are unrelated points. Treating an address as meaningful without
    its space is how a pump-run coil ends up judged as a 0.1 % speed command.
    """

    COIL = "coil"
    DISCRETE_INPUT = "discrete_input"
    HOLDING = "holding"
    INPUT = "input"


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
    """A decoded write: which table, which addresses, and what values.

    ``values`` holds one entry per point written, in address order: register
    words for the register tables, 0/1 for coils. A mask write (FC22) carries
    no value of its own; its effect depends on what the register already holds,
    so it is described by its two masks and ``values`` is empty.
    """

    function_code: int
    address: int
    values: list[int]
    space: Space = Space.HOLDING
    and_mask: int | None = None
    or_mask: int | None = None
    read_address: int | None = None   # FC23 only
    read_count: int | None = None     # FC23 only

    @property
    def is_coil(self) -> bool:
        return self.space is Space.COIL

    @property
    def is_masked(self) -> bool:
        return self.function_code == FC_MASK_WRITE_REGISTER

    def points(self) -> list[tuple[int, int]]:
        """``(address, value)`` for every point this request writes."""
        return [(self.address + i, v) for i, v in enumerate(self.values)]


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
        return WriteRequest(fc, address, [1 if value else 0], space=Space.COIL)

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

    if fc == FC_WRITE_MULTIPLE_COILS:
        if len(pdu) < 6:
            return None
        address, count, byte_count = struct.unpack(">HHB", pdu[1:6])
        body = pdu[6:]
        if count == 0 or count > MAX_COILS_PER_WRITE:
            return None
        if byte_count != (count + 7) // 8 or len(body) != byte_count:
            return None
        return WriteRequest(fc, address, unpack_bits(body, count), space=Space.COIL)

    if fc == FC_MASK_WRITE_REGISTER:
        if len(pdu) != 7:
            return None
        address, and_mask, or_mask = struct.unpack(">HHH", pdu[1:7])
        return WriteRequest(fc, address, [], and_mask=and_mask, or_mask=or_mask)

    if fc == FC_READ_WRITE_MULTIPLE_REGISTERS:
        if len(pdu) < 10:
            return None
        read_address, read_count, address, count, byte_count = struct.unpack(
            ">HHHHB", pdu[1:10]
        )
        body = pdu[10:]
        if not 1 <= read_count <= MAX_REGISTERS_PER_READ:
            return None
        if count == 0 or count > MAX_REGISTERS_PER_READWRITE:
            return None
        if byte_count != count * 2 or len(body) != byte_count:
            return None
        values = list(struct.unpack(f">{count}H", body))
        return WriteRequest(
            fc, address, values, read_address=read_address, read_count=read_count
        )

    return None


@dataclass(frozen=True)
class ReadRequest:
    function_code: int
    address: int
    count: int

    @property
    def space(self) -> Space:
        return _READ_SPACES[self.function_code]


_READ_SPACES = {
    FC_READ_COILS: Space.COIL,
    FC_READ_DISCRETE_INPUTS: Space.DISCRETE_INPUT,
    FC_READ_HOLDING_REGISTERS: Space.HOLDING,
    FC_READ_INPUT_REGISTERS: Space.INPUT,
}


def parse_read(pdu: bytes) -> ReadRequest | None:
    if len(pdu) != 5:
        return None
    fc = pdu[0]
    if fc not in READ_FUNCTION_CODES:
        return None
    address, count = struct.unpack(">HH", pdu[1:5])
    return ReadRequest(fc, address, count)


def pack_bits(bits: list[int]) -> bytes:
    """Pack coil states LSB-first, eight to a byte, as Modbus sends them."""
    out = bytearray((len(bits) + 7) // 8)
    for i, bit in enumerate(bits):
        if bit:
            out[i // 8] |= 1 << (i % 8)
    return bytes(out)


def unpack_bits(data: bytes, count: int) -> list[int]:
    return [(data[i // 8] >> (i % 8)) & 1 for i in range(count)]


# ----------------------------------------------------------------------
# Request building (the client side: masters, and the guard's own polls)
# ----------------------------------------------------------------------
def read_request(function_code: int, address: int, count: int) -> bytes:
    return struct.pack(">BHH", function_code, address, count)


def write_single_register(address: int, value: int) -> bytes:
    return struct.pack(">BHH", FC_WRITE_SINGLE_REGISTER, address, value & 0xFFFF)


def write_single_coil(address: int, on: bool) -> bytes:
    return struct.pack(">BHH", FC_WRITE_SINGLE_COIL, address, 0xFF00 if on else 0x0000)


def write_multiple_registers(address: int, values: list[int]) -> bytes:
    body = struct.pack(f">{len(values)}H", *[v & 0xFFFF for v in values])
    return struct.pack(">BHHB", FC_WRITE_MULTIPLE_REGISTERS, address, len(values), len(body)) + body


def write_multiple_coils(address: int, bits: list[int]) -> bytes:
    body = pack_bits(bits)
    return struct.pack(">BHHB", FC_WRITE_MULTIPLE_COILS, address, len(bits), len(body)) + body


def mask_write_register(address: int, and_mask: int, or_mask: int) -> bytes:
    return struct.pack(">BHHH", FC_MASK_WRITE_REGISTER, address, and_mask, or_mask)


def read_write_multiple_registers(
    read_address: int, read_count: int, write_address: int, values: list[int]
) -> bytes:
    body = struct.pack(f">{len(values)}H", *[v & 0xFFFF for v in values])
    return (
        struct.pack(
            ">BHHHHB",
            FC_READ_WRITE_MULTIPLE_REGISTERS,
            read_address,
            read_count,
            write_address,
            len(values),
            len(body),
        )
        + body
    )


# ----------------------------------------------------------------------
# Response building
# ----------------------------------------------------------------------
def read_registers_response(function_code: int, values: list[int]) -> bytes:
    body = struct.pack(f">{len(values)}H", *[v & 0xFFFF for v in values])
    return struct.pack(">BB", function_code, len(body)) + body


def read_bits_response(function_code: int, bits: list[int]) -> bytes:
    body = pack_bits(bits)
    return struct.pack(">BB", function_code, len(body)) + body


def write_single_response(function_code: int, address: int, value: int) -> bytes:
    return struct.pack(">BHH", function_code, address, value & 0xFFFF)


def write_multiple_response(address: int, count: int, function_code: int = FC_WRITE_MULTIPLE_REGISTERS) -> bytes:
    return struct.pack(">BHH", function_code, address, count)


def mask_write_response(address: int, and_mask: int, or_mask: int) -> bytes:
    return mask_write_register(address, and_mask, or_mask)
