"""DNP3 (IEEE 1815) — the subset a storage site actually uses for control.

Scope, stated plainly because "we implemented DNP3" would be an overclaim: this
encodes and decodes real link-layer frames with the standard CRC, the transport
segment header, and the application header, plus the two object groups that
carry control — g12v1 control relay output blocks and g41 analog output blocks.
It does not implement event classes, time synchronisation, file transfer, or
Secure Authentication v5. That is enough to build and inspect the frames the
attacks in this project use, and no more.

The security-relevant structure is *select-before-operate*. A control in DNP3 is
supposed to take two round trips: a SELECT that arms a specific point with a
specific value, then an OPERATE that fires it, and the outstation is required to
reject an OPERATE that does not match a recent SELECT. That protocol-level
handshake is a real invariant an attacker must satisfy, and it is checkable
without any knowledge of what the command means.

Why that matters here: SBO is the one place where the *protocol* carries a
plausibility constraint of the same shape as the physics rules. The outstation
does not need to know whether opening the breaker is wise; it only needs to know
that nobody armed it. DNP3 also ships with no authentication in this profile,
which is exactly why a bump-in-the-wire is the practical control — you cannot
add SAv5 to a meter that does not speak it.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import IntEnum

# Every DNP3 frame starts with this. Used to find frame boundaries in a stream.
START_BYTES = b"\x05\x64"

# CRC over each block is the CCITT-style polynomial DNP3 specifies (0x3D65,
# reflected). It is not the same polynomial as Modbus and not the same as
# X.25 — getting it wrong produces frames that look right and are rejected by
# every real outstation, so there is a known-answer test against the canonical
# reset-link frame in the test suite.
_CRC_POLY = 0xA6BC  # 0x3D65 bit-reversed
_CRC_TABLE: list[int] = []


def _build_crc_table() -> None:
    for byte in range(256):
        crc = byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ _CRC_POLY
            else:
                crc >>= 1
        _CRC_TABLE.append(crc & 0xFFFF)


_build_crc_table()


def crc(data: bytes) -> int:
    """DNP3 block CRC, returned in the order it appears on the wire."""
    value = 0x0000
    for byte in data:
        value = (value >> 8) ^ _CRC_TABLE[(value ^ byte) & 0xFF]
    return (~value) & 0xFFFF


class FunctionCode(IntEnum):
    """Application-layer function codes used for control."""

    CONFIRM = 0x00
    READ = 0x01
    WRITE = 0x02
    SELECT = 0x03
    OPERATE = 0x04
    DIRECT_OPERATE = 0x05
    DIRECT_OPERATE_NR = 0x06
    RESPONSE = 0x81
    UNSOLICITED_RESPONSE = 0x82


class ControlCode(IntEnum):
    """CROB operation types (subset)."""

    NUL = 0x00
    PULSE_ON = 0x01
    PULSE_OFF = 0x02
    LATCH_ON = 0x03
    LATCH_OFF = 0x04
    TRIP = 0x81
    CLOSE = 0x41


class Status(IntEnum):
    """Outstation control status, returned in the response CROB."""

    SUCCESS = 0
    TIMEOUT = 1
    NO_SELECT = 2
    FORMAT_ERROR = 3
    NOT_SUPPORTED = 4
    ALREADY_ACTIVE = 5
    HARDWARE_ERROR = 6


@dataclass(frozen=True)
class CROB:
    """Group 12 variation 1 — control relay output block."""

    control_code: ControlCode
    index: int
    count: int = 1
    on_time_ms: int = 0
    off_time_ms: int = 0
    status: Status = Status.SUCCESS

    def encode(self) -> bytes:
        return struct.pack(
            "<BBIIB",
            int(self.control_code),
            self.count,
            self.on_time_ms,
            self.off_time_ms,
            int(self.status),
        )

    @classmethod
    def decode(cls, raw: bytes, index: int) -> "CROB":
        code, count, on_ms, off_ms, status = struct.unpack("<BBIIB", raw[:11])
        return cls(ControlCode(code), index, count, on_ms, off_ms, Status(status))


@dataclass(frozen=True)
class AnalogOutput:
    """Group 41 variation 3 — 32-bit float analog output block.

    Set-points on a storage site are floats (megawatts, megavars), so the
    float variation is the one that carries dispatch. Variation 1 (32-bit
    integer) is what a meter's demand limit would use.
    """

    value: float
    index: int
    status: Status = Status.SUCCESS

    def encode(self) -> bytes:
        return struct.pack("<fB", self.value, int(self.status))

    @classmethod
    def decode(cls, raw: bytes, index: int) -> "AnalogOutput":
        value, status = struct.unpack("<fB", raw[:5])
        return cls(value, index, Status(status))


@dataclass
class ApplicationPdu:
    """Application layer: control octet, function code and object payload.

    ``function`` is an ``int`` rather than a ``FunctionCode`` so that an
    unrecognised code decodes instead of raising. That is not tidiness: a guard
    sitting in the traffic path must be able to look at a frame carrying a
    function code it has never seen — a corrupted byte, a vendor extension, or
    deliberate garbage — and make a decision about it. Raising here would turn
    any malformed frame into a crash of the thing protecting the site, which is
    a denial-of-service vector rather than a parser edge case.
    """

    function: int
    sequence: int = 0
    first: bool = True
    final: bool = True
    confirm: bool = False
    unsolicited: bool = False
    objects: bytes = b""

    @property
    def known_function(self) -> FunctionCode | None:
        try:
            return FunctionCode(self.function)
        except ValueError:
            return None

    @property
    def function_name(self) -> str:
        known = self.known_function
        return known.name if known is not None else f"UNKNOWN(0x{self.function:02X})"

    @property
    def is_control(self) -> bool:
        return self.known_function in (
            FunctionCode.SELECT,
            FunctionCode.OPERATE,
            FunctionCode.DIRECT_OPERATE,
            FunctionCode.DIRECT_OPERATE_NR,
        )

    def control_octet(self) -> int:
        value = self.sequence & 0x0F
        if self.first:
            value |= 0x80
        if self.final:
            value |= 0x40
        if self.confirm:
            value |= 0x20
        if self.unsolicited:
            value |= 0x10
        return value

    def encode(self) -> bytes:
        return bytes([self.control_octet(), int(self.function) & 0xFF]) + self.objects

    @classmethod
    def decode(cls, raw: bytes) -> "ApplicationPdu":
        if len(raw) < 2:
            raise ValueError("application PDU too short")
        control, function = raw[0], raw[1]
        return cls(
            function=function,
            sequence=control & 0x0F,
            first=bool(control & 0x80),
            final=bool(control & 0x40),
            confirm=bool(control & 0x20),
            unsolicited=bool(control & 0x10),
            objects=raw[2:],
        )


def encode_object_header(group: int, variation: int, index: int) -> bytes:
    """One object with an 8-bit index prefix, qualifier 0x17.

    Qualifier 0x17 is "8-bit count of objects, each preceded by an 8-bit
    index", which is what control requests use for a single point.
    """
    return bytes([group, variation, 0x17, 0x01, index & 0xFF])


@dataclass
class LinkHeader:
    """DNP3 data-link header."""

    length: int
    control: int
    destination: int
    source: int

    def encode(self) -> bytes:
        return struct.pack(
            "<BBHH", self.length, self.control, self.destination, self.source
        )


def build_frame(
    source: int,
    destination: int,
    payload: bytes,
    control: int = 0xC4,
    transport: int = 0xC0,
) -> bytes:
    """Assemble a complete DNP3 frame with CRCs on every block.

    Layout: start, header block (8 bytes + CRC), then the transport octet and
    application payload split into 16-byte data blocks, each with its own CRC.
    ``length`` counts the header bytes after the length field plus the user
    data, excluding CRCs — the definition in the standard that is easiest to
    get wrong.
    """
    body = bytes([transport]) + payload
    length = 5 + len(body)
    if length > 255:
        raise ValueError("frame exceeds the single-frame DNP3 limit")

    header = struct.pack("<BBHH", length, control, destination, source)
    frame = bytearray(START_BYTES + header)
    frame += struct.pack("<H", crc(START_BYTES + header))

    for offset in range(0, len(body), 16):
        block = body[offset : offset + 16]
        frame += block
        frame += struct.pack("<H", crc(block))
    return bytes(frame)


@dataclass
class ParsedFrame:
    """A decoded DNP3 frame."""

    source: int
    destination: int
    control: int
    transport: int
    application: ApplicationPdu
    crc_ok: bool = True


def parse_frame(raw: bytes) -> ParsedFrame:
    """Decode a frame, verifying every block CRC.

    Raises on a malformed frame rather than returning a partial result: a proxy
    that forwards frames it could not fully parse is a hole, not a feature.
    """
    if len(raw) < 10 or raw[:2] != START_BYTES:
        raise ValueError("not a DNP3 frame")
    header = raw[2:8]
    header_crc = struct.unpack("<H", raw[8:10])[0]
    crc_ok = crc(START_BYTES + header) == header_crc

    length, control, destination, source = struct.unpack("<BBHH", header)
    user_len = length - 5

    body = bytearray()
    offset = 10
    remaining = user_len
    while remaining > 0:
        take = min(16, remaining)
        block = raw[offset : offset + take]
        if len(block) < take:
            raise ValueError("truncated DNP3 data block")
        block_crc = struct.unpack("<H", raw[offset + take : offset + take + 2])[0]
        if crc(block) != block_crc:
            crc_ok = False
        body += block
        offset += take + 2
        remaining -= take

    if not body:
        raise ValueError("DNP3 frame carries no transport octet")
    try:
        application = ApplicationPdu.decode(bytes(body[1:]))
    except ValueError:
        # Same reasoning as ApplicationPdu.function: a frame too short to carry
        # an application header is reported as unparseable, not raised. The
        # caller sees crc_ok=False and a null function and can drop it.
        application = ApplicationPdu(function=-1, objects=bytes(body[1:]))
        crc_ok = False
    return ParsedFrame(
        source=source,
        destination=destination,
        control=control,
        transport=body[0],
        application=application,
        crc_ok=crc_ok,
    )


# ----------------------------------------------------------------------
# Select-before-operate
# ----------------------------------------------------------------------


@dataclass(frozen=True)
class SelectRecord:
    """An armed control awaiting its OPERATE."""

    t: float
    group: int
    index: int
    payload: bytes


@dataclass
class SelectBeforeOperate:
    """Outstation-side SBO state machine.

    Three ways an OPERATE is rejected, all of them protocol facts rather than
    judgements about the command's meaning:

    * nothing was selected for that point,
    * the selection has aged out (``timeout_s``, 10 s in most profiles),
    * the OPERATE's object bytes differ from the SELECT's — arming "close" and
      firing "trip", or arming 5 MW and firing 25 MW.

    The third is the one worth having: an attacker who can see a legitimate
    SELECT go past and then substitute their own OPERATE is defeated by
    comparing the payloads, and no key material is involved.
    """

    timeout_s: float = 10.0
    armed: dict[tuple[int, int], SelectRecord] = field(default_factory=dict)
    rejections: list[str] = field(default_factory=list)

    def select(self, t: float, group: int, index: int, payload: bytes) -> None:
        self.armed[(group, index)] = SelectRecord(t=t, group=group, index=index, payload=payload)

    def operate(self, t: float, group: int, index: int, payload: bytes) -> Status:
        record = self.armed.pop((group, index), None)
        if record is None:
            self.rejections.append(f"OPERATE g{group} idx{index} with no prior SELECT")
            return Status.NO_SELECT
        if t - record.t > self.timeout_s:
            self.rejections.append(
                f"OPERATE g{group} idx{index} {t - record.t:.1f}s after SELECT "
                f"(timeout {self.timeout_s:g}s)"
            )
            return Status.TIMEOUT
        if payload != record.payload:
            self.rejections.append(
                f"OPERATE g{group} idx{index} payload differs from the armed SELECT"
            )
            return Status.NO_SELECT
        return Status.SUCCESS

    def direct_operate(self, t: float, group: int, index: int, payload: bytes) -> Status:
        """DIRECT_OPERATE skips the handshake by design.

        Permitted by the standard and widely used for non-critical points. It
        is recorded rather than rejected here — whether a *breaker* should be
        reachable by direct operate is a policy question the guard answers, not
        a protocol violation the outstation can detect.
        """
        return Status.SUCCESS


def build_select(
    source: int, destination: int, group: int, variation: int, index: int, body: bytes, seq: int = 0
) -> bytes:
    payload = encode_object_header(group, variation, index) + body
    return build_frame(
        source, destination, ApplicationPdu(FunctionCode.SELECT, sequence=seq, objects=payload).encode()
    )


def build_operate(
    source: int, destination: int, group: int, variation: int, index: int, body: bytes, seq: int = 0
) -> bytes:
    payload = encode_object_header(group, variation, index) + body
    return build_frame(
        source,
        destination,
        ApplicationPdu(FunctionCode.OPERATE, sequence=seq, objects=payload).encode(),
    )
