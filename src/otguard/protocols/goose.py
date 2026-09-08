"""IEC 61850 GOOSE — publisher, subscriber and the state-number semantics.

GOOSE carries protection signals between bays on a substation LAN: a trip, a
breaker position, an interlock. It is layer-2 multicast with no routing, no
handshake and — in the base profile — no authentication, which is why it is both
the fastest way to move a trip and the easiest thing on the site to forge.

What makes it checkable without cryptography is the retransmission scheme.
Every publisher maintains two counters:

``stNum``
    Increments on every *state change* in the dataset. Resets ``sqNum`` to zero.

``sqNum``
    Increments on every retransmission of an unchanged state.

A publisher that has said nothing new keeps re-sending the same state with a
rising ``sqNum`` on a backoff schedule, so a subscriber always knows whether its
publisher is alive and whether it has missed a transition. That gives three
things an attacker has to get right, and each failure is detectable:

* **Replay.** Re-sending a captured trip frame carries its original ``stNum``,
  which the subscriber has already seen and passed. Stale by inspection.
* **Takeover.** Injecting with a large ``stNum`` jump wins the race against the
  real publisher, but the jump itself is the signature — real state changes do
  not skip a thousand counts.
* **Silence.** Suppressing the real publisher trips ``timeAllowedToLive``, so
  the subscriber knows it is blind rather than quiet.

None of that authenticates anything. A patient attacker who increments by one
and matches the timing is indistinguishable at this layer, which is the honest
limit of counter-based checks — and the reason the guard cross-checks a trip
against measured fault current (rule B7) rather than trusting the frame.

Transport note: GOOSE is raw layer-2 and needs ``AF_PACKET`` and root to put on
a real wire. The frames built here are byte-exact — a capture would decode in
Wireshark — but the link is an in-process virtual segment
(:class:`VirtualEthernet`) rather than a NIC. What is being evaluated is the
subscriber logic and the guard's use of it, not the kernel's packet path.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any, Callable

ETHERTYPE_GOOSE = 0x88B8
TPID_8021Q = 0x8100
# The standard multicast range for GOOSE is 01:0C:CD:01:00:00 - 01:0C:CD:01:01:FF.
DEFAULT_GOOSE_MAC = bytes.fromhex("010ccd010001")

# ----------------------------------------------------------------------
# Minimal BER, because GOOSE is ASN.1 on the wire
# ----------------------------------------------------------------------


def ber_length(n: int) -> bytes:
    """Definite-form BER length."""
    if n < 0x80:
        return bytes([n])
    if n <= 0xFF:
        return bytes([0x81, n])
    if n <= 0xFFFF:
        return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])
    raise ValueError("GOOSE PDU length out of range")


def ber_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + ber_length(len(value)) + value


def ber_int(value: int) -> bytes:
    """Signed BER INTEGER, minimal encoding."""
    if value == 0:
        return b"\x00"
    length = (value.bit_length() + 8) // 8
    raw = value.to_bytes(length, "big", signed=True)
    # Strip redundant leading 0x00 that a positive value may pick up.
    while len(raw) > 1 and raw[0] == 0x00 and not (raw[1] & 0x80):
        raw = raw[1:]
    return raw


def parse_ber_length(data: bytes, offset: int) -> tuple[int, int]:
    """Return ``(length, new_offset)``."""
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    count = first & 0x7F
    if count == 0 or count > 4:
        raise ValueError("unsupported BER length form")
    value = int.from_bytes(data[offset : offset + count], "big")
    return value, offset + count


def parse_tlvs(data: bytes) -> list[tuple[int, bytes]]:
    out: list[tuple[int, bytes]] = []
    offset = 0
    while offset < len(data):
        tag = data[offset]
        length, offset = parse_ber_length(data, offset + 1)
        out.append((tag, data[offset : offset + length]))
        offset += length
    return out


def encode_utc_time(seconds: float, quality: int = 0x0A) -> bytes:
    """IEC 61850 UtcTime: 4 octets of seconds, 3 of fraction, 1 of quality."""
    whole = int(seconds)
    frac = int((seconds - whole) * (1 << 24)) & 0xFFFFFF
    return struct.pack(">I", whole & 0xFFFFFFFF) + frac.to_bytes(3, "big") + bytes([quality])


def decode_utc_time(raw: bytes) -> float:
    whole = struct.unpack(">I", raw[:4])[0]
    frac = int.from_bytes(raw[4:7], "big")
    return whole + frac / (1 << 24)


# ----------------------------------------------------------------------
# Dataset values
# ----------------------------------------------------------------------

TAG_BOOLEAN = 0x83
TAG_INTEGER = 0x85
TAG_FLOAT = 0x87


def encode_value(value: Any) -> bytes:
    """Encode one dataset member (boolean, integer or float32)."""
    if isinstance(value, bool):
        return ber_tlv(TAG_BOOLEAN, b"\x01" if value else b"\x00")
    if isinstance(value, int):
        return ber_tlv(TAG_INTEGER, ber_int(value))
    if isinstance(value, float):
        # MMS FloatingPoint: leading octet is the exponent width in bits.
        return ber_tlv(TAG_FLOAT, b"\x08" + struct.pack(">f", value))
    raise TypeError(f"unsupported GOOSE dataset type: {type(value).__name__}")


def decode_value(tag: int, raw: bytes) -> Any:
    if tag == TAG_BOOLEAN:
        return raw[0] != 0
    if tag == TAG_INTEGER:
        return int.from_bytes(raw, "big", signed=True)
    if tag == TAG_FLOAT:
        return struct.unpack(">f", raw[1:5])[0]
    raise ValueError(f"unsupported GOOSE value tag 0x{tag:02X}")


# ----------------------------------------------------------------------
# The PDU
# ----------------------------------------------------------------------


@dataclass
class GoosePdu:
    """The application payload of a GOOSE frame."""

    gocb_ref: str
    dat_set: str
    go_id: str
    st_num: int
    sq_num: int
    values: list[Any] = field(default_factory=list)
    time_allowed_to_live_ms: int = 2000
    timestamp: float = 0.0
    test: bool = False
    conf_rev: int = 1
    nds_com: bool = False

    def encode(self) -> bytes:
        body = b"".join(
            [
                ber_tlv(0x80, self.gocb_ref.encode("ascii")),
                ber_tlv(0x81, ber_int(self.time_allowed_to_live_ms)),
                ber_tlv(0x82, self.dat_set.encode("ascii")),
                ber_tlv(0x83, self.go_id.encode("ascii")),
                ber_tlv(0x84, encode_utc_time(self.timestamp)),
                ber_tlv(0x85, ber_int(self.st_num)),
                ber_tlv(0x86, ber_int(self.sq_num)),
                ber_tlv(0x87, b"\x01" if self.test else b"\x00"),
                ber_tlv(0x88, ber_int(self.conf_rev)),
                ber_tlv(0x89, b"\x01" if self.nds_com else b"\x00"),
                ber_tlv(0x8A, ber_int(len(self.values))),
                ber_tlv(0xAB, b"".join(encode_value(v) for v in self.values)),
            ]
        )
        return ber_tlv(0x61, body)

    @classmethod
    def decode(cls, raw: bytes) -> "GoosePdu":
        tlvs = parse_tlvs(raw)
        if not tlvs or tlvs[0][0] != 0x61:
            raise ValueError("not a goosePdu")
        fields_by_tag = dict(parse_tlvs(tlvs[0][1]))

        def as_int(tag: int, default: int = 0) -> int:
            raw_value = fields_by_tag.get(tag)
            if raw_value is None:
                return default
            return int.from_bytes(raw_value, "big", signed=True)

        def as_str(tag: int) -> str:
            return fields_by_tag.get(tag, b"").decode("ascii", errors="replace")

        values: list[Any] = []
        all_data = fields_by_tag.get(0xAB)
        if all_data:
            values = [decode_value(tag, body) for tag, body in parse_tlvs(all_data)]

        return cls(
            gocb_ref=as_str(0x80),
            time_allowed_to_live_ms=as_int(0x81, 2000),
            dat_set=as_str(0x82),
            go_id=as_str(0x83),
            timestamp=decode_utc_time(fields_by_tag.get(0x84, b"\x00" * 8)),
            st_num=as_int(0x85),
            sq_num=as_int(0x86),
            test=bool(fields_by_tag.get(0x87, b"\x00")[0]),
            conf_rev=as_int(0x88, 1),
            nds_com=bool(fields_by_tag.get(0x89, b"\x00")[0]),
            values=values,
        )


@dataclass
class GooseFrame:
    """A complete Ethernet frame carrying a GOOSE PDU."""

    pdu: GoosePdu
    source_mac: bytes
    dest_mac: bytes = DEFAULT_GOOSE_MAC
    appid: int = 0x0001
    vlan_id: int = 0
    vlan_priority: int = 4

    def encode(self) -> bytes:
        apdu = self.pdu.encode()
        header = bytearray()
        header += self.dest_mac
        header += self.source_mac
        if self.vlan_id:
            tci = ((self.vlan_priority & 0x07) << 13) | (self.vlan_id & 0x0FFF)
            header += struct.pack(">HH", TPID_8021Q, tci)
        header += struct.pack(">H", ETHERTYPE_GOOSE)
        # Length covers APPID, Length, Reserved1, Reserved2 and the APDU.
        header += struct.pack(">HH", self.appid, 8 + len(apdu))
        header += struct.pack(">HH", 0, 0)  # Reserved1, Reserved2
        return bytes(header) + apdu

    @classmethod
    def decode(cls, raw: bytes) -> "GooseFrame":
        if len(raw) < 22:
            raise ValueError("frame too short for GOOSE")
        dest_mac, source_mac = raw[0:6], raw[6:12]
        offset = 12
        vlan_id = 0
        vlan_priority = 4
        if struct.unpack(">H", raw[offset : offset + 2])[0] == TPID_8021Q:
            tci = struct.unpack(">H", raw[offset + 2 : offset + 4])[0]
            vlan_priority = (tci >> 13) & 0x07
            vlan_id = tci & 0x0FFF
            offset += 4
        ethertype = struct.unpack(">H", raw[offset : offset + 2])[0]
        if ethertype != ETHERTYPE_GOOSE:
            raise ValueError(f"not a GOOSE ethertype: 0x{ethertype:04X}")
        offset += 2
        appid = struct.unpack(">H", raw[offset : offset + 2])[0]
        offset += 4          # APPID + Length
        offset += 4          # Reserved1 + Reserved2
        return cls(
            pdu=GoosePdu.decode(raw[offset:]),
            source_mac=source_mac,
            dest_mac=dest_mac,
            appid=appid,
            vlan_id=vlan_id,
            vlan_priority=vlan_priority,
        )


# ----------------------------------------------------------------------
# Publisher and subscriber
# ----------------------------------------------------------------------


class GoosePublisher:
    """Maintains the stNum/sqNum discipline for one control block."""

    def __init__(
        self,
        gocb_ref: str,
        go_id: str,
        dat_set: str,
        source_mac: bytes,
        appid: int = 0x0001,
        conf_rev: int = 1,
    ) -> None:
        self.gocb_ref = gocb_ref
        self.go_id = go_id
        self.dat_set = dat_set
        self.source_mac = source_mac
        self.appid = appid
        self.conf_rev = conf_rev
        # Starts at zero so that the first publish carrying a dataset lands on
        # stNum 1, which is what a subscriber expects from a freshly started
        # publisher.
        self.st_num = 0
        self.sq_num = 0
        self.values: list[Any] = []

    def publish(self, t: float, values: list[Any] | None = None) -> GooseFrame:
        """Emit a frame, advancing the counters per the state-change rule."""
        if values is not None and values != self.values:
            self.values = list(values)
            self.st_num += 1
            self.sq_num = 0
        else:
            self.sq_num += 1
        return GooseFrame(
            pdu=GoosePdu(
                gocb_ref=self.gocb_ref,
                dat_set=self.dat_set,
                go_id=self.go_id,
                st_num=self.st_num,
                sq_num=self.sq_num,
                values=list(self.values),
                timestamp=t,
                conf_rev=self.conf_rev,
            ),
            source_mac=self.source_mac,
            appid=self.appid,
        )


@dataclass
class GooseAnomaly:
    """One subscriber objection to a received frame."""

    kind: str          # "replay" | "takeover" | "stale" | "conf_rev" | "timeout"
    detail: str
    gocb_ref: str
    st_num: int = 0
    sq_num: int = 0

    def __str__(self) -> str:
        return f"[GOOSE {self.kind}] {self.detail}"


@dataclass
class _SubscriptionState:
    st_num: int = 0
    sq_num: int = -1
    last_seen_t: float = 0.0
    ttl_ms: int = 2000
    conf_rev: int = 1


class GooseSubscriber:
    """Validates an inbound GOOSE stream against the counter semantics.

    ``st_jump_threshold`` is the one tunable, and it is a genuine trade-off
    rather than a safe default: too low and a subscriber that was briefly
    disconnected reports a takeover when it reconnects, too high and an attacker
    simply jumps by less. It is set from how many transitions a bay could
    plausibly make while this subscriber was not listening.
    """

    def __init__(self, st_jump_threshold: int = 50) -> None:
        self.st_jump_threshold = st_jump_threshold
        self.streams: dict[str, _SubscriptionState] = {}
        self.anomalies: list[GooseAnomaly] = []

    def receive(self, frame: GooseFrame, t: float) -> list[GooseAnomaly]:
        pdu = frame.pdu
        found: list[GooseAnomaly] = []
        state = self.streams.get(pdu.gocb_ref)

        if state is None:
            self.streams[pdu.gocb_ref] = _SubscriptionState(
                st_num=pdu.st_num,
                sq_num=pdu.sq_num,
                last_seen_t=t,
                ttl_ms=pdu.time_allowed_to_live_ms,
                conf_rev=pdu.conf_rev,
            )
            return found

        if pdu.conf_rev != state.conf_rev:
            found.append(
                GooseAnomaly(
                    "conf_rev",
                    f"confRev {pdu.conf_rev} does not match the subscribed {state.conf_rev}",
                    pdu.gocb_ref,
                    pdu.st_num,
                    pdu.sq_num,
                )
            )

        if pdu.st_num < state.st_num:
            found.append(
                GooseAnomaly(
                    "replay",
                    f"stNum {pdu.st_num} is behind the last accepted {state.st_num} — "
                    f"a frame this subscriber has already processed",
                    pdu.gocb_ref,
                    pdu.st_num,
                    pdu.sq_num,
                )
            )
        elif pdu.st_num == state.st_num and pdu.sq_num <= state.sq_num:
            found.append(
                GooseAnomaly(
                    "stale",
                    f"sqNum {pdu.sq_num} repeats or precedes {state.sq_num} within "
                    f"stNum {pdu.st_num}",
                    pdu.gocb_ref,
                    pdu.st_num,
                    pdu.sq_num,
                )
            )
        elif pdu.st_num - state.st_num > self.st_jump_threshold:
            found.append(
                GooseAnomaly(
                    "takeover",
                    f"stNum jumped {pdu.st_num - state.st_num} counts "
                    f"({state.st_num} to {pdu.st_num}); a publisher does not "
                    f"change state that many times unobserved",
                    pdu.gocb_ref,
                    pdu.st_num,
                    pdu.sq_num,
                )
            )

        # Only advance on a frame that was not rejected, so a replay cannot drag
        # the accepted counter backwards and a takeover cannot park it high.
        if not found:
            state.st_num = pdu.st_num
            state.sq_num = pdu.sq_num
            state.conf_rev = pdu.conf_rev
        state.last_seen_t = t
        self.anomalies.extend(found)
        return found

    def check_liveness(self, t: float) -> list[GooseAnomaly]:
        """Report publishers whose timeAllowedToLive has expired.

        A subscriber that stops hearing its publisher is not in a safe state —
        it is blind. Saying so is the difference between a suppressed trip and a
        quiet network.
        """
        found: list[GooseAnomaly] = []
        for ref, state in self.streams.items():
            age_ms = (t - state.last_seen_t) * 1000.0
            if age_ms > state.ttl_ms:
                found.append(
                    GooseAnomaly(
                        "timeout",
                        f"no frame for {age_ms:.0f} ms, exceeding timeAllowedToLive "
                        f"{state.ttl_ms} ms — the publisher is unreachable or suppressed",
                        ref,
                        state.st_num,
                        state.sq_num,
                    )
                )
        self.anomalies.extend(found)
        return found


class VirtualEthernet:
    """An in-process layer-2 segment.

    Stands in for the substation LAN. Real GOOSE needs ``AF_PACKET`` and root;
    the frames on this segment are byte-identical to what would be on a wire,
    which is what the tests assert against.
    """

    def __init__(self) -> None:
        self.listeners: list[Callable[[bytes, float], None]] = []
        self.captured: list[tuple[float, bytes]] = []

    def attach(self, listener: Callable[[bytes, float], None]) -> None:
        self.listeners.append(listener)

    def send(self, frame: bytes, t: float) -> None:
        self.captured.append((t, frame))
        for listener in self.listeners:
            listener(frame, t)
