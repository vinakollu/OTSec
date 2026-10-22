"""The OPC UA binary transport, as much of it as a bump-in-the-wire can read.

This is the module the whole experiment turns on, so it is worth being precise
about what is where on the wire.

Every message on an OPC UA TCP connection begins with the same eight bytes: a
three-byte type (``HEL``, ``ACK``, ``OPN``, ``MSG``, ``CLO``, ``ERR``), a
one-byte chunk marker (``F`` final, ``C`` intermediate, ``A`` abort), and the
total message length as a little-endian uint32. A ``MSG`` chunk then carries:

====================================  ======  ===========================
field                                 bytes   encrypted under SignAndEncrypt
====================================  ======  ===========================
message header                        8       no
secure channel id                     4       no
symmetric security header (token id)  4       no
sequence number                       4       **yes**
request id                            4       **yes**
body                                  rest    **yes**
====================================  ======  ===========================

So a guard watching an encrypted channel is left with sixteen legible bytes per
message: what kind of message it is, how long it is, and which channel and key
it belongs to. It cannot read the request id, so it cannot even pair a response
with a request.

Under ``Sign`` nothing is encrypted and all of it is readable — but the last
bytes of each message are a signature over the whole of it, which the guard
cannot recompute. It can read every write and refuse none of them, because any
frame it fabricates or renumbers fails the other end's signature check.

Under ``None`` the sequence number sits at a known offset in cleartext, which
is what makes inline refusal possible at all: dropping a request leaves the two
ends disagreeing about how many messages have passed, and the guard has to
renumber the rest of the conversation to keep the channel alive.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import Enum

HEADER_LEN = 8
CHANNEL_LEN = 4
TOKEN_LEN = 4
SEQUENCE_LEN = 4
REQUEST_ID_LEN = 4

#: Where the body of a ``MSG`` chunk starts, for a symmetric security header.
BODY_OFFSET = HEADER_LEN + CHANNEL_LEN + TOKEN_LEN + SEQUENCE_LEN + REQUEST_ID_LEN  # 24
SEQUENCE_OFFSET = HEADER_LEN + CHANNEL_LEN + TOKEN_LEN                               # 16
REQUEST_ID_OFFSET = SEQUENCE_OFFSET + SEQUENCE_LEN                                   # 20

#: Bytes of every message a guard can read whatever the security mode is.
LEGIBLE_PREFIX_LEN = SEQUENCE_OFFSET


class SecurityMode(str, Enum):
    """The three modes the experiment runs, named as OPC UA names them."""

    NONE = "None"
    SIGN = "Sign"
    SIGN_AND_ENCRYPT = "SignAndEncrypt"

    @property
    def body_is_readable(self) -> bool:
        """Can a man in the middle decode the request at all?"""
        return self is not SecurityMode.SIGN_AND_ENCRYPT

    @property
    def can_rewrite(self) -> bool:
        """Can it alter, drop or fabricate a message and be believed?"""
        return self is SecurityMode.NONE

    @property
    def enforcement(self) -> str:
        """How this guard is able to say no, given the mode."""
        if self is SecurityMode.NONE:
            return "inline"      # refuse one write, session continues
        if self is SecurityMode.SIGN:
            return "sever"       # the only lever left is cutting the channel
        return "sever"           # and it can only be pulled on blind evidence


@dataclass(frozen=True)
class Message:
    """One framed message off the wire."""

    raw: bytes

    @property
    def message_type(self) -> str:
        return self.raw[:3].decode("ascii", "replace")

    @property
    def chunk_type(self) -> str:
        return chr(self.raw[3])

    @property
    def size(self) -> int:
        return len(self.raw)

    @property
    def is_message_chunk(self) -> bool:
        """A request or response chunk, the only kind worth inspecting."""
        return self.message_type == "MSG"

    @property
    def uses_symmetric_header(self) -> bool:
        """Does this message carry a sequence number the far end is counting?

        ``MSG`` and ``CLO`` both do. Forgetting ``CLO`` is worth a comment,
        because it fails in a way that looks like success: the whole episode
        runs, every write is judged correctly, and then the device rejects the
        close and logs a sequence error that has nothing to do with anything
        under test.
        """
        return self.message_type in ("MSG", "CLO")

    @property
    def is_final(self) -> bool:
        return self.chunk_type == "F"

    @property
    def channel_id(self) -> int:
        return struct.unpack_from("<I", self.raw, HEADER_LEN)[0]

    @property
    def token_id(self) -> int:
        return struct.unpack_from("<I", self.raw, HEADER_LEN + CHANNEL_LEN)[0]

    @property
    def sequence_number(self) -> int:
        return struct.unpack_from("<I", self.raw, SEQUENCE_OFFSET)[0]

    @property
    def request_id(self) -> int:
        return struct.unpack_from("<I", self.raw, REQUEST_ID_OFFSET)[0]

    @property
    def body(self) -> bytes:
        return self.raw[BODY_OFFSET:]

    def renumbered(self, sequence_number: int) -> bytes:
        """The same message with a new sequence number.

        Only meaningful on an unsecured channel. On a signed one the result
        fails verification at the far end, which is the finding rather than a
        limitation of this function.
        """
        out = bytearray(self.raw)
        struct.pack_into("<I", out, SEQUENCE_OFFSET, sequence_number)
        return bytes(out)


def frame(buffer: bytes) -> tuple[list[Message], bytes]:
    """Split whole messages off the front of ``buffer``.

    Returns the messages and whatever partial message is left over. A message
    shorter than its own header, or claiming a length below the header length,
    is treated as the end of anything parseable: the remainder is handed back
    untouched for the caller to forward blind rather than guessed at.
    """
    messages: list[Message] = []
    offset = 0
    while len(buffer) - offset >= HEADER_LEN:
        size = struct.unpack_from("<I", buffer, offset + 4)[0]
        if size < HEADER_LEN:
            break
        if len(buffer) - offset < size:
            break
        messages.append(Message(bytes(buffer[offset:offset + size])))
        offset += size
    return messages, buffer[offset:]


@dataclass
class Visibility:
    """How much of the traffic the guard could actually read.

    Kept as bytes rather than as a yes/no so the encrypted case has a number
    attached to it. "The guard goes blind" is an argument; "the guard can read
    16 of the 113 bytes in a write message and none of the 89 that say which
    node and what value" is a measurement.
    """

    messages: int = 0
    total_bytes: int = 0
    legible_bytes: int = 0
    bodies_decoded: int = 0
    bodies_opaque: int = 0
    by_type: dict[str, int] = field(default_factory=dict)
    write_message_bytes: list[int] = field(default_factory=list)
    #: Request and response chunks only. The handshake is cleartext in every
    #: mode, so counting it flatters the encrypted case: it is the request
    #: bodies that decide whether a write can be judged.
    msg_total_bytes: int = 0
    msg_legible_bytes: int = 0

    def record(self, message: Message, *, body_readable: bool,
               decoded: bool = False, is_write: bool = False) -> None:
        self.messages += 1
        self.total_bytes += message.size
        self.legible_bytes += (
            message.size if body_readable else min(LEGIBLE_PREFIX_LEN, message.size)
        )
        key = f"{message.message_type}/{message.chunk_type}"
        self.by_type[key] = self.by_type.get(key, 0) + 1
        if message.is_message_chunk:
            self.msg_total_bytes += message.size
            self.msg_legible_bytes += (
                message.size if body_readable else min(LEGIBLE_PREFIX_LEN, message.size)
            )
            if decoded:
                self.bodies_decoded += 1
            else:
                self.bodies_opaque += 1
        if is_write:
            self.write_message_bytes.append(message.size)

    @property
    def legible_fraction(self) -> float:
        return self.legible_bytes / self.total_bytes if self.total_bytes else 0.0

    @property
    def msg_legible_fraction(self) -> float:
        return self.msg_legible_bytes / self.msg_total_bytes if self.msg_total_bytes else 0.0

    def as_dict(self) -> dict:
        return {
            "messages": self.messages,
            "total_bytes": self.total_bytes,
            "legible_bytes": self.legible_bytes,
            "legible_fraction": round(self.legible_fraction, 4),
            "msg_total_bytes": self.msg_total_bytes,
            "msg_legible_bytes": self.msg_legible_bytes,
            "msg_legible_fraction": round(self.msg_legible_fraction, 4),
            "bodies_decoded": self.bodies_decoded,
            "bodies_opaque": self.bodies_opaque,
            "by_type": dict(sorted(self.by_type.items())),
            "write_message_bytes": sorted(set(self.write_message_bytes)),
        }
