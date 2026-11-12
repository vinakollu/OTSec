"""Is a device answering, and what exactly did the answer prove?

"Is it online" sounds like one question and is three, each a stronger claim
than the last:

1. A TCP connection opened. Something is listening on that port.
2. Something on the far end speaks the protocol and produced a well-formed
   response.
3. It answered *the thing we asked* — right transaction id, right function,
   plausible payload.

A scanner that reports only up or down throws that distinction away, and the
distinction is most of the value. A PLC whose socket accepts but whose scan
loop has stopped is the dangerous case: a connect-only check calls it healthy
while the plant it controls is frozen. So every probe records which level of
evidence it actually obtained, and the scanner carries that through to the
guard and to the display.

What none of these prove: that the device is *healthy*, that it is the device
we think it is, or that the answer came from the device rather than from
someone in the path. A liveness probe is a question about reachability. On a
network the attacker is assumed to hold, a probe that comes back clean means
the attacker wanted it to, and anyone who can hold a socket open and echo a
canned response keeps a dead device looking alive. This is monitoring, not
authentication, and nothing downstream should treat a green light as more
than "we were answered".
"""

from __future__ import annotations

import asyncio
import struct
import time
from dataclasses import dataclass
from enum import Enum
from typing import Awaitable, Callable

from ..modbus.protocol import (
    FC_READ_INPUT_REGISTERS,
    MBAP_SIZE,
    decode_frame,
    encode_frame,
    is_exception,
    read_request,
)
from ..modbus.registers import IR_LEVEL

#: A probe answers at most this many bytes' worth of response. One Modbus ADU
#: is 260 bytes at most, so anything beyond this is not a reply we asked for.
_MAX_RESPONSE = 260


class Evidence(str, Enum):
    """How strong the answer was.

    Ordered deliberately: a caller can compare ``probe.evidence`` against a
    minimum it is willing to accept, which is how the guard refuses to count a
    measurement source that only managed a TCP handshake.
    """

    NONE = "none"            # nothing answered
    SOCKET = "socket"        # a connection opened, and that is all we learned
    PROTOCOL = "protocol"    # a well-formed protocol response came back
    ANSWERED = "answered"    # it replied to our actual request
    MODEL = "model"          # not measured on a network at all; see CallbackProbe

    @property
    def rank(self) -> int:
        return {
            "none": 0,
            "socket": 1,
            "protocol": 2,
            "answered": 3,
            # A model's own liveness flag is authoritative about the model, so
            # for the purpose of "may this count as a live source" it sits with
            # a real answer. It is kept a separate name so a reader of the
            # results can always tell the two apart.
            "model": 3,
        }[self.value]

    def at_least(self, floor: "Evidence") -> bool:
        return self.rank >= floor.rank


@dataclass(frozen=True)
class ProbeResult:
    """What one probe attempt learned."""

    reachable: bool
    evidence: Evidence = Evidence.NONE
    rtt_ms: float = 0.0
    detail: str = ""

    @classmethod
    def down(cls, detail: str) -> "ProbeResult":
        return cls(reachable=False, evidence=Evidence.NONE, detail=detail)


#: A probe is any async callable that answers whether a device responded. The
#: scanner's state machine does not care how the question is asked, which is
#: what lets a socket probe and a model probe share one device table.
Probe = Callable[[], Awaitable[ProbeResult]]


async def _open(host: str, port: int, timeout: float):
    return await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)


async def _drain(writer) -> None:
    """Close a connection without letting the close itself raise.

    A probe that throws while tidying up reports the device down for a reason
    that has nothing to do with the device.
    """
    try:
        writer.close()
        await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
    except (OSError, asyncio.TimeoutError, ConnectionError):
        pass


class TcpProbe:
    """Open a connection and close it again.

    The weakest useful probe, and the right one for a device whose protocol we
    have no decoder for: a jump server, an HTTPS endpoint, a switch's
    management port. It reports :attr:`Evidence.SOCKET`, and callers that need
    more than that should say so rather than reading a green light as health.
    """

    #: Sensed over a socket, so results are evidence about a real listener.
    networked = True

    def __init__(self, host: str, port: int, timeout_s: float = 1.0) -> None:
        self.host = host
        self.port = port
        self.timeout_s = timeout_s

    async def __call__(self) -> ProbeResult:
        started = time.perf_counter()
        try:
            _reader, writer = await _open(self.host, self.port, self.timeout_s)
        except asyncio.TimeoutError:
            return ProbeResult.down(f"no answer from {self.host}:{self.port} within "
                                    f"{self.timeout_s:g}s")
        except (OSError, ConnectionError) as exc:
            return ProbeResult.down(f"{self.host}:{self.port} refused the connection ({exc})")
        rtt = (time.perf_counter() - started) * 1e3
        await _drain(writer)
        return ProbeResult(
            reachable=True,
            evidence=Evidence.SOCKET,
            rtt_ms=rtt,
            detail=f"{self.host}:{self.port} accepted a connection",
        )


class ModbusProbe:
    """Read a register and check that the reply is the one we asked for.

    This is what an engineer does by hand when a PLC is suspected: ask it for a
    number it should always be able to produce. The default point is the level
    input register, because a controller that cannot answer for its own process
    variable is not usable whatever its socket is doing.

    An exception response still counts as reachable. A device that answers
    "illegal data address" is alive, talking, and telling us our address is
    wrong — which is a scanner configuration problem, not an outage, and
    reporting it as an outage would send somebody to the wrong building.
    """

    #: Sensed over a socket.
    networked = True

    def __init__(
        self,
        host: str,
        port: int,
        *,
        unit_id: int = 1,
        address: int = IR_LEVEL,
        count: int = 1,
        timeout_s: float = 1.0,
    ) -> None:
        self.host = host
        self.port = port
        self.unit_id = unit_id
        self.address = address
        self.count = count
        self.timeout_s = timeout_s
        self._txn = 0

    def _next_txn(self) -> int:
        # Wraps at 16 bits, like the field itself. Matching the id is what tells
        # a reply to this probe apart from traffic already in flight on a
        # connection the device was reusing.
        self._txn = (self._txn + 1) & 0xFFFF
        return self._txn or 1

    async def __call__(self) -> ProbeResult:
        started = time.perf_counter()
        try:
            reader, writer = await _open(self.host, self.port, self.timeout_s)
        except asyncio.TimeoutError:
            return ProbeResult.down(f"no answer from {self.host}:{self.port} within "
                                    f"{self.timeout_s:g}s")
        except (OSError, ConnectionError) as exc:
            return ProbeResult.down(f"{self.host}:{self.port} refused the connection ({exc})")

        txn = self._next_txn()
        request = encode_frame(
            txn, self.unit_id, read_request(FC_READ_INPUT_REGISTERS, self.address, self.count)
        )
        try:
            writer.write(request)
            await asyncio.wait_for(writer.drain(), timeout=self.timeout_s)
            frame, raw = await self._read_frame(reader, started)
        except asyncio.TimeoutError:
            await _drain(writer)
            return ProbeResult(
                reachable=False,
                # The socket opened and then nothing came back. This is the
                # case a connect-only probe calls healthy, and the one worth
                # separating from a refused connection.
                evidence=Evidence.SOCKET,
                rtt_ms=(time.perf_counter() - started) * 1e3,
                detail=f"{self.host}:{self.port} accepted a connection but did not "
                       f"answer a register read",
            )
        except (OSError, ConnectionError, ValueError) as exc:
            await _drain(writer)
            return ProbeResult(
                reachable=False,
                evidence=Evidence.SOCKET,
                rtt_ms=(time.perf_counter() - started) * 1e3,
                detail=f"{self.host}:{self.port} answered something that is not Modbus ({exc})",
            )

        rtt = (time.perf_counter() - started) * 1e3
        await _drain(writer)

        if frame is None:
            return ProbeResult(
                reachable=False,
                evidence=Evidence.SOCKET,
                rtt_ms=rtt,
                detail=f"{self.host}:{self.port} closed the connection mid-reply",
            )
        if frame.transaction_id != txn:
            # Somebody is talking, but not to us about this.
            return ProbeResult(
                reachable=True,
                evidence=Evidence.PROTOCOL,
                rtt_ms=rtt,
                detail=f"{self.host}:{self.port} replied to transaction "
                       f"{frame.transaction_id} rather than {txn}",
            )
        if is_exception(frame.pdu):
            code = frame.pdu[1] if len(frame.pdu) > 1 else 0
            return ProbeResult(
                reachable=True,
                evidence=Evidence.ANSWERED,
                rtt_ms=rtt,
                detail=f"{self.host}:{self.port} refused the read with exception "
                       f"0x{code:02x}, so it is alive and our address is wrong",
            )

        values = _registers(frame.pdu)
        shown = ", ".join(str(v) for v in values) if values else "no registers"
        return ProbeResult(
            reachable=True,
            evidence=Evidence.ANSWERED,
            rtt_ms=rtt,
            detail=f"{self.host}:{self.port} answered register {self.address} with {shown}",
        )

    async def _read_frame(self, reader, started: float):
        """Collect bytes until one whole frame is in hand, or time runs out.

        The MBAP length field is the only thing that says where a frame ends, so
        a probe that reads once and parses works until the reply arrives split
        across two segments, which on a loaded link it eventually does.
        """
        remaining = self.timeout_s
        buffer = b""
        while True:
            if remaining <= 0:
                raise asyncio.TimeoutError
            chunk = await asyncio.wait_for(reader.read(_MAX_RESPONSE), timeout=remaining)
            if not chunk:
                return None, buffer
            buffer += chunk
            if len(buffer) >= MBAP_SIZE:
                frame, rest = decode_frame(buffer)
                if frame is not None:
                    return frame, rest
            if len(buffer) > _MAX_RESPONSE:
                raise ValueError(f"{len(buffer)} bytes with no complete frame in them")
            remaining = self.timeout_s - (time.perf_counter() - started)


def _registers(pdu: bytes) -> list[int]:
    """Unpack a read response body, or give back nothing if it is malformed."""
    if len(pdu) < 2:
        return []
    byte_count = pdu[1]
    body = pdu[2:2 + byte_count]
    if len(body) < byte_count or byte_count % 2:
        return []
    return [v for (v,) in struct.iter_unpack(">H", body)]


class CallbackProbe:
    """Liveness read from a model rather than measured on a network.

    Most of this project's equipment is simulated in process. The tank's
    controller and the guard listen on real sockets and can be probed for real,
    but the battery site's sixteen units, its meter and its relay are objects,
    not listeners, and probing their configured addresses would report every
    one of them down.

    Pretending otherwise would be the worst option: a device table where some
    rows are measurements and others are fiction, with nothing saying which.
    So a modelled device gets a probe that asks the model, and the result is
    stamped :attr:`Evidence.MODEL` so that every display and every report can
    say which rows were sensed over a wire. The scanner's state machine,
    debouncing and transitions are the same either way, which is the part worth
    sharing: those are where the bugs live.

    This is honest about what it is and it is not a network measurement. No
    result from a ``CallbackProbe`` is evidence about real hardware.
    """

    #: Read out of a model. Never evidence about real hardware, and every
    #: display and report that shows one of these rows says so.
    networked = False

    def __init__(
        self,
        online: Callable[[], bool],
        *,
        label: str = "",
        detail: Callable[[], str] | None = None,
    ) -> None:
        self.online = online
        self.label = label
        self.detail = detail

    async def __call__(self) -> ProbeResult:
        started = time.perf_counter()
        try:
            up = bool(self.online())
        except Exception as exc:  # the model is ours, so this is a bug, not an outage
            return ProbeResult.down(f"model for {self.label or 'device'} raised {exc!r}")
        rtt = (time.perf_counter() - started) * 1e3
        if self.detail is not None:
            try:
                detail = self.detail()
            except Exception as exc:
                detail = f"detail unavailable ({exc!r})"
        else:
            detail = f"{self.label or 'device'} reports itself " + ("online" if up else "offline")
        return ProbeResult(
            reachable=up,
            evidence=Evidence.MODEL if up else Evidence.NONE,
            rtt_ms=rtt,
            detail=detail,
        )
