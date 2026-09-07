"""The bump-in-the-wire: a Modbus TCP proxy that enforces the physics guard.

Deployment shape is the whole argument for this project. The proxy is a
transparent hop between the HMI and the PLC:

    HMI / engineering workstation
              |
              v   (listen_port)
       GuardedModbusProxy  --- physics rules, state estimate, trips
              |
              v   (plc_port)
        legacy PLC, untouched

Nothing changes on either side. The controller keeps its firmware and its
certification, the HMI keeps its screens, and the guard needs no vendor's
cooperation to install. For an asset owner running twenty-year-old equipment
that is often the only class of control they can actually deploy.

Three things happen here that the in-process evaluation harness does not have to
worry about:

**Blocked writes get a real Modbus answer.** Dropping the frame would leave the
HMI waiting for a timeout, and an operator staring at a hung screen during an
upset is its own hazard. A blocked write is answered with an ILLEGAL DATA VALUE
exception, which every Modbus master already knows how to display.

**The guard polls the process itself.** It would be simpler to sniff the level
out of whatever the HMI happens to read, but then an attacker blinds the guard
by simply not polling. An independent connection to the PLC means the state
estimate keeps running whatever the operator station does or stops doing.

**Trips are written upstream.** When supervision decides the standing order is
about to take the tank out of its envelope, the guard has to actually move the
actuator, so it holds a second connection of its own to issue that write.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from dataclasses import dataclass, field

from ..config import Config
from ..guard import Command, Observation, PhysicsGuard, Verdict
from ..guard.guard import SupervisionEvent
from .protocol import (
    EX_ILLEGAL_DATA_VALUE,
    FC_WRITE_MULTIPLE_REGISTERS,
    FC_WRITE_SINGLE_REGISTER,
    Frame,
    decode_frame,
    encode_frame,
    exception_pdu,
    parse_write,
)
from .registers import (
    COMMAND_REGISTERS,
    HR_PUMP_CMD,
    HR_VALVE_CMD,
    IR_LEVEL,
    LEVEL_SCALE,
    PCT_SCALE,
    _signed,
    _to_word,
)
from .protocol import FC_READ_INPUT_REGISTERS, parse_read, read_registers_response  # noqa: F401
import struct

log = logging.getLogger(__name__)


@dataclass
class ProxyStats:
    frames_forwarded: int = 0
    writes_inspected: int = 0
    writes_blocked: int = 0
    writes_alarmed: int = 0
    trips_issued: int = 0
    polls: int = 0
    wire_latency_us: list[float] = field(default_factory=list)

    def summary(self) -> str:
        return (
            f"frames={self.frames_forwarded} writes={self.writes_inspected} "
            f"blocked={self.writes_blocked} alarmed={self.writes_alarmed} "
            f"trips={self.trips_issued} polls={self.polls}"
        )


class GuardedModbusProxy:
    """Transparent Modbus TCP proxy with the physics guard inline."""

    def __init__(
        self,
        config: Config,
        plc_host: str = "127.0.0.1",
        plc_port: int = 5020,
        listen_host: str = "127.0.0.1",
        listen_port: int = 5021,
        guard: PhysicsGuard | None = None,
    ) -> None:
        self.config = config
        self.plc_host = plc_host
        self.plc_port = plc_port
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.guard = guard or PhysicsGuard(config)

        self.stats = ProxyStats()
        self.verdicts: list[Verdict] = []
        self.events: list[SupervisionEvent] = []

        self._server: asyncio.AbstractServer | None = None
        self._supervisor_task: asyncio.Task | None = None
        self._supervisor_io: tuple[asyncio.StreamReader, asyncio.StreamWriter] | None = None
        self._txn = 0
        self._started = time.perf_counter()

    # ------------------------------------------------------------------
    # Command inspection
    # ------------------------------------------------------------------
    def _now(self) -> float:
        return time.perf_counter() - self._started

    def _inspect(self, frame: Frame) -> tuple[bool, list[Verdict]]:
        """Judge a write frame. Returns ``(forward?, verdicts)``.

        A multi-register write is judged as a unit: if any register in it is
        refused, the whole frame is refused. Modbus has no partial-success
        response for function 16, and quietly applying half of a rejected write
        would leave the process in a state neither the operator nor the guard
        asked for.
        """
        request = parse_write(frame.pdu)
        if request is None:
            # Unparseable write. The guard cannot vouch for what it cannot read,
            # and a malformed frame at a legacy controller is its own hazard.
            log.warning("unparseable write frame, refusing")
            return False, []

        verdicts: list[Verdict] = []
        allow = True
        now = self._now()
        for offset, raw in enumerate(request.values):
            spec = COMMAND_REGISTERS.get(request.address + offset)
            if spec is None:
                continue  # not a register the guard models
            command = Command(t=now, kind=spec.kind, value=spec.to_engineering(raw))
            verdict = self.guard.check(command)
            verdicts.append(verdict)
            self.stats.writes_inspected += 1
            if verdict.decision.value == "alarm":
                self.stats.writes_alarmed += 1
            if not verdict.allowed:
                allow = False
            for finding in verdict.findings:
                log.warning("%s %s", verdict.decision.value.upper(), finding)

        if not allow:
            self.stats.writes_blocked += 1
        return allow, verdicts

    # ------------------------------------------------------------------
    # Client handling
    # ------------------------------------------------------------------
    async def _handle_client(
        self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter
    ) -> None:
        peer = client_writer.get_extra_info("peername")
        log.info("HMI connected from %s", peer)
        try:
            plc_reader, plc_writer = await asyncio.open_connection(self.plc_host, self.plc_port)
        except OSError as exc:
            log.error("cannot reach PLC at %s:%d (%s)", self.plc_host, self.plc_port, exc)
            client_writer.close()
            return

        try:
            await self._pump(client_reader, client_writer, plc_reader, plc_writer)
        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
            pass
        finally:
            for writer in (plc_writer, client_writer):
                with contextlib.suppress(Exception):
                    writer.close()
                    await writer.wait_closed()
            log.info("HMI %s disconnected", peer)

    async def _pump(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        plc_reader: asyncio.StreamReader,
        plc_writer: asyncio.StreamWriter,
    ) -> None:
        """Relay one client session, inspecting writes on the way through."""
        buffer = b""
        while True:
            chunk = await client_reader.read(4096)
            if not chunk:
                return
            buffer += chunk
            while True:
                try:
                    frame, buffer = decode_frame(buffer)
                except ValueError:
                    log.warning("malformed frame from HMI, dropping connection")
                    return
                if frame is None:
                    break

                started = time.perf_counter()
                if frame.is_write:
                    allow, verdicts = self._inspect(frame)
                    self.verdicts.extend(verdicts)
                    if not allow:
                        # Answer in-protocol rather than dropping the frame.
                        client_writer.write(
                            encode_frame(
                                frame.transaction_id,
                                frame.unit_id,
                                exception_pdu(frame.function_code, EX_ILLEGAL_DATA_VALUE),
                            )
                        )
                        await client_writer.drain()
                        self.stats.wire_latency_us.append(
                            (time.perf_counter() - started) * 1e6
                        )
                        continue

                plc_writer.write(frame.encode())
                await plc_writer.drain()
                response = await self._read_frame(plc_reader)
                if response is None:
                    return
                client_writer.write(response.encode())
                await client_writer.drain()
                self.stats.frames_forwarded += 1
                self.stats.wire_latency_us.append((time.perf_counter() - started) * 1e6)

    @staticmethod
    async def _read_frame(reader: asyncio.StreamReader) -> Frame | None:
        """Read exactly one frame, honouring the MBAP length field."""
        try:
            header = await reader.readexactly(7)
        except asyncio.IncompleteReadError:
            return None
        length = struct.unpack(">H", header[4:6])[0]
        try:
            body = await reader.readexactly(length - 1)
        except asyncio.IncompleteReadError:
            return None
        frame, _ = decode_frame(header + body)
        return frame

    # ------------------------------------------------------------------
    # Independent supervision channel
    # ------------------------------------------------------------------
    async def _supervise_loop(self) -> None:
        """Poll the level ourselves and act on what supervision decides.

        Deliberately not driven by the HMI's traffic: an attacker who stops
        polling would otherwise freeze the guard's state estimate and walk the
        process out of its envelope unobserved.
        """
        period = self.config.plant.dt_s
        try:
            reader, writer = await asyncio.open_connection(self.plc_host, self.plc_port)
        except OSError as exc:
            log.error("supervisor cannot reach PLC (%s)", exc)
            return
        self._supervisor_io = (reader, writer)

        try:
            while True:
                level = await self._poll_level(reader, writer)
                if level is not None:
                    self.stats.polls += 1
                    event = self.guard.observe(Observation(self._now(), level))
                    if event is not None:
                        self.events.append(event)
                        for finding in event.findings:
                            log.warning("SUPERVISION %s", finding)
                        if event.action is not None:
                            await self._apply_trip(reader, writer, event)
                await asyncio.sleep(period)
        except asyncio.CancelledError:
            pass
        except (ConnectionResetError, BrokenPipeError):
            log.warning("supervisor lost its connection to the PLC")
        finally:
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()

    def _next_txn(self) -> int:
        self._txn = (self._txn + 1) & 0xFFFF
        return self._txn

    async def _poll_level(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> float | None:
        pdu = struct.pack(">BHH", FC_READ_INPUT_REGISTERS, IR_LEVEL, 1)
        writer.write(encode_frame(self._next_txn(), 1, pdu))
        await writer.drain()
        frame = await self._read_frame(reader)
        if frame is None or len(frame.pdu) < 4 or frame.pdu[0] & 0x80:
            return None
        raw = struct.unpack(">H", frame.pdu[2:4])[0]
        return _signed(raw) / LEVEL_SCALE

    async def _apply_trip(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        event: SupervisionEvent,
    ) -> None:
        """Write the protective action straight to the PLC."""
        action = event.action
        assert action is not None
        targets: list[tuple[int, float]] = []
        if action.pump_cmd_pct is not None:
            targets.append((HR_PUMP_CMD, action.pump_cmd_pct))
        if action.valve_cmd_pct is not None:
            targets.append((HR_VALVE_CMD, action.valve_cmd_pct))

        for address, value in targets:
            pdu = struct.pack(">BHH", FC_WRITE_SINGLE_REGISTER, address,
                              _to_word(round(value * PCT_SCALE)))
            writer.write(encode_frame(self._next_txn(), 1, pdu))
            await writer.drain()
            await self._read_frame(reader)
        self.stats.trips_issued += 1
        log.warning("TRIP %s", action)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_client, self.listen_host, self.listen_port
        )
        if self.listen_port == 0:
            self.listen_port = self._server.sockets[0].getsockname()[1]
        self._started = time.perf_counter()
        self._supervisor_task = asyncio.create_task(self._supervise_loop())
        log.info(
            "guard listening on %s:%d -> PLC %s:%d",
            self.listen_host,
            self.listen_port,
            self.plc_host,
            self.plc_port,
        )

    async def stop(self) -> None:
        if self._supervisor_task is not None:
            self._supervisor_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._supervisor_task
        if self._server is not None:
            self._server.close()
            with contextlib.suppress(Exception):
                await self._server.wait_closed()

    async def __aenter__(self) -> "GuardedModbusProxy":
        await self.start()
        return self

    async def __aexit__(self, *exc) -> None:
        await self.stop()
