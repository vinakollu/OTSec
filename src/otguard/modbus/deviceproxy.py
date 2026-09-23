"""A bump-in-the-wire that works for any sender and any receiver.

The original :class:`~otguard.modbus.proxy.GuardedModbusProxy` was written
against one PLC with one register map and one operator station. It proved the
idea and it is still what ``scripts/run_demo.py`` drives. This proxy is the
same idea with both ends made variable:

* the executor behind it is described by a :class:`DeviceMap`, so the guard
  reads a drive's speed reference or an RTU's contactor coil as a pump command
  without a rule changing;
* the sender in front of it is identified against an :class:`Inventory`, so a
  rule that cares who is writing has something to key on;
* every write function code is inspected, not the three a PLC demo happens to
  use;
* anything the rules cannot judge is decided by an explicit
  :class:`WirePolicy` rather than by silence.

What the guard does with a verdict is unchanged, and deliberately so. The
physics rules do not know that any of this exists.

Three behaviours carried over from the original, because they were load-bearing
there and are load-bearing here:

**Blocked writes get a real Modbus answer.** Dropping the frame leaves the
master waiting for a timeout, and a hung operator screen during an upset is its
own hazard. A refusal is an ILLEGAL DATA VALUE exception, which every Modbus
master already knows how to display.

**The guard polls the process itself.** Sniffing the level out of whatever a
master happens to read lets an attacker blind the guard by not reading. An
independent connection means the state estimate survives whatever the masters
do or stop doing.

**Trips are written upstream.** Supervision has to actually move the actuator,
through whichever point the device map says drives it.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import struct
import time
from dataclasses import dataclass, field

from ..clock import SimClock
from ..config import Config
from ..guard import Command, Observation, PhysicsGuard, Verdict
from ..guard.guard import SupervisionEvent
from ..guard.types import CommandKind, Decision
from .devicemap import DeviceMap, Point, PointRole
from .inventory import (
    UNKNOWN_SOURCE,
    Inventory,
    SourceDevice,
    WireDecision,
    WirePolicy,
)
from .protocol import (
    EX_ILLEGAL_DATA_VALUE,
    EX_ILLEGAL_FUNCTION,
    READ_FUNCTION_CODES,
    WRITE_FUNCTION_CODES,
    Frame,
    Space,
    decode_frame,
    encode_frame,
    exception_pdu,
    parse_read,
    parse_write,
    read_request,
)

log = logging.getLogger(__name__)


@dataclass
class FrameRecord:
    """One inspected frame, kept so the evaluation can explain every refusal."""

    t: float
    source: str
    unit_id: int
    function_code: int
    forwarded: bool
    wire_reason: WireDecision | None = None
    verdicts: list[Verdict] = field(default_factory=list)
    detail: str = ""

    @property
    def blocked_by_rules(self) -> bool:
        return not self.forwarded and self.wire_reason is None

    @property
    def rule_ids(self) -> list[str]:
        return [r for v in self.verdicts for r in v.rule_ids]


@dataclass
class DeviceProxyStats:
    frames_forwarded: int = 0
    writes_inspected: int = 0
    writes_blocked: int = 0
    writes_alarmed: int = 0
    wire_blocked: int = 0
    trips_issued: int = 0
    polls: int = 0
    wire_latency_us: list[float] = field(default_factory=list)
    by_source: dict[str, int] = field(default_factory=dict)
    wire_reasons: dict[str, int] = field(default_factory=dict)

    def summary(self) -> str:
        return (
            f"frames={self.frames_forwarded} writes={self.writes_inspected} "
            f"blocked={self.writes_blocked} wire_blocked={self.wire_blocked} "
            f"alarmed={self.writes_alarmed} trips={self.trips_issued} polls={self.polls}"
        )


class DeviceGuardProxy:
    """Transparent Modbus TCP proxy, parameterised by both ends of the wire."""

    def __init__(
        self,
        config: Config,
        device_map: DeviceMap,
        target_host: str = "127.0.0.1",
        target_port: int = 5020,
        listen_host: str = "127.0.0.1",
        listen_port: int = 5021,
        guard: PhysicsGuard | None = None,
        inventory: Inventory | None = None,
        policy: WirePolicy | None = None,
        clock: SimClock | None = None,
        enforce: bool = True,
        initial_level_m: float | None = None,
    ) -> None:
        self.config = config
        self.map = device_map
        self.target_host = target_host
        self.target_port = target_port
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.inventory = inventory if inventory is not None else Inventory()
        self.policy = policy or WirePolicy()
        self.clock = clock or SimClock()
        self.enforce = enforce

        self.guard = guard or PhysicsGuard(
            self._adjusted_config(config), initial_level_m=initial_level_m
        )
        self.stats = DeviceProxyStats()
        self.frames: list[FrameRecord] = []
        self.verdicts: list[Verdict] = []
        self.events: list[SupervisionEvent] = []

        self._server: asyncio.AbstractServer | None = None
        self._supervisor_task: asyncio.Task | None = None
        self._txn = 0

    def _adjusted_config(self, config: Config) -> Config:
        """Apply the device map's actuator overrides to the guard's model.

        A contactor-driven pump reaches full speed at once; a drive ramps over
        seconds. The guard is told which it is facing, the same way a commissioning
        engineer would read it off the installed equipment. What it is *not* told
        is the plant's true parameters, which stay 4 % away from the model.
        """
        if not self.map.model_overrides:
            return config
        import dataclasses

        model = dataclasses.replace(config.guard.model, **dict(self.map.model_overrides))
        guard_cfg = dataclasses.replace(config.guard, model=model)
        return dataclasses.replace(config, guard=guard_cfg)

    # ------------------------------------------------------------------
    # Inspection
    # ------------------------------------------------------------------
    def _now(self) -> float:
        return self.clock.now()

    def _inspect(self, frame: Frame, source: SourceDevice) -> FrameRecord:
        """Judge one write frame. The record says whether to forward it and why."""
        now = self._now()
        record = FrameRecord(
            t=now,
            source=source.name,
            unit_id=frame.unit_id,
            function_code=frame.function_code,
            forwarded=True,
        )

        if source is UNKNOWN_SOURCE and not self.policy.permits(WireDecision.UNAUTHORISED_SOURCE):
            return self._refuse(record, WireDecision.UNAUTHORISED_SOURCE,
                                "write from an address not in the device inventory")

        request = parse_write(frame.pdu)
        if request is None:
            return self._refuse(record, WireDecision.UNPARSEABLE,
                                f"malformed write, function {frame.function_code:#04x}")

        # A mask write's effect depends on what the register already holds, so
        # its value cannot be judged from the frame alone. Refusing it is the
        # honest answer; the alternative is reading the register back and racing
        # whatever else is writing to it.
        if request.is_masked:
            point = self.map.lookup(frame.unit_id, request.space, request.address)
            name = point.name if point else f"{request.space.value}[{request.address}]"
            return self._refuse(record, WireDecision.UNJUDGEABLE_WRITE,
                                f"mask write to {name}: the resulting value depends on "
                                f"the register's current contents and cannot be judged "
                                f"from the frame")

        # Each point is examined in turn. A defect the policy refuses ends the
        # frame; a defect the policy permits must not also skip the rules,
        # which is the difference between an ablation and switching the guard
        # off. An out-of-scope write in particular is still a real actuator
        # command, and is judged on its physics once the access check is not
        # the thing stopping it.
        commands: list[tuple[Point, Command]] = []
        for address, raw in request.points():
            point = self.map.lookup(frame.unit_id, request.space, address)
            if point is None:
                self._refuse(
                    record, WireDecision.UNMAPPED_POINT,
                    f"write to unit {frame.unit_id} "
                    f"{request.space.value}[{address}], which the device map "
                    f"does not describe",
                )
                if record.wire_reason is not None:
                    return record
                continue  # permitted, but there is no physics to check it against
            if point.role is PointRole.PARAMETER:
                self._refuse(
                    record, WireDecision.PARAMETER_WRITE,
                    f"write to {point.name}: changing an actuator's configuration "
                    f"invalidates the model the physics rules reason about",
                )
                if record.wire_reason is not None:
                    return record
                continue  # permitted; a parameter moves no actuator directly
            if point.role is PointRole.PASSTHROUGH:
                continue
            if not source.may_write(point.name):
                self._refuse(
                    record, WireDecision.UNAUTHORISED_POINT,
                    f"{source.name} is not configured to write {point.name}",
                )
                if record.wire_reason is not None:
                    return record
                # Permitted: fall through, because the rules can still judge it.
            assert point.kind is not None
            commands.append(
                (point, Command(t=now, kind=point.kind,
                                value=point.to_engineering(raw), source=source.source_class.value))
            )

        allow = True
        for _, command in commands:
            verdict = self.guard.check(command)
            record.verdicts.append(verdict)
            self.verdicts.append(verdict)
            self.stats.writes_inspected += 1
            if verdict.decision is Decision.ALARM:
                self.stats.writes_alarmed += 1
            if not verdict.allowed:
                allow = False
            for finding in verdict.findings:
                log.warning("%s %s [%s]", verdict.decision.value.upper(), finding, source.name)

        # A multi-point write is judged as a unit: Modbus has no partial-success
        # response, and applying half of a refused write leaves the process in a
        # state neither the operator nor the guard asked for.
        if not allow and self.enforce:
            record.forwarded = False
            self.stats.writes_blocked += 1
        elif not allow:
            self.stats.writes_blocked += 1  # counted, not acted on
        return record

    def _refuse(self, record: FrameRecord, reason: WireDecision, detail: str) -> FrameRecord:
        record.detail = detail
        if self.policy.permits(reason):
            log.info("wire policy permits: %s", detail)
            return record
        record.wire_reason = reason
        record.forwarded = not self.enforce
        self.stats.wire_reasons[reason.value] = self.stats.wire_reasons.get(reason.value, 0) + 1
        self.stats.wire_blocked += 1
        log.warning("WIRE-REFUSE %s (%s)", detail, reason.value)
        return record

    def _read_permitted(self, frame: Frame, source: SourceDevice) -> bool:
        """Reads are forwarded unless the sender is not in the inventory at all."""
        if source is UNKNOWN_SOURCE and not self.policy.permits(WireDecision.UNAUTHORISED_SOURCE):
            return False
        return parse_read(frame.pdu) is not None

    # ------------------------------------------------------------------
    # Client handling
    # ------------------------------------------------------------------
    async def _handle_client(
        self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter
    ) -> None:
        peer = client_writer.get_extra_info("peername")
        source = self.inventory.identify(peer)
        log.info("%s connected from %s", source.name, peer)
        try:
            target_reader, target_writer = await asyncio.open_connection(
                self.target_host, self.target_port
            )
        except OSError as exc:
            log.error("cannot reach %s at %s:%d (%s)", self.map.name,
                      self.target_host, self.target_port, exc)
            client_writer.close()
            return

        try:
            await self._pump(client_reader, client_writer, target_reader, target_writer, source)
        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
            pass
        finally:
            for writer in (target_writer, client_writer):
                with contextlib.suppress(Exception):
                    writer.close()
                    await writer.wait_closed()

    async def _pump(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        target_reader: asyncio.StreamReader,
        target_writer: asyncio.StreamWriter,
        source: SourceDevice,
    ) -> None:
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
                    log.warning("malformed frame from %s, dropping connection", source.name)
                    return
                if frame is None:
                    break

                started = time.perf_counter()
                fc = frame.function_code
                self.stats.by_source[source.name] = self.stats.by_source.get(source.name, 0) + 1

                if fc in WRITE_FUNCTION_CODES:
                    record = self._inspect(frame, source)
                    self.frames.append(record)
                    if not record.forwarded:
                        await self._answer(client_writer, frame, EX_ILLEGAL_DATA_VALUE)
                        self.stats.wire_latency_us.append((time.perf_counter() - started) * 1e6)
                        continue
                elif fc in READ_FUNCTION_CODES:
                    if not self._read_permitted(frame, source):
                        await self._answer(client_writer, frame, EX_ILLEGAL_DATA_VALUE)
                        self.stats.wire_latency_us.append((time.perf_counter() - started) * 1e6)
                        continue
                else:
                    # Diagnostics, file transfer, vendor codes: not judged by any
                    # rule, and a channel straight to the device's firmware.
                    record = FrameRecord(self._now(), source.name, frame.unit_id, fc,
                                         forwarded=False)
                    self._refuse(record, WireDecision.UNKNOWN_FUNCTION,
                                 f"function {fc:#04x} is outside the guard's coverage")
                    self.frames.append(record)
                    if not record.forwarded:
                        await self._answer(client_writer, frame, EX_ILLEGAL_FUNCTION)
                        self.stats.wire_latency_us.append((time.perf_counter() - started) * 1e6)
                        continue

                target_writer.write(frame.encode())
                await target_writer.drain()
                response = await self._read_frame(target_reader)
                if response is None:
                    return
                client_writer.write(response.encode())
                await client_writer.drain()
                self.stats.frames_forwarded += 1
                self.stats.wire_latency_us.append((time.perf_counter() - started) * 1e6)

    @staticmethod
    async def _answer(writer: asyncio.StreamWriter, frame: Frame, code: int) -> None:
        writer.write(
            encode_frame(frame.transaction_id, frame.unit_id,
                         exception_pdu(frame.function_code, code))
        )
        await writer.drain()

    @staticmethod
    async def _read_frame(reader: asyncio.StreamReader) -> Frame | None:
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
        period = self.config.plant.dt_s
        try:
            reader, writer = await asyncio.open_connection(self.target_host, self.target_port)
        except OSError as exc:
            log.error("supervisor cannot reach %s (%s)", self.map.name, exc)
            return

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
                        if event.action is not None and self.enforce:
                            await self._apply_trip(reader, writer, event)
                        elif event.action is not None:
                            self.stats.trips_issued += 1  # would have tripped
                await self.clock.sleep(period)
        except asyncio.CancelledError:
            pass
        except (ConnectionResetError, BrokenPipeError):
            log.warning("supervisor lost its connection to %s", self.map.name)
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
        point = self.map.level
        fc = 0x04 if point.space is Space.INPUT else 0x03
        writer.write(encode_frame(self._next_txn(), point.unit_id,
                                  read_request(fc, point.address, 1)))
        await writer.drain()
        frame = await self._read_frame(reader)
        if frame is None or len(frame.pdu) < 4 or frame.pdu[0] & 0x80:
            return None
        raw = struct.unpack(">H", frame.pdu[2:4])[0]
        return point.to_engineering(raw)

    async def _apply_trip(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        event: SupervisionEvent,
    ) -> None:
        """Write the protective action through whichever point drives the actuator."""
        action = event.action
        assert action is not None
        targets = [
            (CommandKind.PUMP, action.pump_cmd_pct),
            (CommandKind.VALVE, action.valve_cmd_pct),
        ]
        for kind, value in targets:
            if value is None or not self.map.has_command(kind):
                continue
            unit_id, pdu = self.map.encode_write(kind, value)
            writer.write(encode_frame(self._next_txn(), unit_id, pdu))
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
        self._supervisor_task = asyncio.create_task(self._supervise_loop())
        log.info("guard listening on %s:%d -> %s %s:%d", self.listen_host, self.listen_port,
                 self.map.name, self.target_host, self.target_port)

    async def stop(self) -> None:
        if self._supervisor_task is not None:
            self._supervisor_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._supervisor_task
        if self._server is not None:
            self._server.close()
            with contextlib.suppress(Exception):
                await self._server.wait_closed()

    async def __aenter__(self) -> "DeviceGuardProxy":
        await self.start()
        return self

    async def __aexit__(self, *exc) -> None:
        await self.stop()
