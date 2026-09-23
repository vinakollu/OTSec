"""A simulated Modbus field device with the water tank running behind it.

One class does the protocol for every executor in the device matrix; the
subclasses only say what their registers mean. That split is deliberate: the
PLC, the drive gateway and the RTU must disagree about *meaning* (units,
scaling, which table a point lives in, what the device does on its own) and
agree exactly on *protocol*, or a difference in results could be a bug in a
hand-written server rather than a property of the device.

Two things run concurrently, as in a real device:

* a Modbus TCP server answering requests against per-unit data tables, and
* a process loop that latches actuator commands out of the tables, steps the
  plant, and publishes measurements back into them.

The process loop is locked to a :class:`~otguard.clock.SimClock`, stepping the
plant in fixed ``dt`` increments until plant time catches up with the clock.
That keeps the plant, the guard and the masters on one timeline when the
experiment runs faster than real time.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging

from ..clock import SimClock
from ..config import Config
from ..sim import WaterTank
from .protocol import (
    EX_GATEWAY_TARGET_FAILED,
    EX_ILLEGAL_DATA_ADDRESS,
    EX_ILLEGAL_DATA_VALUE,
    EX_ILLEGAL_FUNCTION,
    FC_MASK_WRITE_REGISTER,
    FC_READ_COILS,
    FC_READ_DISCRETE_INPUTS,
    FC_READ_HOLDING_REGISTERS,
    FC_READ_INPUT_REGISTERS,
    FC_READ_WRITE_MULTIPLE_REGISTERS,
    FC_WRITE_MULTIPLE_COILS,
    FC_WRITE_MULTIPLE_REGISTERS,
    FC_WRITE_SINGLE_COIL,
    FC_WRITE_SINGLE_REGISTER,
    MAX_COILS_PER_READ,
    MAX_REGISTERS_PER_READ,
    WRITE_FUNCTION_CODES,
    Space,
    decode_frame,
    encode_frame,
    exception_pdu,
    mask_write_response,
    parse_read,
    parse_write,
    read_bits_response,
    read_registers_response,
    write_multiple_response,
)

log = logging.getLogger(__name__)

# How far the process loop will catch up in one wake-up before it gives up and
# lets plant time lag the clock. Only reached if the event loop stalls badly.
_MAX_CATCHUP_STEPS = 200


class UnitTables:
    """The four Modbus data tables of one unit id."""

    def __init__(self, coils: int = 0, discrete: int = 0, holding: int = 0, inputs: int = 0) -> None:
        self.coils = [0] * coils
        self.discrete = [0] * discrete
        self.holding = [0] * holding
        self.input = [0] * inputs

    def table(self, space: Space) -> list[int]:
        return {
            Space.COIL: self.coils,
            Space.DISCRETE_INPUT: self.discrete,
            Space.HOLDING: self.holding,
            Space.INPUT: self.input,
        }[space]


class ModbusDevice:
    """Base class: protocol, tables and process loop. Subclasses give meaning."""

    #: Function codes this device implements. Anything else is answered with
    #: ILLEGAL FUNCTION, as a real device would.
    supported_functions: frozenset[int] = frozenset(
        {
            FC_READ_COILS,
            FC_READ_DISCRETE_INPUTS,
            FC_READ_HOLDING_REGISTERS,
            FC_READ_INPUT_REGISTERS,
            FC_WRITE_SINGLE_COIL,
            FC_WRITE_SINGLE_REGISTER,
            FC_WRITE_MULTIPLE_COILS,
            FC_WRITE_MULTIPLE_REGISTERS,
            FC_MASK_WRITE_REGISTER,
            FC_READ_WRITE_MULTIPLE_REGISTERS,
        }
    )
    #: A standalone device typically ignores the unit id; a gateway routes on it.
    answer_any_unit: bool = False
    #: The unit id :meth:`handle_pdu` addresses when none is given.
    default_unit: int = 1
    name: str = "device"

    def __init__(
        self,
        config: Config,
        host: str = "127.0.0.1",
        port: int = 5020,
        seed: int = 0,
        clock: SimClock | None = None,
        initial_level_m: float | None = None,
    ) -> None:
        self.config = config
        self.host = host
        self.port = port
        self.clock = clock or SimClock()
        self.tank = WaterTank(config.plant, config.safety, seed=seed)
        if initial_level_m is not None:
            self.tank.state.level_m = initial_level_m
        self.units: dict[int, UnitTables] = self.build_units()
        self.scans = 0
        self.writes_applied = 0
        self._server: asyncio.AbstractServer | None = None
        self._scan_task: asyncio.Task | None = None
        self._plant_t = 0.0
        self.configure()
        self.publish()

    # ------------------------------------------------------------------
    # Subclass hooks
    # ------------------------------------------------------------------
    def build_units(self) -> dict[int, UnitTables]:
        raise NotImplementedError

    def configure(self) -> None:
        """Set factory-default register contents."""

    def latch(self) -> None:
        """Apply the actuator commands held in the tables to the plant."""
        raise NotImplementedError

    def publish(self) -> None:
        """Write the plant's measurements back into the tables."""
        raise NotImplementedError

    def local_logic(self) -> None:
        """Anything the device does on its own authority each scan."""

    # ------------------------------------------------------------------
    # Process
    # ------------------------------------------------------------------
    def scan_once(self) -> None:
        """One device scan: own logic, latch commands, solve the plant, publish."""
        self.local_logic()
        self.latch()
        self.tank.step()
        self.publish()
        self.scans += 1

    async def _run_scan_loop(self) -> None:
        dt = self.config.plant.dt_s
        self._plant_t = self.clock.now()
        try:
            while True:
                target = self.clock.now()
                steps = 0
                while self._plant_t + dt <= target and steps < _MAX_CATCHUP_STEPS:
                    self.scan_once()
                    self._plant_t += dt
                    steps += 1
                if steps == _MAX_CATCHUP_STEPS:
                    self._plant_t = target
                await self.clock.sleep(dt)
        except asyncio.CancelledError:
            pass

    # ------------------------------------------------------------------
    # Protocol
    # ------------------------------------------------------------------
    def handle_pdu(self, pdu: bytes) -> bytes:
        """Service a request addressed to the default unit."""
        return self.handle(self.default_unit, pdu)

    def handle(self, unit_id: int, pdu: bytes) -> bytes:
        """Service one request PDU for ``unit_id`` and return the response PDU."""
        if not pdu:
            return exception_pdu(0, EX_ILLEGAL_FUNCTION)
        fc = pdu[0]

        tables = self.units.get(unit_id)
        if tables is None and self.answer_any_unit:
            tables = self.units.get(self.default_unit)
        if tables is None:
            return exception_pdu(fc, EX_GATEWAY_TARGET_FAILED)
        if fc not in self.supported_functions:
            return exception_pdu(fc, EX_ILLEGAL_FUNCTION)

        if fc in (FC_READ_COILS, FC_READ_DISCRETE_INPUTS,
                  FC_READ_HOLDING_REGISTERS, FC_READ_INPUT_REGISTERS):
            return self._read(tables, pdu)
        if fc in WRITE_FUNCTION_CODES:
            return self._write(unit_id, tables, pdu)
        return exception_pdu(fc, EX_ILLEGAL_FUNCTION)

    def _read(self, tables: UnitTables, pdu: bytes) -> bytes:
        request = parse_read(pdu)
        fc = pdu[0]
        if request is None:
            return exception_pdu(fc, EX_ILLEGAL_DATA_VALUE)
        bits = request.space in (Space.COIL, Space.DISCRETE_INPUT)
        limit = MAX_COILS_PER_READ if bits else MAX_REGISTERS_PER_READ
        if not 1 <= request.count <= limit:
            return exception_pdu(fc, EX_ILLEGAL_DATA_VALUE)
        table = tables.table(request.space)
        end = request.address + request.count
        if end > len(table):
            return exception_pdu(fc, EX_ILLEGAL_DATA_ADDRESS)
        values = table[request.address:end]
        return read_bits_response(fc, values) if bits else read_registers_response(fc, values)

    def _write(self, unit_id: int, tables: UnitTables, pdu: bytes) -> bytes:
        fc = pdu[0]
        request = parse_write(pdu)
        if request is None:
            return exception_pdu(fc, EX_ILLEGAL_DATA_VALUE)
        table = tables.table(request.space)

        if request.is_masked:
            if request.address >= len(table):
                return exception_pdu(fc, EX_ILLEGAL_DATA_ADDRESS)
            and_mask, or_mask = request.and_mask or 0, request.or_mask or 0
            current = table[request.address]
            table[request.address] = ((current & and_mask) | (or_mask & ~and_mask)) & 0xFFFF
            self.writes_applied += 1
            self.on_write(unit_id, request.space, [request.address])
            return mask_write_response(request.address, and_mask, or_mask)

        end = request.address + len(request.values)
        if end > len(table):
            return exception_pdu(fc, EX_ILLEGAL_DATA_ADDRESS)
        if fc == FC_READ_WRITE_MULTIPLE_REGISTERS:
            assert request.read_address is not None and request.read_count is not None
            if request.read_address + request.read_count > len(table):
                return exception_pdu(fc, EX_ILLEGAL_DATA_ADDRESS)

        mask = 0x1 if request.space is Space.COIL else 0xFFFF
        for address, value in request.points():
            table[address] = value & mask
        self.writes_applied += 1
        self.on_write(unit_id, request.space, [a for a, _ in request.points()])

        if fc in (FC_WRITE_SINGLE_REGISTER, FC_WRITE_SINGLE_COIL):
            return pdu[:5]  # both are answered with an echo of the request
        if fc == FC_READ_WRITE_MULTIPLE_REGISTERS:
            # The write is performed before the read, per the specification.
            start = request.read_address
            return read_registers_response(fc, table[start:start + request.read_count])
        return write_multiple_response(request.address, len(request.values), fc)

    def on_write(self, unit_id: int, space: Space, addresses: list[int]) -> None:
        """Called after a write lands. Devices that react immediately override it."""

    # ------------------------------------------------------------------
    # TCP
    # ------------------------------------------------------------------
    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        buffer = b""
        try:
            while True:
                chunk = await reader.read(4096)
                if not chunk:
                    break
                buffer += chunk
                # One read can carry several frames, or half of one.
                while True:
                    try:
                        frame, buffer = decode_frame(buffer)
                    except ValueError:
                        log.warning("%s: malformed frame from %s, dropping connection",
                                    self.name, writer.get_extra_info("peername"))
                        return
                    if frame is None:
                        break
                    response = self.handle(frame.unit_id, frame.pdu)
                    writer.write(encode_frame(frame.transaction_id, frame.unit_id, response))
                await writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            pass
        finally:
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle_client, self.host, self.port)
        if self.port == 0:  # ephemeral port for tests
            self.port = self._server.sockets[0].getsockname()[1]
        self._scan_task = asyncio.create_task(self._run_scan_loop())
        log.info("%s listening on %s:%d", self.name, self.host, self.port)

    async def stop(self) -> None:
        if self._scan_task is not None:
            self._scan_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._scan_task
        if self._server is not None:
            self._server.close()
            with contextlib.suppress(Exception):
                await self._server.wait_closed()

    async def __aenter__(self) -> "ModbusDevice":
        await self.start()
        return self

    async def __aexit__(self, *exc) -> None:
        await self.stop()

