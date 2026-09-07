"""A simulated PLC: a Modbus TCP server with the tank running behind it.

Two things happen in one process, exactly as in a real controller:

* a **Modbus server** exposing holding registers (the command path) and input
  registers (the process view), and
* a **scan loop** that latches the commanded actuator positions out of the
  holding registers, advances the plant, and publishes the resulting
  measurements into the input registers.

The PLC is deliberately dumb. It has no notion of a safety envelope and obeys
any in-range word written to it. That is not an oversight to fix here — it is
the premise. Putting the check inside the controller would solve the problem in
the one place a real deployment cannot reach: the legacy PLC that cannot be
patched, recertified, or taken offline.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging

from ..config import Config
from ..sim import WaterTank
from .protocol import (
    EX_ILLEGAL_DATA_ADDRESS,
    EX_ILLEGAL_DATA_VALUE,
    EX_ILLEGAL_FUNCTION,
    FC_READ_HOLDING_REGISTERS,
    FC_READ_INPUT_REGISTERS,
    FC_WRITE_MULTIPLE_REGISTERS,
    FC_WRITE_SINGLE_REGISTER,
    MAX_REGISTERS_PER_READ,
    decode_frame,
    encode_frame,
    exception_pdu,
    parse_read,
    parse_write,
    read_registers_response,
    write_multiple_response,
    write_single_response,
)
from .registers import (
    FLOW_SCALE,
    HOLDING_COUNT,
    HR_LEVEL_SETPOINT,
    HR_PUMP_CMD,
    HR_VALVE_CMD,
    INPUT_COUNT,
    IR_INFLOW,
    IR_LEVEL,
    IR_OUTFLOW,
    IR_PUMP_POS,
    IR_VALVE_POS,
    LEVEL_SCALE,
    PCT_SCALE,
    _signed,
    _to_word,
)

log = logging.getLogger(__name__)


class SimulatedPLC:
    """Modbus TCP server whose registers are backed by the tank simulation."""

    def __init__(
        self,
        config: Config,
        host: str = "127.0.0.1",
        port: int = 5020,
        seed: int = 0,
    ) -> None:
        self.config = config
        self.host = host
        self.port = port
        self.tank = WaterTank(config.plant, config.safety, seed=seed)

        self.holding = [0] * HOLDING_COUNT
        self.input = [0] * INPUT_COUNT
        self.holding[HR_LEVEL_SETPOINT] = _to_word(
            round(config.plant.initial_level_m * LEVEL_SCALE)
        )
        self._publish()

        self._server: asyncio.AbstractServer | None = None
        self._scan_task: asyncio.Task | None = None
        self.scans = 0
        self.writes_applied = 0

    # ------------------------------------------------------------------
    # Process
    # ------------------------------------------------------------------
    def _publish(self) -> None:
        s = self.tank.state
        self.input[IR_LEVEL] = _to_word(round(self.tank.measure() * LEVEL_SCALE))
        self.input[IR_INFLOW] = _to_word(round(s.inflow_m3s * FLOW_SCALE))
        self.input[IR_OUTFLOW] = _to_word(round(s.outflow_m3s * FLOW_SCALE))
        self.input[IR_PUMP_POS] = _to_word(round(s.pump_pos_pct * PCT_SCALE))
        self.input[IR_VALVE_POS] = _to_word(round(s.valve_pos_pct * PCT_SCALE))

    def scan_once(self) -> None:
        """One PLC scan: latch commands, solve the process, publish results."""
        self.tank.set_pump(_signed(self.holding[HR_PUMP_CMD]) / PCT_SCALE)
        self.tank.set_valve(_signed(self.holding[HR_VALVE_CMD]) / PCT_SCALE)
        self.tank.step()
        self._publish()
        self.scans += 1

    async def _run_scan_loop(self) -> None:
        period = self.config.plant.dt_s
        try:
            while True:
                self.scan_once()
                await asyncio.sleep(period)
        except asyncio.CancelledError:
            pass

    # ------------------------------------------------------------------
    # Modbus
    # ------------------------------------------------------------------
    def handle_pdu(self, pdu: bytes) -> bytes:
        """Service one request PDU and return the response PDU."""
        if not pdu:
            return exception_pdu(0, EX_ILLEGAL_FUNCTION)
        fc = pdu[0]

        if fc in (FC_READ_HOLDING_REGISTERS, FC_READ_INPUT_REGISTERS):
            request = parse_read(pdu)
            if request is None:
                return exception_pdu(fc, EX_ILLEGAL_DATA_VALUE)
            if not 1 <= request.count <= MAX_REGISTERS_PER_READ:
                return exception_pdu(fc, EX_ILLEGAL_DATA_VALUE)
            bank = self.holding if fc == FC_READ_HOLDING_REGISTERS else self.input
            end = request.address + request.count
            if request.address < 0 or end > len(bank):
                return exception_pdu(fc, EX_ILLEGAL_DATA_ADDRESS)
            return read_registers_response(fc, bank[request.address:end])

        if fc in (FC_WRITE_SINGLE_REGISTER, FC_WRITE_MULTIPLE_REGISTERS):
            request = parse_write(pdu)
            if request is None:
                return exception_pdu(fc, EX_ILLEGAL_DATA_VALUE)
            end = request.address + len(request.values)
            if request.address < 0 or end > len(self.holding):
                return exception_pdu(fc, EX_ILLEGAL_DATA_ADDRESS)
            for offset, value in enumerate(request.values):
                self.holding[request.address + offset] = value & 0xFFFF
            self.writes_applied += 1
            if fc == FC_WRITE_SINGLE_REGISTER:
                return write_single_response(fc, request.address, request.values[0])
            return write_multiple_response(request.address, len(request.values))

        return exception_pdu(fc, EX_ILLEGAL_FUNCTION)

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
                        log.warning("malformed frame from %s, dropping connection",
                                    writer.get_extra_info("peername"))
                        return
                    if frame is None:
                        break
                    response = self.handle_pdu(frame.pdu)
                    writer.write(encode_frame(frame.transaction_id, frame.unit_id, response))
                await writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            pass
        finally:
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle_client, self.host, self.port)
        if self.port == 0:  # ephemeral port for tests
            self.port = self._server.sockets[0].getsockname()[1]
        self._scan_task = asyncio.create_task(self._run_scan_loop())
        log.info("simulated PLC listening on %s:%d", self.host, self.port)

    async def stop(self) -> None:
        if self._scan_task is not None:
            self._scan_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._scan_task
        if self._server is not None:
            self._server.close()
            with contextlib.suppress(Exception):
                await self._server.wait_closed()

    async def __aenter__(self) -> "SimulatedPLC":
        await self.start()
        return self

    async def __aexit__(self, *exc) -> None:
        await self.stop()
