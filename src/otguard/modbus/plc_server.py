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

Like many real controllers it ignores the unit id in the MBAP header and
answers whatever it is addressed as, and it implements the read/write-multiple
and mask-write function codes as well as the two everyone tests with. Both
matter to a guard in front of it: see ``docs/devices.md``.
"""

from __future__ import annotations

from ..clock import SimClock
from ..config import Config
from .device import ModbusDevice, UnitTables
from .protocol import (
    FC_MASK_WRITE_REGISTER,
    FC_READ_HOLDING_REGISTERS,
    FC_READ_INPUT_REGISTERS,
    FC_READ_WRITE_MULTIPLE_REGISTERS,
    FC_WRITE_MULTIPLE_REGISTERS,
    FC_WRITE_SINGLE_REGISTER,
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


class SimulatedPLC(ModbusDevice):
    """Modbus TCP server whose registers are backed by the tank simulation."""

    name = "plc"
    answer_any_unit = True
    supported_functions = frozenset(
        {
            FC_READ_HOLDING_REGISTERS,
            FC_READ_INPUT_REGISTERS,
            FC_WRITE_SINGLE_REGISTER,
            FC_WRITE_MULTIPLE_REGISTERS,
            FC_MASK_WRITE_REGISTER,
            FC_READ_WRITE_MULTIPLE_REGISTERS,
        }
    )

    def __init__(
        self,
        config: Config,
        host: str = "127.0.0.1",
        port: int = 5020,
        seed: int = 0,
        clock: SimClock | None = None,
        initial_level_m: float | None = None,
    ) -> None:
        super().__init__(config, host, port, seed, clock, initial_level_m)

    @property
    def holding(self) -> list[int]:
        return self.units[1].holding

    @property
    def input(self) -> list[int]:
        return self.units[1].input

    def build_units(self) -> dict[int, UnitTables]:
        return {1: UnitTables(holding=HOLDING_COUNT, inputs=INPUT_COUNT)}

    def configure(self) -> None:
        self.holding[HR_LEVEL_SETPOINT] = _to_word(
            round(self.config.plant.initial_level_m * LEVEL_SCALE)
        )

    def latch(self) -> None:
        self.tank.set_pump(_signed(self.holding[HR_PUMP_CMD]) / PCT_SCALE)
        self.tank.set_valve(_signed(self.holding[HR_VALVE_CMD]) / PCT_SCALE)

    def publish(self) -> None:
        s = self.tank.state
        self.input[IR_LEVEL] = _to_word(round(self.tank.measure() * LEVEL_SCALE))
        self.input[IR_INFLOW] = _to_word(round(s.inflow_m3s * FLOW_SCALE))
        self.input[IR_OUTFLOW] = _to_word(round(s.outflow_m3s * FLOW_SCALE))
        self.input[IR_PUMP_POS] = _to_word(round(s.pump_pos_pct * PCT_SCALE))
        self.input[IR_VALVE_POS] = _to_word(round(s.valve_pos_pct * PCT_SCALE))
