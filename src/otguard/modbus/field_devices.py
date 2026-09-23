"""Executors other than a PLC: a drive gateway and an RTU.

Each runs the same water tank as :class:`SimulatedPLC` and speaks the same
Modbus TCP, but moves the actuators the way that class of device really does.
The differences are the point of the device matrix. Every one of them is
something a guard validated only against a PLC would have got wrong.

``DriveGateway``
    Unit ids matter: three RS-485 devices share one TCP endpoint. The pump
    speed reference is a fraction of the drive's configured maximum frequency,
    so the same register value means a different flow when that parameter
    changes. Ramp and stroke times are parameters too.

``RemoteTerminalUnit``
    The pump is a coil driving a contactor: on or off, and on means full speed
    immediately. The valve and level are 4-20 mA signals in raw ADC counts,
    with a live zero. And the RTU protects the tank on its own with a
    high-level interlock, which changes what an attack does when nothing else
    is in the way.
"""

from __future__ import annotations

from typing import Callable

from .device import ModbusDevice, UnitTables
from .devicemap import (
    POS_HR_SETPOINT,
    POS_HR_STROKE_TIME,
    POS_IR_POSITION,
    POSITIONER_UNIT,
    RTU_AO_SPAN,
    RTU_AO_ZERO,
    RTU_COIL_INTERLOCK_ENABLE,
    RTU_COIL_PUMP_RUN,
    RTU_HR_VALVE_AO,
    RTU_IR_LEVEL_AI,
    RTU_LEVEL_SPAN_M,
    RTU_UNIT,
    TRANSMITTER_UNIT,
    VFD_HR_ACCEL,
    VFD_HR_DECEL,
    VFD_HR_MAX_FREQ,
    VFD_HR_SPEED_REF,
    VFD_IR_OUTPUT_FREQ,
    VFD_NOMINAL_HZ,
    VFD_REF_FULL_SCALE,
    VFD_UNIT,
    XMTR_IR_LEVEL,
    DeviceMap,
    drives_map,
    plc_map,
    rtu_map,
)
from .plc_server import SimulatedPLC
from .registers import _signed, _to_word


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


class DriveGateway(ModbusDevice):
    """A Modbus TCP gateway with a VFD, a valve positioner and a transmitter.

    Factory defaults match the nominal plant: 60 Hz maximum frequency, a 5 s
    ramp (20 %/s) and a 4 s valve stroke (25 %/s). Change a parameter and the
    plant changes with it. The guard's model does not.
    """

    name = "drives"
    default_unit = VFD_UNIT

    def build_units(self) -> dict[int, UnitTables]:
        return {
            VFD_UNIT: UnitTables(holding=16, inputs=4),
            POSITIONER_UNIT: UnitTables(holding=16, inputs=4),
            TRANSMITTER_UNIT: UnitTables(inputs=4),
        }

    def configure(self) -> None:
        vfd = self.units[VFD_UNIT].holding
        vfd[VFD_HR_MAX_FREQ] = 600   # 60.0 Hz
        vfd[VFD_HR_ACCEL] = 50       # 5.0 s
        vfd[VFD_HR_DECEL] = 50
        self.units[POSITIONER_UNIT].holding[POS_HR_STROKE_TIME] = 40  # 4.0 s

    @property
    def max_frequency_hz(self) -> float:
        return _clamp(self.units[VFD_UNIT].holding[VFD_HR_MAX_FREQ] / 10.0, 1.0, 120.0)

    def latch(self) -> None:
        vfd = self.units[VFD_UNIT].holding
        speed_ceiling_pct = self.max_frequency_hz / VFD_NOMINAL_HZ * 100.0
        # Reverse is not enabled: a negative reference is held at zero speed,
        # and a reference above full scale is held at maximum frequency.
        ref = _clamp(_signed(vfd[VFD_HR_SPEED_REF]) / VFD_REF_FULL_SCALE, 0.0, 1.0)
        ramp_s = max(min(vfd[VFD_HR_ACCEL], vfd[VFD_HR_DECEL]) / 10.0, 0.1)
        self.tank.pump_limit_pct = speed_ceiling_pct
        self.tank.pump_slew_pct_s = speed_ceiling_pct / ramp_s
        self.tank.set_pump(ref * speed_ceiling_pct)

        pos = self.units[POSITIONER_UNIT].holding
        stroke_s = max(pos[POS_HR_STROKE_TIME] / 10.0, 0.1)
        self.tank.valve_slew_pct_s = 100.0 / stroke_s
        self.tank.set_valve(_clamp(_signed(pos[POS_HR_SETPOINT]) / 100.0, 0.0, 100.0))

    def publish(self) -> None:
        s = self.tank.state
        hz = s.pump_pos_pct / 100.0 * VFD_NOMINAL_HZ
        self.units[VFD_UNIT].input[VFD_IR_OUTPUT_FREQ] = _to_word(round(hz * 100))
        self.units[POSITIONER_UNIT].input[POS_IR_POSITION] = _to_word(round(s.valve_pos_pct * 100))
        self.units[TRANSMITTER_UNIT].input[XMTR_IR_LEVEL] = _to_word(
            round(self.tank.measure() * 1000)
        )


class RemoteTerminalUnit(ModbusDevice):
    """An RTU with a pump contactor, 4-20 mA I/O and a local interlock.

    The interlock opens the pump contactor whenever the level it reads is at or
    above ``INTERLOCK_LEVEL_M`` and coil 10 is set. It ships enabled.
    """

    name = "rtu"
    default_unit = RTU_UNIT
    INTERLOCK_LEVEL_M = 1.70

    def build_units(self) -> dict[int, UnitTables]:
        return {RTU_UNIT: UnitTables(coils=16, holding=8, inputs=8)}

    def configure(self) -> None:
        tables = self.units[RTU_UNIT]
        tables.coils[RTU_COIL_INTERLOCK_ENABLE] = 1
        tables.holding[RTU_HR_VALVE_AO] = RTU_AO_ZERO
        # A contactor has no ramp: closed means full speed now.
        self.tank.pump_slew_pct_s = 1000.0
        self.interlock_trips = 0
        self._level_m = self.tank.state.level_m

    def local_logic(self) -> None:
        tables = self.units[RTU_UNIT]
        if tables.coils[RTU_COIL_INTERLOCK_ENABLE] and self._level_m >= self.INTERLOCK_LEVEL_M:
            if tables.coils[RTU_COIL_PUMP_RUN]:
                self.interlock_trips += 1
            tables.coils[RTU_COIL_PUMP_RUN] = 0

    def latch(self) -> None:
        tables = self.units[RTU_UNIT]
        self.tank.set_pump(100.0 if tables.coils[RTU_COIL_PUMP_RUN] else 0.0)
        raw = _clamp(tables.holding[RTU_HR_VALVE_AO], RTU_AO_ZERO, RTU_AO_ZERO + RTU_AO_SPAN)
        self.tank.set_valve((raw - RTU_AO_ZERO) / RTU_AO_SPAN * 100.0)

    def publish(self) -> None:
        self._level_m = self.tank.measure()
        raw = RTU_AO_ZERO + self._level_m / RTU_LEVEL_SPAN_M * RTU_AO_SPAN
        self.units[RTU_UNIT].input[RTU_IR_LEVEL_AI] = int(_clamp(round(raw), 0, 0x7FFF))


#: The executors in the device matrix, with the register map the guard is
#: configured with for each.
EXECUTORS: dict[str, tuple[type[ModbusDevice], Callable[[], DeviceMap]]] = {
    "plc": (SimulatedPLC, plc_map),
    "drives": (DriveGateway, drives_map),
    "rtu": (RemoteTerminalUnit, rtu_map),
}
