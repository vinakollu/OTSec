"""What the guard knows about the devices behind it.

The physics rules speak in engineering units: pump percent, valve percent,
level in metres. A field device speaks in 16-bit words and single bits, at
addresses that mean different things on every model of every vendor's
equipment. A ``DeviceMap`` is the translation between the two, and it is the
part of the guard that has to change when the device it protects changes.

Every writable point on a device gets one of three roles:

``COMMAND``
    Moves an actuator the guard models. Translated to a :class:`Command` and
    judged by the physics rules.

``PARAMETER``
    Changes *how* an actuator responds: a drive's maximum frequency, its ramp
    time, a positioner's stroke time, an RTU's local interlock enable. These
    are refused outright. The rules are only as good as the model of the
    actuator they reason about, and a write that changes the actuator's
    behaviour silently invalidates that model. The guard cannot judge the
    commands that follow a parameter change it did not anticipate.

``PASSTHROUGH``
    Known to be physically meaningless to the process (a display register, an
    alarm acknowledge). Forwarded without judgement.

A write to any address that is not listed at all is refused. A guard that
forwards what it does not understand is a guard with a list of the attacks it
happens to know about.

Three maps ship here, one per executor in the device matrix:

``plc``
    The original simulated PLC. Holding registers in tenths of a percent.

``drives``
    A Modbus TCP gateway fronting three RS-485 devices, addressed by unit id:
    a variable-frequency drive on the pump (unit 2), a smart valve positioner
    (unit 3) and a level transmitter (unit 4). The drive takes its speed
    reference as a fraction of its *configured* maximum frequency, PROFIdrive
    style, so 0x4000 means "100 % of whatever the max-frequency parameter says".

``rtu``
    A remote terminal unit driving a fixed-speed pump through a contactor on
    coil 0, the valve through a 4-20 mA analog output, and reading the level
    from a 4-20 mA analog input. It also runs its own high-level interlock,
    enabled by coil 10.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping

from ..guard.types import CommandKind
from . import registers as plc_regs
from .protocol import (
    Space,
    write_single_coil,
    write_single_register,
)
from .registers import _signed, _to_word


class PointRole(str, Enum):
    COMMAND = "command"
    PARAMETER = "parameter"
    PASSTHROUGH = "passthrough"


@dataclass(frozen=True)
class Point:
    """One addressable point on one device, and what it means physically.

    Engineering value and raw word are related linearly::

        raw = value * scale + offset

    For a coil, ``scale=0.01`` turns "pump on" (1) into 100 % and "off" (0)
    into 0 %, and any command below 50 % rounds to off.
    """

    unit_id: int
    space: Space
    address: int
    name: str
    role: PointRole
    kind: CommandKind | None = None
    scale: float = 1.0
    offset: float = 0.0
    signed: bool = False

    def to_engineering(self, raw: int) -> float:
        word = _signed(raw) if self.signed else raw & 0xFFFF
        return (word - self.offset) / self.scale

    def to_raw(self, value: float) -> int:
        raw = round(value * self.scale + self.offset)
        if self.space is Space.COIL:
            return 1 if raw >= 1 else 0
        return _to_word(raw)

    @property
    def key(self) -> tuple[int, Space, int]:
        return (self.unit_id, self.space, self.address)


@dataclass(frozen=True)
class DeviceMap:
    """The register map of one executor, as configured into the guard.

    ``model_overrides`` describes the actuators actually installed where they
    differ from the nominal model in ``config.guard.model``. A contactor-driven
    pump starts instantly; a guard that assumes a five-second drive ramp will
    underestimate how fast it fills.
    """

    name: str
    description: str
    points: tuple[Point, ...]
    level: Point
    model_overrides: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        keys = [p.key for p in self.points]
        if len(keys) != len(set(keys)):
            raise ValueError(f"{self.name}: duplicate point addresses")
        for kind in (CommandKind.PUMP, CommandKind.VALVE):
            if not any(p.kind is kind and p.role is PointRole.COMMAND for p in self.points):
                raise ValueError(f"{self.name}: no command point for {kind.value}")

    def lookup(self, unit_id: int, space: Space, address: int) -> Point | None:
        for point in self.points:
            if point.key == (unit_id, space, address):
                return point
        return None

    def command_point(self, kind: CommandKind) -> Point:
        for point in self.points:
            if point.kind is kind and point.role is PointRole.COMMAND:
                return point
        raise KeyError(f"{self.name} has no command point for {kind.value}")

    def has_command(self, kind: CommandKind) -> bool:
        return any(p.kind is kind and p.role is PointRole.COMMAND for p in self.points)

    def parameters(self) -> list[Point]:
        return [p for p in self.points if p.role is PointRole.PARAMETER]

    @property
    def unit_ids(self) -> set[int]:
        return {p.unit_id for p in self.points} | {self.level.unit_id}

    @property
    def binary_pump(self) -> bool:
        return self.command_point(CommandKind.PUMP).space is Space.COIL

    def encode_write(self, kind: CommandKind, value: float) -> tuple[int, bytes]:
        """The simplest frame that sets ``kind`` to ``value`` on this device.

        Used for the guard's own protective trips and by masters that write one
        point at a time.
        """
        point = self.command_point(kind)
        raw = point.to_raw(value)
        if point.space is Space.COIL:
            return point.unit_id, write_single_coil(point.address, bool(raw))
        return point.unit_id, write_single_register(point.address, raw)


# ----------------------------------------------------------------------
# Executor 1: the original PLC
# ----------------------------------------------------------------------
PLC_UNIT = 1


def plc_map() -> DeviceMap:
    pct = plc_regs.PCT_SCALE
    return DeviceMap(
        name="plc",
        description="PLC, holding registers in 0.1 % and mm",
        points=(
            Point(PLC_UNIT, Space.HOLDING, plc_regs.HR_PUMP_CMD, "pump_cmd",
                  PointRole.COMMAND, CommandKind.PUMP, scale=pct, signed=True),
            Point(PLC_UNIT, Space.HOLDING, plc_regs.HR_VALVE_CMD, "valve_cmd",
                  PointRole.COMMAND, CommandKind.VALVE, scale=pct, signed=True),
            Point(PLC_UNIT, Space.HOLDING, plc_regs.HR_LEVEL_SETPOINT, "level_setpoint",
                  PointRole.COMMAND, CommandKind.SETPOINT,
                  scale=plc_regs.LEVEL_SCALE, signed=True),
            Point(PLC_UNIT, Space.HOLDING, plc_regs.HR_MODE, "mode",
                  PointRole.COMMAND, CommandKind.MODE, signed=True),
        ),
        level=Point(PLC_UNIT, Space.INPUT, plc_regs.IR_LEVEL, "level",
                    PointRole.PASSTHROUGH, scale=plc_regs.LEVEL_SCALE, signed=True),
    )


# ----------------------------------------------------------------------
# Executor 2: drive, positioner and transmitter behind a gateway
# ----------------------------------------------------------------------
VFD_UNIT = 2
POSITIONER_UNIT = 3
TRANSMITTER_UNIT = 4

VFD_HR_SPEED_REF = 1         # 0x4000 = 100 % of max frequency, signed
VFD_HR_MAX_FREQ = 10         # 0.1 Hz
VFD_HR_ACCEL = 11            # 0.1 s, zero to max frequency
VFD_HR_DECEL = 12            # 0.1 s, max frequency to zero
VFD_IR_OUTPUT_FREQ = 0       # 0.01 Hz
VFD_REF_FULL_SCALE = 0x4000
VFD_NOMINAL_HZ = 60.0

POS_HR_SETPOINT = 0          # 0.01 %
POS_HR_STROKE_TIME = 10      # 0.1 s, full travel
POS_IR_POSITION = 0          # 0.01 %

XMTR_IR_LEVEL = 0            # mm


def drives_map() -> DeviceMap:
    return DeviceMap(
        name="drives",
        description="gateway: VFD (unit 2), valve positioner (unit 3), "
                    "level transmitter (unit 4)",
        points=(
            Point(VFD_UNIT, Space.HOLDING, VFD_HR_SPEED_REF, "vfd_speed_ref",
                  PointRole.COMMAND, CommandKind.PUMP,
                  scale=VFD_REF_FULL_SCALE / 100.0, signed=True),
            Point(VFD_UNIT, Space.HOLDING, VFD_HR_MAX_FREQ, "vfd_max_frequency",
                  PointRole.PARAMETER),
            Point(VFD_UNIT, Space.HOLDING, VFD_HR_ACCEL, "vfd_accel_time",
                  PointRole.PARAMETER),
            Point(VFD_UNIT, Space.HOLDING, VFD_HR_DECEL, "vfd_decel_time",
                  PointRole.PARAMETER),
            Point(POSITIONER_UNIT, Space.HOLDING, POS_HR_SETPOINT, "valve_setpoint",
                  PointRole.COMMAND, CommandKind.VALVE, scale=100.0, signed=True),
            Point(POSITIONER_UNIT, Space.HOLDING, POS_HR_STROKE_TIME, "valve_stroke_time",
                  PointRole.PARAMETER),
        ),
        level=Point(TRANSMITTER_UNIT, Space.INPUT, XMTR_IR_LEVEL, "level",
                    PointRole.PASSTHROUGH, scale=1000.0),
    )


# ----------------------------------------------------------------------
# Executor 3: RTU with a contactor, 4-20 mA I/O and a local interlock
# ----------------------------------------------------------------------
RTU_UNIT = 1
RTU_COIL_PUMP_RUN = 0
RTU_COIL_INTERLOCK_ENABLE = 10
RTU_HR_VALVE_AO = 0          # raw 6400 (4 mA) .. 32000 (20 mA)
RTU_IR_LEVEL_AI = 0          # raw 6400 (4 mA) .. 32000 (20 mA) over 0..2 m
RTU_AO_ZERO = 6400
RTU_AO_SPAN = 25600
RTU_LEVEL_SPAN_M = 2.0


def rtu_map() -> DeviceMap:
    return DeviceMap(
        name="rtu",
        description="RTU: pump contactor on coil 0, valve 4-20 mA output, "
                    "level 4-20 mA input, local interlock on coil 10",
        points=(
            Point(RTU_UNIT, Space.COIL, RTU_COIL_PUMP_RUN, "pump_run",
                  PointRole.COMMAND, CommandKind.PUMP, scale=0.01),
            Point(RTU_UNIT, Space.COIL, RTU_COIL_INTERLOCK_ENABLE, "interlock_enable",
                  PointRole.PARAMETER),
            Point(RTU_UNIT, Space.HOLDING, RTU_HR_VALVE_AO, "valve_ao",
                  PointRole.COMMAND, CommandKind.VALVE,
                  scale=RTU_AO_SPAN / 100.0, offset=RTU_AO_ZERO),
        ),
        level=Point(RTU_UNIT, Space.INPUT, RTU_IR_LEVEL_AI, "level",
                    PointRole.PASSTHROUGH,
                    scale=RTU_AO_SPAN / RTU_LEVEL_SPAN_M, offset=RTU_AO_ZERO),
        # A contactor puts the pump at full speed the instant it closes.
        model_overrides={"pump_slew_pct_s": 1000.0},
    )


DEVICE_MAPS = {"plc": plc_map, "drives": drives_map, "rtu": rtu_map}
