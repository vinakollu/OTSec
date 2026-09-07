"""Modbus register map for the water-tank cell.

Scaling matters here in a way it does not in the simulation. Modbus carries
16-bit unsigned words and nothing else — no floats, no units, no metadata. Every
engineering value has to be encoded, and every OT protocol bug story starts with
two ends disagreeing about how. Levels travel as millimetres and actuator
positions as tenths of a percent, which keeps everything in range with room to
spare for the out-of-range writes the attack scenarios need to send.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..guard.types import CommandKind

# --- Holding registers (read/write): the command path the guard inspects ---
HR_PUMP_CMD = 0      # pump speed, 0.1 % per count (0..1000)
HR_VALVE_CMD = 1     # valve position, 0.1 % per count (0..1000)
HR_LEVEL_SETPOINT = 2  # level setpoint, mm
HR_MODE = 3          # 0 = manual, 1 = auto

# --- Input registers (read-only): the process view the guard observes ---
IR_LEVEL = 0         # measured level, mm
IR_INFLOW = 1        # inflow, 0.0001 m^3/s per count
IR_OUTFLOW = 2       # outflow, 0.0001 m^3/s per count
IR_PUMP_POS = 3      # actual pump position, 0.1 %
IR_VALVE_POS = 4     # actual valve position, 0.1 %

HOLDING_COUNT = 8
INPUT_COUNT = 8

PCT_SCALE = 10.0      # counts per percent
LEVEL_SCALE = 1000.0  # counts per metre (i.e. millimetres)
FLOW_SCALE = 10000.0  # counts per m^3/s


@dataclass(frozen=True)
class RegisterSpec:
    """How one holding register maps onto a guard command."""

    address: int
    kind: CommandKind
    scale: float          # engineering units = raw / scale
    name: str

    def to_engineering(self, raw: int) -> float:
        return _signed(raw) / self.scale

    def to_raw(self, value: float) -> int:
        return _to_word(round(value * self.scale))


COMMAND_REGISTERS: dict[int, RegisterSpec] = {
    HR_PUMP_CMD: RegisterSpec(HR_PUMP_CMD, CommandKind.PUMP, PCT_SCALE, "pump_cmd"),
    HR_VALVE_CMD: RegisterSpec(HR_VALVE_CMD, CommandKind.VALVE, PCT_SCALE, "valve_cmd"),
    HR_LEVEL_SETPOINT: RegisterSpec(
        HR_LEVEL_SETPOINT, CommandKind.SETPOINT, LEVEL_SCALE, "level_setpoint"
    ),
    HR_MODE: RegisterSpec(HR_MODE, CommandKind.MODE, 1.0, "mode"),
}


def _signed(raw: int) -> int:
    """Interpret a 16-bit word as signed.

    Needed so that an attacker writing ``pump = -20 %`` (0xFF38 on the wire)
    reaches R1 as -20 and gets rejected, rather than arriving as 65336 and being
    rejected for the wrong reason — or, on a controller that treats it as
    signed, being obeyed.
    """
    raw &= 0xFFFF
    return raw - 0x10000 if raw >= 0x8000 else raw


def _to_word(value: int) -> int:
    """Clamp an int into one 16-bit word, preserving two's-complement negatives."""
    value = max(-0x8000, min(0xFFFF, int(value)))
    return value & 0xFFFF
