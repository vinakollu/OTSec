"""Modbus TCP: framing, a simulated PLC, and the guard-enforcing proxy."""

from .plc_server import SimulatedPLC
from .protocol import Frame, decode_frame, encode_frame, parse_read, parse_write
from .proxy import GuardedModbusProxy, ProxyStats
from .registers import COMMAND_REGISTERS, HR_PUMP_CMD, HR_VALVE_CMD, IR_LEVEL

__all__ = [
    "COMMAND_REGISTERS",
    "Frame",
    "GuardedModbusProxy",
    "HR_PUMP_CMD",
    "HR_VALVE_CMD",
    "IR_LEVEL",
    "ProxyStats",
    "SimulatedPLC",
    "decode_frame",
    "encode_frame",
    "parse_read",
    "parse_write",
]
