"""The devices that send commands.

An HMI is not the only thing that writes to a controller, and the others do
not write like an HMI. A SCADA master polls a hundred points and adjusts a
setpoint every few seconds. A peer controller closes a loop at scan rate. An
engineering workstation is quiet for weeks and then rewrites a drive's
configuration during commissioning. A historian never writes at all.

Those traffic shapes are the reason the guard needs to know who is talking.
A single write-rate threshold that suits an operator clicking a button calls a
peer controller a flood; one loose enough for the peer controller misses a
script hammering the valve from the operator station.

Each master here speaks Modbus TCP over a real socket from its own source
address, so the guard identifies it the same way it would in a plant. They
write through the executor's :class:`DeviceMap`, which is what lets one
implementation drive a PLC holding register, a drive's speed reference and an
RTU's contactor coil without knowing the difference.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import struct
from dataclasses import dataclass, field

from ..clock import SimClock
from ..guard.types import CommandKind
from .devicemap import DeviceMap
from .inventory import SourceClass, SourceDevice
from .protocol import (
    Space,
    decode_frame,
    encode_frame,
    is_exception,
    mask_write_register,
    read_request,
    read_write_multiple_registers,
    write_multiple_coils,
    write_single_coil,
    write_single_register,
)

log = logging.getLogger(__name__)


@dataclass
class MasterStats:
    writes_sent: int = 0
    writes_refused: int = 0
    reads_sent: int = 0
    reads_refused: int = 0

    @property
    def refusal_rate(self) -> float:
        return self.writes_refused / self.writes_sent if self.writes_sent else 0.0


class Master:
    """A Modbus client with its own source address and traffic pattern.

    Subclasses implement :meth:`run`, which is cancelled when the episode ends.
    """

    source_class = SourceClass.HMI
    #: Point names this device writes in normal service. Empty means any.
    writes: frozenset[str] = frozenset()
    read_only = False
    description = ""

    def __init__(
        self,
        name: str,
        device_map: DeviceMap,
        host: str,
        port: int,
        source_address: str,
        clock: SimClock,
    ) -> None:
        self.name = name
        self.map = device_map
        self.host = host
        self.port = port
        self.source_address = source_address
        self.clock = clock
        self.stats = MasterStats()
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._txn = 0

    def as_source_device(self) -> SourceDevice:
        """How this master is described in the guard's inventory."""
        return SourceDevice(
            name=self.name,
            source_class=self.source_class,
            description=self.description,
            writes=self.writes,
            read_only=self.read_only,
        )

    # ------------------------------------------------------------------
    # Transport
    # ------------------------------------------------------------------
    async def connect(self) -> None:
        self._reader, self._writer = await asyncio.open_connection(
            self.host, self.port, local_addr=(self.source_address, 0)
        )

    async def close(self) -> None:
        if self._writer is not None:
            with contextlib.suppress(Exception):
                self._writer.close()
                await self._writer.wait_closed()

    def _next_txn(self) -> int:
        self._txn = (self._txn + 1) & 0xFFFF
        return self._txn

    async def _request(self, unit_id: int, pdu: bytes) -> bytes | None:
        """Send one PDU and return the response, or ``None`` on a dead link."""
        if self._writer is None or self._reader is None:
            return None
        try:
            self._writer.write(encode_frame(self._next_txn(), unit_id, pdu))
            await self._writer.drain()
            header = await self._reader.readexactly(7)
            length = struct.unpack(">H", header[4:6])[0]
            body = await self._reader.readexactly(length - 1)
        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
            return None
        frame, _ = decode_frame(header + body)
        return frame.pdu if frame else None

    async def write_command(self, kind: CommandKind, value: float) -> bool:
        """Set an actuator through whichever point this executor uses for it."""
        if not self.map.has_command(kind):
            return False
        unit_id, pdu = self.map.encode_write(kind, value)
        response = await self._request(unit_id, pdu)
        self.stats.writes_sent += 1
        refused = response is None or is_exception(response)
        if refused:
            self.stats.writes_refused += 1
        return not refused

    async def write_raw(self, unit_id: int, pdu: bytes) -> bool:
        response = await self._request(unit_id, pdu)
        self.stats.writes_sent += 1
        refused = response is None or is_exception(response)
        if refused:
            self.stats.writes_refused += 1
        return not refused

    async def read_level(self) -> float | None:
        point = self.map.level
        fc = 0x04 if point.space is Space.INPUT else 0x03
        response = await self._request(point.unit_id, read_request(fc, point.address, 1))
        self.stats.reads_sent += 1
        if response is None or is_exception(response) or len(response) < 4:
            self.stats.reads_refused += 1
            return None
        return point.to_engineering(struct.unpack(">H", response[2:4])[0])

    async def run(self) -> None:
        """Generate this device's traffic until cancelled."""
        raise NotImplementedError


# ----------------------------------------------------------------------
# Benign masters
# ----------------------------------------------------------------------
class OperatorStation(Master):
    """An HMI: a person watching a screen and occasionally acting.

    Writes are rare and come in ones and twos, which is why the default
    write-rate budget is what it is.
    """

    source_class = SourceClass.HMI
    description = "operator station (HMI)"
    writes = frozenset({"pump_cmd", "valve_cmd", "level_setpoint", "mode",
                        "vfd_speed_ref", "valve_setpoint", "pump_run", "valve_ao"})

    def __init__(self, *args, poll_period_s: float = 1.0, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.poll_period_s = poll_period_s

    async def run(self) -> None:
        while True:
            await self.read_level()
            await self.clock.sleep(self.poll_period_s)


class ScadaMaster(Master):
    """A supervisory master closing a slow level loop.

    Polls the level, and nudges the pump toward a setpoint every few seconds.
    Proportional, deliberately gentle, and it backs off near the limits the way
    a tuned loop does.
    """

    source_class = SourceClass.SCADA
    description = "SCADA supervisory master"
    writes = frozenset({"pump_cmd", "valve_cmd", "level_setpoint",
                        "vfd_speed_ref", "valve_setpoint", "pump_run", "valve_ao"})

    def __init__(self, *args, setpoint_m: float = 1.00, period_s: float = 3.0,
                 gain: float = 120.0, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.setpoint_m = setpoint_m
        self.period_s = period_s
        self.gain = gain

    async def run(self) -> None:
        while True:
            level = await self.read_level()
            if level is not None:
                error = self.setpoint_m - level
                if self.map.binary_pump:
                    # A contactor has two settings; the loop becomes a deadband.
                    demand = 100.0 if error > 0.02 else 0.0
                else:
                    demand = max(0.0, min(100.0, 50.0 + self.gain * error))
                await self.write_command(CommandKind.PUMP, demand)
            await self.clock.sleep(self.period_s)


class PeerController(Master):
    """Another controller writing at scan rate.

    This is the traffic shape that breaks a single global write-rate threshold.
    It writes every ``period_s`` for as long as the episode runs, which for an
    HMI-sized budget looks exactly like a flood.
    """

    source_class = SourceClass.PEER_CONTROLLER
    description = "peer controller, cascade loop"
    writes = frozenset({"valve_cmd", "valve_setpoint", "valve_ao"})

    def __init__(self, *args, period_s: float = 0.5, base_pct: float = 45.0,
                 swing_pct: float = 6.0, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.period_s = period_s
        self.base_pct = base_pct
        self.swing_pct = swing_pct

    async def run(self) -> None:
        import math

        while True:
            t = self.clock.now()
            # A smooth trim, not a square wave: the amplitude stays well below
            # R2's reversal threshold, so what is being tested is the rate.
            demand = self.base_pct + self.swing_pct * math.sin(t / 8.0)
            await self.write_command(CommandKind.VALVE, demand)
            await self.clock.sleep(self.period_s)


class Historian(Master):
    """A data historian. Polls constantly, writes never."""

    source_class = SourceClass.HISTORIAN
    description = "process historian"
    read_only = True

    def __init__(self, *args, period_s: float = 0.5, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.period_s = period_s

    async def run(self) -> None:
        while True:
            await self.read_level()
            await self.clock.sleep(self.period_s)


class EngineeringWorkstation(Master):
    """A commissioning laptop. Quiet, and then it rewrites device configuration.

    Its legitimate job is the one thing the wire policy refuses, which is the
    honest cost of that policy and is reported as such.
    """

    source_class = SourceClass.ENGINEERING
    description = "engineering workstation"

    def __init__(self, *args, period_s: float = 5.0, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.period_s = period_s

    async def run(self) -> None:
        while True:
            await self.read_level()
            await self.clock.sleep(self.period_s)


#: Constructors for the benign masters, by name.
MASTERS: dict[str, type[Master]] = {
    "hmi": OperatorStation,
    "scada": ScadaMaster,
    "peer_controller": PeerController,
    "historian": Historian,
    "engineering": EngineeringWorkstation,
}


# ----------------------------------------------------------------------
# Attack behaviours, written as things a master does
# ----------------------------------------------------------------------
@dataclass
class AttackResult:
    """What an attack managed to get through."""

    attempted: int = 0
    accepted: int = 0
    notes: list[str] = field(default_factory=list)

    def record(self, ok: bool, note: str = "") -> None:
        self.attempted += 1
        if ok:
            self.accepted += 1
        if note:
            self.notes.append(note)


async def attack_overflow(master: Master, result: AttackResult, hold_s: float) -> None:
    """Shut the outlet, run the inlet flat out. Both writes are individually legal."""
    result.record(await master.write_command(CommandKind.VALVE, 0.0), "valve 0 %")
    result.record(await master.write_command(CommandKind.PUMP, 100.0), "pump 100 %")
    await master.clock.sleep(hold_s)


async def attack_valve_hammer(master: Master, result: AttackResult, hold_s: float) -> None:
    """Slam the outlet open and shut. Water hammer, not a level excursion."""
    deadline = master.clock.now() + hold_s
    state = True
    while master.clock.now() < deadline:
        ok = await master.write_command(CommandKind.VALVE, 100.0 if state else 0.0)
        result.record(ok)
        state = not state
        await master.clock.sleep(0.2)


async def attack_write_flood(master: Master, result: AttackResult, hold_s: float) -> None:
    """Hammer the command path as fast as the link allows."""
    deadline = master.clock.now() + hold_s
    while master.clock.now() < deadline:
        result.record(await master.write_command(CommandKind.PUMP, 100.0))
        await master.clock.sleep(0.02)


async def attack_parameter_overspeed(master: Master, result: AttackResult, hold_s: float) -> None:
    """Raise the drive's maximum frequency, then ask for full speed.

    The speed reference never leaves its legal range. The *meaning* of that
    range is what changed, so a guard reasoning about the reference alone sees
    nothing wrong while the pump runs above its rated flow.
    """
    from .devicemap import VFD_HR_MAX_FREQ, VFD_UNIT

    ok = await master.write_raw(VFD_UNIT, write_single_register(VFD_HR_MAX_FREQ, 1200))
    result.record(ok, "max frequency 60 Hz -> 120 Hz")
    result.record(await master.write_command(CommandKind.PUMP, 100.0), "speed reference 100 %")
    result.record(await master.write_command(CommandKind.VALVE, 0.0), "valve 0 %")
    await master.clock.sleep(hold_s)


async def attack_ramp_tamper(master: Master, result: AttackResult, hold_s: float) -> None:
    """Shorten the drive's acceleration ramp so the pump steps instead of ramping."""
    from .devicemap import VFD_HR_ACCEL, VFD_HR_DECEL, VFD_UNIT

    ok = await master.write_raw(VFD_UNIT, write_single_register(VFD_HR_ACCEL, 1))
    result.record(ok, "acceleration 5.0 s -> 0.1 s")
    result.record(await master.write_raw(VFD_UNIT, write_single_register(VFD_HR_DECEL, 1)))
    result.record(await master.write_command(CommandKind.VALVE, 0.0))
    result.record(await master.write_command(CommandKind.PUMP, 100.0))
    await master.clock.sleep(hold_s)


async def attack_interlock_disable(master: Master, result: AttackResult, hold_s: float) -> None:
    """Switch off the RTU's own high-level interlock, then fill the tank.

    Worth running because it is the case where the executor was protecting
    itself. Disabling that protection is a single coil write that changes no
    actuator at all.
    """
    from .devicemap import RTU_COIL_INTERLOCK_ENABLE, RTU_UNIT

    ok = await master.write_raw(
        RTU_UNIT, write_single_coil(RTU_COIL_INTERLOCK_ENABLE, False)
    )
    result.record(ok, "local high-level interlock disabled")
    result.record(await master.write_command(CommandKind.VALVE, 0.0))
    result.record(await master.write_command(CommandKind.PUMP, 100.0))
    await master.clock.sleep(hold_s)


async def attack_coil_sweep(master: Master, result: AttackResult, hold_s: float) -> None:
    """Set the pump contactor and clear the interlock in one FC15 frame.

    A guard that parses single-coil writes and not multiple-coil writes never
    sees either point change.
    """
    from .devicemap import RTU_COIL_PUMP_RUN, RTU_UNIT

    bits = [0] * 11
    bits[RTU_COIL_PUMP_RUN] = 1   # pump on
    bits[10] = 0                  # interlock off
    ok = await master.write_raw(RTU_UNIT, write_multiple_coils(0, bits))
    result.record(ok, "FC15 sweep: pump on and interlock off in one frame")
    result.record(await master.write_command(CommandKind.VALVE, 0.0))
    await master.clock.sleep(hold_s)


async def attack_mask_write(master: Master, result: AttackResult, hold_s: float) -> None:
    """Drive the pump with a mask write instead of a register write.

    Same effect on the device, a function code a narrow parser skips.
    """
    point = master.map.command_point(CommandKind.PUMP)
    if point.space is Space.COIL:
        result.record(False, "device has no maskable pump register")
        return
    result.record(await master.write_command(CommandKind.VALVE, 0.0))
    ok = await master.write_raw(
        point.unit_id, mask_write_register(point.address, 0x0000, point.to_raw(100.0))
    )
    result.record(ok, "FC22 mask write sets the pump command")
    await master.clock.sleep(hold_s)


async def attack_readwrite_sneak(master: Master, result: AttackResult, hold_s: float) -> None:
    """Hide the pump command inside a read/write-multiple frame (FC23)."""
    point = master.map.command_point(CommandKind.PUMP)
    if point.space is Space.COIL:
        result.record(False, "device has no register pump command")
        return
    result.record(await master.write_command(CommandKind.VALVE, 0.0))
    ok = await master.write_raw(
        point.unit_id,
        read_write_multiple_registers(point.address, 1, point.address, [point.to_raw(100.0)]),
    )
    result.record(ok, "FC23 carries the pump command in its write half")
    await master.clock.sleep(hold_s)


async def attack_historian_write(master: Master, result: AttackResult, hold_s: float) -> None:
    """A read-only device starts issuing commands."""
    result.record(await master.write_command(CommandKind.VALVE, 0.0), "historian writes valve")
    result.record(await master.write_command(CommandKind.PUMP, 100.0), "historian writes pump")
    await master.clock.sleep(hold_s)
