"""The multi-device layer: maps, executors, wire policy and the device proxy.

Socket cases drive ``asyncio.run`` directly rather than pulling in
``pytest-asyncio``; each owns one short-lived event loop, which keeps the
dependency list to what the project already ships with.
"""

from __future__ import annotations

import asyncio
import struct

import pytest

from otguard.clock import SimClock
from otguard.config import load_config
from otguard.guard.types import CommandKind
from otguard.modbus import (
    EXECUTORS,
    DeviceGuardProxy,
    DriveGateway,
    Inventory,
    RemoteTerminalUnit,
    SimulatedPLC,
    SourceClass,
    SourceDevice,
    WirePolicy,
    decode_frame,
    encode_frame,
)
from otguard.modbus.devicemap import (
    POS_HR_SETPOINT,
    POSITIONER_UNIT,
    RTU_AO_ZERO,
    RTU_COIL_INTERLOCK_ENABLE,
    RTU_COIL_PUMP_RUN,
    RTU_HR_VALVE_AO,
    RTU_UNIT,
    VFD_HR_ACCEL,
    VFD_HR_MAX_FREQ,
    VFD_HR_SPEED_REF,
    VFD_REF_FULL_SCALE,
    VFD_UNIT,
    drives_map,
    plc_map,
    rtu_map,
)
from otguard.modbus.inventory import PERMISSIVE_POLICY, WireDecision
from otguard.modbus.protocol import (
    FC_READ_INPUT_REGISTERS,
    Space,
    is_exception,
    mask_write_register,
    parse_write,
    read_write_multiple_registers,
    write_multiple_coils,
    write_single_coil,
    write_single_register,
)


@pytest.fixture()
def cfg():
    return load_config()


# ----------------------------------------------------------------------
# Protocol: the write function codes a narrow parser skips
# ----------------------------------------------------------------------
def test_write_multiple_coils_round_trip():
    bits = [1, 0, 1, 1, 0, 0, 0, 1, 1]
    request = parse_write(write_multiple_coils(3, bits))
    assert request.space is Space.COIL
    assert request.address == 3
    assert request.values == bits


def test_mask_write_carries_masks_and_no_value():
    """FC22's effect depends on the register's contents, not on the frame."""
    request = parse_write(mask_write_register(7, 0x00F2, 0x0025))
    assert request.is_masked
    assert request.values == []
    assert (request.and_mask, request.or_mask) == (0x00F2, 0x0025)


def test_read_write_multiple_exposes_its_write_half():
    """The write half of FC23 is a write, however the read half is framed."""
    request = parse_write(read_write_multiple_registers(0, 4, 1, [700, 250]))
    assert request.address == 1
    assert request.values == [700, 250]
    assert request.read_address == 0 and request.read_count == 4


@pytest.mark.parametrize("pdu", [
    write_multiple_coils(0, [1] * 9)[:-1],          # truncated body
    bytes([0x0F, 0, 0, 0, 2, 5]) + b"\x00" * 5,     # byte count disagrees
    bytes([0x16, 0, 0, 0, 0]),                      # mask write too short
])
def test_malformed_writes_are_rejected(pdu):
    assert parse_write(pdu) is None


# ----------------------------------------------------------------------
# Device maps
# ----------------------------------------------------------------------
def test_every_map_describes_both_actuators():
    for build in (plc_map, drives_map, rtu_map):
        device_map = build()
        assert device_map.has_command(CommandKind.PUMP)
        assert device_map.has_command(CommandKind.VALVE)


def test_coil_and_register_at_the_same_address_are_different_points():
    """The bug this prevents: reading a contactor coil as a 0.1 % speed word."""
    device_map = rtu_map()
    coil = device_map.lookup(RTU_UNIT, Space.COIL, 0)
    holding = device_map.lookup(RTU_UNIT, Space.HOLDING, 0)
    assert coil is not None and holding is not None
    assert coil.name != holding.name
    assert coil.kind is CommandKind.PUMP and holding.kind is CommandKind.VALVE


def test_rtu_analog_scaling_round_trips_through_live_zero():
    """4 mA is 0 %, not 0 counts. A guard that forgets the offset reads 25 % low."""
    point = rtu_map().lookup(RTU_UNIT, Space.HOLDING, RTU_HR_VALVE_AO)
    assert point.to_raw(0.0) == RTU_AO_ZERO
    assert point.to_engineering(RTU_AO_ZERO) == pytest.approx(0.0)
    assert point.to_engineering(point.to_raw(62.5)) == pytest.approx(62.5, abs=0.05)


def test_drive_speed_reference_is_a_fraction_of_full_scale():
    point = drives_map().lookup(VFD_UNIT, Space.HOLDING, VFD_HR_SPEED_REF)
    assert point.to_raw(100.0) == VFD_REF_FULL_SCALE
    assert point.to_engineering(VFD_REF_FULL_SCALE // 2) == pytest.approx(50.0)


def test_parameters_are_marked_on_the_devices_that_have_them():
    assert {p.name for p in drives_map().parameters()} >= {"vfd_max_frequency", "vfd_accel_time"}
    assert {p.name for p in rtu_map().parameters()} == {"interlock_enable"}
    assert plc_map().parameters() == []


# ----------------------------------------------------------------------
# Executors
# ----------------------------------------------------------------------
def test_drive_parameter_changes_what_a_command_does(cfg):
    """The premise of the parameter attack: the reference did not change.

    Same speed reference, twice the maximum frequency, twice the flow. Nothing
    a rule reasoning about the reference alone can see.
    """
    device = DriveGateway(cfg, port=0, initial_level_m=1.0)
    device.units[VFD_UNIT].holding[VFD_HR_SPEED_REF] = VFD_REF_FULL_SCALE
    for _ in range(200):
        device.scan_once()
    nominal = device.tank.state.inflow_m3s

    device.units[VFD_UNIT].holding[VFD_HR_MAX_FREQ] = 1200  # 120 Hz
    for _ in range(200):
        device.scan_once()
    assert device.tank.state.inflow_m3s > nominal * 1.5


def test_drive_ramp_parameter_changes_how_fast_the_pump_moves(cfg):
    device = DriveGateway(cfg, port=0, initial_level_m=1.0)
    device.units[VFD_UNIT].holding[VFD_HR_ACCEL] = 1  # 0.1 s to full speed
    device.units[VFD_UNIT].holding[VFD_HR_SPEED_REF] = VFD_REF_FULL_SCALE
    device.scan_once()
    assert device.tank.state.pump_pos_pct == pytest.approx(100.0)


def test_rtu_contactor_is_all_or_nothing(cfg):
    device = RemoteTerminalUnit(cfg, port=0, initial_level_m=1.0)
    device.units[RTU_UNIT].coils[RTU_COIL_PUMP_RUN] = 1
    device.scan_once()
    assert device.tank.state.pump_pos_pct == pytest.approx(100.0)


def test_rtu_interlock_stops_a_fill_on_its_own(cfg):
    """The executor protecting itself, which the guard must not take credit for."""
    device = RemoteTerminalUnit(cfg, port=0, initial_level_m=1.60)
    device.units[RTU_UNIT].coils[RTU_COIL_PUMP_RUN] = 1
    for _ in range(600):
        device.scan_once()
    assert device.interlock_trips >= 1
    assert not device.tank.state.overflowed


def test_rtu_interlock_can_be_switched_off(cfg):
    device = RemoteTerminalUnit(cfg, port=0, initial_level_m=1.60)
    device.units[RTU_UNIT].coils[RTU_COIL_INTERLOCK_ENABLE] = 0
    device.units[RTU_UNIT].coils[RTU_COIL_PUMP_RUN] = 1
    for _ in range(600):
        device.scan_once()
    assert device.tank.state.overflowed


def test_gateway_routes_on_unit_id(cfg):
    """Three devices, one endpoint. Addressing the wrong one is an error."""
    device = DriveGateway(cfg, port=0)
    assert is_exception(device.handle(99, struct.pack(">BHH", 0x03, 0, 1)))
    assert not is_exception(device.handle(VFD_UNIT, struct.pack(">BHH", 0x03, 0, 1)))


def test_plc_answers_any_unit_id(cfg):
    """Many controllers ignore the unit byte; the guard must not assume otherwise."""
    device = SimulatedPLC(cfg, port=0)
    assert not is_exception(device.handle(77, struct.pack(">BHH", 0x03, 0, 1)))


def test_devices_reject_function_codes_they_do_not_implement(cfg):
    device = SimulatedPLC(cfg, port=0)
    assert is_exception(device.handle(1, struct.pack(">BHH", 0x01, 0, 1)))  # no coils


# ----------------------------------------------------------------------
# Wire policy
# ----------------------------------------------------------------------
def test_an_unjudgeable_write_is_refused_whatever_the_policy_says():
    """A mask write's value is not in the frame, so it is never vouched for."""
    assert not PERMISSIVE_POLICY.permits(WireDecision.UNJUDGEABLE_WRITE)
    assert not PERMISSIVE_POLICY.permits(WireDecision.UNPARSEABLE)


def test_the_permissive_policy_forwards_everything_else():
    for decision in (WireDecision.UNKNOWN_FUNCTION, WireDecision.UNMAPPED_POINT,
                     WireDecision.PARAMETER_WRITE, WireDecision.UNAUTHORISED_SOURCE,
                     WireDecision.UNAUTHORISED_POINT):
        assert PERMISSIVE_POLICY.permits(decision)


def test_a_read_only_source_may_write_nothing():
    historian = SourceDevice("historian", SourceClass.HISTORIAN, read_only=True)
    assert not historian.may_write("pump_cmd")


def test_a_scoped_source_may_write_only_its_own_points():
    peer = SourceDevice("peer", SourceClass.PEER_CONTROLLER, writes=frozenset({"valve_cmd"}))
    assert peer.may_write("valve_cmd")
    assert not peer.may_write("pump_cmd")


def test_inventory_identifies_by_address_not_by_port():
    """Source ports are assigned by the client's kernel and identify nothing."""
    inventory = Inventory()
    inventory.add(SourceDevice("hmi", SourceClass.HMI))
    inventory.bind("10.0.0.5", "hmi")
    assert inventory.identify(("10.0.0.5", 51234)).name == "hmi"
    assert inventory.identify(("10.0.0.5", 7)).name == "hmi"
    assert inventory.identify(("10.0.0.6", 51234)).name == "unknown"


# ----------------------------------------------------------------------
# The proxy, over real sockets
# ----------------------------------------------------------------------
async def _stack(cfg, executor, level=1.00, policy=None, source="hmi", scope=None):
    clock = SimClock(speed=50.0)
    device_cls, map_fn = EXECUTORS[executor]
    device_map = map_fn()
    device = device_cls(cfg, port=0, clock=clock, initial_level_m=level)
    await device.start()

    inventory = Inventory()
    inventory.add(SourceDevice(source, SourceClass.HMI, writes=scope or frozenset()))
    inventory.bind("127.0.0.1", source)

    proxy = DeviceGuardProxy(
        cfg, device_map, target_port=device.port, listen_port=0,
        inventory=inventory, policy=policy or WirePolicy(), clock=clock,
        initial_level_m=level,
    )
    await proxy.start()
    reader, writer = await asyncio.open_connection("127.0.0.1", proxy.listen_port)
    return device, proxy, reader, writer


async def _request(reader, writer, unit, pdu, txn=1):
    writer.write(encode_frame(txn, unit, pdu))
    await writer.drain()
    header = await asyncio.wait_for(reader.readexactly(7), timeout=5)
    length = struct.unpack(">H", header[4:6])[0]
    body = await asyncio.wait_for(reader.readexactly(length - 1), timeout=5)
    frame, _ = decode_frame(header + body)
    return frame


async def _teardown(device, proxy, writer):
    writer.close()
    await proxy.stop()
    await device.stop()


@pytest.mark.parametrize("executor", ["plc", "drives", "rtu"])
def test_the_guard_tracks_the_level_through_every_executors_scaling(cfg, executor):
    """One estimator, three encodings: millimetres, a drive's units, 4-20 mA."""
    async def scenario():
        device, proxy, reader, writer = await _stack(cfg, executor, level=1.20)
        try:
            await asyncio.sleep(0.4)
            assert proxy.stats.polls > 5
            assert proxy.guard.estimated_level_m == pytest.approx(
                device.tank.state.level_m, abs=0.05
            )
        finally:
            await _teardown(device, proxy, writer)

    asyncio.run(scenario())


@pytest.mark.parametrize("executor", ["plc", "drives", "rtu"])
def test_a_legal_command_reaches_every_executor(cfg, executor):
    async def scenario():
        device, proxy, reader, writer = await _stack(cfg, executor, level=0.60)
        try:
            unit, pdu = proxy.map.encode_write(CommandKind.VALVE, 40.0)
            response = await _request(reader, writer, unit, pdu)
            assert not is_exception(response.pdu)
            await asyncio.sleep(0.3)
            assert device.tank.state.valve_cmd_pct == pytest.approx(40.0, abs=1.0)
        finally:
            await _teardown(device, proxy, writer)

    asyncio.run(scenario())


def test_a_parameter_write_is_refused(cfg):
    """Changing a drive's maximum frequency invalidates the guard's model of it."""
    async def scenario():
        device, proxy, reader, writer = await _stack(cfg, "drives")
        try:
            response = await _request(
                reader, writer, VFD_UNIT, write_single_register(VFD_HR_MAX_FREQ, 1200)
            )
            assert is_exception(response.pdu)
            assert device.units[VFD_UNIT].holding[VFD_HR_MAX_FREQ] == 600
        finally:
            await _teardown(device, proxy, writer)

    asyncio.run(scenario())


def test_disabling_the_rtu_interlock_is_refused(cfg):
    async def scenario():
        device, proxy, reader, writer = await _stack(cfg, "rtu")
        try:
            response = await _request(
                reader, writer, RTU_UNIT, write_single_coil(RTU_COIL_INTERLOCK_ENABLE, False)
            )
            assert is_exception(response.pdu)
            assert device.units[RTU_UNIT].coils[RTU_COIL_INTERLOCK_ENABLE] == 1
        finally:
            await _teardown(device, proxy, writer)

    asyncio.run(scenario())


def test_a_write_to_an_unmapped_address_is_refused(cfg):
    async def scenario():
        device, proxy, reader, writer = await _stack(cfg, "plc")
        try:
            response = await _request(reader, writer, 1, write_single_register(6, 1))
            assert is_exception(response.pdu)
        finally:
            await _teardown(device, proxy, writer)

    asyncio.run(scenario())


def test_a_mask_write_never_reaches_the_device(cfg):
    """Its effect is not in the frame, so the guard cannot vouch for it."""
    async def scenario():
        device, proxy, reader, writer = await _stack(cfg, "plc", policy=PERMISSIVE_POLICY)
        try:
            response = await _request(reader, writer, 1, mask_write_register(0, 0, 1000))
            assert is_exception(response.pdu)
            assert device.holding[0] == 0
        finally:
            await _teardown(device, proxy, writer)

    asyncio.run(scenario())


def test_the_write_half_of_an_fc23_frame_is_judged(cfg):
    """A pump command hidden in a read/write frame is still a pump command.

    The assertion is that a rule verdict exists for it: a parser that handles
    only FC6 and FC16 produces none, and the command reaches the device
    unexamined. Whether that particular command is then refused is R3's
    business and depends on where the tank is.
    """
    async def scenario():
        device, proxy, reader, writer = await _stack(cfg, "plc", level=1.60)
        try:
            await asyncio.sleep(0.3)
            proxy.guard.acknowledge()
            pdu = read_write_multiple_registers(0, 1, 0, [1000])  # pump 100 %
            await _request(reader, writer, 1, pdu)
            assert proxy.frames, "the FC23 frame was never inspected"
            verdicts = proxy.frames[-1].verdicts
            assert verdicts, "the write half of FC23 produced no rule verdict"
            assert verdicts[0].command.kind is CommandKind.PUMP
            assert verdicts[0].command.value == pytest.approx(100.0)
        finally:
            await _teardown(device, proxy, writer)

    asyncio.run(scenario())


def test_an_fc23_pump_command_is_refused_when_the_rules_object(cfg):
    """And once the tank is high enough for R3 to object, it is refused."""
    async def scenario():
        device, proxy, reader, writer = await _stack(cfg, "plc", level=1.79)
        try:
            await asyncio.sleep(0.3)
            proxy.guard.acknowledge()
            pdu = read_write_multiple_registers(0, 1, 0, [1000])
            response = await _request(reader, writer, 1, pdu)
            assert is_exception(response.pdu)
            assert device.holding[0] != 1000, "the write reached the PLC anyway"
        finally:
            await _teardown(device, proxy, writer)

    asyncio.run(scenario())


def test_a_multi_coil_write_is_parsed_and_scoped(cfg):
    """FC15 can carry an interlock change beside a pump start."""
    async def scenario():
        device, proxy, reader, writer = await _stack(cfg, "rtu")
        try:
            bits = [0] * 11
            bits[RTU_COIL_PUMP_RUN] = 1
            response = await _request(reader, writer, RTU_UNIT, write_multiple_coils(0, bits))
            assert is_exception(response.pdu), "the interlock coil in the sweep was ignored"
            assert device.units[RTU_UNIT].coils[RTU_COIL_INTERLOCK_ENABLE] == 1
        finally:
            await _teardown(device, proxy, writer)

    asyncio.run(scenario())


def test_an_unknown_source_is_refused(cfg):
    async def scenario():
        clock = SimClock(speed=50.0)
        device = SimulatedPLC(cfg, port=0, clock=clock, initial_level_m=1.0)
        await device.start()
        proxy = DeviceGuardProxy(
            cfg, plc_map(), target_port=device.port, listen_port=0,
            inventory=Inventory(), clock=clock, initial_level_m=1.0,
        )
        await proxy.start()
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy.listen_port)
        try:
            response = await _request(reader, writer, 1, write_single_register(1, 400))
            assert is_exception(response.pdu)
        finally:
            await _teardown(device, proxy, writer)

    asyncio.run(scenario())


def test_a_source_may_not_write_outside_its_scope(cfg):
    async def scenario():
        device, proxy, reader, writer = await _stack(
            cfg, "plc", scope=frozenset({"valve_cmd"})
        )
        try:
            unit, pdu = proxy.map.encode_write(CommandKind.VALVE, 30.0)
            assert not is_exception((await _request(reader, writer, unit, pdu)).pdu)
            unit, pdu = proxy.map.encode_write(CommandKind.PUMP, 30.0)
            assert is_exception((await _request(reader, writer, unit, pdu)).pdu)
        finally:
            await _teardown(device, proxy, writer)

    asyncio.run(scenario())


def test_a_permitted_defect_still_reaches_the_physics_rules(cfg):
    """The ablation has to disable the policy, not the whole guard.

    A write the policy would refuse for access reasons is still a real actuator
    command. With the policy permissive it must be forwarded to the rules and
    judged on its physics, or "policy off" silently measures a guard with no
    rules at all and credits the policy with everything they would have caught.
    """
    async def scenario():
        device, proxy, reader, writer = await _stack(
            cfg, "plc", level=1.79, policy=PERMISSIVE_POLICY,
            scope=frozenset({"valve_cmd"}),          # pump is out of scope
        )
        try:
            await asyncio.sleep(0.3)
            proxy.guard.acknowledge()
            unit, pdu = proxy.map.encode_write(CommandKind.PUMP, 100.0)
            response = await _request(reader, writer, unit, pdu)
            assert proxy.frames[-1].verdicts, "an out-of-scope write skipped the rules"
            assert is_exception(response.pdu), "R3 did not judge the command"
            assert not proxy.stats.wire_reasons, "the policy was supposed to permit it"
        finally:
            await _teardown(device, proxy, writer)

    asyncio.run(scenario())


def test_a_permitted_parameter_write_does_not_hide_a_command_beside_it(cfg):
    """An FC15 sweep carries a pump start and an interlock bit in one frame."""
    async def scenario():
        device, proxy, reader, writer = await _stack(
            cfg, "rtu", level=1.79, policy=PERMISSIVE_POLICY
        )
        try:
            await asyncio.sleep(0.3)
            proxy.guard.acknowledge()
            bits = [0] * 11
            bits[RTU_COIL_PUMP_RUN] = 1
            await _request(reader, writer, RTU_UNIT, write_multiple_coils(0, bits))
            kinds = [v.command.kind for f in proxy.frames for v in f.verdicts]
            assert CommandKind.PUMP in kinds, "the pump coil in the sweep was not judged"
        finally:
            await _teardown(device, proxy, writer)

    asyncio.run(scenario())


def test_an_unimplemented_function_code_is_refused(cfg):
    """Diagnostics and vendor codes are a channel straight to the firmware."""
    async def scenario():
        device, proxy, reader, writer = await _stack(cfg, "plc")
        try:
            response = await _request(reader, writer, 1, struct.pack(">BHH", 0x08, 0, 0))
            assert is_exception(response.pdu)
        finally:
            await _teardown(device, proxy, writer)

    asyncio.run(scenario())


def test_reads_are_forwarded_untouched(cfg):
    async def scenario():
        device, proxy, reader, writer = await _stack(cfg, "plc", level=1.20)
        try:
            device.scan_once()
            pdu = struct.pack(">BHH", FC_READ_INPUT_REGISTERS, 0, 1)
            response = await _request(reader, writer, 1, pdu)
            assert not is_exception(response.pdu)
            assert struct.unpack(">H", response.pdu[2:4])[0] / 1000.0 == pytest.approx(1.20, abs=0.05)
        finally:
            await _teardown(device, proxy, writer)

    asyncio.run(scenario())


@pytest.mark.parametrize("executor", ["plc", "drives"])
def test_supervision_trips_through_each_executors_actuator(cfg, executor):
    """The trip has to be written through whichever point drives the pump."""
    async def scenario():
        device, proxy, reader, writer = await _stack(cfg, executor, level=1.62)
        try:
            await asyncio.sleep(0.2)
            proxy.guard.acknowledge()
            unit, pdu = proxy.map.encode_write(CommandKind.PUMP, 100.0)
            await _request(reader, writer, unit, pdu)
            await asyncio.sleep(1.2)
            assert proxy.stats.trips_issued >= 1
            assert not device.tank.state.overflowed
        finally:
            await _teardown(device, proxy, writer)

    asyncio.run(scenario())
