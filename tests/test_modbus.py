"""Framing correctness and the guard's behaviour over a real socket.

Async cases drive ``asyncio.run`` directly rather than pulling in
``pytest-asyncio``; each test owns one short-lived event loop, which keeps the
dependency list to what the project actually ships with.
"""

from __future__ import annotations

import asyncio
import struct

import pytest

from otguard.config import load_config
from otguard.modbus import GuardedModbusProxy, SimulatedPLC, decode_frame, encode_frame
from otguard.modbus.protocol import (
    FC_READ_INPUT_REGISTERS,
    FC_WRITE_MULTIPLE_REGISTERS,
    FC_WRITE_SINGLE_REGISTER,
    Frame,
    is_exception,
    parse_read,
    parse_write,
)
from otguard.modbus.registers import (
    HR_PUMP_CMD,
    HR_VALVE_CMD,
    IR_LEVEL,
    LEVEL_SCALE,
    PCT_SCALE,
    _signed,
)


# ----------------------------------------------------------------------
# Framing
# ----------------------------------------------------------------------
def test_frame_round_trip():
    pdu = struct.pack(">BHH", FC_WRITE_SINGLE_REGISTER, 1, 500)
    frame, rest = decode_frame(encode_frame(0x1234, 7, pdu))
    assert rest == b""
    assert frame == Frame(0x1234, 7, pdu)
    assert frame.is_write


def test_mbap_length_counts_the_unit_byte():
    """The off-by-one every hand-rolled Modbus implementation makes once."""
    pdu = b"\x03\x00\x00\x00\x02"
    raw = encode_frame(1, 1, pdu)
    length = struct.unpack(">H", raw[4:6])[0]
    assert length == len(pdu) + 1
    assert len(raw) == 7 + len(pdu)


def test_decode_waits_for_a_complete_frame():
    """TCP splits frames; a parser that assumes otherwise fails under load."""
    raw = encode_frame(1, 1, b"\x03\x00\x00\x00\x02")
    for cut in range(1, len(raw)):
        frame, rest = decode_frame(raw[:cut])
        assert frame is None
        assert rest == raw[:cut]
    frame, rest = decode_frame(raw)
    assert frame is not None and rest == b""


def test_decode_handles_coalesced_frames():
    a = encode_frame(1, 1, b"\x03\x00\x00\x00\x01")
    b = encode_frame(2, 1, b"\x03\x00\x01\x00\x01")
    first, rest = decode_frame(a + b)
    assert first.transaction_id == 1
    second, rest = decode_frame(rest)
    assert second.transaction_id == 2 and rest == b""


def test_decode_rejects_a_foreign_protocol_id():
    raw = bytearray(encode_frame(1, 1, b"\x03\x00\x00\x00\x01"))
    raw[2:4] = struct.pack(">H", 9)
    with pytest.raises(ValueError):
        decode_frame(bytes(raw))


@pytest.mark.parametrize(
    "pdu",
    [
        b"",
        b"\x06\x00",                      # truncated single write
        b"\x10\x00\x00\x00\x02\x02\x00",  # byte count disagrees with data
        b"\x10\x00\x00\x00\x00\x00",      # zero registers
        b"\x05\x00\x00\x12\x34",          # invalid coil value
    ],
)
def test_parse_write_rejects_malformed_pdus(pdu):
    assert parse_write(pdu) is None


def test_parse_write_multiple_registers():
    pdu = struct.pack(">BHHB", FC_WRITE_MULTIPLE_REGISTERS, 0, 2, 4) + struct.pack(">HH", 700, 250)
    request = parse_write(pdu)
    assert request.address == 0
    assert request.values == [700, 250]


def test_parse_read():
    assert parse_read(struct.pack(">BHH", FC_READ_INPUT_REGISTERS, 0, 5)).count == 5
    assert parse_read(b"\x99\x00\x00\x00\x01") is None


def test_negative_values_survive_the_wire():
    """``pump = -20 %`` must reach the range rule as -20, not as 65516.

    Reading it unsigned would either reject it for the wrong reason or, on a
    controller that treats the word as signed, let it through.
    """
    assert _signed(0xFF38) == -200
    assert _signed(0x0000) == 0
    assert _signed(0x7FFF) == 32767


# ----------------------------------------------------------------------
# PLC
# ----------------------------------------------------------------------
def test_plc_serves_reads_and_writes():
    async def scenario():
        config = load_config()
        plc = SimulatedPLC(config, port=0)
        response = plc.handle_pdu(struct.pack(">BHH", FC_WRITE_SINGLE_REGISTER, HR_PUMP_CMD, 600))
        assert not is_exception(response)
        assert plc.holding[HR_PUMP_CMD] == 600

        response = plc.handle_pdu(struct.pack(">BHH", FC_READ_INPUT_REGISTERS, IR_LEVEL, 1))
        assert not is_exception(response)

        # Out-of-range address and unknown function must be exceptions.
        assert is_exception(plc.handle_pdu(struct.pack(">BHH", FC_READ_INPUT_REGISTERS, 900, 1)))
        assert is_exception(plc.handle_pdu(b"\x63\x00\x00\x00\x01"))

    asyncio.run(scenario())


def test_plc_obeys_whatever_it_is_told():
    """The premise of the project: the controller has no safety opinion."""
    config = load_config()
    plc = SimulatedPLC(config, port=0)
    plc.handle_pdu(struct.pack(">BHH", FC_WRITE_SINGLE_REGISTER, HR_PUMP_CMD, 1000))
    plc.handle_pdu(struct.pack(">BHH", FC_WRITE_SINGLE_REGISTER, HR_VALVE_CMD, 0))
    plc.tank.state.level_m = 1.75
    for _ in range(600):
        plc.scan_once()
    assert plc.tank.state.overflowed


# ----------------------------------------------------------------------
# Proxy
# ----------------------------------------------------------------------
async def _stack(config, initial_level_m=0.95):
    plc = SimulatedPLC(config, port=0)
    await plc.start()
    plc.tank.state.level_m = initial_level_m
    proxy = GuardedModbusProxy(config, plc_port=plc.port, listen_port=0)
    await proxy.start()
    reader, writer = await asyncio.open_connection("127.0.0.1", proxy.listen_port)
    return plc, proxy, reader, writer


async def _request(reader, writer, pdu, txn=1):
    writer.write(encode_frame(txn, 1, pdu))
    await writer.drain()
    header = await asyncio.wait_for(reader.readexactly(7), timeout=5)
    length = struct.unpack(">H", header[4:6])[0]
    body = await asyncio.wait_for(reader.readexactly(length - 1), timeout=5)
    frame, _ = decode_frame(header + body)
    return frame


async def _teardown(plc, proxy, writer):
    writer.close()
    await proxy.stop()
    await plc.stop()


def test_proxy_forwards_a_legal_write():
    async def scenario():
        config = load_config()
        plc, proxy, reader, writer = await _stack(config)
        try:
            pdu = struct.pack(">BHH", FC_WRITE_SINGLE_REGISTER, HR_PUMP_CMD, int(50 * PCT_SCALE))
            response = await _request(reader, writer, pdu)
            assert not is_exception(response.pdu)
            assert plc.holding[HR_PUMP_CMD] == int(50 * PCT_SCALE)
        finally:
            await _teardown(plc, proxy, writer)

    asyncio.run(scenario())


def test_proxy_refuses_an_out_of_range_write_in_protocol():
    """A blocked write gets a Modbus exception, not a dropped frame.

    Dropping it would leave the HMI waiting for a timeout — an operator staring
    at a frozen screen mid-upset is a hazard the guard should not introduce.
    """
    async def scenario():
        config = load_config()
        plc, proxy, reader, writer = await _stack(config)
        try:
            pdu = struct.pack(">BHH", FC_WRITE_SINGLE_REGISTER, HR_VALVE_CMD, 2500)  # 250 %
            response = await _request(reader, writer, pdu)
            assert is_exception(response.pdu)
            assert response.pdu[1] == 0x03  # ILLEGAL DATA VALUE
            assert plc.holding[HR_VALVE_CMD] != 2500, "the write reached the PLC anyway"
            assert proxy.stats.writes_blocked == 1
        finally:
            await _teardown(plc, proxy, writer)

    asyncio.run(scenario())


def test_proxy_passes_reads_through_untouched():
    async def scenario():
        config = load_config()
        plc, proxy, reader, writer = await _stack(config, initial_level_m=1.20)
        try:
            plc.scan_once()
            pdu = struct.pack(">BHH", FC_READ_INPUT_REGISTERS, IR_LEVEL, 1)
            response = await _request(reader, writer, pdu)
            assert not is_exception(response.pdu)
            level = struct.unpack(">H", response.pdu[2:4])[0] / LEVEL_SCALE
            assert level == pytest.approx(1.20, abs=0.05)
        finally:
            await _teardown(plc, proxy, writer)

    asyncio.run(scenario())


def test_proxy_supervises_without_any_hmi_traffic():
    """The guard polls the plant itself, so an attacker cannot blind it by
    simply not reading."""
    async def scenario():
        config = load_config()
        plc, proxy, reader, writer = await _stack(config, initial_level_m=1.60)
        try:
            # One legal write sets up a runaway, then the HMI goes silent.
            pdu = struct.pack(">BHH", FC_WRITE_SINGLE_REGISTER, HR_PUMP_CMD, int(100 * PCT_SCALE))
            await _request(reader, writer, pdu)
            await asyncio.sleep(4.0)
            assert proxy.stats.polls > 10, "supervisor never polled the PLC"
            assert proxy.stats.trips_issued >= 1, "no protective trip was issued"
            assert not plc.tank.state.overflowed
        finally:
            await _teardown(plc, proxy, writer)

    asyncio.run(scenario())
