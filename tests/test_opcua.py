"""The OPC UA layer, and the claim the whole experiment rests on.

The claim is narrow and worth testing rather than asserting: under one security
mode a bump-in-the-wire can read a write, decide about it, and refuse it
without the session noticing; under another it can read none of it. Both halves
are tested against a real server over a real socket, because the difference
lives entirely in bytes on a wire and an in-process mock would be testing the
mock.

The framing tests are unit tests and need no server. They are not decoration:
the byte offsets in :mod:`otguard.opcua.framing` were wrong once, and the
symptom was a proxy that decoded node identifiers out of the middle of a
request header and reported them as writes.
"""

from __future__ import annotations

import struct

import pytest

from otguard.guard.types import CommandKind
from otguard.modbus.devicemap import PointRole
from otguard.opcua.framing import (
    BODY_OFFSET,
    LEGIBLE_PREFIX_LEN,
    SEQUENCE_OFFSET,
    Message,
    SecurityMode,
    Visibility,
    frame,
)
from otguard.opcua.nodes import TANK_POINTS, NodeMap


def _msg(kind: bytes = b"MSG", chunk: bytes = b"F", channel: int = 7,
         token: int = 3, sequence: int = 11, request: int = 11,
         body: bytes = b"\x01\x02\x03\x04") -> bytes:
    size = BODY_OFFSET + len(body)
    return (kind + chunk + struct.pack("<I", size)
            + struct.pack("<IIII", channel, token, sequence, request) + body)


# ----------------------------------------------------------------------
# Framing
# ----------------------------------------------------------------------
def test_the_body_starts_after_the_security_and_sequence_headers():
    """24 bytes in, not 16. Getting this wrong decodes header bytes as a request."""
    assert BODY_OFFSET == 24
    assert SEQUENCE_OFFSET == 16
    assert LEGIBLE_PREFIX_LEN == 16


def test_fields_read_back_off_the_wire():
    message = Message(_msg(channel=9, token=4, sequence=22, request=23, body=b"\xaa\xbb"))
    assert message.message_type == "MSG"
    assert message.chunk_type == "F"
    assert message.is_message_chunk and message.is_final
    assert message.channel_id == 9
    assert message.token_id == 4
    assert message.sequence_number == 22
    assert message.request_id == 23
    assert message.body == b"\xaa\xbb"


def test_frame_splits_whole_messages_and_keeps_the_remainder():
    stream = _msg(sequence=1) + _msg(sequence=2)
    messages, rest = frame(stream)
    assert [m.sequence_number for m in messages] == [1, 2]
    assert rest == b""

    partial = stream[:-3]
    messages, rest = frame(partial)
    assert [m.sequence_number for m in messages] == [1]
    assert len(rest) == len(_msg(sequence=2)) - 3


def test_frame_refuses_to_guess_at_a_nonsense_length():
    broken = b"MSG" + b"F" + struct.pack("<I", 2) + b"\x00" * 8
    messages, rest = frame(broken)
    assert messages == []
    assert rest == broken


def test_renumbering_touches_only_the_sequence_number():
    original = Message(_msg(sequence=5, request=5))
    rewritten = Message(original.renumbered(9))
    assert rewritten.sequence_number == 9
    assert rewritten.request_id == original.request_id
    assert rewritten.channel_id == original.channel_id
    assert rewritten.body == original.body
    assert len(rewritten.raw) == len(original.raw)


def test_close_messages_are_counted_too():
    """CLO carries a sequence number the far end checks. Missing it fails late.

    Everything in the episode works, every write is judged correctly, and then
    the device rejects the close with a sequence error that looks like a bug in
    something else entirely.
    """
    assert Message(_msg(kind=b"CLO")).uses_symmetric_header
    assert Message(_msg(kind=b"MSG")).uses_symmetric_header
    assert not Message(_msg(kind=b"HEL")).uses_symmetric_header


def test_what_each_mode_permits():
    assert SecurityMode.NONE.body_is_readable and SecurityMode.NONE.can_rewrite
    # Readable, and not rewritable: the guard can judge every write and alter
    # none of them, because it cannot sign what it would have changed.
    assert SecurityMode.SIGN.body_is_readable
    assert not SecurityMode.SIGN.can_rewrite
    assert not SecurityMode.SIGN_AND_ENCRYPT.body_is_readable
    assert not SecurityMode.SIGN_AND_ENCRYPT.can_rewrite


def test_visibility_counts_the_legible_prefix_of_an_opaque_message():
    message = Message(_msg(body=b"\x00" * 80))
    seen = Visibility()
    seen.record(message, body_readable=False)
    assert seen.messages == 1
    assert seen.total_bytes == message.size
    assert seen.legible_bytes == LEGIBLE_PREFIX_LEN
    assert seen.bodies_opaque == 1
    assert seen.msg_legible_fraction < 0.2


def test_visibility_counts_a_readable_message_whole():
    message = Message(_msg(body=b"\x00" * 80))
    seen = Visibility()
    seen.record(message, body_readable=True, decoded=True, is_write=True)
    assert seen.legible_bytes == message.size
    assert seen.msg_legible_fraction == 1.0
    assert seen.bodies_decoded == 1


# ----------------------------------------------------------------------
# The node map
# ----------------------------------------------------------------------
class _FakeNodeId:
    def __init__(self, identifier, namespace=2):
        self.Identifier = identifier
        self.NamespaceIndex = namespace


def test_the_map_resolves_a_configured_point():
    point = NodeMap().lookup(_FakeNodeId("Tank.PumpCommand"))
    assert point is not None
    assert point.kind is CommandKind.PUMP
    assert point.role is PointRole.COMMAND


def test_the_map_does_not_recognise_a_node_it_was_not_given():
    assert NodeMap().lookup(_FakeNodeId("Tank.Mystery")) is None
    assert NodeMap().lookup(_FakeNodeId("Tank.PumpCommand", namespace=4)) is None
    assert NodeMap().lookup(_FakeNodeId(2600)) is None


def test_the_parameter_node_is_not_a_command():
    """It has no physical meaning a rule can predict, so no rule may judge it."""
    point = NodeMap().lookup(_FakeNodeId("Tank.PumpMaxSpeed"))
    assert point is not None
    assert point.role is PointRole.PARAMETER
    assert point.kind is None


def test_the_actuators_start_shut():
    """Matching what the guard assumes about a plant it was just inserted into."""
    for point in TANK_POINTS:
        if point.kind in (CommandKind.PUMP, CommandKind.VALVE):
            assert point.initial == 0.0, point.identifier


# ----------------------------------------------------------------------
# Over a real socket
# ----------------------------------------------------------------------
pytest.importorskip("asyncua", reason="the OPC UA layer is an optional extra")


@pytest.fixture(scope="module")
def certs(tmp_path_factory):
    """Generated once: three RSA keys cost more than every other test here."""
    import asyncio

    from otguard.opcua.certs import ensure_certs

    return asyncio.run(ensure_certs(tmp_path_factory.mktemp("opcua-certs")))


def _run(coro):
    import asyncio

    return asyncio.run(coro)


def test_a_saved_run_round_trips(tmp_path):
    """Redrawing a table must not need another forty-two handshakes.

    ``as_dict`` and ``from_dict`` sit next to each other and drift apart the
    moment a field is added to one; this notices.
    """
    from otguard.eval.opcua_experiment import CellResult, MasterStats, Pair
    from otguard.eval.opcua_report import load_pairs, write_report

    def cell(enforced: bool, damaged: bool) -> CellResult:
        out = CellResult(
            scenario="setpoint_jump", mode=SecurityMode.NONE, enforced=enforced,
            detected=True, first_detection_t=31.5, damaged=damaged,
            peak_level_m=1.42, min_level_m=0.88, writes_decoded=12,
            writes_blocked=1 if enforced else 0, wire_blocked=0, alarms=2,
            trips=1, blind_trips=0, polls=40, severed_at=None,
            rules_fired=("R1", "R3"), wire_reasons=("parameter_write",),
            visibility={"msg_total_bytes": 900, "msg_legible_bytes": 900},
            latency_us=[12.0, 18.5],
        )
        out.honest = MasterStats(attempted=9, accepted=9)
        out.recovery = MasterStats(attempted=4, accepted=0)
        out.attack = MasterStats(attempted=1, accepted=0 if enforced else 1)
        return out

    original = Pair(guarded=cell(True, False), unguarded=cell(False, True))
    path = write_report([original], tmp_path)
    restored = load_pairs(path)

    assert len(restored) == 1
    assert restored[0].outcome == original.outcome
    for got, want in ((restored[0].guarded, original.guarded),
                      (restored[0].unguarded, original.unguarded)):
        assert got.as_dict() == want.as_dict()


def test_the_blind_supervisor_rearms_per_direction(config):
    """Stopping an overflow sets up a dry-out, and the guard has to see it.

    Shutting the pump leaves the outlet open, which is itself a dry-out
    configuration. The first version of the blind supervisor kept one rearm
    timestamp for both directions, so the dry-out trip was suppressed for ten
    seconds and the tank emptied to 0.00 m in the write-flood episode while the
    guard held a satisfied high-level latch.

    ``PhysicsGuard`` already carries a comment explaining why its own rearm is
    per direction. This is the same mistake made again in a new file.
    """
    import asyncio

    from otguard.opcua.proxy import OpcUaGuardProxy

    proxy = OpcUaGuardProxy(config, SecurityMode.SIGN_AND_ENCRYPT, enforce=True)

    async def feed(t: float, level: float) -> None:
        proxy._readings.append((t, level))
        await proxy._blind_supervise(t, level)

    async def run() -> None:
        for t, level in ((0.0, 1.60), (1.0, 1.70), (2.0, 1.85)):
            await feed(t, level)
        assert proxy.stats.blind_trips == 1, "no trip on the rising level"
        # Falling fast, well inside the ten-second rearm window.
        for t, level in ((3.0, 1.00), (4.0, 0.40), (5.0, 0.15)):
            await feed(t, level)
        assert proxy.stats.blind_trips == 2, (
            "the dry-out trip was swallowed by the high-level rearm timer"
        )

    asyncio.run(run())
    directions = [
        ("pump" if e.action.pump_cmd_pct is not None else "valve")
        for e in proxy.events if e.action is not None
    ]
    assert directions == ["pump", "valve"], directions


def test_the_no_attack_episode_is_not_called_a_miss(config, certs):
    """The false-alarm baseline must not share a word with a failure."""
    from otguard.eval.opcua_experiment import Pair, run_cell

    cell = _run(run_cell("none", SecurityMode.NONE, config, certs, enforce=True,
                         duration_s=40.0, speed=40.0))
    assert not cell.error, cell.error
    assert Pair(guarded=cell, unguarded=cell).outcome == "no attack"


def test_an_unsecured_channel_is_read_judged_and_refused(config, certs):
    """The whole mechanism, end to end, on the mode where all of it works."""
    from otguard.eval.opcua_experiment import run_cell

    cell = _run(run_cell("setpoint_jump", SecurityMode.NONE, config, certs,
                         enforce=True, duration_s=60.0, speed=40.0))
    assert not cell.error, cell.error
    assert cell.writes_decoded > 0, "nothing was read off the wire"
    assert cell.writes_blocked >= 1, "the out-of-range set-point was not refused"
    assert cell.attack.accepted == 0
    assert "R1" in cell.rules_fired
    # The session has to survive the refusal, or the refusal is a disconnection.
    assert cell.severed_at is None
    assert cell.honest.accepted > 0


def test_an_encrypted_channel_leaves_the_command_guard_nothing(config, certs):
    """The claim the experiment exists to make, measured rather than argued."""
    from otguard.eval.opcua_experiment import run_cell

    cell = _run(run_cell("setpoint_jump", SecurityMode.SIGN_AND_ENCRYPT, config, certs,
                         enforce=True, duration_s=60.0, speed=40.0))
    assert not cell.error, cell.error
    assert cell.writes_decoded == 0
    assert cell.writes_blocked == 0
    assert cell.visibility["bodies_opaque"] > 0
    assert cell.visibility["msg_legible_bytes"] < cell.visibility["msg_total_bytes"]
    assert cell.visibility["msg_legible_fraction"] < 0.5
    # The attacker's write lands, because there was nothing to refuse it with.
    assert cell.attack.accepted == 1


def test_ordinary_traffic_is_not_refused_in_any_mode(config, certs):
    """The false-alarm case. Without it the refusals above mean nothing."""
    from otguard.eval.opcua_experiment import run_cell

    for mode in (SecurityMode.NONE, SecurityMode.SIGN_AND_ENCRYPT):
        cell = _run(run_cell("none", mode, config, certs, enforce=True,
                             duration_s=60.0, speed=40.0))
        assert not cell.error, (mode, cell.error)
        assert cell.honest.attempted > 0, mode
        assert cell.honest.refused == 0, (mode, cell.honest)
        assert cell.writes_blocked == 0, mode
        assert cell.wire_blocked == 0, mode
        assert not cell.detected, mode


def test_not_enforcing_still_evaluates_the_rules(config, certs):
    """The ablation lesson, pinned.

    Twice in this project a switch meant to disable one mechanism has disabled
    the thing it was being compared against, and both times the result looked
    like a finding. ``enforce=False`` is the counterfactual column of every
    table here, so it has to change what the guard does and nothing about what
    it evaluates.
    """
    from otguard.eval.opcua_experiment import run_cell

    cell = _run(run_cell("setpoint_jump", SecurityMode.NONE, config, certs,
                         enforce=False, duration_s=60.0, speed=40.0))
    assert not cell.error, cell.error
    assert cell.detected, "the rules stopped running when enforcement was turned off"
    assert "R1" in cell.rules_fired
    assert cell.writes_blocked == 0
    assert cell.attack.accepted == 1
