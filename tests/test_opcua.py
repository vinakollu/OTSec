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

from otguard.bess.types import SiteCommandKind
from otguard.guard.wire import PointRole
from otguard.opcua.framing import (
    BODY_OFFSET,
    LEGIBLE_PREFIX_LEN,
    SEQUENCE_OFFSET,
    Message,
    SecurityMode,
    Visibility,
    frame,
)
from otguard.opcua.nodes import SITE_POINTS, NodeMap


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
    point = NodeMap().lookup(_FakeNodeId("Site.DispatchSetpoint"))
    assert point is not None
    assert point.kind is SiteCommandKind.SITE_POWER
    assert point.role is PointRole.COMMAND


def test_the_map_does_not_recognise_a_node_it_was_not_given():
    assert NodeMap().lookup(_FakeNodeId("Site.Mystery")) is None
    assert NodeMap().lookup(_FakeNodeId("Site.DispatchSetpoint", namespace=4)) is None
    assert NodeMap().lookup(_FakeNodeId(2600)) is None


def test_the_parameter_node_is_not_a_command():
    """It has no physical meaning a rule can predict, so no rule may judge it."""
    point = NodeMap().lookup(_FakeNodeId("Site.RampLimit"))
    assert point is not None
    assert point.role is PointRole.PARAMETER
    assert point.kind is None


def test_the_contract_limit_is_writable_and_that_is_the_point():
    """The export limit sits in a register an engineer may change.

    That is why an attacker raises it before dispatching against it, and why
    the rules judge a proposed limit against the transformer rather than
    against the limit itself. A guard that read this node as its constraint
    would be checking the attacker's own work.
    """
    limit = NodeMap().lookup(_FakeNodeId("Site.ExportLimit"))
    assert limit is not None and limit.writable
    assert limit.kind is SiteCommandKind.POI_LIMIT
    writable = {p.identifier for p in SITE_POINTS if p.writable}
    assert writable == {"Site.DispatchSetpoint", "Site.ExportLimit",
                        "Site.Breaker", "Site.RampLimit"}


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
            scenario="limit_tamper", mode=SecurityMode.NONE, enforced=enforced,
            detected=True, first_detection_t=31.5, damaged=damaged,
            peak_poi_mw=14.2, min_poi_mw=-0.9, peak_mva=14.4, writes_decoded=12,
            writes_blocked=1 if enforced else 0, wire_blocked=0, alarms=2,
            trips=1, blind_trips=0, polls=40, severed_at=None,
            rules_fired=("B3", "B4"), wire_reasons=("parameter_write",),
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
    """Stopping a runaway export sets up a runaway import, and both count.

    A site has two ways out of its envelope and the transformer does not care
    which direction the power is going. The first version of this supervisor
    kept one rearm timestamp for both, so having tripped on an export it would
    swallow the next trip on a charge of the same size, and a guard that has
    already acted once would sit through the opposite excursion holding a
    satisfied latch.

    The physics guard carries a comment explaining why its own rearm is per
    direction. This pins the same mistake against being made again here.
    """
    import asyncio

    from otguard.opcua.proxy import OpcUaGuardProxy

    proxy = OpcUaGuardProxy(config, SecurityMode.SIGN_AND_ENCRYPT, enforce=True)

    async def feed(t: float, poi_mw: float) -> None:
        proxy._readings.append((t, poi_mw))
        await proxy._blind_supervise(t, poi_mw)

    async def run() -> None:
        for t, poi in ((0.0, 20.0), (1.0, 23.0), (2.0, 26.0)):
            await feed(t, poi)
        assert proxy.stats.blind_trips == 1, "no trip on the rising export"
        # Charging hard the other way, well inside the rearm window.
        for t, poi in ((3.0, -10.0), (4.0, -22.0), (5.0, -27.0)):
            await feed(t, poi)
        assert proxy.stats.blind_trips == 2, (
            "the import trip was swallowed by the export rearm timer"
        )

    asyncio.run(run())
    # Both trips are recorded, and the rearm map holds a separate timestamp
    # for each direction rather than one shared between them.
    assert len([e for e in proxy.events if e.action is not None]) == 2
    assert set(proxy._blind_trip_t) == {"high", "low"}


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

    cell = _run(run_cell("limit_tamper", SecurityMode.NONE, config, certs,
                         enforce=True, duration_s=60.0, speed=40.0))
    assert not cell.error, cell.error
    assert cell.writes_decoded > 0, "nothing was read off the wire"
    assert cell.writes_blocked >= 1, "the out-of-range set-point was not refused"
    assert cell.attack.accepted == 0
    assert "B3" in cell.rules_fired
    # The session has to survive the refusal, or the refusal is a disconnection.
    assert cell.severed_at is None
    assert cell.honest.accepted > 0


def test_an_encrypted_channel_leaves_the_command_guard_nothing(config, certs):
    """The claim the experiment exists to make, measured rather than argued."""
    from otguard.eval.opcua_experiment import run_cell

    cell = _run(run_cell("limit_tamper", SecurityMode.SIGN_AND_ENCRYPT, config, certs,
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

    cell = _run(run_cell("limit_tamper", SecurityMode.NONE, config, certs,
                         enforce=False, duration_s=60.0, speed=40.0))
    assert not cell.error, cell.error
    assert cell.detected, "the rules stopped running when enforcement was turned off"
    assert "B3" in cell.rules_fired
    assert cell.writes_blocked == 0
    assert cell.attack.accepted == 1
