"""DNP3, GOOSE, PRP and REST.

The framing tests are known-answer where a canonical vector exists, because a
CRC or a tag number that is subtly wrong produces frames that look plausible in
a hex dump and are rejected by every real device.
"""

from __future__ import annotations

import struct

import pytest

from otguard.protocols import dnp3, goose, prp, rest


# ----------------------------------------------------------------------
# DNP3
# ----------------------------------------------------------------------


def test_dnp3_crc_matches_the_canonical_reset_link_frame():
    """Known answer: 05 64 05 C0 01 00 00 04 E9 21.

    The DNP3 CRC uses polynomial 0x3D65, which is not the Modbus polynomial and
    not X.25. Anchoring against a published frame is the only way to know the
    implementation is right rather than merely self-consistent.
    """
    header = bytes.fromhex("0564" "05" "C0" "0100" "0004")
    assert struct.pack("<H", dnp3.crc(header)) == bytes.fromhex("e921")


def test_dnp3_frame_round_trip():
    body = dnp3.CROB(dnp3.ControlCode.CLOSE, index=0).encode()
    frame = dnp3.build_select(source=1, destination=10, group=12, variation=1, index=0, body=body)
    parsed = dnp3.parse_frame(frame)
    assert parsed.source == 1
    assert parsed.destination == 10
    assert parsed.application.known_function is dnp3.FunctionCode.SELECT
    assert parsed.crc_ok


@pytest.mark.parametrize("position", [4, 12, 20])
def test_dnp3_corruption_is_detected(position):
    body = dnp3.CROB(dnp3.ControlCode.CLOSE, index=0).encode()
    frame = bytearray(dnp3.build_select(1, 10, 12, 1, 0, body))
    frame[position] ^= 0xFF
    assert not dnp3.parse_frame(bytes(frame)).crc_ok


def test_dnp3_unknown_function_code_decodes_instead_of_raising():
    """A guard in the traffic path must not crash on a malformed frame.

    Raising here would turn any garbage frame into a denial of service against
    the thing protecting the site.
    """
    pdu = dnp3.ApplicationPdu(function=0xFC, objects=b"\x00")
    decoded = dnp3.ApplicationPdu.decode(pdu.encode())
    assert decoded.known_function is None
    assert "UNKNOWN" in decoded.function_name


def test_sbo_rejects_operate_without_select():
    sbo = dnp3.SelectBeforeOperate()
    body = dnp3.CROB(dnp3.ControlCode.CLOSE, index=0).encode()
    assert sbo.operate(0.0, 12, 0, body) is dnp3.Status.NO_SELECT


def test_sbo_accepts_a_matched_pair():
    sbo = dnp3.SelectBeforeOperate()
    body = dnp3.CROB(dnp3.ControlCode.CLOSE, index=0).encode()
    sbo.select(0.0, 12, 0, body)
    assert sbo.operate(1.0, 12, 0, body) is dnp3.Status.SUCCESS


def test_sbo_times_out():
    sbo = dnp3.SelectBeforeOperate(timeout_s=10.0)
    body = dnp3.CROB(dnp3.ControlCode.CLOSE, index=0).encode()
    sbo.select(0.0, 12, 0, body)
    assert sbo.operate(30.0, 12, 0, body) is dnp3.Status.TIMEOUT


def test_sbo_rejects_a_substituted_payload():
    """The case worth having: arm a close, fire a trip.

    Defeats an attacker who watches a legitimate SELECT go past and substitutes
    their own OPERATE, with no key material involved.
    """
    sbo = dnp3.SelectBeforeOperate()
    sbo.select(0.0, 12, 0, dnp3.CROB(dnp3.ControlCode.CLOSE, index=0).encode())
    substituted = dnp3.CROB(dnp3.ControlCode.TRIP, index=0).encode()
    assert sbo.operate(1.0, 12, 0, substituted) is dnp3.Status.NO_SELECT


def test_sbo_select_is_consumed_by_one_operate():
    sbo = dnp3.SelectBeforeOperate()
    body = dnp3.CROB(dnp3.ControlCode.LATCH_ON, index=3).encode()
    sbo.select(0.0, 12, 3, body)
    assert sbo.operate(1.0, 12, 3, body) is dnp3.Status.SUCCESS
    assert sbo.operate(2.0, 12, 3, body) is dnp3.Status.NO_SELECT


# ----------------------------------------------------------------------
# GOOSE
# ----------------------------------------------------------------------


def _publisher():
    return goose.GoosePublisher(
        "SITE/LLN0$GO$gcbTrip", "TripBlk", "SITE/LLN0$DS$Trip",
        bytes.fromhex("001122334455"),
    )


def test_goose_frame_has_the_right_ethertype_and_length():
    frame = _publisher().publish(1000.0, [False]).encode()
    assert frame[:6] == goose.DEFAULT_GOOSE_MAC
    assert struct.unpack(">H", frame[12:14])[0] == goose.ETHERTYPE_GOOSE
    declared = struct.unpack(">H", frame[16:18])[0]
    # Length covers APPID, Length, Reserved1, Reserved2 and the APDU.
    assert declared == len(frame) - 14


def test_goose_round_trip_is_byte_identical():
    frame = _publisher().publish(1000.0, [True, 4200.0, 7])
    raw = frame.encode()
    assert goose.GooseFrame.decode(raw).encode() == raw


def test_goose_decodes_values():
    frame = _publisher().publish(1000.0, [True, 1.5, 42])
    values = goose.GooseFrame.decode(frame.encode()).pdu.values
    assert values[0] is True
    assert values[1] == pytest.approx(1.5)
    assert values[2] == 42


def test_state_change_increments_stnum_and_resets_sqnum():
    pub = _publisher()
    first = pub.publish(0.0, [False])
    assert (first.pdu.st_num, first.pdu.sq_num) == (1, 0)
    retransmit = pub.publish(1.0)
    assert (retransmit.pdu.st_num, retransmit.pdu.sq_num) == (1, 1)
    changed = pub.publish(2.0, [True])
    assert (changed.pdu.st_num, changed.pdu.sq_num) == (2, 0)


def test_subscriber_accepts_an_honest_stream():
    pub, sub = _publisher(), goose.GooseSubscriber()
    assert sub.receive(pub.publish(0.0, [False]), 0.0) == []
    for i in range(5):
        assert sub.receive(pub.publish(i + 1.0), i + 1.0) == []
    assert sub.receive(pub.publish(9.0, [True]), 9.0) == []


def test_subscriber_catches_a_replayed_frame():
    pub, sub = _publisher(), goose.GooseSubscriber()
    sub.receive(pub.publish(0.0, [False]), 0.0)
    trip = pub.publish(1.0, [True])
    sub.receive(trip, 1.0)
    replay = goose.GooseFrame.decode(trip.encode())
    found = sub.receive(replay, 5.0)
    assert found and found[0].kind in ("replay", "stale")


def test_subscriber_catches_a_takeover_jump():
    pub, sub = _publisher(), goose.GooseSubscriber(st_jump_threshold=50)
    sub.receive(pub.publish(0.0, [False]), 0.0)
    forged = pub.publish(1.0, [True])
    forged.pdu.st_num += 5000
    found = sub.receive(forged, 1.0)
    assert found and found[0].kind == "takeover"


def test_rejected_frame_does_not_advance_the_accepted_counters():
    """A replay must not be able to drag the subscriber's state backwards."""
    pub, sub = _publisher(), goose.GooseSubscriber()
    sub.receive(pub.publish(0.0, [False]), 0.0)
    good = pub.publish(1.0, [True])
    sub.receive(good, 1.0)
    before = sub.streams[good.pdu.gocb_ref].st_num
    stale = goose.GooseFrame.decode(good.encode())
    stale.pdu.st_num = 1
    sub.receive(stale, 2.0)
    assert sub.streams[good.pdu.gocb_ref].st_num == before


def test_subscriber_reports_a_silent_publisher():
    pub, sub = _publisher(), goose.GooseSubscriber()
    sub.receive(pub.publish(0.0, [False]), 0.0)
    found = sub.check_liveness(30.0)
    assert found and found[0].kind == "timeout"


# ----------------------------------------------------------------------
# PRP
# ----------------------------------------------------------------------


def test_prp_trailer_round_trip():
    trailer = prp.RedundancyControlTrailer(sequence=1234, lan=prp.LanId.B, lsdu_size=64)
    assert prp.RedundancyControlTrailer.decode(trailer.encode()) == trailer


def test_prp_lsdu_size_counts_the_trailer():
    payload = b"x" * 40
    _, trailer = prp.strip_rct(prp.append_rct(payload, 1, prp.LanId.A))
    assert trailer.lsdu_size == len(payload) + prp.RCT_SIZE


def test_prp_delivers_once_and_discards_the_duplicate():
    link, node = prp.PrpLink(), prp.PrpNode()
    a, b = link.send(b"payload", 0.0)
    assert node.receive(a, prp.LanId.A, 0.0) == b"payload"
    assert node.receive(b, prp.LanId.B, 0.001) is None
    assert node.anomalies == []


def test_prp_flags_a_frame_that_arrived_on_one_lan_only():
    """What an attacker injecting from a single switch looks like."""
    link, node = prp.PrpLink(), prp.PrpNode(pair_window_s=0.05)
    forged = link.inject(b"FORGED", 0.0, prp.LanId.A)
    node.receive(forged, prp.LanId.A, 0.0)
    node.flush(1.0)
    assert any(a.kind == "single_lan" for a in node.anomalies)


def test_prp_flags_disagreeing_copies():
    """A frame modified in transit on one path."""
    node = prp.PrpNode()
    node.receive(prp.append_rct(b"SETPOINT-5MW", 7, prp.LanId.A), prp.LanId.A, 0.0)
    node.receive(prp.append_rct(b"SETPOINT-25MW", 7, prp.LanId.B), prp.LanId.B, 0.001)
    assert any(a.kind == "content_mismatch" for a in node.anomalies)


def test_prp_rejects_a_non_prp_trailer():
    with pytest.raises(ValueError):
        prp.strip_rct(b"no trailer here at all")


# ----------------------------------------------------------------------
# REST
# ----------------------------------------------------------------------


def test_rest_rejects_an_unknown_token():
    api = rest.SiteControllerApi()
    response = api.handle(
        rest.Request(0.0, rest.Method.PUT, "/api/v1/site/setpoint", {"site_setpoint_mw": 5.0})
    )
    assert response.status == 401


def test_rest_enforces_roles():
    api = rest.SiteControllerApi()
    operator = api.register(rest.issue_token(b"k", "sched", rest.Role.OPERATOR, "supervisory"))
    response = api.handle(
        rest.Request(0.0, rest.Method.PUT, "/api/v1/site/limits",
                    {"poi_limit_mw": 40.0}, token=operator.value)
    )
    assert response.status == 403


def test_rest_expires_tokens():
    api = rest.SiteControllerApi()
    token = api.register(rest.issue_token(b"k", "eng", rest.Role.ENGINEER, "engineering"))
    late = rest.Request(token.lifetime_s + 10.0, rest.Method.PUT, "/api/v1/site/limits",
                        {"poi_limit_mw": 22.0}, token=token.value)
    assert api.handle(late).status == 401


def test_a_valid_engineer_token_raises_the_export_limit():
    """The point of the module: authentication is not plausibility.

    Nothing here is broken. The request is authentic, the role is sufficient,
    and the API applies it — which is why the guard has to see these calls
    rather than trusting the controller to police itself.
    """
    api = rest.SiteControllerApi()
    engineer = api.register(rest.issue_token(b"k", "eng", rest.Role.ENGINEER, "engineering"))
    response = api.handle(
        rest.Request(0.0, rest.Method.PUT, "/api/v1/site/limits",
                    {"poi_limit_mw": 40.0}, token=engineer.value)
    )
    assert response.ok
    assert api.state["poi_limit_mw"] == 40.0
