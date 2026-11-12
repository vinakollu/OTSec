"""Device scanner: probes, the up/down state machine, and what it costs the vote.

The last group is the one that matters. The scanner exists because a
measurement that has stopped arriving still has a value, and a majority vote
cannot tell a frozen reading from an agreeing one.

Async cases drive ``asyncio.run`` directly, as the rest of this suite does.
"""

from __future__ import annotations

import asyncio

import pytest

from otguard.bess.site import BessSite
from otguard.bess.types import MeasurementSource
from otguard.config import ScanConfig, load_config
from otguard.guard.site_guard import SiteGuard
from otguard.modbus import SimulatedPLC
from otguard.modbus.registers import IR_LEVEL
from otguard.scan import (
    CallbackProbe,
    Evidence,
    ModbusProbe,
    Reachability,
    ScanTarget,
    Scanner,
    TcpProbe,
    site_targets,
    tank_targets,
)


# ----------------------------------------------------------------------
# Probes
# ----------------------------------------------------------------------
def test_modbus_probe_reads_a_register_off_a_real_plc(config):
    async def scenario():
        plc = SimulatedPLC(config, port=0)
        await plc.start()
        try:
            return await ModbusProbe("127.0.0.1", plc.port, address=IR_LEVEL)()
        finally:
            await plc.stop()

    result = asyncio.run(scenario())
    assert result.reachable
    # Not merely that a socket opened: the controller answered the question.
    assert result.evidence is Evidence.ANSWERED
    assert result.rtt_ms > 0.0


def test_probes_report_a_closed_port_as_down():
    async def scenario():
        # Port 1 on loopback: privileged, and nothing in this environment binds it.
        return (
            await TcpProbe("127.0.0.1", 1, timeout_s=0.5)(),
            await ModbusProbe("127.0.0.1", 1, timeout_s=0.5)(),
        )

    tcp, modbus = asyncio.run(scenario())
    assert not tcp.reachable and tcp.evidence is Evidence.NONE
    assert not modbus.reachable and modbus.evidence is Evidence.NONE


def test_a_socket_that_accepts_and_says_nothing_is_not_up():
    """The failure a connect-only check calls healthy.

    A listener that accepts and never answers is a PLC whose scan loop has
    stopped, and it is the whole reason the Modbus probe asks for a register
    instead of settling for a handshake.
    """
    async def scenario():
        async def accept_and_ignore(reader, writer):
            await asyncio.sleep(5)

        server = await asyncio.start_server(accept_and_ignore, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            return (
                await TcpProbe("127.0.0.1", port, timeout_s=0.5)(),
                await ModbusProbe("127.0.0.1", port, timeout_s=0.5)(),
            )
        finally:
            server.close()

    tcp, modbus = asyncio.run(scenario())
    assert tcp.reachable, "a connect-only probe is satisfied, which is the point"
    assert not modbus.reachable
    # It got as far as a socket and no further, and the result says exactly that.
    assert modbus.evidence is Evidence.SOCKET


def test_callback_probe_is_labelled_as_a_model_read():
    probe = CallbackProbe(lambda: True, label="MP01")
    result = asyncio.run(probe())
    assert result.reachable
    assert result.evidence is Evidence.MODEL
    assert probe.networked is False, "no report may present this as a measurement"


def test_a_probe_that_raises_is_a_failure_not_a_crash():
    def explode() -> bool:
        raise RuntimeError("bad model")

    scanner = Scanner(ScanConfig(fail_threshold=1), targets=[
        ScanTarget(name="broken", probe=CallbackProbe(explode), min_evidence=Evidence.MODEL)
    ])
    changes = asyncio.run(scanner.scan_once())
    assert [c.current for c in changes] == [Reachability.DOWN]
    assert "bad model" in scanner.status("broken").detail


# ----------------------------------------------------------------------
# The state machine
# ----------------------------------------------------------------------
def _toggle_scanner(flag: dict, cfg: ScanConfig) -> Scanner:
    return Scanner(cfg, targets=[
        ScanTarget(
            name="dev",
            probe=CallbackProbe(lambda: flag["up"], label="dev"),
            min_evidence=Evidence.MODEL,
        )
    ])


def test_one_missed_poll_does_not_take_a_device_down():
    """Debouncing, which is what keeps a dropped poll out of the vote."""
    flag = {"up": True}
    scanner = _toggle_scanner(flag, ScanConfig(fail_threshold=3, ok_threshold=1))

    async def scenario():
        await scanner.scan_once()
        assert scanner.status("dev").state is Reachability.UP
        flag["up"] = False
        first = await scanner.scan_once()
        second = await scanner.scan_once()
        third = await scanner.scan_once()
        return first, second, third

    first, second, third = asyncio.run(scenario())
    assert first == [] and second == [], "one failure is not an outage"
    assert [c.current for c in third] == [Reachability.DOWN]


def test_recovery_waits_for_the_ok_threshold():
    flag = {"up": False}
    scanner = _toggle_scanner(flag, ScanConfig(fail_threshold=1, ok_threshold=2))

    async def scenario():
        await scanner.scan_once()
        assert scanner.status("dev").state is Reachability.DOWN
        flag["up"] = True
        return await scanner.scan_once(), await scanner.scan_once()

    first, second = asyncio.run(scenario())
    assert first == [], "slower to forgive than to condemn"
    assert [c.current for c in second] == [Reachability.UP]


def test_an_unprobed_device_counts_as_reachable():
    """Nothing has been asked yet, so nothing may be condemned yet.

    Answering "down" for a device that has not been looked at would drop every
    measurement out of the vote for the first few sweeps of a run, which is a
    blind spot the scanner would have created by itself.
    """
    scanner = Scanner(targets=[
        ScanTarget(name="dev", probe=CallbackProbe(lambda: True), min_evidence=Evidence.MODEL)
    ])
    assert scanner.status("dev").state is Reachability.UNKNOWN
    assert scanner.reachable("dev")
    assert scanner.unreachable_sources() == set()


def test_duplicate_device_names_are_refused():
    scanner = Scanner(targets=[ScanTarget(name="dev", probe=CallbackProbe(lambda: True))])
    with pytest.raises(ValueError, match="already being scanned"):
        scanner.add(ScanTarget(name="dev", probe=CallbackProbe(lambda: True)))


def test_tank_targets_probe_the_controller_over_a_real_socket(config):
    async def scenario():
        plc = SimulatedPLC(config, port=0)
        await plc.start()
        try:
            scanner = Scanner(
                ScanConfig(ok_threshold=1), targets=tank_targets(plc_port=plc.port)
            )
            await scanner.scan_once()
            return scanner.status("plc01")
        finally:
            await plc.stop()

    status = asyncio.run(scenario())
    assert status.state is Reachability.UP
    assert status.target.critical
    assert status.target.networked, "the tank stack is sensed over real sockets"


# ----------------------------------------------------------------------
# What it costs the vote
# ----------------------------------------------------------------------
def _site_and_guard(seed: int = 7):
    cfg = load_config()
    site = BessSite(cfg.bess.site, cfg.bess.safety, cfg.bess.pack, seed=seed)
    guard = SiteGuard(cfg)
    targets, network = site_targets(site)
    return cfg, site, guard, Scanner(cfg.scan, targets=targets), network


def test_site_targets_cover_the_topology_and_name_the_three_measurements():
    _cfg, site, _guard, scanner, _net = _site_and_guard()
    assert len(scanner.snapshot()) == len(site.packs) + 11
    sources = {
        s.target.name: s.target.measurement_source
        for s in scanner.snapshot()
        if s.target.measurement_source is not None
    }
    assert sources == {
        "meter01": MeasurementSource.POI_METER,
        "relay87": MeasurementSource.RELAY,
        "sitectrl": MeasurementSource.TELEMETRY,
    }
    assert all(not s.target.networked for s in scanner.snapshot()), (
        "every site row is a model read and must be labelled as one"
    )


def test_a_lost_link_freezes_a_reading_rather_than_removing_it():
    """The premise the scanner rests on.

    If an offline meter simply stopped reporting, the guard would notice on its
    own and none of this would be needed.
    """
    _cfg, site, _guard, _scanner, _net = _site_and_guard()
    for unit in site.packs:
        unit.set_power(1.2)
    for _ in range(200):
        site.step(0.5, 0.0)

    before = site.observe(1.0).poi_meter_mw
    site.set_link(MeasurementSource.POI_METER, False)
    for _ in range(200):
        site.step(0.5, 0.0)
    for unit in site.packs:
        unit.set_power(0.05)
    for _ in range(400):
        site.step(0.5, 0.0)

    after = site.observe(2.0)
    assert after.poi_meter_mw == pytest.approx(before, abs=0.2), "frozen, not gone"
    assert abs(after.poi_meter_mw - site.state.p_poi_mw) > 5.0, "and now badly wrong"


def test_two_stale_measurements_invert_the_majority_vote():
    """The result this whole feature exists for.

    Freeze two of the three measurements while the site ramps down. The two
    stale readings agree with each other, because they are both stuck at the
    same old number, so the majority is wrong and the vote names the one
    honest instrument as the liar. The guard then believes the site is
    exporting 18 MW while it is nearly idle.

    This is the README's stated failure mode reached by a cheaper route: an
    attacker who can make all three measurements agree defeats B6, and cutting
    two comms links makes two of them agree without touching a meter.
    """
    async def run(connect_scanner: bool):
        _cfg, site, guard, scanner, _net = _site_and_guard()
        for unit in site.packs:
            unit.set_power(1.2)
        t, dt = 0.0, 0.5
        for step in range(1600):
            site.step(dt, t)
            t += dt
            if step == 100:
                site.set_link(MeasurementSource.POI_METER, False)
            if step == 700:
                site.set_link(MeasurementSource.RELAY, False)
            if step == 760:
                for unit in site.packs:
                    unit.set_power(0.05)
            if step % 10 == 0:
                await scanner.scan_once()
                if connect_scanner:
                    guard.set_live_sources(scanner.live_sources())
            guard.observe(site.observe(t))
        return site.state.p_poi_mw, guard

    truth, blind = asyncio.run(run(connect_scanner=False))
    _truth, told = asyncio.run(run(connect_scanner=True))

    # Without the scanner the two frozen readings carry the vote.
    assert abs(blind.site_power_mw - truth) > 15.0
    assert blind.voter.alarm is MeasurementSource.TELEMETRY, (
        "the honest source is the one accused"
    )

    # With it, both stale sources are dropped and the guard runs on the one
    # measurement still arriving.
    assert abs(told.site_power_mw - truth) < 0.5
    assert told.voter.alarm is None
    assert told.voter.counted == {MeasurementSource.TELEMETRY}
    assert not told.can_name_lying_source


def test_losing_quorum_is_reported_once_and_says_what_it_costs():
    async def scenario():
        _cfg, site, guard, scanner, _net = _site_and_guard()
        for unit in site.packs:
            unit.set_power(1.0)
        site.set_link(MeasurementSource.POI_METER, False)
        for _ in range(5):
            await scanner.scan_once()
        guard.set_live_sources(scanner.live_sources())

        quorum: list[str] = []
        t = 0.0
        for _ in range(40):
            site.step(0.5, t)
            t += 0.5
            event = guard.observe(site.observe(t))
            if event is not None:
                quorum += [
                    f.detail for f in event.findings
                    if f.rule_id == "B6" and f.rule_name == "quorum"
                ]
        return quorum

    quorum = asyncio.run(scenario())
    assert len(quorum) == 1, "reported on the change, not on every scan"
    assert "stopped being refreshed" in quorum[0]
    assert "can no longer say which of them is wrong" in quorum[0]


def test_a_stale_source_is_not_accused_of_lying():
    """An absent measurement has not been caught doing anything.

    Integrating a frozen reading's drift from consensus would eventually name
    it a liar for the crime of not being there, and send an engineer to
    recalibrate a meter whose only fault is a dead switch.
    """
    _cfg, site, guard, _scanner, _net = _site_and_guard()
    for unit in site.packs:
        unit.set_power(1.2)
    guard.set_live_sources({MeasurementSource.RELAY, MeasurementSource.TELEMETRY})
    site.set_link(MeasurementSource.POI_METER, False)

    t = 0.0
    for _ in range(600):
        site.step(0.5, t)
        t += 0.5
        guard.observe(site.observe(t))

    assert guard.voter.alarm is None
    assert guard.voter.cusum[MeasurementSource.POI_METER] == 0.0


def test_a_guard_nobody_tells_counts_every_source():
    """The ablation has to be the untouched path, or it measures nothing."""
    _cfg, _site, guard, _scanner, _net = _site_and_guard()
    assert guard.voter.counted == set(MeasurementSource)
    assert guard.can_name_lying_source
