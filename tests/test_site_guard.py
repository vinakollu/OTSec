"""The site rules, the estimators and the vote.

Several of these pin design decisions that a tidier implementation gets wrong.
Where that is the case the docstring says which mistake the test exists to
prevent, because the assertion on its own does not explain why the rule is
phrased so awkwardly.
"""

from __future__ import annotations

import dataclasses

import pytest

from otguard.bess import BessSite
from otguard.bess.types import (
    BreakerState,
    MeasurementSource,
    PackReport,
    SiteCommand,
    SiteCommandKind,
    SiteObservation,
)
from otguard.config import load_config
from otguard.guard.site_guard import SiteGuard
from otguard.site import default_site_topology


@pytest.fixture()
def cfg():
    return load_config()


@pytest.fixture()
def guard(cfg):
    return SiteGuard(cfg)


def settle(guard: SiteGuard, site: BessSite, seconds: float = 20.0, dt: float = 0.5) -> None:
    t = 0.0
    while t < seconds:
        site.step(dt, t)
        t += dt
        guard.observe(site.observe(t))


def cmd(kind, value, device="", **kw):
    kw.setdefault("zone", "control")
    kw.setdefault("protocol", "modbus_tcp")
    return SiteCommand(t=100.0, kind=kind, value=value, device=device, **kw)


# ----------------------------------------------------------------------
# B1 capability
# ----------------------------------------------------------------------


def test_b1_blocks_power_beyond_capability(guard):
    verdict = guard.check(cmd(SiteCommandKind.PACK_POWER, 3.5, "MP01"))
    assert "B1" in verdict.rule_ids
    assert not verdict.allowed


def test_b1_allows_a_deliverable_setpoint(guard):
    assert guard.check(cmd(SiteCommandKind.PACK_POWER, 1.0, "MP01")).allowed


def test_b1_uses_state_not_a_configured_maximum(cfg):
    """Capability is recomputed from SoC, so it cannot be raised by a write."""
    guard = SiteGuard(cfg, initial_soc=0.03)
    verdict = guard.check(cmd(SiteCommandKind.PACK_POWER, 1.5, "MP01"))
    assert "B1" in verdict.rule_ids


def test_b1_enforces_the_apparent_power_circle(guard):
    guard.check(cmd(SiteCommandKind.PACK_POWER, 1.8, "MP02"))
    verdict = guard.check(cmd(SiteCommandKind.PACK_REACTIVE, 1.8, "MP02"))
    assert "B1" in verdict.rule_ids


# ----------------------------------------------------------------------
# B3 balance
# ----------------------------------------------------------------------


def test_b3_catches_an_aggregate_that_no_single_command_reveals(cfg):
    """The distributed attack: each set-point plausible, the sum is not.

    This is the case that justifies reasoning at site level at all.
    """
    guard = SiteGuard(cfg)
    blocked = 0
    for i in range(16):
        verdict = guard.check(cmd(SiteCommandKind.PACK_POWER, 1.45, f"MP{i + 1:02d}"))
        blocked += int(not verdict.allowed)
    assert blocked > 0


def test_b3_refuses_a_limit_above_the_transformer_rating(guard):
    """No authorisation makes 40 MW deliverable through 25 MVA of iron."""
    verdict = guard.check(
        cmd(SiteCommandKind.POI_LIMIT, 40.0, zone="engineering",
            protocol="rest", source="jump01")
    )
    assert "B3" in verdict.rule_ids
    assert not verdict.allowed


def test_b3_permits_a_limit_reduction(guard):
    """A curtailment order is a normal, legitimate instruction."""
    verdict = guard.check(
        cmd(SiteCommandKind.POI_LIMIT, 16.0, zone="engineering",
            protocol="rest", source="jump01")
    )
    assert verdict.allowed


def test_b3_allows_a_command_that_reduces_an_existing_excursion(cfg):
    """The counterfactual test.

    The mistake this prevents: a rule phrased as "does this leave the site over
    the limit?" blocks the operator's own recovery, because while the site is
    over the limit *every* command leaves it over the limit. A guard that
    refuses the way out is worse than no guard at the moment it matters.
    """
    guard = SiteGuard(cfg)
    for i in range(16):
        guard.check(cmd(SiteCommandKind.PACK_POWER, 1.30, f"MP{i + 1:02d}"))
    guard.poi_limit_mw = 12.0  # a curtailment order arrives

    reducing = guard.check(cmd(SiteCommandKind.PACK_POWER, 0.90, "MP01"))
    assert reducing.allowed, "a command that improves an excursion must pass"


def test_b3_still_blocks_a_command_that_worsens_an_excursion(cfg):
    guard = SiteGuard(cfg)
    for i in range(16):
        guard.check(cmd(SiteCommandKind.PACK_POWER, 1.30, f"MP{i + 1:02d}"))
    guard.poi_limit_mw = 12.0
    worse = guard.check(cmd(SiteCommandKind.PACK_POWER, 1.90, "MP01"))
    assert not worse.allowed


# ----------------------------------------------------------------------
# B4 ramp and the frequency exemption
# ----------------------------------------------------------------------


def _ramp_setup(cfg, frequency_hz):
    # Settle past the command timestamp: B4 measures over a window ending at
    # the command's time, so a history that stops 90 s earlier leaves the
    # window empty and the rule silently has nothing to say.
    guard = SiteGuard(cfg)
    site = BessSite(cfg.bess.site, cfg.bess.safety, cfg.bess.pack, seed=2)
    settle(guard, site, 105.0)
    guard.frequency_hz = frequency_hz
    return guard


def test_b4_blocks_a_fast_ramp_at_nominal_frequency(cfg):
    guard = _ramp_setup(cfg, 60.0)
    verdicts = [
        guard.check(cmd(SiteCommandKind.PACK_POWER, 1.8, f"MP{i + 1:02d}"))
        for i in range(16)
    ]
    assert any("B4" in v.rule_ids for v in verdicts)


def test_b4_permits_the_same_ramp_during_a_frequency_excursion(cfg):
    """Physics as context, not as a looser threshold.

    Same commands as the test above. The grid asked for this one, and blocking
    it would break the site's contracted service and its obligation to the grid.
    """
    guard = _ramp_setup(cfg, 59.65)
    verdicts = [
        guard.check(cmd(SiteCommandKind.PACK_POWER, 1.15, f"MP{i + 1:02d}"))
        for i in range(16)
    ]
    assert not any("B4" in v.rule_ids for v in verdicts)


# ----------------------------------------------------------------------
# B5 thermal
# ----------------------------------------------------------------------


def test_b5_blocks_disabling_thermal_management_under_load(cfg):
    """The equilibrium check.

    The mistake this prevents: with cooling off the thermal time constant runs
    to hours, so a horizon-only lookahead sees a couple of degrees and stays
    quiet while the unit is on its way to well past its trip.
    """
    guard = SiteGuard(cfg)
    site = BessSite(cfg.bess.site, cfg.bess.safety, cfg.bess.pack, seed=3)
    settle(guard, site, 10.0)
    guard.check(cmd(SiteCommandKind.PACK_POWER, 1.8, "MP01"))
    verdict = guard.check(cmd(SiteCommandKind.PACK_COOLING, 0.0, "MP01"))
    assert "B5" in verdict.rule_ids
    assert not verdict.allowed


def test_b5_permits_restoring_cooling(cfg):
    guard = SiteGuard(cfg)
    guard.estimators["MP01"].note_cooling(False)
    guard.estimators["MP01"].note_power(1.8)
    assert guard.check(cmd(SiteCommandKind.PACK_COOLING, 1.0, "MP01")).allowed


def test_b5_permits_reducing_power_on_a_hot_unit(cfg):
    """The counterfactual again: a reduction is never worse than holding."""
    guard = SiteGuard(cfg, initial_temp_c=50.0)
    guard.estimators["MP01"].note_power(1.9)
    assert guard.check(cmd(SiteCommandKind.PACK_POWER, 0.3, "MP01")).allowed


# ----------------------------------------------------------------------
# B6 cross-source voting
# ----------------------------------------------------------------------


def _observe_with_bias(guard, site, source, rate, duration=1500.0, dt=0.5):
    t = 0.0
    while t < duration:
        site.step(dt, t)
        t += dt
        honest = site.observe(t)
        bias = rate * t
        guard.observe(
            SiteObservation(
                t=honest.t,
                packs=honest.packs,
                poi_meter_mw=honest.poi_meter_mw - (bias if source == "meter" else 0.0),
                relay_mw=honest.relay_mw - (bias if source == "relay" else 0.0),
                frequency_hz=honest.frequency_hz,
                voltage_pu=honest.voltage_pu,
                breaker=honest.breaker,
                bus_live=honest.bus_live,
                fault_current_a=honest.fault_current_a,
            )
        )


def _loaded(cfg, guard, power=1.0):
    site = BessSite(cfg.bess.site, cfg.bess.safety, cfg.bess.pack, seed=5)
    for unit in site.packs:
        unit.set_power(power)
    for est in guard.estimators.values():
        est.note_power(power)
    return site


def test_vote_is_quiet_when_nobody_is_lying(cfg, guard):
    site = _loaded(cfg, guard)
    _observe_with_bias(guard, site, "none", 0.0, duration=1200.0)
    assert guard.voter.alarm is None


def test_vote_catches_a_biased_meter_and_names_it(cfg, guard):
    site = _loaded(cfg, guard)
    _observe_with_bias(guard, site, "meter", 0.002)
    assert guard.voter.alarm is MeasurementSource.POI_METER


def test_vote_names_the_relay_when_the_relay_is_the_liar(cfg, guard):
    """Attribution, not just detection — the vote identifies which source."""
    site = _loaded(cfg, guard)
    _observe_with_bias(guard, site, "relay", 0.002)
    assert guard.voter.alarm is MeasurementSource.RELAY


def test_a_slow_bias_is_still_caught(cfg, guard):
    """The tank version's unsolved case.

    A residual detector bounds an attacker's rate; a vote bounds their
    displacement, so ramping slowly buys time rather than immunity.
    """
    site = _loaded(cfg, guard)
    _observe_with_bias(guard, site, "meter", 0.0004, duration=2400.0)
    assert guard.voter.alarm is MeasurementSource.POI_METER


def test_disabling_voting_reproduces_the_blind_spot(cfg):
    """The control that makes the comparison mean anything.

    The flag has to stop the voter itself, not merely the rule that reports it.
    """
    ablated = dataclasses.replace(
        cfg,
        bess=dataclasses.replace(
            cfg.bess,
            guard=dataclasses.replace(
                cfg.bess.guard,
                crosssource=dataclasses.replace(cfg.bess.guard.crosssource, enabled=False),
            ),
        ),
    )
    guard = SiteGuard(ablated)
    site = _loaded(ablated, guard)
    _observe_with_bias(guard, site, "meter", 0.002)
    assert guard.voter.alarm is None


def test_trusted_power_excludes_a_source_under_suspicion(cfg, guard):
    site = _loaded(cfg, guard)
    _observe_with_bias(guard, site, "meter", 0.005)
    assert guard.voter.alarm is MeasurementSource.POI_METER
    observation = site.observe(2000.0)
    trusted = guard.voter.trusted_power_mw(observation)
    assert abs(trusted - observation.relay_mw) < 1.0


def test_telemetry_is_referred_to_the_point_of_interconnection(cfg, guard):
    """Otherwise the telemetry sum is an outlier by construction.

    It is measured at the LV bus, the other two at the POI. Comparing the raw
    numbers names the wrong source and makes the vote meaningless.
    """
    site = _loaded(cfg, guard, power=1.4)
    for i in range(400):
        site.step(0.5, i * 0.5)
    observation = site.observe(200.0)
    referred = guard.voter._referred(observation)

    raw_gap = abs(observation.telemetry_mw - observation.poi_meter_mw)
    referred_gap = abs(referred[MeasurementSource.TELEMETRY] - observation.poi_meter_mw)
    # The raw gap is a large fraction of the vote's tolerance, so leaving it
    # uncorrected makes the telemetry sum a permanent outlier.
    assert raw_gap > 0.5 * cfg.bess.guard.crosssource.tolerance_mw
    assert referred_gap < 0.25 * raw_gap


# ----------------------------------------------------------------------
# B2 energy
# ----------------------------------------------------------------------


def _run_soc_offset(cfg, offset, transient, duration=1200.0, dt=0.5):
    guard = SiteGuard(cfg, initial_soc=0.55)
    site = BessSite(cfg.bess.site, cfg.bess.safety, cfg.bess.pack, seed=9, initial_soc=0.55)
    for unit in site.packs:
        unit.set_power(0.5)
    for est in guard.estimators.values():
        est.note_power(0.5)
    t = 0.0
    while t < duration:
        site.step(dt, t)
        t += dt
        obs = site.observe(t)
        active = (600.0 <= t < 600.0 + dt) if transient else (t >= 200.0)
        if active:
            packs = tuple(
                PackReport(p.device, p.p_mw, p.q_mvar, min(1.0, p.soc + offset),
                           p.temp_c, p.online, p.cooling_enabled)
                for p in obs.packs
            )
            obs = SiteObservation(
                t=obs.t, packs=packs, poi_meter_mw=obs.poi_meter_mw,
                relay_mw=obs.relay_mw, frequency_hz=obs.frequency_hz,
                voltage_pu=obs.voltage_pu, breaker=obs.breaker,
                bus_live=obs.bus_live, fault_current_a=obs.fault_current_a,
            )
        guard.observe(obs)
    return guard.estimators["MP01"].estimate


def test_b2_catches_a_sustained_soc_offset(cfg):
    assert _run_soc_offset(cfg, 0.10, transient=False).integrity_alarm


def test_b2_tolerates_a_battery_management_re_anchor(cfg):
    """A one-sample correction of a few percent is normal operation.

    Persistence is what separates this from a spoof, not magnitude.
    """
    assert not _run_soc_offset(cfg, 0.04, transient=True).integrity_alarm


def test_b2_catches_a_small_but_held_offset(cfg):
    """2% held is caught even though 4% for one sample is not."""
    assert _run_soc_offset(cfg, 0.02, transient=False).integrity_alarm


def test_estimator_is_quiet_on_honest_telemetry(cfg):
    guard = SiteGuard(cfg, initial_soc=0.55)
    site = BessSite(cfg.bess.site, cfg.bess.safety, cfg.bess.pack, seed=4, initial_soc=0.55)
    for unit in site.packs:
        unit.set_power(0.9)
    for est in guard.estimators.values():
        est.note_power(0.9)
    settle(guard, site, 900.0)
    assert not any(e.estimate.integrity_alarm for e in guard.estimators.values())


def test_estimator_models_delivered_power_not_the_setpoint(cfg):
    """Otherwise the energy balance diverges on every ramp and derate.

    The plant integrates what the inverter did; an estimator that integrates
    the set-point produces a residual indistinguishable from an attack.
    """
    guard = SiteGuard(cfg, initial_soc=0.55)
    est = guard.estimators["MP01"]
    est.note_power(10.0)  # far beyond capability
    est.update(0.55, 25.0, 0.5)
    assert est._p_actual_mw <= cfg.bess.guard.model.power_mw + 1e-6


# ----------------------------------------------------------------------
# B7 interlocks
# ----------------------------------------------------------------------


def test_b7_blocks_an_out_of_sync_close(guard):
    guard.sync_ok = False
    guard.bus_live = True
    verdict = guard.check(cmd(SiteCommandKind.BREAKER, 1.0, protocol="dnp3"))
    assert "B7" in verdict.rule_ids
    assert not verdict.allowed


def test_b7_permits_a_synchronised_close(guard):
    guard.sync_ok = True
    assert guard.check(cmd(SiteCommandKind.BREAKER, 1.0, protocol="dnp3")).allowed


def test_b7_blocks_a_trip_that_no_fault_current_corroborates(guard):
    """A forged protection signal. The frame can be faked, the current cannot."""
    guard.fault_current_a = 0.0
    verdict = guard.check(cmd(SiteCommandKind.BREAKER, 0.0, protocol="goose"))
    assert "B7" in verdict.rule_ids


def test_b7_permits_a_trip_during_a_real_fault(guard):
    guard.fault_current_a = 4000.0
    assert guard.check(cmd(SiteCommandKind.BREAKER, 0.0, protocol="goose")).allowed


def test_b7_lockout_is_directional(cfg):
    """R5's lesson: a lockout must not forbid the way out.

    A latch against closing must still allow tripping, or the guard strands the
    site in the state that caused the trip.
    """
    guard = SiteGuard(cfg)
    guard.lockout_directions.add("close")
    guard.fault_current_a = 4000.0
    assert not guard.check(cmd(SiteCommandKind.BREAKER, 1.0, protocol="dnp3")).allowed
    assert guard.check(cmd(SiteCommandKind.BREAKER, 0.0, protocol="goose")).allowed


def test_acknowledge_clears_the_latches(cfg, guard):
    site = _loaded(cfg, guard)
    _observe_with_bias(guard, site, "meter", 0.005)
    assert guard.voter.alarm is not None
    guard.acknowledge()
    assert guard.voter.alarm is None


# ----------------------------------------------------------------------
# B8 provenance
# ----------------------------------------------------------------------


def test_b8_blocks_a_write_from_the_enterprise_zone(guard):
    verdict = guard.check(
        cmd(SiteCommandKind.PACK_POWER, 1.0, "MP01", zone="enterprise", source="historian")
    )
    assert "B8" in verdict.rule_ids
    assert not verdict.allowed


def test_b8_permits_the_site_controller_dispatching_within_its_own_zone(guard):
    """No conduit describes control-to-control, and none should be needed.

    Requiring one flags the site's own normal operation, which is the single
    largest source of benign traffic there is.
    """
    assert guard.check(cmd(SiteCommandKind.PACK_POWER, 1.0, "MP01", zone="control")).allowed


def test_b8_requires_the_jump_server_on_the_engineering_path(guard):
    verdict = guard.check(
        cmd(SiteCommandKind.RAMP_LIMIT, 5.0, zone="engineering",
            conduit="engineering_to_control", protocol="rest", source="engws01")
    )
    assert "B8" in verdict.rule_ids


def test_b8_permits_an_engineering_change_through_the_bastion(guard):
    verdict = guard.check(
        cmd(SiteCommandKind.RAMP_LIMIT, 5.0, zone="engineering",
            conduit="engineering_to_control", protocol="rest", source="jump01")
    )
    assert "B8" not in verdict.rule_ids


# ----------------------------------------------------------------------
# Supervision
# ----------------------------------------------------------------------


def test_standing_alarms_surface_without_any_command_traffic(cfg, guard):
    """The tank version's hole: one legal command, then wait.

    B2 and B6 detect continuously, but if they only reached a decision when a
    command arrived, a spoof found at 60 s would go unreported on a site whose
    dispatch writes on change.
    """
    site = _loaded(cfg, guard)
    _observe_with_bias(guard, site, "meter", 0.005)
    assert guard.verdicts == [], "no commands were sent in this test"
    assert any(
        f.rule_id == "B6" for e in guard.supervision_events for f in e.findings
    )


def test_supervision_reports_each_alarm_once(cfg, guard):
    site = _loaded(cfg, guard)
    _observe_with_bias(guard, site, "meter", 0.005, duration=2400.0)
    b6 = [f for e in guard.supervision_events for f in e.findings if f.rule_id == "B6"]
    assert len(b6) == 1


# ----------------------------------------------------------------------
# Topology
# ----------------------------------------------------------------------


def test_topology_permits_the_documented_paths():
    topology = default_site_topology(4)
    assert topology.permitted("supervisory", "control", "dnp3") is not None
    assert topology.permitted("control", "field", "modbus_tcp") is not None
    assert topology.permitted("enterprise", "control", "modbus_tcp") is None


def test_dmz_level_distance_is_not_thirty_one(cfg):
    """The DMZ is stored as 35 to keep the enum integral; rank fixes the maths."""
    topology = default_site_topology(2)
    assert topology.crosses_levels("dmz", "control") == pytest.approx(1.5)
    assert topology.crosses_levels("enterprise", "field") == pytest.approx(3.0)
