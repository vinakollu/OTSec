"""The battery physics, and the properties the guard rules depend on."""

from __future__ import annotations

import math

import pytest

from otguard.bess import BessSite
from otguard.bess.megapack import Megapack
from otguard.config import load_config


@pytest.fixture()
def cfg():
    return load_config()


# ----------------------------------------------------------------------
# Energy
# ----------------------------------------------------------------------


def test_soc_falls_when_discharging(cfg):
    pack = Megapack("MP01", cfg.bess.pack, initial_soc=0.5)
    pack.set_power(1.0)
    for _ in range(600):
        pack.step(1.0)
    assert pack.state.soc < 0.5


def test_round_trip_loses_energy(cfg):
    """Charging then discharging the same AC energy must not break even.

    The efficiency asymmetry is what makes the energy balance a usable
    detector; a lossless model would drift against any real plant.
    """
    pack = Megapack("MP01", cfg.bess.pack, initial_soc=0.5)
    pack.set_power(-1.0)
    for _ in range(600):
        pack.step(1.0)
    charged = pack.state.soc
    pack.set_power(1.0)
    for _ in range(600):
        pack.step(1.0)
    assert pack.state.soc < 0.5
    assert charged > 0.5


def test_soc_is_bounded(cfg):
    pack = Megapack("MP01", cfg.bess.pack, initial_soc=0.99)
    pack.set_power(-1.9)
    for _ in range(5000):
        pack.step(1.0)
    assert 0.0 <= pack.state.soc <= 1.0


# ----------------------------------------------------------------------
# Capability
# ----------------------------------------------------------------------


def test_discharge_derates_near_empty(cfg):
    pack = Megapack("MP01", cfg.bess.pack)
    assert pack.max_discharge_mw(0.5, 25.0) == pytest.approx(cfg.bess.pack.power_mw)
    assert pack.max_discharge_mw(0.05, 25.0) < cfg.bess.pack.power_mw
    assert pack.max_discharge_mw(0.0, 25.0) == pytest.approx(0.0)


def test_charge_derates_near_full_and_in_the_cold(cfg):
    """Not a mirror of the discharge curve — cold limits charging specifically."""
    pack = Megapack("MP01", cfg.bess.pack)
    assert pack.max_charge_mw(0.95, 25.0) < cfg.bess.pack.power_mw
    cold = pack.max_charge_mw(0.5, -5.0)
    warm = pack.max_charge_mw(0.5, 25.0)
    assert cold < warm
    assert pack.max_discharge_mw(0.5, -5.0) == pytest.approx(warm)


def test_command_beyond_capability_is_clamped_not_delivered(cfg):
    """An over-power command must not produce over-power.

    If the plant delivered what was asked, a command the guard blocked would
    still have done damage in the unguarded run, and the guard would get credit
    for preventing something that could not happen.
    """
    pack = Megapack("MP01", cfg.bess.pack, initial_soc=0.5)
    pack.set_power(10.0)
    for _ in range(50):
        pack.step(0.5)
    assert pack.state.p_mw <= cfg.bess.pack.power_mw + 1e-6


def test_reactive_power_is_curtailed_before_real_power(cfg):
    """Vars give way to watts, so Q cannot be used to smuggle extra P."""
    pack = Megapack("MP01", cfg.bess.pack, initial_soc=0.5)
    pack.set_power(1.9)
    pack.set_reactive(2.0)
    for _ in range(50):
        pack.step(0.5)
    s = math.hypot(pack.state.p_mw, pack.state.q_mvar)
    assert s <= cfg.bess.pack.apparent_mva + 1e-3
    assert pack.state.p_mw == pytest.approx(1.9, abs=1e-2)


# ----------------------------------------------------------------------
# Thermal
# ----------------------------------------------------------------------


def test_cooling_on_stays_inside_the_envelope(cfg):
    """Normal full-power operation must not damage the unit."""
    pack = Megapack("MP01", cfg.bess.pack, initial_soc=1.0)
    pack.set_power(cfg.bess.pack.power_mw)
    for _ in range(3600):
        pack.step(1.0)
    assert not pack.state.overheated


def test_cooling_off_runs_away(cfg):
    """The thermal attack vector: same duty, thermal management disabled."""
    pack = Megapack("MP01", cfg.bess.pack, initial_soc=1.0)
    pack.set_power(cfg.bess.pack.power_mw)
    pack.set_cooling(False)
    for _ in range(4000):
        pack.step(1.0)
    assert pack.state.overheated


# ----------------------------------------------------------------------
# Site
# ----------------------------------------------------------------------


def test_fleet_can_out_produce_the_interconnection(cfg):
    """The premise of every export-limit attack.

    If the fleet could not exceed the limit, the limit would be enforced by
    physics and there would be nothing to guard.
    """
    site = BessSite(cfg.bess.site, cfg.bess.safety, cfg.bess.pack)
    assert site.fleet_capability_mw > cfg.bess.site.poi_limit_mw
    assert site.fleet_capability_mw > cfg.bess.site.poi_rating_mw


def test_transformer_losses_have_the_same_sign_convention_both_ways(cfg):
    """Losses always reduce delivered power, whichever way it flows."""
    site = BessSite(cfg.bess.site, cfg.bess.safety, cfg.bess.pack)
    for unit in site.packs:
        unit.set_power(1.0)
    for i in range(200):
        site.step(0.5, i * 0.5)
    assert site.state.p_poi_mw < site.state.p_site_mw

    for unit in site.packs:
        unit.set_power(-1.0)
    for i in range(400):
        site.step(0.5, i * 0.5)
    assert site.state.p_poi_mw < site.state.p_site_mw


def test_poi_overload_latches(cfg):
    site = BessSite(cfg.bess.site, cfg.bess.safety, cfg.bess.pack)
    for unit in site.packs:
        unit.set_power(cfg.bess.pack.power_mw)
    for i in range(400):
        site.step(0.5, i * 0.5)
    assert site.state.poi_overloaded
    assert "POI overload" in site.damage_summary()


def test_three_measurements_agree_when_nobody_is_lying(cfg):
    """The precondition for the vote meaning anything.

    Compared at the point of interconnection: the telemetry sum is measured at
    the LV bus and is expected to differ by the house load and transformer
    losses, which is exactly why the voter refers it before comparing.
    """
    site = BessSite(cfg.bess.site, cfg.bess.safety, cfg.bess.pack)
    for unit in site.packs:
        unit.set_power(1.0)
    for i in range(200):
        site.step(0.5, i * 0.5)
    obs = site.observe(100.0)
    assert abs(obs.poi_meter_mw - obs.relay_mw) < 0.3


def test_out_of_sync_close_damages_the_switchgear(cfg):
    site = BessSite(cfg.bess.site, cfg.bess.safety, cfg.bess.pack)
    site.set_breaker(False)
    site.state.frequency_hz = 59.0
    site.state.bus_live = True
    assert not site.sync_ok()
    site.set_breaker(True)
    assert site.state.breaker_damaged


def test_dead_bus_close_is_permitted(cfg):
    """Black start must remain possible; there is nothing to synchronise to."""
    site = BessSite(cfg.bess.site, cfg.bess.safety, cfg.bess.pack)
    site.set_breaker(False)
    site.state.bus_live = False
    assert site.sync_ok()
    site.set_breaker(True)
    assert not site.state.breaker_damaged
