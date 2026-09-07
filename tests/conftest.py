"""Shared fixtures."""

from __future__ import annotations

import pytest

from otguard.config import Config, load_config
from otguard.guard import Observation, PhysicsGuard
from otguard.sim import WaterTank


@pytest.fixture
def config() -> Config:
    return load_config()


@pytest.fixture
def tank(config: Config) -> WaterTank:
    return WaterTank(config.plant, config.safety, seed=1)


def build_settled_guard(config: Config, level_m: float, warmup_s: float = 5.0):
    """A guard whose estimator has locked on to a quiet plant at ``level_m``.

    Most rules are meaningless until the state estimate has converged, so tests
    that poke at them need this rather than a fresh guard.

    Returns ``(plant, guard, t)``.
    """
    plant = WaterTank(config.plant, config.safety, seed=1)
    plant.state.level_m = level_m
    guard = PhysicsGuard(config, initial_level_m=level_m)
    t = 0.0
    for _ in range(int(warmup_s / config.plant.dt_s)):
        plant.step()
        t += config.plant.dt_s
        guard.observe(Observation(t, plant.measure()))
    return plant, guard, t


@pytest.fixture
def settled_guard(config: Config):
    """Factory fixture: ``settled_guard(level_m)`` -> ``(plant, guard, t)``."""

    def _make(level_m: float, warmup_s: float = 5.0, cfg: Config | None = None):
        return build_settled_guard(cfg or config, level_m, warmup_s)

    return _make


@pytest.fixture
def config_without_supervision() -> Config:
    """Config with continuous supervision off.

    Needed to unit-test R3's *command-time* behaviour in isolation. With
    supervision running, a tank parked near a limit trips before the command
    under test is ever issued, and the assertion ends up measuring the trip
    rather than the rule.
    """
    return load_config(overrides={"guard": {"supervision": {"enabled": False}}})
