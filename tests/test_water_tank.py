"""The simulator has to be right before anything measured against it means much."""

from __future__ import annotations

import math

import pytest

from otguard.sim import WaterTank


def test_equilibrium_matches_the_analytic_solution(config):
    """Pump and valve both wide open settle where Q_in == Q_out.

    Solving ``pump_max_flow = valve_coeff * sqrt(h)`` with the default
    parameters gives exactly 1.0 m. Checking against the closed form rather than
    a recorded number means a change to the integrator cannot quietly redefine
    what "correct" is.
    """
    tank = WaterTank(config.plant, config.safety, seed=0)
    tank.state.level_m = 0.5
    tank.set_pump(100)
    tank.set_valve(100)
    for _ in range(6000):
        tank.step()

    expected = (config.plant.pump_max_flow_m3s / config.plant.valve_coeff) ** 2
    assert expected == pytest.approx(1.0)
    assert tank.state.level_m == pytest.approx(expected, abs=1e-3)


def test_fill_rate_is_bounded_by_the_pump(config):
    """With the outlet shut, dh/dt is exactly pump flow over area."""
    tank = WaterTank(config.plant, config.safety, seed=0)
    tank.state.level_m = 0.5
    tank.set_pump(100)
    tank.set_valve(0)
    tank.state.pump_pos_pct = 100.0  # skip the slew, we are testing the balance

    before = tank.state.level_m
    for _ in range(10):
        tank.step()
    rate = (tank.state.level_m - before) / (10 * config.plant.dt_s)
    assert rate == pytest.approx(
        config.plant.pump_max_flow_m3s / config.plant.area_m2, rel=1e-6
    )


def test_actuators_slew_rather_than_jump(config):
    """A command is a request; the actuator still has to travel."""
    tank = WaterTank(config.plant, config.safety, seed=0)
    tank.set_valve(100)
    tank.step()
    # One 0.1 s step at 25 %/s moves the valve 2.5 %, not 100 %.
    assert tank.state.valve_pos_pct == pytest.approx(config.plant.valve_slew_pct_s * config.plant.dt_s)

    for _ in range(200):
        tank.step()
    assert tank.state.valve_pos_pct == pytest.approx(100.0)


def test_commands_are_clamped_to_the_actuator_range(config):
    """The plant clamps, which is exactly why something upstream must not."""
    tank = WaterTank(config.plant, config.safety, seed=0)
    tank.set_valve(250)
    assert tank.state.valve_cmd_pct == 100.0
    tank.set_pump(-20)
    assert tank.state.pump_cmd_pct == 0.0


def test_overflow_and_dryout_flags(config):
    tank = WaterTank(config.plant, config.safety, seed=0)
    tank.state.level_m = 1.79
    tank.set_pump(100)
    tank.state.pump_pos_pct = 100.0
    for _ in range(100):
        tank.step()
    assert tank.state.overflowed
    assert not tank.state.dried_out

    tank = WaterTank(config.plant, config.safety, seed=0)
    tank.state.level_m = 0.25
    tank.set_valve(100)
    tank.state.valve_pos_pct = 100.0
    for _ in range(200):
        tank.step()
    assert tank.state.dried_out


def test_level_never_goes_negative(config):
    tank = WaterTank(config.plant, config.safety, seed=0)
    tank.state.level_m = 0.05
    tank.set_valve(100)
    tank.state.valve_pos_pct = 100.0
    for _ in range(2000):
        tank.step()
    assert tank.state.level_m >= 0.0


def test_measurement_is_noisy_but_unbiased(config):
    tank = WaterTank(config.plant, config.safety, seed=7)
    samples = [tank.measure() for _ in range(4000)]
    mean = sum(samples) / len(samples)
    assert mean == pytest.approx(tank.state.level_m, abs=0.001)
    spread = math.sqrt(sum((s - mean) ** 2 for s in samples) / len(samples))
    assert spread == pytest.approx(config.plant.level_noise_std_m, rel=0.15)


def test_simulation_is_deterministic_for_a_seed(config):
    """Same seed, same measurements — the evaluation depends on replayability.

    The dynamics themselves carry no randomness, so the seed only shows up in
    ``measure``. That is the sequence to compare: identical within a seed, and
    different across seeds, which together show the seed is actually wired to
    the noise and not ignored.
    """
    def run(seed: int) -> list[float]:
        tank = WaterTank(config.plant, config.safety, seed=seed)
        tank.set_pump(70)
        tank.set_valve(40)
        out = []
        for _ in range(200):
            tank.step()
            out.append(tank.measure())
        return out

    assert run(3) == run(3)
    assert run(3) != run(4)
