"""Each rule, exercised on the case it exists for and the case it must not fire on.

The negative tests carry as much weight as the positive ones. A rule that
catches its attack but also stops a legitimate emergency drain has not made the
plant safer.
"""

from __future__ import annotations

import pytest

from otguard.guard import Command, CommandKind, Decision, Observation
from otguard.guard.rules import _count_reversals


# ----------------------------------------------------------------------
# R1 — range
# ----------------------------------------------------------------------
@pytest.mark.parametrize(
    "kind, value",
    [
        (CommandKind.VALVE, 250.0),
        (CommandKind.VALVE, -5.0),
        (CommandKind.PUMP, 101.0),
        (CommandKind.PUMP, -20.0),
        (CommandKind.SETPOINT, 1.95),
        (CommandKind.SETPOINT, 0.05),
    ],
)
def test_r1_blocks_out_of_range(kind, value, settled_guard):
    _, guard, t = settled_guard(0.9)
    verdict = guard.check(Command(t, kind, value))
    assert verdict.decision is Decision.BLOCK
    assert "R1" in verdict.rule_ids


@pytest.mark.parametrize(
    "kind, value",
    [
        (CommandKind.VALVE, 0.0),
        (CommandKind.VALVE, 100.0),
        (CommandKind.PUMP, 50.0),
        (CommandKind.SETPOINT, 1.20),
    ],
)
def test_r1_allows_in_range(kind, value, settled_guard):
    _, guard, t = settled_guard(0.9)
    assert not guard.check(Command(t, kind, value)).flagged


# ----------------------------------------------------------------------
# R2 — dynamics
# ----------------------------------------------------------------------
def test_r2_catches_valve_oscillation(settled_guard):
    _, guard, t = settled_guard(1.0)
    decisions = []
    for i in range(8):
        t += 0.2
        decisions.append(guard.check(Command(t, CommandKind.VALVE, 100.0 if i % 2 == 0 else 0.0)))
    assert any(d.decision is Decision.BLOCK and "R2" in d.rule_ids for d in decisions)


def test_r2_ignores_a_single_large_step(settled_guard):
    """An operator slamming a valve open once is not water hammer."""
    _, guard, t = settled_guard(1.0)
    assert not guard.check(Command(t, CommandKind.VALVE, 25.0)).flagged
    assert not guard.check(Command(t + 5.0, CommandKind.VALVE, 100.0)).flagged
    assert not guard.check(Command(t + 10.0, CommandKind.PUMP, 0.0)).flagged


def test_r2_ignores_a_slow_monotonic_ramp(settled_guard):
    """Ramping an actuator in one direction never reverses, so it never trips."""
    _, guard, t = settled_guard(1.0)
    flagged = False
    for step in range(0, 101, 10):
        t += 1.0
        flagged |= guard.check(Command(t, CommandKind.VALVE, float(step))).flagged
    assert not flagged


def test_r2_catches_command_flood(settled_guard):
    _, guard, t = settled_guard(1.0)
    decisions = []
    for _ in range(60):
        t += 0.05  # 20 Hz
        decisions.append(guard.check(Command(t, CommandKind.PUMP, 50.0)))
    assert any("R2" in d.rule_ids for d in decisions)


@pytest.mark.parametrize(
    "values, amplitude, expected",
    [
        ([0, 100, 0, 100], 25, 2),
        ([0, 100, 0, 100, 0], 25, 3),
        ([0, 10, 0, 10], 25, 0),        # below the amplitude floor
        ([0, 25, 50, 75, 100], 20, 0),  # monotonic ramp
        ([50], 25, 0),
        ([], 25, 0),
    ],
)
def test_reversal_counting(values, amplitude, expected):
    assert _count_reversals(values, amplitude) == expected


# ----------------------------------------------------------------------
# R3 — inertia lookahead
# ----------------------------------------------------------------------
def _place_near_the_limit(guard, level_m=1.70, pump_pct=100.0, valve_pct=40.0):
    """Park the guard's estimate at a filling, near-limit operating point.

    Set directly rather than simulated into place so the test states the
    condition it is testing. Driving there through the plant would take seconds
    of simulated fill, during which the level moves and the assertion quietly
    becomes about a different operating point than the one intended.
    """
    state = guard.estimator.state
    state.level_m = level_m
    state.pump_pos_pct = state.pump_cmd_pct = pump_pct
    state.valve_pos_pct = state.valve_cmd_pct = valve_pct


def test_r3_blocks_an_aggravating_command_near_the_limit(
    config_without_supervision, settled_guard
):
    """Shutting the outlet on a filling tank near its limit is refused.

    ``valve = 0`` is a perfectly legal value and R1 has no objection to it. It
    is the combination with where the process already is — 1.70 m and rising —
    that puts the predicted trajectory over the top.
    """
    _, guard, t = settled_guard(1.70, cfg=config_without_supervision)
    _place_near_the_limit(guard)

    verdict = guard.check(Command(t, CommandKind.VALVE, 0.0))
    assert verdict.decision is Decision.BLOCK
    assert "R3" in verdict.rule_ids


def test_r3_never_blocks_a_corrective_command(config_without_supervision, settled_guard):
    """The rule that would make the guard dangerous if it got this wrong.

    From the identical state as the test above — filling, near the limit —
    opening the outlet or stopping the pump is the right move. A prediction rule
    that only asked "does the trajectory violate the envelope?" would reject
    these too, because the excursion is already underway, and the guard would be
    worse than useless in the moment it matters most.
    """
    _, guard, t = settled_guard(1.72, cfg=config_without_supervision)
    _place_near_the_limit(guard, level_m=1.72)

    assert not guard.check(Command(t, CommandKind.VALVE, 100.0)).flagged
    assert not guard.check(Command(t, CommandKind.PUMP, 0.0)).flagged


def test_lockout_still_allows_draining_after_an_overflow_trip(config, settled_guard):
    """A high trip must not also forbid emptying the tank.

    Locking out *every* configuration whose equilibrium sits outside the
    envelope reads as the conservative choice and is in fact the dangerous one:
    pump shut against an open outlet settles at empty, so it would refuse every
    recovery action an operator could take and strand the process at the level
    that caused the trip.
    """
    _, guard, t = settled_guard(1.75)
    guard.trip_latched = True
    guard.trip_directions = {"high"}
    guard.estimator.note_accepted(CommandKind.PUMP, 0.0)

    assert not guard.check(Command(t, CommandKind.VALVE, 100.0)).flagged
    assert not guard.check(Command(t + 1, CommandKind.PUMP, 0.0)).flagged


def test_r3_ignores_setpoint_and_mode(settled_guard):
    _, guard, t = settled_guard(1.75)
    verdict = guard.check(Command(t, CommandKind.SETPOINT, 1.50))
    assert "R3" not in verdict.rule_ids


# ----------------------------------------------------------------------
# R4 — sensor/model consistency
# ----------------------------------------------------------------------
def test_r4_stays_quiet_on_honest_telemetry(config, settled_guard):
    """120 s of ordinary operation must not raise a sensor-integrity alarm."""
    plant, guard, t = settled_guard(1.0)
    plant.set_pump(60)
    plant.set_valve(60)  # this pair balances at 1.0 m, so nothing saturates
    guard.estimator.note_accepted(CommandKind.PUMP, 60)
    guard.estimator.note_accepted(CommandKind.VALVE, 60)
    for _ in range(1200):
        plant.step()
        t += config.plant.dt_s
        guard.observe(Observation(t, plant.measure()))

    assert not guard.estimator.integrity_alarm
    assert guard.estimator.cusum_peak < config.guard.consistency.cusum_threshold


@pytest.mark.parametrize("bias, max_delay_s", [(-0.30, 1.0), (-0.05, 2.0), (0.30, 1.0)])
def test_r4_catches_an_injected_bias(config, bias, max_delay_s, settled_guard):
    plant, guard, t = settled_guard(1.0)
    plant.set_pump(60)
    plant.set_valve(60)
    guard.estimator.note_accepted(CommandKind.PUMP, 60)
    guard.estimator.note_accepted(CommandKind.VALVE, 60)

    start = t
    detected = None
    for _ in range(int(max_delay_s / config.plant.dt_s) + 5):
        plant.step()
        t += config.plant.dt_s
        guard.observe(Observation(t, plant.measure() + bias))
        if detected is None and guard.estimator.integrity_alarm:
            detected = t - start
    assert detected is not None and detected <= max_delay_s


def test_r4_goes_open_loop_once_the_sensor_is_untrusted(config, settled_guard):
    """The estimate must stop taking corrections from a transmitter caught lying.

    This is what keeps the lookahead usable during a spoofing attack: the guard
    dead reckons on physics instead of following the attacker's fiction.
    """
    plant, guard, t = settled_guard(1.0)
    assert guard.estimator.sensor_trusted

    plant.set_pump(100)
    guard.estimator.note_accepted(CommandKind.PUMP, 100)
    frozen = plant.measure()
    for _ in range(300):
        plant.step()
        t += config.plant.dt_s
        guard.observe(Observation(t, frozen))

    assert guard.estimator.integrity_alarm
    assert not guard.estimator.sensor_trusted
    # Dead reckoning should track the truth far better than the frozen reading.
    assert abs(guard.estimated_level_m - plant.state.level_m) < abs(frozen - plant.state.level_m)


def test_acknowledge_clears_the_latches(config, settled_guard):
    plant, guard, t = settled_guard(1.0)
    for _ in range(50):
        plant.step()
        t += config.plant.dt_s
        guard.observe(Observation(t, plant.measure() - 0.5))
    assert guard.estimator.integrity_alarm

    guard.acknowledge()
    assert not guard.estimator.integrity_alarm
    assert guard.estimator.sensor_trusted
    assert not guard.trip_latched


# ----------------------------------------------------------------------
# R5 — post-trip lockout
# ----------------------------------------------------------------------
def test_r5_is_inert_until_a_trip_latches(settled_guard):
    _, guard, t = settled_guard(1.0)
    assert not guard.trip_latched
    # pump 100 / valve 0 settles at infinity, but with no trip latched R5 is silent.
    assert "R5" not in guard.check(Command(t, CommandKind.PUMP, 100.0)).rule_ids


def test_r5_refuses_runaway_configurations_after_a_trip(settled_guard):
    _, guard, t = settled_guard(1.0)
    guard.trip_latched = True
    guard.trip_directions = {"high"}
    guard.estimator.note_accepted(CommandKind.VALVE, 0.0)

    # Filling against a shut outlet settles at infinity -> refused.
    blocked = guard.check(Command(t, CommandKind.PUMP, 100.0))
    assert blocked.decision is Decision.BLOCK
    assert "R5" in blocked.rule_ids


def test_r5_still_admits_a_self_limiting_recovery(settled_guard):
    """Lockout must leave the operator a way to recover the plant."""
    _, guard, t = settled_guard(1.0)
    guard.trip_latched = True
    guard.trip_directions = {"high"}
    guard.estimator.note_accepted(CommandKind.VALVE, 50.0)

    # pump 46 % against valve 50 % settles near 1.0 m, inside the envelope.
    assert "R5" not in guard.check(Command(t, CommandKind.PUMP, 46.0)).rule_ids


def test_equilibrium_level_matches_the_closed_form(config, settled_guard):
    _, guard, _ = settled_guard(1.0)
    model = config.guard.model
    h = guard.estimator.equilibrium_level(pump_cmd_pct=50.0, valve_cmd_pct=50.0)
    expected = (model.pump_max_flow_m3s * 0.5 / (model.valve_coeff * 0.5)) ** 2
    assert h == pytest.approx(expected)

    assert guard.estimator.equilibrium_level(pump_cmd_pct=100.0, valve_cmd_pct=0.0) == float("inf")
    assert guard.estimator.equilibrium_level(pump_cmd_pct=0.0, valve_cmd_pct=50.0) == 0.0
