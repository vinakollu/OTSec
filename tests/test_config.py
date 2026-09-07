"""Configuration loading.

The strictness test matters more than it looks. A silently ignored typo in the
YAML — ``max_reversal`` for ``max_reversals`` — leaves a rule running on its
default while the report claims it was tuned, and the resulting numbers are
wrong in the flattering direction.
"""

from __future__ import annotations

import pytest

from otguard.config import DEFAULT_CONFIG_PATH, Config, load_config


def test_default_config_file_loads():
    assert DEFAULT_CONFIG_PATH.exists()
    config = load_config()
    assert isinstance(config, Config)


def test_the_shipped_defaults_are_internally_consistent():
    config = load_config()
    safety, guard, plant = config.safety, config.guard, config.plant

    assert safety.level_min_m < safety.level_max_m < plant.height_m

    # An operator setpoint must not be able to provoke a supervision trip on its
    # own: the ceiling has to sit at least one reaction horizon of fill below
    # the overflow limit.
    max_fill_rate = plant.pump_max_flow_m3s / plant.area_m2
    headroom = safety.level_max_m - guard.range.setpoint_m[1]
    assert headroom > max_fill_rate * guard.supervision.horizon_s * 0.5, (
        "the highest legal setpoint is too close to the overflow limit"
    )

    # R4 is a detector, not a tracker: it only works if the filter trusts the
    # model more than the transmitter.
    assert guard.consistency.process_noise_std_m < guard.consistency.sensor_noise_std_m

    # Supervision needs a longer view than the per-command check, since a
    # standing order has to be caught while it is still correctable.
    assert guard.supervision.horizon_s >= guard.prediction.horizon_s


def test_guard_model_deliberately_differs_from_the_plant():
    """A guard that only works with a perfect model proves nothing."""
    config = load_config()
    assert config.guard.model.pump_max_flow_m3s != config.plant.pump_max_flow_m3s
    assert config.guard.model.valve_coeff != config.plant.valve_coeff


def test_overrides_merge_without_clobbering_siblings():
    config = load_config(overrides={"guard": {"supervision": {"enabled": False}}})
    assert config.guard.supervision.enabled is False
    # Sibling keys in the same block survive.
    assert config.guard.supervision.horizon_s == load_config().guard.supervision.horizon_s
    assert config.guard.range.pump_pct == load_config().guard.range.pump_pct


def test_unknown_keys_are_rejected():
    with pytest.raises(ValueError, match="max_reversal"):
        load_config(overrides={"guard": {"dynamics": {"max_reversal": 3}}})

    with pytest.raises(ValueError, match="tank_area"):
        load_config(overrides={"plant": {"tank_area": 2.0}})

    with pytest.raises(ValueError, match="supervison"):
        load_config(overrides={"guard": {"supervison": {"enabled": False}}})


def test_enforcement_lookup_by_rule_id():
    enforcement = load_config().guard.enforcement
    assert enforcement.for_rule("R1") == "block"
    assert enforcement.for_rule("R4") == "alarm"
    assert enforcement.for_rule("R5") == "block"
    assert enforcement.for_rule("R9") == "alarm"  # unknown rules fail safe-ish


def test_yaml_lists_become_tuples():
    config = load_config()
    assert isinstance(config.guard.range.pump_pct, tuple)
    assert config.guard.range.pump_pct == (0.0, 100.0)
