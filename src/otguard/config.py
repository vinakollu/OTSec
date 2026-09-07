"""Typed configuration for the plant, the safety envelope and the guard.

The dataclasses here are the single source of truth for every tunable number in
the project. ``load_config`` reads ``config/default.yaml`` (or any override) and
inflates it into these types so that a typo in the YAML fails loudly at startup
rather than silently producing a guard with a disabled rule.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any, Mapping

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_PATH = REPO_ROOT / "config" / "default.yaml"

Enforcement = str  # "block" | "alarm"


@dataclass(frozen=True)
class PlantConfig:
    """Ground truth of the simulated process. The guard never sees this."""

    area_m2: float = 1.0
    height_m: float = 2.0
    initial_level_m: float = 0.5
    pump_max_flow_m3s: float = 0.05
    valve_coeff: float = 0.05
    pump_slew_pct_s: float = 20.0
    valve_slew_pct_s: float = 25.0
    level_noise_std_m: float = 0.005
    dt_s: float = 0.1


@dataclass(frozen=True)
class SafetyConfig:
    """The envelope whose violation counts as physical damage."""

    level_min_m: float = 0.20
    level_max_m: float = 1.80


@dataclass(frozen=True)
class ModelConfig:
    """The guard's nominal model of the plant — deliberately imperfect."""

    area_m2: float = 1.0
    pump_max_flow_m3s: float = 0.052
    valve_coeff: float = 0.048
    pump_slew_pct_s: float = 20.0
    valve_slew_pct_s: float = 25.0


@dataclass(frozen=True)
class RangeConfig:
    pump_pct: tuple[float, float] = (0.0, 100.0)
    valve_pct: tuple[float, float] = (0.0, 100.0)
    setpoint_m: tuple[float, float] = (0.30, 1.60)


@dataclass(frozen=True)
class DynamicsConfig:
    window_s: float = 3.0
    reversal_amplitude_pct: float = 25.0
    max_reversals: int = 3
    max_command_rate_hz: float = 10.0


@dataclass(frozen=True)
class PredictionConfig:
    horizon_s: float = 3.0
    margin_m: float = 0.0


@dataclass(frozen=True)
class SupervisionConfig:
    """Continuous re-checking of standing orders, independent of new commands."""

    enabled: bool = True
    horizon_s: float = 5.0
    trip: bool = True
    rearm_after_s: float = 10.0
    latch_trip: bool = True


@dataclass(frozen=True)
class DegradedConfig:
    """Behaviour once sensor integrity is lost."""

    enabled: bool = True
    equilibrium_check: bool = True


@dataclass(frozen=True)
class ConsistencyConfig:
    process_noise_std_m: float = 0.001
    sensor_noise_std_m: float = 0.005
    cusum_threshold: float = 30.0
    cusum_slack: float = 1.0
    latch_alarm: bool = True
    open_loop_on_alarm: bool = True


@dataclass(frozen=True)
class EnforcementConfig:
    R1_range: Enforcement = "block"
    R2_dynamics: Enforcement = "block"
    R3_prediction: Enforcement = "block"
    R4_consistency: Enforcement = "alarm"
    R5_lockout: Enforcement = "block"

    def for_rule(self, rule_id: str) -> Enforcement:
        """Look up the enforcement mode for a rule id such as ``"R1"``."""
        for f in fields(self):
            if f.name.split("_", 1)[0] == rule_id:
                return getattr(self, f.name)
        return "alarm"


@dataclass(frozen=True)
class GuardConfig:
    model: ModelConfig = field(default_factory=ModelConfig)
    range: RangeConfig = field(default_factory=RangeConfig)
    dynamics: DynamicsConfig = field(default_factory=DynamicsConfig)
    prediction: PredictionConfig = field(default_factory=PredictionConfig)
    supervision: SupervisionConfig = field(default_factory=SupervisionConfig)
    degraded: DegradedConfig = field(default_factory=DegradedConfig)
    consistency: ConsistencyConfig = field(default_factory=ConsistencyConfig)
    enforcement: EnforcementConfig = field(default_factory=EnforcementConfig)


@dataclass(frozen=True)
class Config:
    plant: PlantConfig = field(default_factory=PlantConfig)
    safety: SafetyConfig = field(default_factory=SafetyConfig)
    guard: GuardConfig = field(default_factory=GuardConfig)


def _build(cls: type, data: Mapping[str, Any] | None) -> Any:
    """Recursively inflate ``data`` into the dataclass ``cls``.

    Unknown keys raise: a silently ignored ``max_reversal`` typo would disable a
    rule and quietly inflate the detection rate.
    """
    if data is None:
        return cls()
    if not isinstance(data, Mapping):
        raise TypeError(f"expected a mapping for {cls.__name__}, got {type(data).__name__}")

    known = {f.name: f for f in fields(cls)}
    unknown = set(data) - set(known)
    if unknown:
        raise ValueError(f"unknown key(s) for {cls.__name__}: {sorted(unknown)}")

    # Every dataclass reaching this helper is flat; nesting is assembled
    # explicitly in ``load_config``/``_build_guard``.
    kwargs: dict[str, Any] = {}
    for name in known:
        if name not in data:
            continue
        value = data[name]
        kwargs[name] = tuple(value) if isinstance(value, list) else value
    return cls(**kwargs)


def load_config(path: str | Path | None = None, overrides: Mapping[str, Any] | None = None) -> Config:
    """Load configuration from YAML, applying an optional nested override dict."""
    path = Path(path) if path is not None else DEFAULT_CONFIG_PATH
    raw: dict[str, Any] = {}
    if path.exists():
        loaded = yaml.safe_load(path.read_text())
        if loaded:
            raw = loaded
    if overrides:
        raw = _deep_merge(raw, overrides)

    return Config(
        plant=_build(PlantConfig, raw.get("plant")),
        safety=_build(SafetyConfig, raw.get("safety")),
        guard=_build_guard(raw.get("guard")),
    )


def _build_guard(data: Mapping[str, Any] | None) -> GuardConfig:
    if data is None:
        return GuardConfig()
    known = {
        "model",
        "range",
        "dynamics",
        "prediction",
        "supervision",
        "degraded",
        "consistency",
        "enforcement",
    }
    unknown = set(data) - known
    if unknown:
        raise ValueError(f"unknown key(s) for GuardConfig: {sorted(unknown)}")
    return GuardConfig(
        model=_build(ModelConfig, data.get("model")),
        range=_build(RangeConfig, data.get("range")),
        dynamics=_build(DynamicsConfig, data.get("dynamics")),
        prediction=_build(PredictionConfig, data.get("prediction")),
        supervision=_build(SupervisionConfig, data.get("supervision")),
        degraded=_build(DegradedConfig, data.get("degraded")),
        consistency=_build(ConsistencyConfig, data.get("consistency")),
        enforcement=_build(EnforcementConfig, data.get("enforcement")),
    )


def _deep_merge(base: Mapping[str, Any], override: Mapping[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(dict(base))
    for key, value in override.items():
        if isinstance(value, Mapping) and isinstance(out.get(key), Mapping):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out
