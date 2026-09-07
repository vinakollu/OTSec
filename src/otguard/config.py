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


# ----------------------------------------------------------------------
# Battery energy storage site (the Megapack-class add-on)
# ----------------------------------------------------------------------
#
# These live alongside the tank configuration rather than in their own module so
# that the promise at the top of this file still holds: one file, one object,
# every tunable number. The site rules are numbered B1..B8 to keep them
# distinguishable from the tank's R1..R5 in logs and figures.


@dataclass(frozen=True)
class MegapackConfig:
    """One battery unit. Defaults are Megapack-2-XL-class figures.

    ``thermal_mass_mjc`` is the one deliberate departure from realism: a 3.9 MWh
    pack is tens of tonnes of cells and has a thermal time constant of hours,
    which would make every thermal scenario longer than the rest of the suite
    combined. It is compressed to give a time constant of ~20 minutes. The
    direction of that error is safe to state plainly — a slower real plant gives
    the guard's lookahead *more* warning, not less, so the compressed model is
    the pessimistic case for detection.
    """

    energy_mwh: float = 3.916
    power_mw: float = 1.927
    apparent_mva: float = 2.1
    efficiency: float = 0.96          # one-way; round trip is the square
    initial_soc: float = 0.55
    # Capability derating
    soc_derate_low: float = 0.10      # discharge tapers below this
    soc_derate_high: float = 0.90     # charge tapers above this
    temp_derate_c: float = 45.0
    temp_max_c: float = 58.0          # capability reaches zero here
    temp_cold_c: float = 10.0         # charge tapers below this
    temp_cold_min_c: float = -10.0
    # Damage thresholds
    soc_min_hard: float = 0.02
    soc_max_hard: float = 0.98
    temp_trip_c: float = 52.0         # below temp_max_c: damage before capability ends
    # Thermal
    ambient_c: float = 25.0
    thermal_mass_mjc: float = 4.0
    cooling_mw_per_c: float = 0.0035
    # Passive convection with the thermal-management system shut down. Two
    # orders of magnitude weaker than forced cooling, which is why disabling
    # HVAC — not commanding more power — is the way to actually cook a pack:
    # normal full-power operation settles well inside limits, but the same
    # power with cooling off runs away.
    cooling_residual_mw_per_c: float = 0.00035
    aux_mw: float = 0.002
    # Inverter
    slew_mw_s: float = 5.0


@dataclass(frozen=True)
class SiteConfig:
    """The fleet, the transformer and the measurement chain.

    ``poi_limit_mw`` is contractual and writable; ``poi_rating_mw`` is the
    transformer nameplate and is not. The fleet is deliberately built larger
    than the limit — 16 units at 1.927 MW against a 20 MW export limit — because
    that is how these sites are actually built, and it is what makes the limit a
    thing an attacker can violate rather than a physical impossibility.
    """

    n_packs: int = 16
    poi_limit_mw: float = 20.0        # contractual export limit (writable)
    poi_rating_mw: float = 25.0       # transformer nameplate (physical)
    ramp_limit_mw_s: float = 2.0      # grid-code ramp
    transformer_loss_mw: float = 0.25   # copper loss at nameplate
    transformer_noload_mw: float = 0.03
    aux_base_mw: float = 0.15
    aux_thermal_mw_per_c: float = 0.002
    ambient_ref_c: float = 25.0
    nominal_frequency_hz: float = 60.0
    dt_s: float = 0.5
    # Independent measurement noise. These set the floor for how tight rule B6's
    # agreement band can be.
    meter_noise_mw: float = 0.02
    relay_noise_mw: float = 0.05
    pack_power_noise_mw: float = 0.01
    soc_noise: float = 0.001
    temp_noise_c: float = 0.2


@dataclass(frozen=True)
class SiteSafetyConfig:
    """What counts as physical damage at the site level."""

    poi_overload_factor: float = 1.0   # damage above rating x this
    sync_freq_hz: float = 0.1
    sync_voltage_pu: float = 0.03
    sync_angle_deg: float = 10.0


@dataclass(frozen=True)
class CapabilityConfig:
    """B1: inverter capability envelope."""

    margin_mw: float = 0.05
    margin_mvar: float = 0.05


@dataclass(frozen=True)
class EnergyConfig:
    """B2: state-of-charge conservation.

    Tuned as a detector, not a tracker — the lesson the tank's R4 taught. A
    filter with enough gain to follow the reported SoC will absorb an injected
    offset and go quiet exactly when it matters.
    """

    process_noise_soc: float = 2e-5
    sensor_noise_soc: float = 0.001
    # Set so that a battery-management re-anchor at the top of charge — a
    # bounded, one-off correction of a few percent — does not latch, while a
    # sustained offset large enough to hide over-discharge does.
    #
    # This is a magnitude discriminator, not a structural one, and it is worth
    # being plain about that: a re-anchor and a spoof have the same shape, a
    # step followed by a constant offset. The weak filter gain means the
    # accumulated CUSUM from a step is bounded rather than unbounded, so the
    # threshold separates them by size. scripts/run_site_eval.py --soc-sweep
    # measures where that boundary actually falls.
    cusum_threshold: float = 150.0
    # The slack has to exceed the largest *persistent* residual that honest
    # operation leaves behind, or the CUSUM integrates model error without
    # bound and alarms on any site given enough uptime. A latched alarm puts
    # the estimator open-loop, so it can never re-converge afterwards — the
    # failure compounds rather than settling.
    cusum_slack: float = 2.0
    latch_alarm: bool = True


@dataclass(frozen=True)
class BalanceConfig:
    """B3: site power balance and the export limit."""

    reconcile_tolerance_mw: float = 0.5
    poi_margin_mw: float = 0.10
    limit_grace_mw: float = 0.25


@dataclass(frozen=True)
class SiteRampConfig:
    """B4: ramp limit, with an exemption for genuine frequency events.

    A fast ramp is not suspicious in itself — it is what a battery is *for*
    during a frequency excursion. What makes it suspicious is a fast ramp with
    the grid sitting at nominal. The exemption is the rule's whole point: it is
    physics supplying context, not a threshold being loosened.
    """

    deadband_hz: float = 0.036        # normal interconnection frequency band
    event_multiplier: float = 6.0     # ramp allowance during a real excursion
    # Must span at least one dispatch write period. A site controller issues a
    # ramp as a sequence of set-point steps, so a window shorter than its write
    # period contains exactly one step and measures the step height over the
    # window length — roughly double the true rate — flagging every honest ramp.
    window_s: float = 4.0


@dataclass(frozen=True)
class SiteThermalConfig:
    """B5: thermal lookahead."""

    horizon_s: float = 300.0
    margin_c: float = 0.0


@dataclass(frozen=True)
class CrossSourceConfig:
    """B6: agreement between the three independent power measurements.

    This is the rule the water-tank project could not have. With three sources a
    disagreement does not just raise an alarm — a majority vote names which
    source is lying, which is the difference between "something is wrong" and
    "the revenue meter is being spoofed, trust the relay".
    """

    tolerance_mw: float = 0.40
    cusum_threshold: float = 12.0
    cusum_slack: float = 0.5
    latch_alarm: bool = True
    enabled: bool = True


@dataclass(frozen=True)
class InterlockConfig:
    """B7: switchgear interlocks and protection corroboration."""

    require_sync: bool = True
    fault_corroboration_a: float = 100.0
    latch_lockout: bool = True


@dataclass(frozen=True)
class ProvenanceConfig:
    """B8: which zones may originate which writes (IEC 62443).

    Not a physics rule, and labelled as such throughout so the distinction stays
    honest. It earns its place for the same structural reason the physics rules
    do: its authority comes from the plant's architecture rather than from
    recognising the attack.
    """

    enabled: bool = True
    control_zones: tuple[str, ...] = ("control",)
    engineering_zones: tuple[str, ...] = ("engineering",)
    require_jump_server: bool = True


@dataclass(frozen=True)
class SiteEnforcementConfig:
    B1_capability: Enforcement = "block"
    B2_energy: Enforcement = "alarm"
    B3_balance: Enforcement = "block"
    B4_ramp: Enforcement = "block"
    B5_thermal: Enforcement = "block"
    B6_crosssource: Enforcement = "alarm"
    B7_interlock: Enforcement = "block"
    B8_provenance: Enforcement = "block"

    def for_rule(self, rule_id: str) -> Enforcement:
        for f in fields(self):
            if f.name.split("_", 1)[0] == rule_id:
                return getattr(self, f.name)
        return "alarm"


@dataclass(frozen=True)
class SiteSupervisionConfig:
    """Continuous re-checking of standing site orders."""

    enabled: bool = True
    horizon_s: float = 60.0
    trip: bool = True
    latch_trip: bool = True
    rearm_after_s: float = 30.0


@dataclass(frozen=True)
class SiteModelConfig:
    """The guard's model of the fleet — deliberately imperfect.

    Every value here is a few per cent away from the corresponding entry in
    :class:`MegapackConfig`. A guard tested against a model identical to the
    plant measures nothing except its own arithmetic.
    """

    energy_mwh: float = 3.95
    power_mw: float = 1.90
    apparent_mva: float = 2.1
    efficiency: float = 0.955
    thermal_mass_mjc: float = 4.3
    cooling_mw_per_c: float = 0.0033
    ambient_c: float = 25.0
    temp_derate_c: float = 45.0
    temp_max_c: float = 58.0
    # The protection set-point the guard is told to respect. A nameplate figure,
    # not a secret: knowing where the equipment trips is not the same as knowing
    # the plant's true thermal parameters, which the entries above deliberately
    # get slightly wrong.
    temp_trip_c: float = 52.0
    soc_derate_low: float = 0.10
    soc_derate_high: float = 0.90
    # The guard's model of the transformer and house load, used to refer the
    # Megapack telemetry sum (measured at the LV bus) to the point of
    # interconnection (where the meter and relay measure). Without this the
    # three "measurements of site power" are measurements of two different
    # quantities and the telemetry sum is an outlier by construction.
    #
    # Slightly wrong on purpose, like every other entry here. The residual error
    # after referral is what sets the floor on how tight the cross-source
    # agreement band can be.
    aux_base_mw: float = 0.16
    # House load rises with pack temperature — the thermal management system is
    # itself a load. Omitting this term costs about half a megawatt on a hot day,
    # which lands directly in the bus-to-POI referral and shows up as the
    # telemetry sum disagreeing with the meter and the relay.
    aux_thermal_mw_per_c: float = 0.0019
    ambient_ref_c: float = 25.0
    transformer_loss_mw: float = 0.26
    transformer_noload_mw: float = 0.032
    poi_rating_mw: float = 25.0
    # Inverter slew, so the estimator can predict the power that was actually
    # *delivered* rather than the power that was asked for. Without this the
    # energy balance diverges during every ramp and derate, because the plant
    # integrates what the inverter did and the estimator integrates the
    # set-point.
    slew_mw_s: float = 4.8


@dataclass(frozen=True)
class SiteGuardConfig:
    model: SiteModelConfig = field(default_factory=SiteModelConfig)
    capability: CapabilityConfig = field(default_factory=CapabilityConfig)
    energy: EnergyConfig = field(default_factory=EnergyConfig)
    balance: BalanceConfig = field(default_factory=BalanceConfig)
    ramp: SiteRampConfig = field(default_factory=SiteRampConfig)
    thermal: SiteThermalConfig = field(default_factory=SiteThermalConfig)
    crosssource: CrossSourceConfig = field(default_factory=CrossSourceConfig)
    interlock: InterlockConfig = field(default_factory=InterlockConfig)
    provenance: ProvenanceConfig = field(default_factory=ProvenanceConfig)
    supervision: SiteSupervisionConfig = field(default_factory=SiteSupervisionConfig)
    enforcement: SiteEnforcementConfig = field(default_factory=SiteEnforcementConfig)


@dataclass(frozen=True)
class BessConfig:
    site: SiteConfig = field(default_factory=SiteConfig)
    pack: MegapackConfig = field(default_factory=MegapackConfig)
    safety: SiteSafetyConfig = field(default_factory=SiteSafetyConfig)
    guard: SiteGuardConfig = field(default_factory=SiteGuardConfig)


@dataclass(frozen=True)
class Config:
    plant: PlantConfig = field(default_factory=PlantConfig)
    safety: SafetyConfig = field(default_factory=SafetyConfig)
    guard: GuardConfig = field(default_factory=GuardConfig)
    bess: BessConfig = field(default_factory=BessConfig)


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
        bess=_build_bess(raw.get("bess")),
    )


def _build_bess(data: Mapping[str, Any] | None) -> BessConfig:
    if data is None:
        return BessConfig()
    known = {"site", "pack", "safety", "guard"}
    unknown = set(data) - known
    if unknown:
        raise ValueError(f"unknown key(s) for BessConfig: {sorted(unknown)}")
    return BessConfig(
        site=_build(SiteConfig, data.get("site")),
        pack=_build(MegapackConfig, data.get("pack")),
        safety=_build(SiteSafetyConfig, data.get("safety")),
        guard=_build_site_guard(data.get("guard")),
    )


def _build_site_guard(data: Mapping[str, Any] | None) -> SiteGuardConfig:
    if data is None:
        return SiteGuardConfig()
    builders = {
        "model": SiteModelConfig,
        "capability": CapabilityConfig,
        "energy": EnergyConfig,
        "balance": BalanceConfig,
        "ramp": SiteRampConfig,
        "thermal": SiteThermalConfig,
        "crosssource": CrossSourceConfig,
        "interlock": InterlockConfig,
        "provenance": ProvenanceConfig,
        "supervision": SiteSupervisionConfig,
        "enforcement": SiteEnforcementConfig,
    }
    unknown = set(data) - set(builders)
    if unknown:
        raise ValueError(f"unknown key(s) for SiteGuardConfig: {sorted(unknown)}")
    return SiteGuardConfig(
        **{name: _build(cls, data.get(name)) for name, cls in builders.items()}
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
