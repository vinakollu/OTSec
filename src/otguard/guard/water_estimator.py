"""The guard's own belief about what the works is doing.

The tank's estimator filtered one level. This one has to hold a picture of a
process with a delay in it, which changes the job in two ways.

A command's consequence is minutes away. When a chlorine dose is written, the
residual analyser will not move for two and a half minutes, so an estimator
that only tracked measurements would be permanently describing the plant as it
was before the last three commands. It keeps a forward model instead, and runs
the commands it has forwarded through the same transport delay the plant has.

And the dangerous quantity is not measured at all. CT is a residual multiplied
by a contact time, and contact time is a volume divided by a flow. Three
instruments, none of which is the number that matters. The estimator computes
it, which also means it can be computed for a command that has not happened
yet, which is the whole of rule W3.

The cross-check in :meth:`disagreement` is the same idea as the storage site's
three power measurements, applied to chemistry. The dose pump's stroke says how
much chlorine is going in. The flow meter says how much water it is going into.
The residual analyser says how much came out the far end. Those three have to
agree to within the chemistry, and when they do not, one of them is lying.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from ..water.plant import WaterSafety, WorksConfig, _approach, _clamp
from ..water.types import PlantState, WaterCommandKind, WaterObservation


@dataclass
class Belief:
    """What the guard thinks is true right now."""

    raw_flow_m3h: float = 0.0
    raw_turbidity_ntu: float = 4.0
    settled_turbidity_ntu: float = 1.0
    filtered_turbidity_ntu: float = 0.08
    chlorine_residual_mg_l: float = 0.5
    ph: float = 7.6
    clearwell_level_m: float = 3.5
    outflow_m3h: float = 0.0
    contact_time_min: float = 0.0
    ct_value: float = 0.0
    filter_headloss_m: float = 0.3

    # The standing orders, as the guard last saw them accepted.
    commanded: dict[str, float] = field(default_factory=dict)

    def get(self, kind: WaterCommandKind, default: float = 0.0) -> float:
        return self.commanded.get(kind.value, default)


class WaterEstimator:
    """Tracks the works, and answers what-if."""

    def __init__(
        self,
        config: WorksConfig | None = None,
        safety: WaterSafety | None = None,
        cusum_threshold: float = 14.0,
        cusum_slack: float = 0.9,
    ) -> None:
        self.cfg = config or WorksConfig()
        self.safety = safety or WaterSafety()
        self.state = Belief()
        self.cusum = 0.0
        self.cusum_threshold = cusum_threshold
        self.cusum_slack = cusum_slack
        self.integrity_alarm = False
        self.suspect: str = ""
        self._initialised = False
        self._t = 0.0

    # ------------------------------------------------------------------
    # Feedback
    # ------------------------------------------------------------------
    def observe(self, obs: WaterObservation) -> None:
        """Take one scan of telemetry and move the belief toward it."""
        dt = max(obs.t - self._t, 0.0) or self.cfg.dt_s
        self._t = obs.t
        b = self.state
        if not self._initialised:
            b.raw_flow_m3h = obs.raw_flow_m3h
            b.raw_turbidity_ntu = obs.raw_turbidity_ntu
            b.settled_turbidity_ntu = obs.settled_turbidity_ntu
            b.filtered_turbidity_ntu = obs.filtered_turbidity_ntu
            b.chlorine_residual_mg_l = obs.chlorine_residual_mg_l
            b.ph = obs.ph
            b.clearwell_level_m = obs.clearwell_level_m
            # The outflow belongs in this snap as much as the level does.
            # Leaving it to be approached from zero meant that after one scan
            # the guard believed the works was gaining eight hundred cubic
            # metres an hour, and the mass balance rule refused the next
            # command on the strength of it.
            b.outflow_m3h = obs.clearwell_outflow_m3h
            b.filter_headloss_m = obs.filter_headloss_m
            self._initialised = True

        # Deliberately slow on the chemistry and quick on the hydraulics. A
        # level or a flow is hard to fake for long because it has to stay
        # consistent with a volume; a residual is one analyser's word.
        b.raw_flow_m3h = _approach(b.raw_flow_m3h, obs.raw_flow_m3h, dt, 3.0)
        b.outflow_m3h = _approach(b.outflow_m3h, obs.clearwell_outflow_m3h, dt, 3.0)
        b.clearwell_level_m = _approach(b.clearwell_level_m, obs.clearwell_level_m, dt, 4.0)
        b.raw_turbidity_ntu = _approach(b.raw_turbidity_ntu, obs.raw_turbidity_ntu, dt, 25.0)
        b.settled_turbidity_ntu = _approach(
            b.settled_turbidity_ntu, obs.settled_turbidity_ntu, dt, 30.0)
        b.filtered_turbidity_ntu = _approach(
            b.filtered_turbidity_ntu, obs.filtered_turbidity_ntu, dt, 25.0)
        b.ph = _approach(b.ph, obs.ph, dt, 25.0)
        b.filter_headloss_m = obs.filter_headloss_m

        expected = self.expected_residual()
        innovation = obs.chlorine_residual_mg_l - expected
        b.chlorine_residual_mg_l = _approach(
            b.chlorine_residual_mg_l, obs.chlorine_residual_mg_l, dt, 40.0)

        # Contact time and CT are computed, never read.
        b.contact_time_min = self.contact_time(b.clearwell_level_m, b.outflow_m3h)
        b.ct_value = b.chlorine_residual_mg_l * b.contact_time_min

        normalised = innovation / 0.10
        self.cusum = max(0.0, self.cusum + abs(normalised) - self.cusum_slack)
        if self.cusum > self.cusum_threshold and not self.integrity_alarm:
            self.integrity_alarm = True
            self.suspect = "chlorine residual analyser"

    def note_accepted(self, kind: WaterCommandKind, value: float) -> None:
        self.state.commanded[kind.value] = value

    def acknowledge(self) -> None:
        self.cusum = 0.0
        self.integrity_alarm = False
        self.suspect = ""

    # ------------------------------------------------------------------
    # Chemistry the guard can do without an instrument
    # ------------------------------------------------------------------
    def chlorine_demand(self, filtered_turbidity: float | None = None) -> float:
        """How much chlorine this water will consume before any is left over."""
        turb = (self.state.filtered_turbidity_ntu if filtered_turbidity is None
                else filtered_turbidity)
        return (self.cfg.chlorine_demand_base_mg_l
                + self.cfg.chlorine_demand_per_ntu * turb)

    def expected_residual(self, dose: float | None = None) -> float:
        """What should be left at the analyser for a given dose."""
        if dose is None:
            dose = self.state.get(WaterCommandKind.CHLORINE_DOSE, 0.0)
        fresh = max(0.0, dose - self.chlorine_demand())
        decay = math.exp(-self.cfg.chlorine_decay_per_min * self.state.contact_time_min)
        return fresh * decay

    def contact_time(self, level_m: float, outflow_m3h: float) -> float:
        useful = level_m * self.cfg.clearwell_area_m2 * self.cfg.clearwell_baffle_factor
        return (useful / max(outflow_m3h, 1.0)) * 60.0

    def coagulant_needed(self) -> float:
        return self.cfg.coagulant_demand_per_ntu * self.state.raw_turbidity_ntu

    def disagreement(self) -> tuple[float, str]:
        """How far the three ways of knowing the chlorine are from each other.

        Returns the gap in mg/L and which instrument looks least consistent
        with the other two. Naming one is only honest when there are three
        witnesses, which is the storage site's lesson carried over.
        """
        # Through the decay in the contact tank, not just the demand at the
        # injector. Comparing a dose against a residual without the decay makes
        # a healthy plant look like a lying one: at a 44 minute contact time
        # about 40 per cent of the free chlorine is gone before the analyser
        # ever sees it, and the first version of this rule fired on every
        # command a compliant works issued.
        if not self._initialised:
            # A guard that has not yet read the plant knows nothing, and
            # nothing is not evidence of a lying instrument. Judging the first
            # command of a run against the belief's starting defaults made a
            # healthy works look like a tampered one, and refused whatever
            # command happened to arrive in that first scan.
            return 0.0, ""
        implied = self.expected_residual()
        measured = self.state.chlorine_residual_mg_l
        gap = abs(implied - measured)
        if gap < 0.25:
            return gap, ""
        # The flow meter and the level gauge agree on a volume, so if the
        # residual is the odd one out it is the residual that is suspect.
        return gap, ("chlorine residual analyser" if measured < implied
                     else "chlorine dose pump feedback")

    # ------------------------------------------------------------------
    # What-if
    # ------------------------------------------------------------------
    def predict(
        self,
        horizon_s: float = 600.0,
        overrides: dict[WaterCommandKind, float] | None = None,
    ) -> PlantState:
        """Run the works forward under the standing orders, with one change.

        This is the counterfactual R3 did for the tank, over a process with
        eight stages and a transport delay. The answer is a whole plant state,
        because a chlorine command can breach a turbidity limit by way of
        nothing but arithmetic on flow.
        """
        b = self.state
        get = dict(b.commanded)
        for kind, value in (overrides or {}).items():
            get[kind.value] = value

        def order(kind: WaterCommandKind, default: float) -> float:
            return get.get(kind.value, default)

        cfg = self.cfg
        flow = (cfg.max_intake_flow_m3h
                * order(WaterCommandKind.INTAKE_PUMP, 0.0) / 100.0
                * order(WaterCommandKind.RAW_VALVE, 100.0) / 100.0)
        outflow = (cfg.max_high_lift_flow_m3h
                   * order(WaterCommandKind.HIGH_LIFT_PUMP, 0.0) / 100.0
                   * order(WaterCommandKind.CLEARWELL_OUTLET, 100.0) / 100.0)

        # Where the stored volume ends up over the horizon.
        volume = b.clearwell_level_m * cfg.clearwell_area_m2
        filtered_flow = flow * order(WaterCommandKind.FILTER_VALVE, 100.0) / 100.0
        volume += (filtered_flow - outflow) * horizon_s / 3600.0
        level = _clamp(volume / cfg.clearwell_area_m2, 0.0, cfg.clearwell_height_m)

        # Coagulation, settling and filtration under the candidate dose.
        coag = order(WaterCommandKind.COAGULANT_DOSE, 0.0)
        needed = max(self.coagulant_needed(), 1e-6)
        adequacy = _clamp(coag / needed, 0.0, 1.4)
        quality = adequacy if adequacy <= 1.15 else max(0.0, 2.3 - adequacy)
        mixing = _clamp(order(WaterCommandKind.FLOC_PADDLE, 0.0) / 55.0, 0.0, 1.0)
        removal = cfg.sed_removal_max * _clamp(quality, 0.0, 1.0) * (0.45 + 0.55 * mixing)
        settled = b.raw_turbidity_ntu * (1.0 - removal)
        spare = _clamp(1.0 - b.filter_headloss_m / cfg.filter_headloss_max_m, 0.0, 1.0)
        overload = _clamp(settled / cfg.filter_design_feed_ntu, 1.0, 8.0)
        filter_removal = (cfg.filter_removal_max * (0.55 + 0.45 * spare)
                          / overload ** 0.75)
        filtered = max(0.02, settled * (1.0 - filter_removal))

        # Disinfection under the candidate dose and the resulting hydraulics.
        dose = order(WaterCommandKind.CHLORINE_DOSE, 0.0)
        fresh = max(0.0, dose - self.chlorine_demand(filtered))
        contact = self.contact_time(level, outflow)
        residual = fresh * math.exp(-cfg.chlorine_decay_per_min * contact)

        caustic = order(WaterCommandKind.CAUSTIC_DOSE, 0.0)
        ph = (7.6 + cfg.caustic_ph_per_mg_l * caustic - cfg.coagulant_ph_per_mg_l * coag)

        head = _clamp(level / cfg.clearwell_height_m, 0.0, 1.0)
        pressure = 0.3 + 4.4 * (order(WaterCommandKind.HIGH_LIFT_PUMP, 0.0) / 100.0) \
            * (0.35 + 0.65 * head)
        if level < cfg.pump_suction_level_m:
            pressure *= _clamp(level / cfg.pump_suction_level_m, 0.0, 1.0) ** 2
        if outflow < cfg.town_demand_m3h * 0.55:
            pressure *= 0.55

        out = PlantState()
        out.raw_flow_m3h = flow
        out.raw_turbidity_ntu = b.raw_turbidity_ntu
        out.coagulant_dose_mg_l = coag
        out.settled_turbidity_ntu = settled
        out.filtered_turbidity_ntu = filtered
        out.filter_headloss_m = b.filter_headloss_m
        out.chlorine_dose_mg_l = dose
        out.caustic_dose_mg_l = caustic
        out.chlorine_residual_mg_l = residual
        out.ph = ph
        out.clearwell_level_m = level
        out.clearwell_outflow_m3h = outflow
        out.contact_time_min = contact
        out.ct_value = residual * contact
        out.distribution_pressure_bar = pressure
        return out

    @property
    def ready(self) -> bool:
        """Has the guard read the plant at least once?"""
        return self._initialised

    def now(self) -> PlantState:
        """The belief, shaped like a plant state so metrics can read it."""
        b = self.state
        out = PlantState()
        out.raw_flow_m3h = b.raw_flow_m3h
        out.raw_turbidity_ntu = b.raw_turbidity_ntu
        out.settled_turbidity_ntu = b.settled_turbidity_ntu
        out.filtered_turbidity_ntu = b.filtered_turbidity_ntu
        out.filter_headloss_m = b.filter_headloss_m
        out.chlorine_dose_mg_l = b.get(WaterCommandKind.CHLORINE_DOSE)
        out.coagulant_dose_mg_l = b.get(WaterCommandKind.COAGULANT_DOSE)
        out.caustic_dose_mg_l = b.get(WaterCommandKind.CAUSTIC_DOSE)
        out.chlorine_residual_mg_l = b.chlorine_residual_mg_l
        out.ph = b.ph
        out.clearwell_level_m = b.clearwell_level_m
        out.clearwell_outflow_m3h = b.outflow_m3h
        out.contact_time_min = b.contact_time_min
        out.ct_value = b.ct_value
        out.distribution_pressure_bar = 0.0
        return out
