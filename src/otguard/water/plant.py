"""A conventional surface-water treatment works, simulated stage by stage.

Eight stages, in the order water goes through them: raw intake, coagulation,
flocculation, sedimentation, filtration, disinfection, clearwell storage and
high-lift distribution. It is the arrangement most municipal plants on a river
or reservoir use, and it is modelled here at the level a guard needs rather
than the level a process engineer would want.

Three properties of it do the work this project cares about.

**Inertia, again.** Water takes minutes to cross the works. A dose entering the
chlorine injector now is not measurable at the residual analyser for several
minutes, so a command and its consequence are separated by a transport delay.
The tank's argument was that a level cannot jump; here a dose cannot be
unsent, which is worse.

**Chemistry does not look dangerous.** A chlorine dose is a small number in
milligrams per litre. Ten times a normal dose is still a small number. There is
no range check that distinguishes 0.9 from 9.0 without knowing what the water
needs, and what the water needs depends on how much of it there is and how
dirty it was when it arrived.

**The dangerous quantity is nobody's single measurement.** Disinfection is not
a residual, it is CT: the residual multiplied by the time the water spent in
contact with it. Cut the contact time by pumping harder and the residual can be
perfectly normal while the water leaves under-disinfected. No instrument on the
plant reads CT. It has to be computed from three.

Deliberate simplifications, stated because they bound every result that uses
this: one filter bed rather than a bank, no sludge handling, no raw-water
reservoir dynamics, temperature fixed, and disinfection credited by a single CT
figure rather than by the per-pathogen tables a regulator would use. The
chemistry is first-order where real chemistry is not.
"""

from __future__ import annotations

import math
import random
from collections import deque
from dataclasses import dataclass

from .types import PlantState, Stage


@dataclass(frozen=True)
class WorksConfig:
    """The iron. None of it is writable, which is the point of checking against it."""

    # Hydraulics
    max_intake_flow_m3h: float = 1800.0
    clearwell_area_m2: float = 420.0
    clearwell_height_m: float = 6.0
    clearwell_baffle_factor: float = 0.6      # plug-flow efficiency, dimensionless
    max_high_lift_flow_m3h: float = 1900.0
    pump_suction_level_m: float = 1.30   # below this the high-lift pumps lose suction
    town_demand_m3h: float = 1200.0

    # Chemical feed capacity, in mg/L achievable at full flow
    max_coagulant_mg_l: float = 60.0
    max_chlorine_mg_l: float = 12.0
    max_caustic_mg_l: float = 60.0

    # Process behaviour
    coagulant_demand_per_ntu: float = 1.6     # mg/L of coagulant per NTU of raw
    sed_removal_max: float = 0.86
    filter_removal_max: float = 0.985
    filter_design_feed_ntu: float = 0.85    # what the filters are sized to receive
    filter_headloss_rate_m_per_h: float = 0.45
    filter_headloss_max_m: float = 2.4
    chlorine_demand_base_mg_l: float = 0.55
    chlorine_demand_per_ntu: float = 1.1
    chlorine_decay_per_min: float = 0.012
    caustic_ph_per_mg_l: float = 0.045
    coagulant_ph_per_mg_l: float = 0.011
    dt_s: float = 1.0

    # Transport: how long water takes to get from the injector to the analyser
    chlorine_transport_s: float = 150.0
    coagulant_transport_s: float = 240.0


@dataclass(frozen=True)
class WaterSafety:
    """The envelope, and where each number comes from.

    These are the drinking-water limits a plant is actually run against, not
    numbers chosen to make a demonstration work. A guard that enforced anything
    looser would be letting water out that a regulator would act on.
    """

    turbidity_action_ntu: float = 0.30     # filtered water, the operating target
    turbidity_breach_ntu: float = 1.00     # never exceeded, at any time
    residual_min_mg_l: float = 0.20        # leaving the works
    residual_max_mg_l: float = 4.00        # maximum residual disinfectant level
    ph_min: float = 6.5
    ph_max: float = 8.5
    ct_required: float = 6.0               # mg·min/L, the inactivation credit needed
    clearwell_min_m: float = 1.00
    clearwell_max_m: float = 5.60
    pressure_min_bar: float = 1.40         # below this, the mains can draw in
    pressure_max_bar: float = 6.00


class _Delay:
    """A first-in-first-out transport delay, in scans.

    Chemistry injected now arrives at the analyser later. Without this the
    plant is a calculator and every dose is visible the instant it is written,
    which would quietly remove the hardest thing about defending a works.
    """

    def __init__(self, seconds: float, dt_s: float, initial: float = 0.0) -> None:
        self.depth = max(1, int(round(seconds / dt_s)))
        self._queue: deque[float] = deque([initial] * self.depth, maxlen=self.depth)

    def push(self, value: float) -> float:
        out = self._queue[0]
        self._queue.append(value)
        return out

    def fill(self, value: float) -> None:
        self._queue = deque([value] * self.depth, maxlen=self.depth)


class WaterWorks:
    """The plant. Step it, read it, and it does not care who wrote to it."""

    def __init__(
        self,
        config: WorksConfig | None = None,
        safety: WaterSafety | None = None,
        seed: int = 0,
    ) -> None:
        self.cfg = config or WorksConfig()
        self.safety = safety or WaterSafety()
        self.rng = random.Random(seed)
        self.state = PlantState()
        self.state.clearwell_level_m = 3.5
        self.state.max_chlorine_dose_mg_l = 5.0
        self._cl_delay = _Delay(self.cfg.chlorine_transport_s, self.cfg.dt_s)
        self._coag_delay = _Delay(self.cfg.coagulant_transport_s, self.cfg.dt_s, 6.4)
        self._settle()

    # ------------------------------------------------------------------
    # Commands in
    # ------------------------------------------------------------------
    def set_intake_pump(self, pct: float) -> None:
        self.state.intake_pump_pct = _clamp(pct, 0.0, 100.0)

    def set_raw_valve(self, pct: float) -> None:
        self.state.raw_valve_pct = _clamp(pct, 0.0, 100.0)

    def set_coagulant(self, mg_l: float) -> None:
        self.state.coagulant_dose_mg_l = _clamp(mg_l, 0.0, self.cfg.max_coagulant_mg_l)

    def set_polymer(self, mg_l: float) -> None:
        self.state.polymer_dose_mg_l = _clamp(mg_l, 0.0, 5.0)

    def set_floc_paddle(self, pct: float) -> None:
        self.state.floc_paddle_pct = _clamp(pct, 0.0, 100.0)

    def set_filter_valve(self, pct: float) -> None:
        self.state.filter_valve_pct = _clamp(pct, 0.0, 100.0)

    def set_backwash(self, on: float) -> None:
        self.state.filter_in_backwash = on >= 0.5

    def set_chlorine(self, mg_l: float) -> None:
        """The dose pump obeys its configured ceiling, and the ceiling is writable.

        This is the Oldsmar shape in one line. The controller does exactly what
        it is told to do and refuses anything above its limit, and the limit is
        a register somebody can write.
        """
        ceiling = min(self.state.max_chlorine_dose_mg_l, self.cfg.max_chlorine_mg_l)
        self.state.chlorine_dose_mg_l = _clamp(mg_l, 0.0, ceiling)

    def set_caustic(self, mg_l: float) -> None:
        ceiling = min(self.state.max_caustic_dose_mg_l, self.cfg.max_caustic_mg_l)
        self.state.caustic_dose_mg_l = _clamp(mg_l, 0.0, ceiling)

    def set_high_lift_pump(self, pct: float) -> None:
        self.state.high_lift_pump_pct = _clamp(pct, 0.0, 100.0)

    def set_clearwell_outlet(self, pct: float) -> None:
        self.state.clearwell_outlet_pct = _clamp(pct, 0.0, 100.0)

    def set_max_chlorine_dose(self, mg_l: float) -> None:
        self.state.max_chlorine_dose_mg_l = max(0.0, mg_l)

    def set_max_caustic_dose(self, mg_l: float) -> None:
        self.state.max_caustic_dose_mg_l = max(0.0, mg_l)

    def set_turbidity_alarm(self, ntu: float) -> None:
        self.state.turbidity_alarm_ntu = max(0.0, ntu)

    # ------------------------------------------------------------------
    # One scan
    # ------------------------------------------------------------------
    def step(self, dt: float | None = None) -> PlantState:
        dt = self.cfg.dt_s if dt is None else dt
        s, cfg = self.state, self.cfg
        s.t += dt

        # --- raw water -------------------------------------------------
        s.raw_turbidity_ntu = max(
            0.4, s.raw_turbidity_ntu + self.rng.gauss(0.0, 0.012)
        )
        flow = (cfg.max_intake_flow_m3h * (s.intake_pump_pct / 100.0)
                * (s.raw_valve_pct / 100.0))
        s.raw_flow_m3h = flow

        # --- coagulation and settling ---------------------------------
        # What the water needs depends on how dirty it is. Dosing to a fixed
        # number is how a plant ends up under-coagulated after a storm.
        needed = cfg.coagulant_demand_per_ntu * s.raw_turbidity_ntu
        arrived_coag = self._coag_delay.push(s.coagulant_dose_mg_l)
        adequacy = 0.0 if needed <= 0 else _clamp(arrived_coag / needed, 0.0, 1.4)
        # Over-dosing past about 1.15x stops helping and starts carrying floc over.
        quality = adequacy if adequacy <= 1.15 else max(0.0, 2.3 - adequacy)
        mixing = _clamp(s.floc_paddle_pct / 55.0, 0.0, 1.0)
        removal = cfg.sed_removal_max * _clamp(quality, 0.0, 1.0) * (0.45 + 0.55 * mixing)
        target_settled = s.raw_turbidity_ntu * (1.0 - removal)
        s.settled_turbidity_ntu = _approach(s.settled_turbidity_ntu, target_settled, dt, 90.0)

        # --- filtration -----------------------------------------------
        if s.filter_in_backwash:
            s.filter_headloss_m = max(0.25, s.filter_headloss_m - 0.9 * dt / 60.0)
            filtered_flow = 0.0
        else:
            load = s.settled_turbidity_ntu * max(flow, 0.0) / cfg.max_intake_flow_m3h
            s.filter_headloss_m = min(
                cfg.filter_headloss_max_m,
                s.filter_headloss_m + cfg.filter_headloss_rate_m_per_h * load * dt / 3600.0,
            )
            filtered_flow = flow * (s.filter_valve_pct / 100.0)
        # A blinding filter stops removing before it stops passing water.
        spare = _clamp(1.0 - s.filter_headloss_m / cfg.filter_headloss_max_m, 0.0, 1.0)
        # A filter asked to do the clarifier's job does it badly. Sand beds are
        # sized for the water a working clarifier hands them; feed one several
        # times that and particles pass straight through rather than being
        # caught. Without this term the model lets a filter cover for a failed
        # coagulation stage indefinitely, which is the opposite of what a filter
        # does, and it would make cutting the coagulant look survivable.
        overload = _clamp(s.settled_turbidity_ntu / cfg.filter_design_feed_ntu, 1.0, 8.0)
        filter_removal = cfg.filter_removal_max * (0.55 + 0.45 * spare) / overload ** 0.75
        target_filtered = max(0.02, s.settled_turbidity_ntu * (1.0 - filter_removal))
        s.filtered_turbidity_ntu = _approach(
            s.filtered_turbidity_ntu, target_filtered, dt, 45.0
        )

        # --- disinfection ---------------------------------------------
        demand = (cfg.chlorine_demand_base_mg_l
                  + cfg.chlorine_demand_per_ntu * s.filtered_turbidity_ntu)
        arrived_cl = self._cl_delay.push(s.chlorine_dose_mg_l)
        fresh_residual = max(0.0, arrived_cl - demand)

        # --- clearwell -------------------------------------------------
        demanded = (cfg.max_high_lift_flow_m3h * (s.high_lift_pump_pct / 100.0)
                    * (s.clearwell_outlet_pct / 100.0))
        volume = s.clearwell_level_m * cfg.clearwell_area_m2
        # Pumps cannot send water the clearwell does not have. Without this the
        # model happily reported a steady flow to the town out of an empty
        # tank, which hides the one consequence that matters.
        available = volume * 3600.0 / max(dt, 1e-6) + filtered_flow
        outflow = min(demanded, max(0.0, available))
        s.clearwell_outflow_m3h = outflow
        volume += (filtered_flow - outflow) * dt / 3600.0
        s.clearwell_level_m = _clamp(
            volume / cfg.clearwell_area_m2, 0.0, cfg.clearwell_height_m
        )

        # Contact time is the clearwell's useful volume divided by how fast the
        # water is being pulled through it. Pump harder and it falls.
        useful_m3 = s.clearwell_level_m * cfg.clearwell_area_m2 * cfg.clearwell_baffle_factor
        s.contact_time_min = (useful_m3 / max(outflow, 1.0)) * 60.0
        decay = math.exp(-cfg.chlorine_decay_per_min * s.contact_time_min)
        s.chlorine_residual_mg_l = _approach(
            s.chlorine_residual_mg_l, fresh_residual * decay, dt, 30.0
        )
        s.ct_value = s.chlorine_residual_mg_l * s.contact_time_min

        # --- pH --------------------------------------------------------
        target_ph = (s.raw_ph
                     + cfg.caustic_ph_per_mg_l * s.caustic_dose_mg_l
                     - cfg.coagulant_ph_per_mg_l * arrived_coag)
        s.ph = _approach(s.ph, target_ph, dt, 60.0)

        # --- distribution ----------------------------------------------
        head = _clamp(s.clearwell_level_m / cfg.clearwell_height_m, 0.0, 1.0)
        target_p = 0.3 + 4.4 * (s.high_lift_pump_pct / 100.0) * (0.35 + 0.65 * head)
        # Suction. Below the pumps' intake the column breaks and they pass air
        # instead of water, so pressure does not sag gently towards a low value
        # — it goes.
        if s.clearwell_level_m < cfg.pump_suction_level_m:
            target_p *= _clamp(s.clearwell_level_m / cfg.pump_suction_level_m, 0.0, 1.0) ** 2
        if outflow < cfg.town_demand_m3h * 0.55:
            target_p *= 0.55   # the town is drawing more than the plant is sending
        s.distribution_pressure_bar = _approach(s.distribution_pressure_bar, target_p, dt, 20.0)

        self._score_harm(outflow)
        return s

    # ------------------------------------------------------------------
    # What counts as harm
    # ------------------------------------------------------------------
    def _score_harm(self, outflow_m3h: float) -> None:
        """Harm is water leaving the works, not a number crossing a line.

        A residual below the minimum while the outlet is shut is a plant with a
        problem. The same residual while 1200 m3/h is going to the town is a
        public health incident, and only the second one is recorded here.
        """
        s, safe = self.state, self.safety
        leaving = outflow_m3h > 1.0

        if s.clearwell_level_m >= self.cfg.clearwell_height_m - 1e-6:
            s.harms.add("clearwell_overflow")
        if s.clearwell_level_m <= 0.02:
            s.harms.add("clearwell_empty")
        if not leaving:
            return
        if s.ct_value < safe.ct_required or s.chlorine_residual_mg_l < safe.residual_min_mg_l:
            s.harms.add("under_disinfected")
        if s.chlorine_residual_mg_l > safe.residual_max_mg_l:
            s.harms.add("chemical_overdose")
        if s.filtered_turbidity_ntu > safe.turbidity_breach_ntu:
            s.harms.add("turbidity_breach")
        if not (safe.ph_min <= s.ph <= safe.ph_max):
            s.harms.add("ph_excursion")
        if s.distribution_pressure_bar < safe.pressure_min_bar:
            s.harms.add("pressure_loss")

    def clear_harm(self) -> None:
        self.state.harms.clear()

    # ------------------------------------------------------------------
    # Measurement
    # ------------------------------------------------------------------
    def measure(self) -> dict[str, float]:
        """What the instruments report, with their own noise on top."""
        s = self.state
        return {
            "raw_flow_m3h": max(0.0, s.raw_flow_m3h + self.rng.gauss(0, 3.0)),
            "raw_turbidity_ntu": max(0.0, s.raw_turbidity_ntu + self.rng.gauss(0, 0.05)),
            "settled_turbidity_ntu": max(0.0, s.settled_turbidity_ntu + self.rng.gauss(0, 0.02)),
            "filtered_turbidity_ntu": max(0.0, s.filtered_turbidity_ntu + self.rng.gauss(0, 0.004)),
            "chlorine_residual_mg_l": max(0.0, s.chlorine_residual_mg_l + self.rng.gauss(0, 0.012)),
            "ph": s.ph + self.rng.gauss(0, 0.012),
            "clearwell_level_m": max(0.0, s.clearwell_level_m + self.rng.gauss(0, 0.004)),
            "distribution_pressure_bar": max(0.0, s.distribution_pressure_bar + self.rng.gauss(0, 0.01)),
            "clearwell_outflow_m3h": max(0.0, s.clearwell_outflow_m3h + self.rng.gauss(0, 3.0)),
        }

    # ------------------------------------------------------------------
    def _settle(self) -> None:
        """Run the works to a steady, compliant operating point."""
        s = self.state
        s.intake_pump_pct, s.raw_valve_pct = 62.0, 100.0
        s.filter_valve_pct, s.clearwell_outlet_pct = 100.0, 100.0
        inflow = self.cfg.max_intake_flow_m3h * 0.62
        s.high_lift_pump_pct = 100.0 * inflow / self.cfg.max_high_lift_flow_m3h
        s.coagulant_dose_mg_l = self.cfg.coagulant_demand_per_ntu * s.raw_turbidity_ntu
        s.floc_paddle_pct = 60.0
        s.chlorine_dose_mg_l = 1.5
        s.caustic_dose_mg_l = 8.0
        self._coag_delay.fill(s.coagulant_dose_mg_l)
        self._cl_delay.fill(s.chlorine_dose_mg_l)
        for _ in range(900):
            self.step(1.0)
        self.clear_harm()


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def _approach(current: float, target: float, dt: float, tau_s: float) -> float:
    """First-order lag. Nothing in a works changes instantly."""
    if tau_s <= 0:
        return target
    alpha = 1.0 - math.exp(-dt / tau_s)
    return current + (target - current) * alpha


STAGE_ORDER: tuple[Stage, ...] = tuple(Stage)
