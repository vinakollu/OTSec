"""Electro-thermal model of a single Megapack-class battery unit.

Three couplings make this worth simulating rather than treating the fleet as one
big number, and each one becomes a guard rule:

*Energy is conserved.* State of charge is the integral of power over capacity,
adjusted for conversion losses. A reported SoC that does not match the power the
unit has been commanded to deliver is a lie, and no amount of protocol
compromise changes the arithmetic. (Rule B2.)

*Capability is state-dependent.* A unit near empty cannot discharge at full
power and a hot unit cannot run at full power in either direction. The limit is
not a configured number an attacker can raise — it is what the cells will do.
(Rule B1.)

*Heat follows current, and cooling is slow.* Losses go as the square of power
while the cooling system removes heat proportionally to temperature rise, so a
sustained over-power command shows up as a thermal trajectory long before it
shows up as damage. That lead time is what makes a lookahead worth computing.
(Rule B5.)

The model is deliberately a lumped single-cell-equivalent: one SoC, one
temperature, one power. Cell-level imbalance, degradation over cycles and the
detailed inverter switching model are all out of scope, and the guard's own
model (:class:`~otguard.guard.site_estimator.PackEstimator`) is given slightly
wrong parameters on purpose so that "the guard knows the plant exactly" is never
what is being measured.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from ..config import MegapackConfig

# Megawatt-seconds per megawatt-hour. Every energy balance below runs in MJ/MW·s
# rather than MWh so that the integration step is in seconds like everything
# else; converting once here is cheaper than converting in the inner loop.
SECONDS_PER_HOUR = 3600.0


@dataclass
class PackState:
    """Ground truth for one unit. The guard never reads this directly."""

    device: str
    soc: float
    temp_c: float
    p_mw: float = 0.0            # actual AC power, positive = export
    q_mvar: float = 0.0
    p_cmd_mw: float = 0.0        # commanded AC power
    q_cmd_mvar: float = 0.0
    online: bool = True
    cooling_enabled: bool = True
    # Damage flags, latched. These are the outcomes the evaluation scores.
    overcharged: bool = False
    deep_discharged: bool = False
    overheated: bool = False

    @property
    def damaged(self) -> bool:
        return self.overcharged or self.deep_discharged or self.overheated


class Megapack:
    """One battery unit: SoC, temperature and a power-tracking inverter."""

    def __init__(
        self,
        device: str,
        cfg: MegapackConfig,
        initial_soc: float | None = None,
        initial_temp_c: float | None = None,
    ) -> None:
        self.cfg = cfg
        self.state = PackState(
            device=device,
            soc=cfg.initial_soc if initial_soc is None else initial_soc,
            temp_c=cfg.ambient_c if initial_temp_c is None else initial_temp_c,
        )

    # ------------------------------------------------------------------
    # Capability
    # ------------------------------------------------------------------
    def max_discharge_mw(self, soc: float | None = None, temp_c: float | None = None) -> float:
        """Largest export the unit can sustain in its current state.

        Falls off linearly below ``soc_derate_low`` because the cells cannot hold
        terminal voltage as they empty, and again above ``temp_derate_c`` because
        the thermal system cannot remove the losses.
        """
        soc = self.state.soc if soc is None else soc
        temp_c = self.state.temp_c if temp_c is None else temp_c
        return self.cfg.power_mw * self._soc_derate_discharge(soc) * self._thermal_derate(temp_c)

    def max_charge_mw(self, soc: float | None = None, temp_c: float | None = None) -> float:
        """Largest import the unit can accept, as a positive magnitude.

        Falls off above ``soc_derate_high`` (constant-voltage taper near full)
        and below ``temp_cold_c`` — charging a cold lithium cell at full rate
        plates lithium metal, so the limit tightens in the cold as well as the
        heat, which is why this is not a mirror image of the discharge curve.
        """
        soc = self.state.soc if soc is None else soc
        temp_c = self.state.temp_c if temp_c is None else temp_c
        cold = 1.0
        if temp_c < self.cfg.temp_cold_c:
            span = max(self.cfg.temp_cold_c - self.cfg.temp_cold_min_c, 1e-6)
            cold = _clamp((temp_c - self.cfg.temp_cold_min_c) / span, 0.0, 1.0)
        return (
            self.cfg.power_mw
            * self._soc_derate_charge(soc)
            * self._thermal_derate(temp_c)
            * cold
        )

    def _soc_derate_discharge(self, soc: float) -> float:
        if soc >= self.cfg.soc_derate_low:
            return 1.0
        return _clamp(soc / max(self.cfg.soc_derate_low, 1e-6), 0.0, 1.0)

    def _soc_derate_charge(self, soc: float) -> float:
        if soc <= self.cfg.soc_derate_high:
            return 1.0
        span = max(1.0 - self.cfg.soc_derate_high, 1e-6)
        return _clamp((1.0 - soc) / span, 0.0, 1.0)

    def _thermal_derate(self, temp_c: float) -> float:
        if temp_c <= self.cfg.temp_derate_c:
            return 1.0
        span = max(self.cfg.temp_max_c - self.cfg.temp_derate_c, 1e-6)
        return _clamp((self.cfg.temp_max_c - temp_c) / span, 0.0, 1.0)

    def apparent_mva(self, p_mw: float, q_mvar: float) -> float:
        return math.hypot(p_mw, q_mvar)

    # ------------------------------------------------------------------
    # Commands
    # ------------------------------------------------------------------
    def set_power(self, p_mw: float) -> None:
        self.state.p_cmd_mw = p_mw

    def set_reactive(self, q_mvar: float) -> None:
        self.state.q_cmd_mvar = q_mvar

    def set_cooling(self, enabled: bool) -> None:
        """Enable or disable the thermal-management system.

        Exposed as a command because it is one on real equipment, and
        because switching it off is a far more effective attack than any
        power set-point: the pack keeps reporting a legal power while its
        temperature leaves the envelope.
        """
        self.state.cooling_enabled = enabled

    def set_online(self, online: bool) -> None:
        self.state.online = online
        if not online:
            self.state.p_cmd_mw = 0.0
            self.state.q_cmd_mvar = 0.0

    # ------------------------------------------------------------------
    # Integration
    # ------------------------------------------------------------------
    def step(self, dt: float) -> None:
        """Advance one scan.

        Order matters: the inverter first clamps the command to what the unit can
        physically do, *then* the energy and thermal states integrate the power
        that actually flowed. An attacker who commands 3 MW from a unit rated
        1.9 MW does not get 3 MW — they get the clamp, plus the heat. Modelling
        it the other way round would let a rejected command do damage and would
        flatter the guard.
        """
        st = self.state
        if not st.online:
            st.p_cmd_mw = 0.0
            st.q_cmd_mvar = 0.0

        target_p = self._physically_achievable(st.p_cmd_mw)
        target_q = self._clamp_reactive(target_p, st.q_cmd_mvar)

        # Inverter slew. Fast compared with the thermal and energy states, but
        # not instantaneous, which is what makes a commanded step distinguishable
        # from a measured one.
        max_step = self.cfg.slew_mw_s * dt
        st.p_mw += _clamp(target_p - st.p_mw, -max_step, max_step)
        st.q_mvar += _clamp(target_q - st.q_mvar, -max_step, max_step)

        self._integrate_energy(dt)
        self._integrate_thermal(dt)
        self._latch_damage()

    def _physically_achievable(self, p_cmd_mw: float) -> float:
        """Clamp a command to the present capability envelope."""
        if not self.state.online:
            return 0.0
        if p_cmd_mw >= 0.0:
            return min(p_cmd_mw, self.max_discharge_mw())
        return -min(-p_cmd_mw, self.max_charge_mw())

    def _clamp_reactive(self, p_mw: float, q_cmd_mvar: float) -> float:
        """Hold the inverter inside its apparent-power circle.

        Real power wins: an inverter asked for more vars than the circle allows
        curtails vars, not watts. Which means an attacker cannot use a var
        command to sneak past a watt limit.
        """
        headroom_sq = self.cfg.apparent_mva**2 - p_mw**2
        if headroom_sq <= 0.0:
            return 0.0
        headroom = math.sqrt(headroom_sq)
        return _clamp(q_cmd_mvar, -headroom, headroom)

    def _integrate_energy(self, dt: float) -> None:
        """SoC is the integral of DC power over capacity.

        The efficiency asymmetry is the point: discharging pulls *more* out of
        the cells than reaches the grid, charging puts *less* in than came off
        it. A guard that assumed a lossless round trip would drift against the
        real SoC by several percent per cycle and would eventually alarm on an
        honest unit.
        """
        st = self.state
        eta = self.cfg.efficiency
        if st.p_mw >= 0.0:
            p_dc = st.p_mw / eta        # export: cells supply the losses too
        else:
            p_dc = st.p_mw * eta        # import: losses never reach the cells
        st.soc -= (p_dc * dt) / (self.cfg.energy_mwh * SECONDS_PER_HOUR)
        st.soc = _clamp(st.soc, 0.0, 1.0)

    def _integrate_thermal(self, dt: float) -> None:
        """First-order thermal mass with quadratic conversion losses."""
        st = self.state
        loss_mw = self._loss_mw(st.p_mw, st.q_mvar)
        coeff = (
            self.cfg.cooling_mw_per_c
            if st.cooling_enabled
            else self.cfg.cooling_residual_mw_per_c
        )
        cooling_mw = coeff * (st.temp_c - self.cfg.ambient_c)
        d_temp = (loss_mw - cooling_mw) * dt / max(self.cfg.thermal_mass_mjc, 1e-9)
        st.temp_c += d_temp

    def _loss_mw(self, p_mw: float, q_mvar: float) -> float:
        """Conversion loss, quadratic in apparent current.

        Anchored so that at rated power the loss equals the one-way efficiency
        deficit, which keeps the thermal model and the energy model telling the
        same story about where the missing megawatts went.
        """
        rated = max(self.cfg.power_mw, 1e-9)
        loss_at_rated = rated * (1.0 - self.cfg.efficiency)
        s = math.hypot(p_mw, q_mvar)
        return loss_at_rated * (s / rated) ** 2 + self.cfg.aux_mw

    def _latch_damage(self) -> None:
        st = self.state
        if st.soc <= self.cfg.soc_min_hard:
            st.deep_discharged = True
        if st.soc >= self.cfg.soc_max_hard:
            st.overcharged = True
        if st.temp_c >= self.cfg.temp_trip_c:
            st.overheated = True

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------
    def measure_soc(self, rng_value: float = 0.0) -> float:
        return _clamp(self.state.soc + rng_value, 0.0, 1.0)

    def measure_temp_c(self, rng_value: float = 0.0) -> float:
        return self.state.temp_c + rng_value

    def measure_power_mw(self, rng_value: float = 0.0) -> float:
        return self.state.p_mw + rng_value


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))
