"""State estimation for the site: per-pack SoC and thermal, and source voting.

Two estimators live here, and they answer different questions.

:class:`PackEstimator` answers *"is this unit telling the truth about itself?"*
It runs the guard's own model of one Megapack forward from the power that was
actually commanded, and compares the predicted SoC and temperature against what
the unit reports. It is tuned the way the water-tank project's R4 had to be
tuned, and for the same reason: a filter with enough gain to track the reported
value will absorb an injected offset within a couple of samples and go quiet
exactly when it should be shouting. Low gain, CUSUM on the normalised residual,
latched alarm.

:class:`SourceVoter` answers *"which of my measurements is lying?"* — a question
the tank version could not ask at all. With one level transmitter, a
disagreement between model and sensor is ambiguous: either the sensor is being
spoofed or the model is wrong. With three independent measurements of site
power, the majority is evidence in a way no single sensor can be, and the
outlier is named rather than merely suspected.

That distinction is the reason this add-on exists. The tank's stealthy-bias
result was that residual detectors bound an attacker's *rate*, not their
eventual displacement — ramp slowly enough and the CUSUM never accumulates.
Voting is not subject to that bound. A slow bias on the revenue meter separates
it from the relay and the telemetry sum at exactly the same rate it accumulates,
and the separation is compared against the other sources' *current* agreement
rather than against a drifting internal model. The attacker's choice becomes:
move slowly and be found by the vote, or corrupt all three independently.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from ..bess.types import MeasurementSource, SiteObservation
from ..config import CrossSourceConfig, EnergyConfig, SiteModelConfig

SECONDS_PER_HOUR = 3600.0


@dataclass
class PackEstimate:
    """The guard's belief about one unit."""

    device: str
    soc: float
    temp_c: float
    p_mw: float = 0.0
    q_mvar: float = 0.0
    cooling_enabled: bool = True
    soc_cusum_high: float = 0.0
    soc_cusum_low: float = 0.0
    integrity_alarm: bool = False
    alarm_detail: str = ""

    @property
    def soc_cusum(self) -> float:
        return max(self.soc_cusum_high, self.soc_cusum_low)


class PackEstimator:
    """Dead-reckons one Megapack from its commands and checks its reports.

    The estimator is driven by *accepted commands*, not by telemetry. That is
    what makes it independent evidence: if it were steered by the reported SoC
    it would converge on whatever the attacker chose to report, which is the
    failure mode the tank project documented at length.
    """

    def __init__(
        self,
        device: str,
        model: SiteModelConfig,
        energy: EnergyConfig,
        initial_soc: float,
        initial_temp_c: float,
    ) -> None:
        self.device = device
        self.model = model
        self.cfg = energy
        self.estimate = PackEstimate(device=device, soc=initial_soc, temp_c=initial_temp_c)
        self._variance = energy.sensor_noise_soc**2
        # What the inverter is actually delivering, as distinct from what it was
        # told to deliver. The plant integrates the former; an estimator that
        # integrates the latter diverges on every ramp and every derate, and the
        # resulting residual is indistinguishable from an attack.
        self._p_actual_mw = 0.0

    # -- command tracking ------------------------------------------------
    def note_power(self, p_mw: float) -> None:
        self.estimate.p_mw = p_mw

    def deliverable_mw(self, p_cmd_mw: float, soc: float, temp_c: float) -> float:
        """Clamp a set-point to what the modelled unit could actually produce."""
        m = self.model
        thermal = 1.0
        if temp_c > m.temp_derate_c:
            span = max(m.temp_max_c - m.temp_derate_c, 1e-6)
            thermal = _clamp((m.temp_max_c - temp_c) / span, 0.0, 1.0)
        if p_cmd_mw >= 0.0:
            soc_factor = 1.0 if soc >= m.soc_derate_low else _clamp(soc / max(m.soc_derate_low, 1e-6), 0.0, 1.0)
            return min(p_cmd_mw, m.power_mw * soc_factor * thermal)
        span = max(1.0 - m.soc_derate_high, 1e-6)
        soc_factor = 1.0 if soc <= m.soc_derate_high else _clamp((1.0 - soc) / span, 0.0, 1.0)
        return -min(-p_cmd_mw, m.power_mw * soc_factor * thermal)

    def _advance_actual(self, dt: float, soc: float, temp_c: float) -> float:
        """Slew the delivered power toward the clamped set-point."""
        target = self.deliverable_mw(self.estimate.p_mw, soc, temp_c)
        step = self.model.slew_mw_s * dt
        self._p_actual_mw += _clamp(target - self._p_actual_mw, -step, step)
        return self._p_actual_mw

    def note_reactive(self, q_mvar: float) -> None:
        self.estimate.q_mvar = q_mvar

    def note_cooling(self, enabled: bool) -> None:
        self.estimate.cooling_enabled = enabled

    # -- prediction ------------------------------------------------------
    def predict_soc(self, soc: float, p_mw: float, dt: float) -> float:
        eta = self.model.efficiency
        p_dc = p_mw / eta if p_mw >= 0.0 else p_mw * eta
        return _clamp(soc - (p_dc * dt) / (self.model.energy_mwh * SECONDS_PER_HOUR), 0.0, 1.0)

    def predict_temp(self, temp_c: float, p_mw: float, q_mvar: float, dt: float, cooling: bool) -> float:
        rated = max(self.model.power_mw, 1e-9)
        loss_at_rated = rated * (1.0 - self.model.efficiency)
        s = math.hypot(p_mw, q_mvar)
        loss = loss_at_rated * (s / rated) ** 2
        coeff = self.model.cooling_mw_per_c if cooling else self.model.cooling_mw_per_c * 0.1
        cooling_mw = coeff * (temp_c - self.model.ambient_c)
        return temp_c + (loss - cooling_mw) * dt / max(self.model.thermal_mass_mjc, 1e-9)

    def project(self, horizon_s: float, dt: float = 5.0, p_mw: float | None = None) -> tuple[float, float]:
        """Roll the model forward. Returns ``(soc, peak temperature)``."""
        est = self.estimate
        setpoint = est.p_mw if p_mw is None else p_mw
        soc, temp = est.soc, est.temp_c
        actual = self._p_actual_mw
        peak = temp
        steps = max(1, int(horizon_s / dt))
        for _ in range(steps):
            target = self.deliverable_mw(setpoint, soc, temp)
            step = self.model.slew_mw_s * dt
            actual += _clamp(target - actual, -step, step)
            soc = self.predict_soc(soc, actual, dt)
            temp = self.predict_temp(temp, actual, est.q_mvar, dt, est.cooling_enabled)
            peak = max(peak, temp)
        return soc, peak

    # -- correction ------------------------------------------------------
    def update(self, reported_soc: float, reported_temp_c: float, dt: float) -> None:
        """Advance the estimate and test the report against it."""
        est = self.estimate

        delivered = self._advance_actual(dt, est.soc, est.temp_c)
        predicted_soc = self.predict_soc(est.soc, delivered, dt)
        predicted_temp = self.predict_temp(
            est.temp_c, delivered, est.q_mvar, dt, est.cooling_enabled
        )

        self._variance += self.cfg.process_noise_soc**2
        innovation = reported_soc - predicted_soc
        innovation_var = self._variance + self.cfg.sensor_noise_soc**2
        gain = self._variance / innovation_var if innovation_var > 0 else 0.0

        # Deliberately low: the filter is a detector of disagreement, not a
        # tracker of the transmitter. See the module docstring.
        gain = min(gain, 0.05)

        if est.integrity_alarm and self.cfg.latch_alarm:
            # Once the unit is caught lying, stop taking its word for anything
            # and run open loop on the commands.
            est.soc = predicted_soc
            est.temp_c = predicted_temp
        else:
            est.soc = _clamp(predicted_soc + gain * innovation, 0.0, 1.0)
            est.temp_c = predicted_temp + gain * (reported_temp_c - predicted_temp)
            self._variance = (1.0 - gain) * self._variance

        normalised = innovation / max(math.sqrt(innovation_var), 1e-12)
        slack = self.cfg.cusum_slack
        est.soc_cusum_high = max(0.0, est.soc_cusum_high + normalised - slack)
        est.soc_cusum_low = max(0.0, est.soc_cusum_low - normalised - slack)

        if est.soc_cusum > self.cfg.cusum_threshold and not est.integrity_alarm:
            est.integrity_alarm = True
            est.alarm_detail = (
                f"{self.device} reported SoC drifted {innovation * 100:+.2f}% from the "
                f"energy balance implied by its own accepted commands "
                f"(CUSUM {est.soc_cusum:.1f} over {self.cfg.cusum_threshold:g})"
            )

    def acknowledge(self) -> None:
        est = self.estimate
        est.integrity_alarm = False
        est.alarm_detail = ""
        est.soc_cusum_high = est.soc_cusum_low = 0.0


# ----------------------------------------------------------------------
# Cross-source voting
# ----------------------------------------------------------------------


@dataclass
class VoteResult:
    """The outcome of comparing the three power measurements."""

    t: float
    values: dict[MeasurementSource, float]
    consensus_mw: float
    outlier: MeasurementSource | None = None
    spread_mw: float = 0.0
    disagreement_mw: float = 0.0

    @property
    def has_outlier(self) -> bool:
        return self.outlier is not None

    def describe(self) -> str:
        parts = ", ".join(
            f"{src.label} {value:+.3f} MW" for src, value in self.values.items()
        )
        return parts


class SourceVoter:
    """Majority vote across the three independent site-power measurements.

    The algorithm is deliberately the simplest thing that works, because the
    strength comes from the physical independence of the inputs rather than from
    the statistics: take the median as consensus, measure each source's distance
    from it, and if exactly one source is beyond tolerance while the others agree
    with each other, name it.

    A CUSUM runs on the *named outlier's* deviation so that a bias too small to
    breach the tolerance on any single scan still accumulates. This is the part
    that closes the tank's stealthy-bias gap: the deviation being integrated is
    measured against two sources that are currently agreeing, not against a
    model that the attacker has been slowly dragging.
    """

    def __init__(self, cfg: CrossSourceConfig, model: SiteModelConfig | None = None) -> None:
        self.cfg = cfg
        self.model = model or SiteModelConfig()
        self.cusum: dict[MeasurementSource, float] = {src: 0.0 for src in MeasurementSource}
        self.alarm: MeasurementSource | None = None
        self.alarm_detail = ""
        self.history: list[VoteResult] = []

    def _referred(self, observation: SiteObservation) -> dict[MeasurementSource, float]:
        """Put all three measurements at the same electrical point.

        The revenue meter and the relay both measure at the point of
        interconnection. The telemetry sum measures at the LV bus, upstream of
        the house load and the transformer, so it reads high on export by
        several hundred kilowatts. Comparing the raw numbers makes the telemetry
        sum a permanent outlier and the vote meaningless — which is exactly what
        the first version of this did.
        """
        values = {src: observation.measurement(src) for src in MeasurementSource}
        temps = [p.temp_c for p in observation.packs if p.online]
        values[MeasurementSource.TELEMETRY] = self._bus_to_poi(
            values[MeasurementSource.TELEMETRY], temps
        )
        return values

    def _bus_to_poi(self, p_bus_mw: float, temps_c: list[float] | None = None) -> float:
        m = self.model
        rated = max(m.poi_rating_mw, 1e-9)
        loss = m.transformer_loss_mw * (p_bus_mw / rated) ** 2 + m.transformer_noload_mw
        aux = m.aux_base_mw
        for temp in temps_c or []:
            aux += m.aux_thermal_mw_per_c * max(0.0, temp - m.ambient_ref_c)
        return p_bus_mw - aux - loss

    def vote(self, observation: SiteObservation) -> VoteResult:
        values = self._referred(observation)
        ordered = sorted(values.values())
        if not self.cfg.enabled:
            # Ablation path. The flag has to stop the voter, not just the rule
            # that reports it: gating only the rule would leave the alarm
            # latching anyway and make the "without voting" comparison a
            # measurement of nothing.
            result = VoteResult(
                t=observation.t,
                values=values,
                consensus_mw=ordered[len(ordered) // 2],
                spread_mw=max(ordered) - min(ordered),
            )
            self.history.append(result)
            return result
        consensus = ordered[len(ordered) // 2]     # median of three

        deviations = {src: value - consensus for src, value in values.items()}
        spread = max(ordered) - min(ordered)

        outlier: MeasurementSource | None = None
        beyond = [src for src, dev in deviations.items() if abs(dev) > self.cfg.tolerance_mw]
        if len(beyond) == 1:
            # The other two agree with each other, so the odd one out is named.
            candidate = beyond[0]
            others = [v for src, v in values.items() if src is not candidate]
            if abs(others[0] - others[1]) <= self.cfg.tolerance_mw:
                outlier = candidate

        result = VoteResult(
            t=observation.t,
            values=values,
            consensus_mw=consensus,
            outlier=outlier,
            spread_mw=spread,
            disagreement_mw=abs(deviations[outlier]) if outlier else 0.0,
        )

        self._accumulate(deviations, result)
        self.history.append(result)
        return result

    def _accumulate(self, deviations: dict[MeasurementSource, float], result: VoteResult) -> None:
        """Integrate each source's deviation from consensus.

        Normalising by the tolerance makes the CUSUM dimensionless, so the
        threshold means "this many tolerance-widths of sustained deviation"
        rather than a megawatt-seconds figure nobody can reason about.
        """
        tolerance = max(self.cfg.tolerance_mw, 1e-9)
        for src, deviation in deviations.items():
            normalised = abs(deviation) / tolerance
            self.cusum[src] = max(0.0, self.cusum[src] + normalised - self.cfg.cusum_slack)

        if self.alarm is not None and self.cfg.latch_alarm:
            return

        for src, value in self.cusum.items():
            if value > self.cfg.cusum_threshold:
                self.alarm = src
                self.alarm_detail = (
                    f"{src.label} has diverged from the other two measurements of site "
                    f"power for long enough to rule out noise "
                    f"(CUSUM {value:.1f} over {self.cfg.cusum_threshold:g}; "
                    f"currently {result.values[src]:+.3f} MW against a consensus of "
                    f"{result.consensus_mw:+.3f} MW). Trust the majority, not this source."
                )
                break

    def trusted_power_mw(self, observation: SiteObservation) -> float:
        """Site power according to the sources that are not under suspicion.

        This is what makes the vote actionable rather than merely informative:
        once a source is named, the rest of the guard keeps running on the
        remaining two instead of going blind or believing the liar.
        """
        values = self._referred(observation)
        if self.alarm is not None:
            values.pop(self.alarm, None)
        ordered = sorted(values.values())
        if not ordered:
            return 0.0
        if len(ordered) == 2:
            return sum(ordered) / 2.0
        return ordered[len(ordered) // 2]

    def acknowledge(self) -> None:
        self.alarm = None
        self.alarm_detail = ""
        for src in self.cusum:
            self.cusum[src] = 0.0


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))
