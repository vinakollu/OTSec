"""The guard's own belief about the physical state of the tank.

This is what separates the project from a static rule list. Range checks only
need the command; the interesting rules need to know *where the process
actually is* and *where it is heading*, and they have to work from a nominal
model that is slightly wrong and a sensor that may be lying.

Three jobs:

``update``
    A scalar Kalman filter over the level. It is deliberately run at a low gain
    (the guard trusts physics more than the transmitter) so that a spoofed
    sensor keeps producing a visible innovation instead of being absorbed into
    the estimate within a couple of samples.

``cusum``
    A two-sided CUSUM on the normalised innovation. A single noisy sample means
    nothing; a *sustained* disagreement between model and sensor is either an
    instrument fault or a false-data-injection attack, and either way the
    operator should stop trusting the reading.

``predict``
    Integrates the nominal model forward under a hypothetical command. This is
    the inertia lookahead: "if I let this command through and it sticks for the
    next few seconds, where does the tank end up?"

Known limitation, stated up front because the evaluation measures it: an
attacker who ramps a bias slowly enough stays inside the CUSUM slack and is not
detected by R4. That is the standard stealthy-attack result for residual-based
detectors, and ``scripts/run_eval.py --stealth-sweep`` quantifies how much
damage such an attacker can do before R3 catches the *consequence*.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from ..config import ConsistencyConfig, ModelConfig, SafetyConfig
from .types import CommandKind


@dataclass
class EstimatorState:
    level_m: float
    level_var: float
    pump_pos_pct: float
    valve_pos_pct: float
    pump_cmd_pct: float
    valve_cmd_pct: float


@dataclass
class Prediction:
    """Result of integrating the model forward under a held command."""

    final_level_m: float
    max_level_m: float
    min_level_m: float
    time_to_max_s: float
    time_to_min_s: float


class TankEstimator:
    """Scalar Kalman filter + CUSUM + forward predictor for the water tank."""

    def __init__(
        self,
        model: ModelConfig,
        consistency: ConsistencyConfig,
        dt_s: float,
        initial_level_m: float,
    ) -> None:
        self.model = model
        self.cfg = consistency
        self.dt_s = dt_s

        self._q_var = consistency.process_noise_std_m ** 2
        self._r_var = consistency.sensor_noise_std_m ** 2

        self.state = EstimatorState(
            level_m=initial_level_m,
            level_var=self._r_var,
            pump_pos_pct=0.0,
            valve_pos_pct=0.0,
            pump_cmd_pct=0.0,
            valve_cmd_pct=0.0,
        )

        # CUSUM accumulators for the two directions of disagreement.
        self.cusum_high = 0.0
        self.cusum_low = 0.0
        self.cusum_peak = 0.0
        self.last_innovation = 0.0
        self.last_normalised_innovation = 0.0

        # Sensor-integrity latch. Once raised it stays up until acknowledged,
        # and (if configured) the filter stops trusting the transmitter.
        self.integrity_alarm = False
        self.integrity_alarm_t: float | None = None
        self.open_loop = False

        self._initialised = False
        self._t = 0.0

    # ------------------------------------------------------------------
    # Command bookkeeping
    # ------------------------------------------------------------------
    def note_accepted(self, kind: CommandKind, value: float) -> None:
        """Record a command the guard let through, so the model tracks reality."""
        if kind is CommandKind.PUMP:
            self.state.pump_cmd_pct = _clamp(value, 0.0, 100.0)
        elif kind is CommandKind.VALVE:
            self.state.valve_cmd_pct = _clamp(value, 0.0, 100.0)
        # SETPOINT and MODE do not move an actuator directly.

    # ------------------------------------------------------------------
    # Filtering
    # ------------------------------------------------------------------
    def update(self, measured_level_m: float, dt: float | None = None) -> float:
        """Advance the model one step, then correct with the sensor.

        Returns the normalised innovation, i.e. how many standard deviations the
        sensor disagreed with the model's prediction.
        """
        dt = self.dt_s if dt is None else dt
        s = self.state
        self._t += dt

        if not self._initialised:
            # Trust the first reading to place the filter; nothing to compare to.
            s.level_m = measured_level_m
            self._initialised = True

        # --- Predict ---
        s.pump_pos_pct = _slew(s.pump_pos_pct, s.pump_cmd_pct, self.model.pump_slew_pct_s * dt)
        s.valve_pos_pct = _slew(s.valve_pos_pct, s.valve_cmd_pct, self.model.valve_slew_pct_s * dt)
        s.level_m = _integrate(self.model, s.level_m, s.pump_pos_pct, s.valve_pos_pct, dt)
        s.level_var += self._q_var

        # --- Correct ---
        innovation = measured_level_m - s.level_m
        innovation_var = s.level_var + self._r_var
        normalised = innovation / math.sqrt(innovation_var)

        if not self.open_loop:
            gain = s.level_var / innovation_var
            s.level_m += gain * innovation
            s.level_var = (1.0 - gain) * s.level_var
        # In open loop the prediction stands uncorrected: the transmitter has
        # been caught lying, so the model is the better witness. Variance keeps
        # growing, which is the honest statement that confidence is decaying.

        self.last_innovation = innovation
        self.last_normalised_innovation = normalised

        # --- CUSUM on the normalised innovation ---
        slack = self.cfg.cusum_slack
        self.cusum_high = max(0.0, self.cusum_high + normalised - slack)
        self.cusum_low = max(0.0, self.cusum_low - normalised - slack)
        self.cusum_peak = max(self.cusum_peak, self.cusum)

        if self.cusum > self.cfg.cusum_threshold and not self.integrity_alarm:
            self.integrity_alarm = True
            self.integrity_alarm_t = self._t
            if self.cfg.open_loop_on_alarm:
                self.open_loop = True

        return normalised

    @property
    def sensor_trusted(self) -> bool:
        """False once the transmitter has been caught disagreeing with physics."""
        return not self.open_loop

    def acknowledge(self) -> None:
        """Operator acknowledgement: clear the latch and resume closed loop."""
        self.integrity_alarm = False
        self.integrity_alarm_t = None
        self.open_loop = False
        self.reset_cusum()

    @property
    def cusum(self) -> float:
        """The larger of the two one-sided statistics."""
        return max(self.cusum_high, self.cusum_low)

    def reset_cusum(self) -> None:
        self.cusum_high = 0.0
        self.cusum_low = 0.0
        self.cusum_peak = 0.0

    # ------------------------------------------------------------------
    # Lookahead
    # ------------------------------------------------------------------
    def predict(
        self,
        horizon_s: float,
        pump_cmd_pct: float | None = None,
        valve_cmd_pct: float | None = None,
    ) -> Prediction:
        """Integrate the nominal model forward, holding the given commands.

        ``None`` means "keep whatever is currently commanded". The actuator slew
        model is included, which is what makes the answer inertia-aware rather
        than a naive steady-state extrapolation.
        """
        s = self.state
        level = s.level_m
        pump_pos = s.pump_pos_pct
        valve_pos = s.valve_pos_pct
        pump_cmd = s.pump_cmd_pct if pump_cmd_pct is None else _clamp(pump_cmd_pct, 0.0, 100.0)
        valve_cmd = s.valve_cmd_pct if valve_cmd_pct is None else _clamp(valve_cmd_pct, 0.0, 100.0)

        dt = self.dt_s
        steps = max(1, int(round(horizon_s / dt)))

        max_level = min_level = level
        t_max = t_min = 0.0

        for i in range(steps):
            pump_pos = _slew(pump_pos, pump_cmd, self.model.pump_slew_pct_s * dt)
            valve_pos = _slew(valve_pos, valve_cmd, self.model.valve_slew_pct_s * dt)
            level = _integrate(self.model, level, pump_pos, valve_pos, dt)
            t = (i + 1) * dt
            if level > max_level:
                max_level, t_max = level, t
            if level < min_level:
                min_level, t_min = level, t

        return Prediction(
            final_level_m=level,
            max_level_m=max_level,
            min_level_m=min_level,
            time_to_max_s=t_max,
            time_to_min_s=t_min,
        )


    # ------------------------------------------------------------------
    # Sensor-independent reasoning
    # ------------------------------------------------------------------
    def equilibrium_level(
        self,
        pump_cmd_pct: float | None = None,
        valve_cmd_pct: float | None = None,
    ) -> float:
        """Level this actuator pair settles at, ignoring the current state.

        Solving ``Q_in = Q_out`` for the tank gives::

            h_eq = ( pump_flow / (valve_coeff * valve_fraction) ) ** 2

        The point of this quantity is that **it does not use the level sensor at
        all** — it follows from the commands alone. That makes it the one piece
        of state reasoning that survives a compromised transmitter, which is why
        degraded mode leans on it.

        Returns ``inf`` for a configuration that fills without bound (any inflow
        against a shut outlet) and ``0.0`` for one that empties the vessel.
        """
        s = self.state
        pump = s.pump_cmd_pct if pump_cmd_pct is None else pump_cmd_pct
        valve = s.valve_cmd_pct if valve_cmd_pct is None else valve_cmd_pct

        inflow = self.model.pump_max_flow_m3s * (max(pump, 0.0) / 100.0)
        outlet_gain = self.model.valve_coeff * (max(valve, 0.0) / 100.0)

        if inflow <= 0.0:
            # No inflow: an open outlet drains the tank, a shut one holds it.
            return float(s.level_m) if outlet_gain <= 0.0 else 0.0
        if outlet_gain <= 0.0:
            return math.inf  # filling against a closed outlet
        return (inflow / outlet_gain) ** 2


def _integrate(model: ModelConfig, level: float, pump_pos: float, valve_pos: float, dt: float) -> float:
    """One Euler step of the nominal mass balance."""
    inflow = model.pump_max_flow_m3s * (pump_pos / 100.0)
    outflow = model.valve_coeff * (valve_pos / 100.0) * math.sqrt(max(level, 0.0))
    return max(0.0, level + dt * (inflow - outflow) / model.area_m2)


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def _slew(current: float, target: float, max_step: float) -> float:
    delta = target - current
    if abs(delta) <= max_step:
        return target
    return current + math.copysign(max_step, delta)
