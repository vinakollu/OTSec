"""A single water tank with an inlet pump and an outlet valve.

The process is deliberately the simplest one that still has the property the
whole project rests on: **inertia**. The level cannot jump. Whatever an attacker
writes to the actuator registers, the tank still has to fill and drain at a rate
set by geometry and gravity, and that is the invariant the guard enforces.

Model
-----
Mass balance on the tank::

    A * dh/dt = Q_in(t) - Q_out(t)

with a linear pump characteristic and an orifice (Torricelli) outlet::

    Q_in  = pump_max_flow * (pump_pos / 100)
    Q_out = valve_coeff * (valve_pos / 100) * sqrt(max(h, 0))

``pump_pos`` and ``valve_pos`` are *actual* actuator positions, which chase the
commanded positions at a finite slew rate. That distinction matters: a command
is a request, and the physical actuator takes seconds to honour it. Integration
is explicit Euler at ``dt_s`` (0.1 s by default), which is far below the ~40 s
dominant time constant of the tank.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

import numpy as np

from ..config import PlantConfig, SafetyConfig


@dataclass
class PlantState:
    """Everything true about the process at one instant."""

    t: float = 0.0
    level_m: float = 0.5
    pump_pos_pct: float = 0.0   # actual actuator position
    valve_pos_pct: float = 0.0
    pump_cmd_pct: float = 0.0   # last accepted command
    valve_cmd_pct: float = 0.0
    inflow_m3s: float = 0.0
    outflow_m3s: float = 0.0
    overflowed: bool = False
    dried_out: bool = False


@dataclass
class WaterTank:
    """Forward simulation of the tank.

    ``step`` advances one ``dt``; ``measure`` returns the *sensor* view, which is
    the only thing a guard or an HMI would normally see.
    """

    config: PlantConfig
    safety: SafetyConfig
    state: PlantState = field(init=False)
    _rng: np.random.Generator = field(init=False)

    def __init__(
        self,
        config: PlantConfig,
        safety: SafetyConfig,
        seed: int = 0,
    ) -> None:
        self.config = config
        self.safety = safety
        self._rng = np.random.default_rng(seed)
        self.state = PlantState(level_m=config.initial_level_m)

    # ------------------------------------------------------------------
    # Actuation
    # ------------------------------------------------------------------
    def set_pump(self, pct: float) -> None:
        """Accept a pump command (0-100 %). The actuator still has to travel."""
        self.state.pump_cmd_pct = _clamp(pct, 0.0, 100.0)

    def set_valve(self, pct: float) -> None:
        """Accept a valve command (0-100 %)."""
        self.state.valve_cmd_pct = _clamp(pct, 0.0, 100.0)

    # ------------------------------------------------------------------
    # Dynamics
    # ------------------------------------------------------------------
    def step(self, dt: float | None = None) -> PlantState:
        """Advance the simulation by one time step and return the new state."""
        cfg = self.config
        dt = cfg.dt_s if dt is None else dt
        s = self.state

        # Actuators slew toward their commanded positions at a finite rate.
        s.pump_pos_pct = _slew(s.pump_pos_pct, s.pump_cmd_pct, cfg.pump_slew_pct_s * dt)
        s.valve_pos_pct = _slew(s.valve_pos_pct, s.valve_cmd_pct, cfg.valve_slew_pct_s * dt)

        s.inflow_m3s = cfg.pump_max_flow_m3s * (s.pump_pos_pct / 100.0)
        s.outflow_m3s = cfg.valve_coeff * (s.valve_pos_pct / 100.0) * math.sqrt(max(s.level_m, 0.0))

        s.level_m += dt * (s.inflow_m3s - s.outflow_m3s) / cfg.area_m2
        s.t += dt

        # Physical limits of the vessel, and the damage flags the evaluation
        # scores against.
        if s.level_m >= cfg.height_m:
            s.level_m = cfg.height_m
            s.overflowed = True
        if s.level_m <= 0.0:
            s.level_m = 0.0
        if s.level_m >= self.safety.level_max_m:
            s.overflowed = True
        if s.level_m <= self.safety.level_min_m:
            s.dried_out = True

        return s

    # ------------------------------------------------------------------
    # Sensing
    # ------------------------------------------------------------------
    def measure(self) -> float:
        """Level as the transmitter reports it: truth plus Gaussian noise."""
        noise = self._rng.normal(0.0, self.config.level_noise_std_m)
        return float(self.state.level_m + noise)

    @property
    def in_safe_envelope(self) -> bool:
        return self.safety.level_min_m < self.state.level_m < self.safety.level_max_m


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def _slew(current: float, target: float, max_step: float) -> float:
    """Move ``current`` toward ``target`` by at most ``max_step``."""
    delta = target - current
    if abs(delta) <= max_step:
        return target
    return current + math.copysign(max_step, delta)
