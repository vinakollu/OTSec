"""Scenario description: labelled command streams plus optional sensor attacks.

A scenario is the unit the evaluation scores. It bundles everything needed to
replay one episode deterministically:

* the initial process state and how long to run,
* the writes that arrive at the guard and **whether each one is malicious**,
* any manipulation applied to the sensor channel,
* a supervisory controller, so that "normal" traffic looks like a real plant
  rather than a hand-written sequence that happens to avoid every rule.

Ground truth lives here and nowhere else. The guard never sees the ``malicious``
flag, the ``attack_window`` or the controller's internals — the harness uses them
only to score what the guard decided.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Protocol

from ..guard.types import Command, CommandKind

# Rewrites the honest sensor reading into what the guard is told.
# Signature: (t, true_level_m, honest_reading_m) -> reported_reading_m
SensorAttack = Callable[[float, float, float], float]


@dataclass(frozen=True)
class ScheduledCommand:
    """One write, with the ground-truth label the guard is not allowed to see."""

    t: float
    kind: CommandKind
    value: float
    malicious: bool = False
    note: str = ""

    def to_command(self) -> Command:
        return Command(
            t=self.t,
            kind=self.kind,
            value=self.value,
            source="attacker" if self.malicious else "hmi",
        )


class Controller(Protocol):
    """Supervisory control loop that emits writes like a real HMI would."""

    def reset(self) -> None:
        ...

    def update(self, t: float, level_m: float) -> list[ScheduledCommand]:
        ...


@dataclass
class Scenario:
    """One reproducible episode."""

    name: str
    category: str            # "attack" | "normal"
    description: str
    duration_s: float
    initial_level_m: float = 0.80
    commands: list[ScheduledCommand] = field(default_factory=list)
    sensor_attack: SensorAttack | None = None
    attack_window: tuple[float, float] | None = None
    controller: Controller | None = None
    expected_rules: tuple[str, ...] = ()   # documentation, not an assertion
    seed: int = 0

    @property
    def is_attack(self) -> bool:
        return self.category == "attack"

    def in_attack_window(self, t: float) -> bool:
        if self.attack_window is None:
            return self.is_attack
        start, end = self.attack_window
        return start <= t <= end

    def __str__(self) -> str:
        return f"{self.name} ({self.category}, {self.duration_s:g}s)"


class LevelController:
    """A plain PI level controller that writes like an HMI, not like a scan loop.

    Two details keep it honest as a source of *benign* traffic:

    ``write_period_s``
        Supervisory systems write on a slow cycle, not every scan. Emitting a
        command per simulation step would trip R2's flood check and make the
        false-alarm rate meaningless.

    ``deadband_pct``
        Write-on-change. A controller that rewrites an unchanged value forever
        is not what real traffic looks like.
    """

    def __init__(
        self,
        setpoint_m: float,
        kp: float = 250.0,
        ki: float = 8.0,
        write_period_s: float = 1.0,
        deadband_pct: float = 2.0,
        valve_pct: float = 30.0,
        setpoint_schedule: list[tuple[float, float]] | None = None,
        valve_schedule: list[tuple[float, float]] | None = None,
    ) -> None:
        self.initial_setpoint_m = setpoint_m
        self.kp = kp
        self.ki = ki
        self.write_period_s = write_period_s
        self.deadband_pct = deadband_pct
        self.initial_valve_pct = valve_pct
        # Operator-initiated changes: (time, new value). This is how startup and
        # shutdown are expressed — as an operator moving a target, with the loop
        # doing the actual actuation, rather than as a hand-scripted ramp.
        self.setpoint_schedule = sorted(setpoint_schedule or [])
        self.valve_schedule = sorted(valve_schedule or [])
        self.reset()

    def reset(self) -> None:
        self.setpoint_m = self.initial_setpoint_m
        self.valve_pct = self.initial_valve_pct
        self._integral = 0.0
        self._last_write_t: float | None = None
        self._last_pump_cmd: float | None = None
        self._last_valve_cmd: float | None = None
        self._applied_setpoints = 0
        self._applied_valves = 0

    def set_setpoint(self, setpoint_m: float) -> None:
        self.setpoint_m = setpoint_m

    def _apply_schedules(self, t: float) -> None:
        while (
            self._applied_setpoints < len(self.setpoint_schedule)
            and self.setpoint_schedule[self._applied_setpoints][0] <= t
        ):
            self.setpoint_m = self.setpoint_schedule[self._applied_setpoints][1]
            self._applied_setpoints += 1
            self._integral = 0.0  # bumpless-ish transfer on an operator change
        while (
            self._applied_valves < len(self.valve_schedule)
            and self.valve_schedule[self._applied_valves][0] <= t
        ):
            self.valve_pct = self.valve_schedule[self._applied_valves][1]
            self._applied_valves += 1

    def update(self, t: float, level_m: float) -> list[ScheduledCommand]:
        self._apply_schedules(t)
        if self._last_write_t is not None and (t - self._last_write_t) < self.write_period_s:
            return []
        dt = self.write_period_s if self._last_write_t is None else t - self._last_write_t
        self._last_write_t = t

        error = self.setpoint_m - level_m
        candidate = self.kp * error + self.ki * self._integral
        # Only integrate while the actuator has authority left (anti-windup).
        if 0.0 < candidate < 100.0:
            self._integral += error * dt
        pump_cmd = max(0.0, min(100.0, self.kp * error + self.ki * self._integral))

        out: list[ScheduledCommand] = []
        if self._last_pump_cmd is None or abs(pump_cmd - self._last_pump_cmd) >= self.deadband_pct:
            out.append(ScheduledCommand(t, CommandKind.PUMP, round(pump_cmd, 1)))
            self._last_pump_cmd = pump_cmd
        if self._last_valve_cmd is None or abs(self.valve_pct - self._last_valve_cmd) >= self.deadband_pct:
            out.append(ScheduledCommand(t, CommandKind.VALVE, round(self.valve_pct, 1)))
            self._last_valve_cmd = self.valve_pct
        return out
