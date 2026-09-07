"""Deterministic replay of one scenario through the plant and the guard.

The loop below is the reference implementation of how the guard is meant to be
wired, and the Modbus proxy mirrors it exactly:

1. advance the plant one scan,
2. read the level sensor (an attacker may rewrite this),
3. hand the reading to the guard, which updates its estimate and supervises the
   standing order — a trip here is applied to the plant,
4. collect the writes due this scan (controller and/or attacker), run each past
   the guard, and apply only the ones it allows.

Running the guard *in process* rather than over a socket is deliberate: the
evaluation has to be reproducible to the sample, and scheduler jitter on a
loopback TCP connection would show up in the detection numbers. Network cost is
measured separately, end to end, by ``scripts/run_demo.py``.

Every run can be repeated with the guard disabled (``enforce=False``), which is
what makes the "what would have happened anyway" column in the results table
possible. Without that column, "no overflow occurred" says nothing.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..config import Config
from ..guard import Command, CommandKind, Decision, Observation, PhysicsGuard, Verdict
from ..guard.guard import SupervisionEvent
from ..scenarios.base import Scenario, ScheduledCommand
from ..sim import WaterTank

# Seconds of quiet operation before a scenario starts, so the state estimator
# has locked on. Detection times are reported relative to the end of warm-up.
WARMUP_S = 5.0


@dataclass
class Sample:
    """One scan cycle of recorded telemetry."""

    t: float
    true_level_m: float
    reported_level_m: float
    estimated_level_m: float
    pump_cmd_pct: float
    valve_cmd_pct: float
    cusum: float


@dataclass
class RunResult:
    """Everything one scenario replay produced."""

    scenario: Scenario
    enforced: bool
    samples: list[Sample] = field(default_factory=list)
    verdicts: list[tuple[Verdict, bool]] = field(default_factory=list)  # (verdict, was_malicious)
    supervision_events: list[SupervisionEvent] = field(default_factory=list)
    overflowed: bool = False
    dried_out: bool = False
    min_level_m: float = 0.0
    max_level_m: float = 0.0
    first_detection_t: float | None = None
    first_damage_t: float | None = None

    @property
    def damaged(self) -> bool:
        """Did the process leave its safety envelope at any point?"""
        return self.overflowed or self.dried_out

    @property
    def detected(self) -> bool:
        return self.first_detection_t is not None

    @property
    def prevented(self) -> bool:
        """Attack detected *and* no damage done."""
        return self.scenario.is_attack and self.detected and not self.damaged

    def latencies_us(self) -> list[float]:
        return [v.latency_us for v, _ in self.verdicts]

    @property
    def lead_time_s(self) -> float | None:
        """How long before damage the guard first objected.

        ``None`` when there was no damage in the unguarded run either, i.e. the
        question does not arise. Negative would mean the alarm came too late.
        """
        if self.first_detection_t is None or self.first_damage_t is None:
            return None
        return self.first_damage_t - self.first_detection_t


def run_scenario(scenario: Scenario, config: Config, enforce: bool = True) -> RunResult:
    """Replay ``scenario`` once and return the full record.

    With ``enforce=False`` the guard still watches and records, but its verdicts
    and trips are not applied — the counterfactual run.
    """
    plant = WaterTank(config.plant, config.safety, seed=scenario.seed)
    plant.state.level_m = scenario.initial_level_m

    guard = PhysicsGuard(config, initial_level_m=scenario.initial_level_m)
    controller = scenario.controller
    if controller is not None:
        controller.reset()

    dt = config.plant.dt_s
    result = RunResult(
        scenario=scenario,
        enforced=enforce,
        min_level_m=plant.state.level_m,
        max_level_m=plant.state.level_m,
    )

    pending: list[ScheduledCommand] = sorted(scenario.commands, key=lambda c: c.t)
    next_index = 0

    # ------------------------------------------------------------------
    # Warm-up: let the estimator converge on a quiet plant before scoring.
    # ------------------------------------------------------------------
    t = -WARMUP_S
    while t < 0.0:
        plant.step(dt)
        t += dt
        guard.observe(Observation(t, plant.measure()))
    guard.reset_log()
    plant.state.overflowed = False
    plant.state.dried_out = False

    # ------------------------------------------------------------------
    # Scored run
    # ------------------------------------------------------------------
    t = 0.0
    steps = int(round(scenario.duration_s / dt))
    for _ in range(steps):
        plant.step(dt)
        t = round(t + dt, 6)

        # --- sensing, possibly through the attacker ---
        honest = plant.measure()
        reported = honest
        if scenario.sensor_attack is not None:
            reported = scenario.sensor_attack(t, plant.state.level_m, honest)

        # --- estimate + supervise the standing order ---
        event = guard.observe(Observation(t, reported))
        if event is not None:
            result.supervision_events.append(event)
            _note_detection(result, t, scenario)
            if enforce and event.action is not None:
                if event.action.pump_cmd_pct is not None:
                    plant.set_pump(event.action.pump_cmd_pct)
                if event.action.valve_cmd_pct is not None:
                    plant.set_valve(event.action.valve_cmd_pct)

        # --- writes due this scan ---
        due: list[ScheduledCommand] = []
        while next_index < len(pending) and pending[next_index].t <= t:
            due.append(pending[next_index])
            next_index += 1
        if controller is not None:
            due.extend(controller.update(t, reported))

        for scheduled in due:
            command = Command(
                t=t,
                kind=scheduled.kind,
                value=scheduled.value,
                source="attacker" if scheduled.malicious else "hmi",
            )
            verdict = guard.check(command)
            result.verdicts.append((verdict, scheduled.malicious))
            if verdict.flagged:
                _note_detection(result, t, scenario)

            applied = verdict.allowed or not enforce
            if applied:
                _apply(plant, command)

        # --- telemetry ---
        result.samples.append(
            Sample(
                t=t,
                true_level_m=plant.state.level_m,
                reported_level_m=reported,
                estimated_level_m=guard.estimated_level_m,
                pump_cmd_pct=plant.state.pump_cmd_pct,
                valve_cmd_pct=plant.state.valve_cmd_pct,
                cusum=guard.cusum,
            )
        )
        result.min_level_m = min(result.min_level_m, plant.state.level_m)
        result.max_level_m = max(result.max_level_m, plant.state.level_m)
        if plant.state.overflowed or plant.state.dried_out:
            if result.first_damage_t is None:
                result.first_damage_t = t

    result.overflowed = plant.state.overflowed
    result.dried_out = plant.state.dried_out
    return result


def _apply(plant: WaterTank, command: Command) -> None:
    """Push an accepted command at the plant. Setpoint/mode do not actuate."""
    if command.kind is CommandKind.PUMP:
        plant.set_pump(command.value)
    elif command.kind is CommandKind.VALVE:
        plant.set_valve(command.value)


def _note_detection(result: RunResult, t: float, scenario: Scenario) -> None:
    """Record the first objection raised inside the attack window."""
    if result.first_detection_t is not None:
        return
    if scenario.is_attack and not scenario.in_attack_window(t):
        return
    result.first_detection_t = t
