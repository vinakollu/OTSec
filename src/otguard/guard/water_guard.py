"""The guard for the works: judge each command, watch the standing order, act.

Same two calls as every other guard in this project. ``check`` rules on a
command heading for a controller; ``observe`` takes a scan of telemetry and
decides whether the orders currently in force are taking the water somewhere it
must not go.

What is different here is what a protective action means. On the tank, tripping
meant shutting a pump: one actuator, one direction, done. On a works the safe
move depends on which way the water is going wrong, and two of the four are
counter-intuitive enough to be worth stating.

If the water is under-disinfected, the safe action is not more chlorine — that
takes minutes to arrive and the water leaving now is already short. It is to
slow the outlet, which raises contact time immediately on the water already in
the tank.

If the water is over-dosed, cutting the dose does not help the water already
past the injector either. Closing the outlet is what stops it reaching anybody,
and it is the only move that acts on water that has already been treated badly.

Both of those reduce supply, which is a real cost and is why a trip latches
until a person clears it rather than resolving itself.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Sequence

from ..water.metrics import catalogue
from ..water.plant import WaterSafety, WorksConfig
from ..water.topology import Topology
from ..water.types import PlantState, WaterCommand, WaterCommandKind, WaterObservation
from .types import RuleFinding
from .water_estimator import WaterEstimator
from .water_rules import WaterContext, WaterRule, default_rules


class Decision(str, Enum):
    ALLOW = "allow"
    ALARM = "alarm"
    BLOCK = "block"


@dataclass
class WaterVerdict:
    command: WaterCommand
    decision: Decision
    findings: list[RuleFinding] = field(default_factory=list)
    latency_us: float = 0.0

    @property
    def allowed(self) -> bool:
        return self.decision is not Decision.BLOCK

    @property
    def flagged(self) -> bool:
        return bool(self.findings)

    @property
    def rule_ids(self) -> list[str]:
        return [f.rule_id for f in self.findings]


@dataclass
class ProtectiveAction:
    """A command the guard issues on its own authority."""

    t: float
    writes: dict[WaterCommandKind, float]
    reason: str
    plain: str = ""


@dataclass
class SupervisionEvent:
    t: float
    findings: list[RuleFinding]
    action: ProtectiveAction | None = None


class WaterGuard:
    """Physics and chemistry as policy, in front of a treatment works."""

    def __init__(
        self,
        works: WorksConfig | None = None,
        safety: WaterSafety | None = None,
        topology: Topology | None = None,
        rules: Sequence[WaterRule] | None = None,
        horizon_s: float = 600.0,
        enforce: bool = True,
    ) -> None:
        self.works = works or WorksConfig()
        self.safety = safety or WaterSafety()
        self.topology = topology or Topology()
        self.rules = list(rules) if rules is not None else default_rules()
        self.estimator = WaterEstimator(self.works, self.safety)
        self.horizon_s = horizon_s
        self.enforce = enforce

        self.verdicts: list[WaterVerdict] = []
        self.events: list[SupervisionEvent] = []
        self.locked_out = False
        self.trips = 0
        self.blocked = 0
        self.alarmed = 0
        self.inspected = 0
        self._history: list[WaterCommand] = []
        self._last_direction: str | None = None
        self._metrics = catalogue(self.safety)

    # ------------------------------------------------------------------
    # Commands
    # ------------------------------------------------------------------
    def check(self, command: WaterCommand) -> WaterVerdict:
        started = time.perf_counter()
        ctx = WaterContext(
            estimator=self.estimator,
            works=self.works,
            safety=self.safety,
            topology=self.topology,
            now=command.t,
            history=tuple(self._history[-64:]),
            locked_out=self.locked_out,
        )
        findings = [f for f in (rule.check(command, ctx) for rule in self.rules)
                    if f is not None]
        decision = Decision.BLOCK if findings else Decision.ALLOW
        # Every rule here blocks. A works has no rule whose honest answer is
        # "let it through but mention it": a dose that fails W2 is a dose that
        # must not reach the injector.
        verdict = WaterVerdict(command, decision, findings,
                               (time.perf_counter() - started) * 1e6)

        if self.enforce and decision is Decision.BLOCK:
            self.blocked += 1
        else:
            self.estimator.note_accepted(command.kind, command.value)
            if findings:
                self.alarmed += 1
        self.inspected += 1
        self._history.append(command)
        self.verdicts.append(verdict)
        return verdict

    # ------------------------------------------------------------------
    # Telemetry
    # ------------------------------------------------------------------
    def observe(self, obs: WaterObservation) -> SupervisionEvent | None:
        self.estimator.observe(obs)
        return self._supervise(obs.t)

    def _supervise(self, t: float) -> SupervisionEvent | None:
        """Is the standing order taking the water out of the envelope?

        Edge-triggered per direction, for the reason the tank's supervision is:
        shutting the outlet to stop an overdose is itself a condition that will
        empty the mains, and a single latch would swallow the second alarm.
        """
        predicted = self.estimator.predict(self.horizon_s)
        breach = self._first_breach(predicted)
        if breach is None:
            self._last_direction = None
            return None

        metric, value, direction = breach
        if self._last_direction == f"{metric.key}:{direction}":
            return None
        self._last_direction = f"{metric.key}:{direction}"

        limit = metric.limit_high if direction == "high" else metric.limit_low
        finding = RuleFinding(
            "W6", "supervision",
            f"the orders in force take {metric.label.lower()} to "
            f"{metric.format(value)} {metric.unit} within "
            f"{self.horizon_s / 60:.0f} minutes, past "
            f"{metric.format(limit or 0.0)} {metric.unit}",
            margin=abs(value - (limit or 0.0)),
        )
        action = self._safe_move(t, metric.key, direction, predicted)
        if action is not None:
            self.trips += 1
            self.locked_out = True
            for kind, value_ in action.writes.items():
                self.estimator.note_accepted(kind, value_)
        event = SupervisionEvent(t, [finding], action)
        self.events.append(event)
        return event

    def _first_breach(self, predicted: PlantState):
        for metric in self._metrics:
            if metric.limit_low is None and metric.limit_high is None:
                continue
            value = metric.value(predicted)
            if metric.limit_high is not None and value > metric.limit_high:
                return metric, value, "high"
            if metric.limit_low is not None and value < metric.limit_low:
                return metric, value, "low"
        return None

    def _safe_move(self, t: float, key: str, direction: str,
                   predicted: PlantState) -> ProtectiveAction | None:
        """What to actually do about it.

        Each of these reduces what the works can deliver. That is the trade a
        protective action is: supply for safety, taken deliberately, and held
        until somebody who can see the whole plant decides otherwise.
        """
        commanded = self.estimator.state.commanded
        outlet = commanded.get(WaterCommandKind.CLEARWELL_OUTLET.value, 100.0)

        if key == "chlorine_residual" and direction == "high":
            return ProtectiveAction(
                t, {WaterCommandKind.CLEARWELL_OUTLET: 0.0,
                    WaterCommandKind.CHLORINE_DOSE: 1.2},
                "over-chlorinated water held in the clearwell",
                "Closed the outlet so the over-dosed water cannot reach the town, "
                "and put the chlorine dose back to normal.",
            )
        if key in ("ct", "chlorine_residual") and direction == "low":
            return ProtectiveAction(
                t, {WaterCommandKind.CLEARWELL_OUTLET: max(10.0, outlet * 0.35)},
                "outlet slowed to restore contact time",
                "Slowed the water leaving the plant so it spends longer with the "
                "chlorine. Sending it out faster was the reason it was not being "
                "disinfected.",
            )
        if key == "filtered_turbidity" and direction == "high":
            return ProtectiveAction(
                t, {WaterCommandKind.CLEARWELL_OUTLET: 0.0,
                    WaterCommandKind.INTAKE_PUMP: 0.0},
                "cloudy water held back",
                "Stopped sending water out and shut the raw water pumps. Cloudy "
                "water hides bacteria from the chlorine.",
            )
        if key == "ph":
            return ProtectiveAction(
                t, {WaterCommandKind.CLEARWELL_OUTLET: 0.0,
                    WaterCommandKind.CAUSTIC_DOSE: 8.0},
                "pH excursion held back",
                "Closed the outlet and returned the caustic dose to normal. The "
                "water was drifting outside the safe pH band.",
            )
        if key == "clearwell_level" and direction == "low":
            return ProtectiveAction(
                t, {WaterCommandKind.HIGH_LIFT_PUMP: 0.0},
                "high-lift stopped before the tank empties",
                "Stopped the pumps sending water to the town. The storage tank was "
                "about to run dry, which damages the pumps and cuts supply.",
            )
        if key == "clearwell_level" and direction == "high":
            return ProtectiveAction(
                t, {WaterCommandKind.INTAKE_PUMP: 0.0},
                "intake stopped before the tank overflows",
                "Stopped drawing river water. The treated water tank was about to "
                "overflow.",
            )
        if key == "pressure" and direction == "low":
            return ProtectiveAction(
                t, {WaterCommandKind.HIGH_LIFT_PUMP: 70.0},
                "pressure held up",
                "Brought the pumps back up. If pressure in the mains collapses, "
                "dirty water can be drawn in through leaks.",
            )
        return None

    # ------------------------------------------------------------------
    def acknowledge(self) -> None:
        """An operator clearing the lockout. Deliberately a person's decision."""
        self.locked_out = False
        self._last_direction = None
        self.estimator.acknowledge()

    def reset_log(self) -> None:
        self.verdicts.clear()
        self.events.clear()
        self.trips = self.blocked = self.alarmed = self.inspected = 0
