"""``PhysicsGuard`` — the bump-in-the-wire decision engine.

Protocol-agnostic on purpose. The same object serves the deterministic
evaluation harness and the live Modbus proxy; nothing below this line knows what
a function code is.

Wiring it up takes two calls:

``observe(Observation)``
    Feed it every process-variable read that flows back from the PLC. This is
    how the estimator stays synchronised with the plant.

``check(Command) -> Verdict``
    Feed it every write heading for the PLC. The verdict says whether to forward
    the frame, and carries the findings to log or alarm on.

The split matters for the latency budget: ``observe`` runs the filter once per
scan cycle, while ``check`` only runs the rules. The expensive part (integrating
the model forward in R3) is bounded by ``horizon_s / dt`` steps and is the number
``scripts/bench_latency.py`` measures.
"""

from __future__ import annotations

import math
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Iterable, Sequence

from ..config import Config
from .estimator import TankEstimator
from .rules import GuardContext, Rule, default_rules
from .types import Command, CommandKind, Decision, Observation, RuleFinding, Verdict

# How much command history to retain. Only R2's sliding window reads it, so this
# just needs to comfortably exceed ``dynamics.window_s`` at the flood rate.
_HISTORY_MAXLEN = 512


@dataclass(frozen=True)
class ProtectiveAction:
    """An actuator override the guard issues on its own authority.

    The guard is normally passive — it forwards or drops what the HMI sends. A
    trip is the one case where it *originates* a command, because a standing
    order is about to take the process out of its safety envelope and there is
    nobody else left to stop it.
    """

    t: float
    pump_cmd_pct: float | None = None
    valve_cmd_pct: float | None = None
    reason: str = ""

    def __str__(self) -> str:
        parts = []
        if self.pump_cmd_pct is not None:
            parts.append(f"pump={self.pump_cmd_pct:g}%")
        if self.valve_cmd_pct is not None:
            parts.append(f"valve={self.valve_cmd_pct:g}%")
        return f"TRIP t={self.t:7.2f}s {' '.join(parts)}  <- {self.reason}"


@dataclass
class SupervisionEvent:
    """One edge-triggered supervision alarm, with the trip it caused (if any)."""

    t: float
    findings: list[RuleFinding]
    action: ProtectiveAction | None = None


@dataclass
class GuardStats:
    """Running tally, useful for a live operator display."""

    commands_seen: int = 0
    allowed: int = 0
    alarmed: int = 0
    blocked: int = 0
    findings_by_rule: dict[str, int] = field(default_factory=dict)

    def record(self, verdict: Verdict) -> None:
        self.commands_seen += 1
        if verdict.decision is Decision.BLOCK:
            self.blocked += 1
        elif verdict.decision is Decision.ALARM:
            self.alarmed += 1
        else:
            self.allowed += 1
        for finding in verdict.findings:
            self.findings_by_rule[finding.rule_id] = (
                self.findings_by_rule.get(finding.rule_id, 0) + 1
            )


class PhysicsGuard:
    """Evaluates commands against the physics of the process."""

    def __init__(
        self,
        config: Config,
        rules: Sequence[Rule] | None = None,
        initial_level_m: float | None = None,
    ) -> None:
        self.config = config
        self.rules: list[Rule] = list(rules) if rules is not None else default_rules()
        self.estimator = TankEstimator(
            model=config.guard.model,
            consistency=config.guard.consistency,
            dt_s=config.plant.dt_s,
            initial_level_m=(
                config.plant.initial_level_m if initial_level_m is None else initial_level_m
            ),
        )
        self._history: deque[Command] = deque(maxlen=_HISTORY_MAXLEN)
        self.stats = GuardStats()
        self.verdicts: list[Verdict] = []
        self.supervision_events: list[SupervisionEvent] = []
        self._now = 0.0
        self._supervision_direction: str | None = None
        # Rearm is tracked per direction. Shutting the pump to stop an overflow
        # leaves the outlet open, so the very next scan legitimately needs a
        # dry-out trip; a single global timer would swallow it and the guard
        # would empty the tank it had just saved.
        self._last_trip_t: dict[str, float] = {}
        self.trip_latched = False
        self.trip_direction: str | None = None

    # ------------------------------------------------------------------
    # Process feedback
    # ------------------------------------------------------------------
    def observe(self, observation: Observation) -> SupervisionEvent | None:
        """Ingest one process-variable read, advance the estimate, supervise.

        Returns a :class:`SupervisionEvent` on the scan where a standing order is
        first found to be heading out of the envelope, otherwise ``None``. The
        caller is responsible for applying any :class:`ProtectiveAction` the
        event carries to the actual plant — the guard cannot reach the wires
        itself.
        """
        dt = max(observation.t - self._now, 0.0) or self.config.plant.dt_s
        self._now = observation.t
        self.estimator.update(observation.level_m, dt=dt)
        return self._supervise(observation.t)

    def _supervise(self, t: float) -> SupervisionEvent | None:
        """Re-check the currently held command against the safety envelope.

        Unlike R3 at command time there is no counterfactual to compare with:
        the standing order *is* the status quo, so the envelope is checked
        absolutely. Edge-triggered, so a single developing excursion produces
        one alarm rather than one per scan.
        """
        cfg = self.config.guard.supervision
        if not cfg.enabled:
            return None

        high = self.config.safety.level_max_m - self.config.guard.prediction.margin_m
        low = self.config.safety.level_min_m + self.config.guard.prediction.margin_m
        pred = self.estimator.predict(cfg.horizon_s)

        breach_high = pred.max_level_m > high
        breach_low = pred.min_level_m < low

        # Degraded mode: the lookahead above is computed from an estimate that
        # the transmitter has been steering, so it cannot be the last word.
        # Fall back on the equilibrium implied by the commands, which needs no
        # level reading at all.
        equilibrium_detail = ""
        degraded = self.config.guard.degraded
        if degraded.enabled and degraded.equilibrium_check and self.estimator.integrity_alarm:
            h_eq = self.estimator.equilibrium_level()
            if h_eq > high:
                breach_high = True
                equilibrium_detail = (
                    f"degraded mode: commanded pump "
                    f"{self.estimator.state.pump_cmd_pct:g}% / valve "
                    f"{self.estimator.state.valve_cmd_pct:g}% settles at "
                    f"{self._fmt_level(h_eq)} m, outside the envelope, and the level "
                    f"transmitter is no longer trusted"
                )
            elif h_eq < low:
                breach_low = True
                equilibrium_detail = (
                    f"degraded mode: commanded pump "
                    f"{self.estimator.state.pump_cmd_pct:g}% / valve "
                    f"{self.estimator.state.valve_cmd_pct:g}% drains to "
                    f"{self._fmt_level(h_eq)} m, outside the envelope, and the level "
                    f"transmitter is no longer trusted"
                )

        if not (breach_high or breach_low):
            self._supervision_direction = None
            return None

        # Edge-triggered *per direction*. Tripping the pump to stop an overflow
        # leaves an open outlet, which is itself a dry-out configuration; a
        # single boolean latch would suppress that second alarm and leave the
        # process running away in the other direction.
        direction = "high" if breach_high else "low"
        if self._supervision_direction == direction:
            return None
        self._supervision_direction = direction

        if equilibrium_detail:
            detail = equilibrium_detail
        elif breach_high:
            detail = (
                f"standing order drives overflow: level reaches "
                f"{pred.max_level_m:.3f} m in {pred.time_to_max_s:.1f}s "
                f"(limit {high:.2f} m) with pump held at "
                f"{self.estimator.state.pump_cmd_pct:g}%"
            )
        else:
            detail = (
                f"standing order drives dry-out: level falls to "
                f"{pred.min_level_m:.3f} m in {pred.time_to_min_s:.1f}s "
                f"(limit {low:.2f} m) with valve held at "
                f"{self.estimator.state.valve_cmd_pct:g}%"
            )

        finding = RuleFinding(
            "R3",
            "supervision",
            detail,
            margin=(pred.max_level_m - high) if breach_high else (low - pred.min_level_m),
        )

        action = None
        previous = self._last_trip_t.get(direction)
        rearmed = previous is None or (t - previous) >= cfg.rearm_after_s
        if cfg.trip and rearmed:
            # Safe state depends on which way the process is running away:
            # stop filling, or stop draining.
            action = ProtectiveAction(
                t=t,
                pump_cmd_pct=0.0 if breach_high else None,
                valve_cmd_pct=0.0 if breach_low else None,
                reason=detail,
            )
            self._last_trip_t[direction] = t
            if action.pump_cmd_pct is not None:
                self.estimator.note_accepted(CommandKind.PUMP, action.pump_cmd_pct)
            if action.valve_cmd_pct is not None:
                self.estimator.note_accepted(CommandKind.VALVE, action.valve_cmd_pct)
            if cfg.latch_trip:
                self.trip_latched = True
                self.trip_direction = direction

        event = SupervisionEvent(t=t, findings=[finding], action=action)
        self.supervision_events.append(event)
        self.stats.findings_by_rule["R3"] = self.stats.findings_by_rule.get("R3", 0) + 1
        return event

    # ------------------------------------------------------------------
    # Command inspection
    # ------------------------------------------------------------------
    def check(self, command: Command) -> Verdict:
        """Judge one command. This is the call on the real-time path."""
        started = time.perf_counter()

        self._now = max(self._now, command.t)
        ctx = GuardContext(
            estimator=self.estimator,
            config=self.config.guard,
            safety=self.config.safety,
            history=tuple(self._history),
            now=command.t,
            trip_latched=self.trip_latched,
            trip_direction=self.trip_direction,
        )

        findings: list[RuleFinding] = []
        for rule in self.rules:
            finding = rule.check(command, ctx)
            if finding is not None:
                findings.append(finding)

        decision = self._decide(findings)

        # The estimator must track what the PLC actually received, so only
        # forwarded commands move its actuator model.
        if decision is not Decision.BLOCK:
            self.estimator.note_accepted(command.kind, command.value)

        # R2 reasons about attempts, not just successes: a blocked flood is
        # still a flood, and forgetting it would let an attacker launder an
        # oscillation attack through the guard one rejected packet at a time.
        self._history.append(command)

        latency_us = (time.perf_counter() - started) * 1e6
        verdict = Verdict(command=command, decision=decision, findings=findings, latency_us=latency_us)
        self.stats.record(verdict)
        self.verdicts.append(verdict)
        return verdict

    @staticmethod
    def _fmt_level(value: float) -> str:
        return "infinity" if math.isinf(value) else f"{value:.2f}"

    def _decide(self, findings: Iterable[RuleFinding]) -> Decision:
        """Blocking beats alarming; a clean sheet is an allow."""
        decision = Decision.ALLOW
        for finding in findings:
            mode = self.config.guard.enforcement.for_rule(finding.rule_id)
            if mode == "block":
                return Decision.BLOCK
            decision = Decision.ALARM
        return decision

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------
    @property
    def estimated_level_m(self) -> float:
        return self.estimator.state.level_m

    @property
    def cusum(self) -> float:
        return self.estimator.cusum

    def latencies_us(self) -> list[float]:
        return [v.latency_us for v in self.verdicts]

    def acknowledge(self) -> None:
        """Operator reset: clear the trip lockout and the sensor-integrity latch.

        Deliberately manual. Auto-clearing either latch would hand the decision
        back to whoever is writing the commands, which under this threat model
        is exactly the party you are trying to stop.
        """
        self.trip_latched = False
        self.trip_direction = None
        self._supervision_direction = None
        self._last_trip_t.clear()
        self.estimator.acknowledge()

    def reset_log(self) -> None:
        """Clear recorded verdicts and stats, keeping the state estimate."""
        self.verdicts.clear()
        self.supervision_events.clear()
        self.stats = GuardStats()
