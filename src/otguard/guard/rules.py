"""The four physics-plausibility rule families.

Every rule answers the same question in a different way: *given what the process
is physically doing right now, could a sane operator be issuing this command?*
None of them looks at signatures, payload bytes, or who sent the packet. That is
the whole point — the guard's authority comes from the plant's dynamics, which
an attacker on the HMI cannot renegotiate.

======  ==================================================================
Rule    What it enforces
======  ==================================================================
R1      Static envelope. The command is outside the range the equipment can
        physically or safely accept at any time.
R2      Actuation dynamics. Each command is individually legal but the
        *sequence* is not something a human or a controller would produce —
        valve slamming (water hammer) or a machine-gun write flood.
R3      Inertia lookahead. The command is legal today but, given where the
        tank is and how fast it is moving, letting it stand drives the process
        out of its safety envelope within the reaction horizon.
R4      State consistency. The reported level has stopped agreeing with what
        physics says it should be, so the sensor — not the command — is the
        thing that can no longer be trusted.
======  ==================================================================

R3 deserves one note on design. It does not simply ask "does the predicted
trajectory violate the envelope?", because when a process is already heading for
trouble that test rejects the *corrective* command too, which would be worse
than having no guard at all. Instead it compares the candidate command against
the counterfactual of holding what is currently commanded, and objects only when
the candidate makes the excursion strictly worse. A command that improves the
trajectory is always allowed, however dire the situation.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Protocol, Sequence

from ..config import GuardConfig, SafetyConfig
from .estimator import TankEstimator
from .types import Command, CommandKind, RuleFinding

# Tolerance for "strictly worse than the counterfactual", in metres.
_WORSE_EPS = 1e-6


@dataclass
class GuardContext:
    """Everything a rule is allowed to look at when judging a command."""

    estimator: TankEstimator
    config: GuardConfig
    safety: SafetyConfig
    history: Sequence[Command]  # accepted + attempted, newest last
    now: float
    trip_latched: bool = False
    trip_directions: frozenset[str] = frozenset()  # subset of {"high", "low"}


class Rule(Protocol):
    rule_id: str
    name: str

    def check(self, command: Command, ctx: GuardContext) -> RuleFinding | None:
        ...


# ----------------------------------------------------------------------
# R1 — static range / envelope
# ----------------------------------------------------------------------
class RangeRule:
    """Reject commands outside the equipment's physical or safe operating range.

    The cheapest rule in the set and the one most likely to be dismissed as
    trivial, but it is the only thing standing between an attacker and a raw
    out-of-range write on a controller that will happily accept ``valve = 250``
    because nobody ever told it not to.
    """

    rule_id = "R1"
    name = "range"

    def check(self, command: Command, ctx: GuardContext) -> RuleFinding | None:
        cfg = ctx.config.range
        limits = {
            CommandKind.PUMP: cfg.pump_pct,
            CommandKind.VALVE: cfg.valve_pct,
            CommandKind.SETPOINT: cfg.setpoint_m,
        }.get(command.kind)

        if limits is None:  # MODE has no continuous range
            return None

        low, high = limits
        if command.value < low:
            return RuleFinding(
                self.rule_id,
                self.name,
                f"{command.kind.value}={command.value:g}{command.kind.unit} below "
                f"minimum {low:g}{command.kind.unit}",
                margin=low - command.value,
            )
        if command.value > high:
            return RuleFinding(
                self.rule_id,
                self.name,
                f"{command.kind.value}={command.value:g}{command.kind.unit} above "
                f"maximum {high:g}{command.kind.unit}",
                margin=command.value - high,
            )
        return None


# ----------------------------------------------------------------------
# R2 — actuation dynamics
# ----------------------------------------------------------------------
class DynamicsRule:
    """Reject command *sequences* that no operator or controller would emit.

    Two sub-checks share one sliding window:

    ``reversals``
        Large, repeated direction changes on the same actuator. Cycling a valve
        open/closed at a few hertz is a textbook water-hammer attack: every
        individual command is in range, and the pressure transient can burst a
        pipe long before any level-based rule notices.

    ``flood``
        Sustained write rate far above what an HMI produces. A human clicks; a
        script hammers.
    """

    rule_id = "R2"
    name = "dynamics"

    def check(self, command: Command, ctx: GuardContext) -> RuleFinding | None:
        cfg = ctx.config.dynamics
        window_start = ctx.now - cfg.window_s
        recent = [c for c in ctx.history if c.t >= window_start]

        # --- flood ---
        rate = (len(recent) + 1) / cfg.window_s
        if rate > cfg.max_command_rate_hz:
            return RuleFinding(
                self.rule_id,
                self.name,
                f"command flood: {rate:.1f} writes/s over {cfg.window_s:g}s window "
                f"exceeds {cfg.max_command_rate_hz:g}/s",
                margin=rate - cfg.max_command_rate_hz,
            )

        # --- reversals (per actuator) ---
        if command.kind not in (CommandKind.PUMP, CommandKind.VALVE):
            return None

        values = [c.value for c in recent if c.kind is command.kind]
        values.append(command.value)
        reversals = _count_reversals(values, cfg.reversal_amplitude_pct)
        if reversals > cfg.max_reversals:
            return RuleFinding(
                self.rule_id,
                self.name,
                f"{command.kind.value} oscillation: {reversals} reversals >"
                f"{cfg.reversal_amplitude_pct:g}% in {cfg.window_s:g}s "
                f"(limit {cfg.max_reversals})",
                margin=float(reversals - cfg.max_reversals),
            )
        return None


def _count_reversals(values: Sequence[float], min_amplitude: float) -> int:
    """Count direction changes where both legs exceed ``min_amplitude``."""
    deltas = [
        (b - a)
        for a, b in zip(values, values[1:])
        if abs(b - a) >= min_amplitude
    ]
    return sum(
        1
        for a, b in zip(deltas, deltas[1:])
        if a * b < 0
    )


# ----------------------------------------------------------------------
# R3 — inertia-aware safety prediction
# ----------------------------------------------------------------------
class PredictionRule:
    """Reject commands whose consequences leave the safety envelope.

    Integrates the guard's nominal model forward over the reaction horizon under
    the candidate command, and compares against the counterfactual of holding
    the current command. Objects only when the candidate is *strictly worse* in
    the direction of the violation, so corrective action is never blocked.
    """

    rule_id = "R3"
    name = "prediction"

    def check(self, command: Command, ctx: GuardContext) -> RuleFinding | None:
        if command.kind not in (CommandKind.PUMP, CommandKind.VALVE):
            return None

        cfg = ctx.config.prediction
        horizon = cfg.horizon_s
        high_limit = ctx.safety.level_max_m - cfg.margin_m
        low_limit = ctx.safety.level_min_m + cfg.margin_m

        kwargs = (
            {"pump_cmd_pct": command.value}
            if command.kind is CommandKind.PUMP
            else {"valve_cmd_pct": command.value}
        )
        candidate = ctx.estimator.predict(horizon, **kwargs)
        baseline = ctx.estimator.predict(horizon)

        if candidate.max_level_m > high_limit and candidate.max_level_m > baseline.max_level_m + _WORSE_EPS:
            return RuleFinding(
                self.rule_id,
                self.name,
                f"predicted overflow: level reaches {candidate.max_level_m:.3f} m in "
                f"{candidate.time_to_max_s:.1f}s (limit {high_limit:.2f} m; "
                f"holding current command peaks at {baseline.max_level_m:.3f} m)",
                margin=candidate.max_level_m - high_limit,
            )

        if candidate.min_level_m < low_limit and candidate.min_level_m < baseline.min_level_m - _WORSE_EPS:
            return RuleFinding(
                self.rule_id,
                self.name,
                f"predicted dry-out: level falls to {candidate.min_level_m:.3f} m in "
                f"{candidate.time_to_min_s:.1f}s (limit {low_limit:.2f} m; "
                f"holding current command bottoms at {baseline.min_level_m:.3f} m)",
                margin=low_limit - candidate.min_level_m,
            )

        return None


# ----------------------------------------------------------------------
# R4 — estimator / sensor consistency
# ----------------------------------------------------------------------
class ConsistencyRule:
    """Raise the alarm when the reported level stops obeying the model.

    Driven by the CUSUM statistic the estimator accumulates on its normalised
    innovation. A sustained disagreement means the level reading is no longer
    evidence about the tank — the classic precondition for a false-data-injection
    or replay attack, where the operator's screen looks calm while the process
    walks off a cliff.

    Note this rule does not depend on the command under inspection at all. It is
    a property of the *channel*, evaluated at command time so that the operator
    is told "you are flying blind" at the moment they act.
    """

    rule_id = "R4"
    name = "consistency"

    def check(self, command: Command, ctx: GuardContext) -> RuleFinding | None:
        cfg = ctx.config.consistency
        est = ctx.estimator

        # A latched alarm keeps reporting until acknowledged. Without the latch
        # the alarm would clear itself the moment the filter finished absorbing
        # the injected offset — which is precisely when the operator is most
        # thoroughly deceived.
        firing = est.integrity_alarm if cfg.latch_alarm else est.cusum > cfg.cusum_threshold
        if not firing:
            return None

        statistic = est.cusum_peak if cfg.latch_alarm else est.cusum
        direction = "above" if est.cusum_high >= est.cusum_low else "below"
        suffix = "; estimator running open-loop on the model" if est.open_loop else ""
        return RuleFinding(
            self.rule_id,
            self.name,
            f"sensor/model divergence: CUSUM {statistic:.1f} exceeds "
            f"{cfg.cusum_threshold:g} (reported level running {direction} the "
            f"physical model; last residual {est.last_innovation:+.3f} m){suffix}",
            margin=statistic - cfg.cusum_threshold,
        )


# ----------------------------------------------------------------------
# R5 — post-trip lockout
# ----------------------------------------------------------------------
class LockoutRule:
    """After a latched trip, admit only self-limiting actuator configurations.

    This closes the gap that makes an unlatched trip worthless. When the guard
    forces the pump shut to stop an overflow, the compromised HMI is still there
    and still writing; one second later it re-sends ``pump = 100`` and the trip
    is undone. Cycling that way, the guard alarms forever while the tank fills
    anyway.

    So while the trip is latched, a command to the pump or valve is refused if
    the resulting pair would come to rest *past the limit that tripped*.

    The direction matters, and getting it wrong makes the rule dangerous. A
    blanket "equilibrium must be inside the envelope" test looks tidier but
    forbids draining the tank after an overflow trip — pump shut against an open
    outlet settles at empty, so every recovery action a plant operator would
    reach for is refused, and the guard traps the process in the state it just
    rescued it from. Only the aggravating direction is locked out: after a high
    trip the guard refuses configurations that fill without bound and permits
    every one that lowers the level.

    The test deliberately uses only the commands, never the level reading, which
    is what lets it hold up when the transmitter is the thing under attack. It
    stays in force until :meth:`PhysicsGuard.acknowledge` is called — the
    equivalent of a manual reset on a safety instrumented system.
    """

    rule_id = "R5"
    name = "lockout"

    def check(self, command: Command, ctx: GuardContext) -> RuleFinding | None:
        if not ctx.trip_latched or not ctx.trip_directions:
            return None
        if command.kind not in (CommandKind.PUMP, CommandKind.VALVE):
            return None

        kwargs = (
            {"pump_cmd_pct": command.value}
            if command.kind is CommandKind.PUMP
            else {"valve_cmd_pct": command.value}
        )
        h_eq = ctx.estimator.equilibrium_level(**kwargs)
        high = ctx.safety.level_max_m
        low = ctx.safety.level_min_m

        if "high" in ctx.trip_directions and h_eq > high:
            settles = "infinity" if math.isinf(h_eq) else f"{h_eq:.2f} m"
            limit, margin, sense = f"{high:.2f}", h_eq - high, "overflow"
        elif "low" in ctx.trip_directions and h_eq < low:
            settles = f"{h_eq:.2f} m"
            limit, margin, sense = f"{low:.2f}", low - h_eq, "dry-out"
        else:
            return None

        return RuleFinding(
            self.rule_id,
            self.name,
            f"{sense} trip latched: {command.kind.value}="
            f"{command.value:g}{command.kind.unit} would settle at {settles} "
            f"(limit {limit} m) — configurations that re-establish the tripped "
            f"condition are refused until the trip is acknowledged",
            margin=margin,
        )


def default_rules() -> list[Rule]:
    """The rule set in evaluation order (cheapest and most certain first)."""
    return [RangeRule(), DynamicsRule(), PredictionRule(), ConsistencyRule(), LockoutRule()]
