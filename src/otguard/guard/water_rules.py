"""W1 to W8: what a command has to survive before it reaches the water.

The tank's five rules were about one quantity with inertia. These are about a
process where the dangerous command looks ordinary and its consequence is
somewhere else. Four of them have no equivalent in the earlier work, and those
four are the reason this plant was worth building.

**W2 is the Oldsmar rule.** In February 2021 somebody raised a sodium
hydroxide set-point at a Florida water plant from about 100 ppm to about
11,100 ppm. Every value in that sentence is a legal number for a chemical
dosed in parts per million, and no range check distinguishes them. What does
distinguish them is the water: a dose is only sane relative to how much water
there is and how much chemical that water actually needs. W2 asks that
question, and it asks it of the *ceiling* too, because an attacker who cannot
exceed a limit will raise the limit first.

**W3 is the counterfactual**, the same shape as the tank's: run the works
forward under this command and see where the water ends up. It is here that a
chlorine command gets refused for breaching a turbidity limit, which sounds
wrong until you notice that both come out of the same arithmetic on flow.

**W4 asks three instruments the same question.** The dose pump says how much
chlorine is going in, the flow meter says how much water it is going into, the
residual analyser says how much came out. Chemistry relates them. When they
stop agreeing, one is lying, and with three witnesses the guard can say which.

**W5 is conservation.** Water in, water out, and the change in what is stored.
A flow meter can report whatever an attacker likes, but it cannot do so and
still have the clearwell level agree with it.

The rest are more familiar: W1 is range, W6 supervises the standing order,
W7 is interlocks and W8 is provenance.
"""

from __future__ import annotations

import math

from dataclasses import dataclass
from typing import Protocol

from ..water.metrics import Metric, catalogue
from ..water.plant import WaterSafety, WorksConfig
from ..water.topology import Topology
from ..water.types import PointRole, WaterCommand, WaterCommandKind
from .types import RuleFinding
from .water_estimator import WaterEstimator


@dataclass
class WaterContext:
    """Everything a rule may look at when judging one command."""

    estimator: WaterEstimator
    works: WorksConfig
    safety: WaterSafety
    topology: Topology
    now: float
    history: tuple[WaterCommand, ...] = ()
    locked_out: bool = False


class WaterRule(Protocol):
    rule_id: str
    name: str

    def check(self, command: WaterCommand, ctx: WaterContext) -> RuleFinding | None:
        ...


# ----------------------------------------------------------------------
# W1, the equipment's own rating
# ----------------------------------------------------------------------
#: What each point can physically be, regardless of what anybody wants.
RANGES: dict[WaterCommandKind, tuple[float, float]] = {
    WaterCommandKind.INTAKE_PUMP: (0.0, 100.0),
    WaterCommandKind.RAW_VALVE: (0.0, 100.0),
    WaterCommandKind.FLOC_PADDLE: (0.0, 100.0),
    WaterCommandKind.FILTER_VALVE: (0.0, 100.0),
    WaterCommandKind.HIGH_LIFT_PUMP: (0.0, 100.0),
    WaterCommandKind.CLEARWELL_OUTLET: (0.0, 100.0),
    WaterCommandKind.BACKWASH: (0.0, 1.0),
    WaterCommandKind.MODE: (0.0, 1.0),
    WaterCommandKind.POLYMER_DOSE: (0.0, 5.0),
}


class RangeRule:
    """W1: the command has to be something the equipment can do."""

    rule_id = "W1"
    name = "equipment range"

    def check(self, command: WaterCommand, ctx: WaterContext) -> RuleFinding | None:
        kind = command.kind
        if kind in RANGES:
            low, high = RANGES[kind]
        elif kind is WaterCommandKind.COAGULANT_DOSE:
            low, high = 0.0, ctx.works.max_coagulant_mg_l
        elif kind in (WaterCommandKind.CHLORINE_DOSE, WaterCommandKind.MAX_CHLORINE_DOSE):
            low, high = 0.0, ctx.works.max_chlorine_mg_l
        elif kind in (WaterCommandKind.CAUSTIC_DOSE, WaterCommandKind.MAX_CAUSTIC_DOSE):
            low, high = 0.0, ctx.works.max_caustic_mg_l
        elif kind is WaterCommandKind.TURBIDITY_ALARM:
            low, high = 0.0, ctx.safety.turbidity_breach_ntu
        else:
            return None

        if low <= command.value <= high:
            return None
        return RuleFinding(
            self.rule_id, self.name,
            f"{kind.label} of {command.value:g}{kind.unit} is outside what the "
            f"equipment can do ({low:g} to {high:g}{kind.unit})",
            margin=max(command.value - high, low - command.value),
        )


# ----------------------------------------------------------------------
# W2, a dose is only sane relative to the water
# ----------------------------------------------------------------------
def _least_decay(ctx: "WaterContext") -> float:
    """How little chlorine the works could lose before the analyser.

    Decay over the shortest contact time the clearwell can produce: its
    minimum level, emptied at the fastest the high-lift pumps run. Anything
    authorised against this stays authorised when somebody opens the pumps.
    """
    useful = (ctx.safety.clearwell_min_m * ctx.works.clearwell_area_m2
              * ctx.works.clearwell_baffle_factor)
    contact_min = (useful / max(ctx.works.max_high_lift_flow_m3h, 1.0)) * 60.0
    return math.exp(-ctx.works.chlorine_decay_per_min * contact_min)


class DoseRule:
    """W2: chemical doses measured against what this water actually needs.

    The absolute half of this rule checks a *ceiling* against the iron and the
    toxicology rather than against itself, which is the storage site's
    transformer-nameplate trick: no authorisation makes 11 mg/L of chlorine
    drinkable, so raising the limit to permit it buys the attacker nothing.
    """

    rule_id = "W2"
    name = "dose proportioning"

    #: How far above what the water needs a dose may legitimately sit. Plants
    #: run a margin; they do not run ten times a margin.
    tolerance = 2.6

    def check(self, command: WaterCommand, ctx: WaterContext) -> RuleFinding | None:
        est = ctx.estimator
        kind = command.kind

        if kind is WaterCommandKind.MAX_CHLORINE_DOSE:
            # A dose is measured at the injector and the limit applies at the
            # analyser, and chlorine decays on the way between them. Comparing
            # the two directly refused the ceiling this works already runs at,
            # which is the same error the cross-instrument rule carried until
            # the decay was put into it.
            #
            # The decay used here is the least the works could give, not the
            # decay it happens to be giving now: an attacker who collapses the
            # contact time shortens the journey, and a ceiling authorised
            # against a long contact would then permit a residual the long
            # contact was the only thing holding down.
            safe_ceiling = ctx.safety.residual_max_mg_l / _least_decay(ctx)
            safe_ceiling += est.chlorine_demand()
            if command.value > safe_ceiling:
                return RuleFinding(
                    self.rule_id, self.name,
                    f"a chlorine ceiling of {command.value:g} mg/L would permit water "
                    f"to leave above the {ctx.safety.residual_max_mg_l:g} mg/L limit. "
                    f"This water needs {est.chlorine_demand():.2f} mg/L, so nothing "
                    f"above {safe_ceiling:.2f} mg/L is authorisable by anyone",
                    margin=command.value - safe_ceiling,
                )
            return None

        if kind is WaterCommandKind.MAX_CAUSTIC_DOSE:
            ph_room = max(0.0, ctx.safety.ph_max - est.state.ph)
            safe_ceiling = est.state.commanded.get(
                WaterCommandKind.CAUSTIC_DOSE.value, 0.0
            ) + ph_room / max(ctx.works.caustic_ph_per_mg_l, 1e-6)
            if command.value > safe_ceiling + 5.0:
                return RuleFinding(
                    self.rule_id, self.name,
                    f"a caustic ceiling of {command.value:g} mg/L would permit a pH "
                    f"above {ctx.safety.ph_max:g}. The water is at pH "
                    f"{est.state.ph:.2f} and has {ph_room:.2f} of room",
                    margin=command.value - safe_ceiling,
                )
            return None

        if kind is WaterCommandKind.CHLORINE_DOSE:
            demand = est.chlorine_demand()
            headroom = demand + ctx.safety.residual_max_mg_l
            if command.value > headroom:
                return RuleFinding(
                    self.rule_id, self.name,
                    f"a chlorine dose of {command.value:g} mg/L into water needing "
                    f"{demand:.2f} mg/L would leave "
                    f"{command.value - demand:.2f} mg/L in the mains, above the "
                    f"{ctx.safety.residual_max_mg_l:g} mg/L limit",
                    margin=command.value - headroom,
                )
            return None

        if kind is WaterCommandKind.COAGULANT_DOSE:
            needed = est.coagulant_needed()
            if needed > 0 and command.value > needed * self.tolerance:
                return RuleFinding(
                    self.rule_id, self.name,
                    f"a coagulant dose of {command.value:g} mg/L is "
                    f"{command.value / needed:.1f} times what water at "
                    f"{est.state.raw_turbidity_ntu:.1f} NTU needs. Overdosing carries "
                    f"floc through the filters instead of settling it",
                    margin=command.value - needed * self.tolerance,
                )
            return None
        return None


# ----------------------------------------------------------------------
# W3, run the works forward under this command
# ----------------------------------------------------------------------
class ConsequenceRule:
    """W3: where does the water end up if this command sticks?"""

    rule_id = "W3"
    name = "consequence"

    def __init__(self, horizon_s: float = 600.0,
                 balance_horizon_s: float = 7200.0) -> None:
        self.horizon_s = horizon_s
        #: How far ahead the water balance is followed. It has to be much
        #: longer than the dosing horizon because the two consequences move at
        #: different speeds: a dose reaches the analyser in under three
        #: minutes, and a clearwell this size takes over an hour to empty. Ten
        #: minutes of prediction cannot see the second one at all, which is how
        #: opening the high-lift pumps right up read as harmless.
        self.balance_horizon_s = balance_horizon_s
        self._metrics: list[Metric] | None = None

    def _limits(self, safety: WaterSafety) -> list[Metric]:
        if self._metrics is None:
            self._metrics = [m for m in catalogue(safety)
                             if m.limit_low is not None or m.limit_high is not None]
        return self._metrics

    def check(self, command: WaterCommand, ctx: WaterContext) -> RuleFinding | None:
        if command.kind.role is PointRole.LIMIT:
            return None   # a ceiling moves nothing; W2 judges it
        before = ctx.estimator.predict(self.horizon_s)
        after = ctx.estimator.predict(self.horizon_s, {command.kind: command.value})

        for metric in self._limits(ctx.safety):
            now_value = metric.value(after)
            was_value = metric.value(before)
            breached = metric.health(now_value).value == "breach"
            if not breached or metric.health(was_value).value == "breach":
                continue   # already heading there without this command
            if metric.limit_high is not None and now_value > metric.limit_high:
                return RuleFinding(
                    self.rule_id, self.name,
                    f"{command.kind.label} of {command.value:g}{command.kind.unit} "
                    f"drives {metric.label.lower()} to {metric.format(now_value)} "
                    f"{metric.unit} within {self.horizon_s / 60:.0f} minutes, past the "
                    f"limit of {metric.format(metric.limit_high)} {metric.unit}",
                    margin=now_value - metric.limit_high,
                )
            if metric.limit_low is not None and now_value < metric.limit_low:
                return RuleFinding(
                    self.rule_id, self.name,
                    f"{command.kind.label} of {command.value:g}{command.kind.unit} "
                    f"drops {metric.label.lower()} to {metric.format(now_value)} "
                    f"{metric.unit} within {self.horizon_s / 60:.0f} minutes, below the "
                    f"minimum of {metric.format(metric.limit_low)} {metric.unit}",
                    margin=metric.limit_low - now_value,
                )
        return self._balance(command, ctx)

    def _balance(self, command: WaterCommand, ctx: WaterContext) -> RuleFinding | None:
        """Does the works still put in as much water as it takes out?

        Checked as a rate rather than as a level at some horizon. A works that
        is sending more to the town than it is treating is on its way out of
        the envelope whether that takes twenty minutes or two hours, and the
        level at any one horizon does not say so.
        """
        after = ctx.estimator.predict(1.0, {command.kind: command.value})
        orders = dict(ctx.estimator.state.commanded)
        orders[command.kind.value] = command.value
        valve = orders.get(WaterCommandKind.FILTER_VALVE.value, 100.0) / 100.0
        inflow = after.raw_flow_m3h * valve
        outflow = after.clearwell_outflow_m3h
        net = inflow - outflow
        area = ctx.works.clearwell_area_m2
        level = ctx.estimator.state.clearwell_level_m
        if net < 0.0:
            store_m3 = (level - ctx.safety.clearwell_min_m) * area
            seconds = store_m3 / max(-net, 1e-6) * 3600.0
            if seconds < self.balance_horizon_s:
                return RuleFinding(
                    self.rule_id, self.name,
                    f"{command.kind.label} of {command.value:g}{command.kind.unit} "
                    f"sends {outflow:.0f} m³/h to the town while the works is "
                    f"treating {inflow:.0f} m³/h, which empties the treated water "
                    f"tank to its minimum in about {seconds / 60:.0f} minutes",
                    margin=-net,
                )
        elif net > 0.0:
            headroom_m3 = (ctx.safety.clearwell_max_m - level) * area
            seconds = headroom_m3 / max(net, 1e-6) * 3600.0
            if seconds < self.balance_horizon_s:
                return RuleFinding(
                    self.rule_id, self.name,
                    f"{command.kind.label} of {command.value:g}{command.kind.unit} "
                    f"treats {inflow:.0f} m³/h while sending {outflow:.0f} m³/h out, "
                    f"which overflows the treated water tank in about "
                    f"{seconds / 60:.0f} minutes",
                    margin=net,
                )
        return None


# ----------------------------------------------------------------------
# W4, three instruments, one chemistry
# ----------------------------------------------------------------------
class CrossInstrumentRule:
    """W4: the dose, the flow and the residual have to tell the same story."""

    rule_id = "W4"
    name = "instrument agreement"

    #: Commands whose safety is decided on the chlorine reading. A disagreement
    #: about the chlorine is a reason to refuse these and no reason at all to
    #: refuse a filter valve or an alarm setting: every rule here blocks, so a
    #: rule that fires on commands it cannot speak to takes the plant down on
    #: the strength of an unrelated instrument.
    bears_on = frozenset({
        WaterCommandKind.CHLORINE_DOSE, WaterCommandKind.MAX_CHLORINE_DOSE,
        WaterCommandKind.HIGH_LIFT_PUMP, WaterCommandKind.CLEARWELL_OUTLET,
    })

    def check(self, command: WaterCommand, ctx: WaterContext) -> RuleFinding | None:
        if command.kind not in self.bears_on:
            return None
        gap, suspect = ctx.estimator.disagreement()
        if not suspect:
            return None
        return RuleFinding(
            self.rule_id, self.name,
            f"the dose pump and the residual analyser disagree by {gap:.2f} mg/L. "
            f"the {suspect} is the one that does not fit the other two, so this "
            f"command is being judged on a reading the guard does not trust",
            margin=gap,
        )


# ----------------------------------------------------------------------
# W5, conservation of water
# ----------------------------------------------------------------------
class MassBalanceRule:
    """W5: what goes in, minus what comes out, is what the tank level says."""

    rule_id = "W5"
    name = "mass balance"

    tolerance_m3h = 260.0

    def check(self, command: WaterCommand, ctx: WaterContext) -> RuleFinding | None:
        b = ctx.estimator.state
        implied = b.raw_flow_m3h - b.outflow_m3h
        # Over a settled plant the stored volume should be changing at about
        # the difference between the two meters. A meter lying about flow has
        # to make the clearwell level lie with it.
        predicted = ctx.estimator.predict(300.0)
        change_m3h = ((predicted.clearwell_level_m - b.clearwell_level_m)
                      * ctx.works.clearwell_area_m2) / (300.0 / 3600.0)
        gap = abs(implied - change_m3h)
        if gap <= self.tolerance_m3h:
            return None
        return RuleFinding(
            self.rule_id, self.name,
            f"the flow meters say the works is gaining {implied:.0f} m³/h but the "
            f"stored volume is changing at {change_m3h:.0f} m³/h. One of the two "
            f"is wrong by {gap:.0f} m³/h",
            margin=gap - self.tolerance_m3h,
        )


# ----------------------------------------------------------------------
# W7, interlocks
# ----------------------------------------------------------------------
class InterlockRule:
    """W7: sequences that are unsafe whatever the numbers say."""

    rule_id = "W7"
    name = "interlock"

    def check(self, command: WaterCommand, ctx: WaterContext) -> RuleFinding | None:
        b = ctx.estimator.state
        kind = command.kind

        if kind is WaterCommandKind.BACKWASH and command.value >= 0.5:
            if b.raw_flow_m3h > 50.0 and b.get(WaterCommandKind.FILTER_VALVE, 0.0) > 5.0:
                return RuleFinding(
                    self.rule_id, self.name,
                    "backwash was commanded while the filter is still in service and "
                    f"passing {b.raw_flow_m3h:.0f} m³/h. The wash water would go "
                    "straight to the clearwell",
                )

        if kind is WaterCommandKind.HIGH_LIFT_PUMP and command.value > 5.0:
            if b.clearwell_level_m < ctx.safety.clearwell_min_m:
                return RuleFinding(
                    self.rule_id, self.name,
                    f"the high-lift pumps were commanded to {command.value:g}% with "
                    f"only {b.clearwell_level_m:.2f} m in the clearwell, below the "
                    f"{ctx.safety.clearwell_min_m:g} m minimum. The pumps would run dry",
                    margin=ctx.safety.clearwell_min_m - b.clearwell_level_m,
                )

        if kind is WaterCommandKind.INTAKE_PUMP and command.value > 70.0:
            if b.filter_headloss_m > ctx.works.filter_headloss_max_m * 0.85:
                return RuleFinding(
                    self.rule_id, self.name,
                    f"raising the raw water pumps to {command.value:g}% with the filter "
                    f"{100 * b.filter_headloss_m / ctx.works.filter_headloss_max_m:.0f}% "
                    "blinded would push dirty water through it",
                )
        return None


# ----------------------------------------------------------------------
# W8, who is allowed to write this
# ----------------------------------------------------------------------
class ProvenanceRule:
    """W8: the point, the device and the zone have to be consistent.

    Weak evidence, and the code says so everywhere this project uses it. An
    attacker on the operator station inherits the operator station's rights.
    What it does catch is a command arriving from a zone that has no business
    issuing one, which is how the Oldsmar session and every jump-server
    intrusion in the catalogue arrived.
    """

    rule_id = "W8"
    name = "provenance"

    #: Which zones may originate a command at all.
    allowed_zones = frozenset({"supervisory", "operations", "control"})

    def check(self, command: WaterCommand, ctx: WaterContext) -> RuleFinding | None:
        if command.zone not in self.allowed_zones:
            return RuleFinding(
                self.rule_id, self.name,
                f"a command arrived from the {command.zone} zone, which does not "
                f"issue commands to the plant at all",
            )
        if command.kind.role is PointRole.LIMIT and command.zone == "supervisory":
            return RuleFinding(
                self.rule_id, self.name,
                f"{command.kind.label} is a configuration change and arrived from the "
                f"supervisory zone. Limits are changed from engineering, under a work "
                f"order, not from an operator screen",
            )
        if command.device and not ctx.topology.may_write(command.device, command.kind):
            return RuleFinding(
                self.rule_id, self.name,
                f"{command.device} is not configured to write {command.kind.label}",
            )
        return None


# ----------------------------------------------------------------------
# W6, the lockout, after the guard has had to act
# ----------------------------------------------------------------------
class LockoutRule:
    """W6: once the guard has tripped, the source that caused it stays out.

    Clearing it is a person's job. Letting the plant come back on its own
    hands the decision to whoever was writing the commands, which under this
    threat model is the party the trip was protecting the water from.
    """

    rule_id = "W6"
    name = "lockout"

    def check(self, command: WaterCommand, ctx: WaterContext) -> RuleFinding | None:
        if not ctx.locked_out:
            return None
        if command.kind.role in (PointRole.DOSE, PointRole.ACTUATOR, PointRole.LIMIT):
            return RuleFinding(
                self.rule_id, self.name,
                "the guard has taken protective action and is holding the plant. "
                "an operator has to acknowledge before commands are accepted again",
            )
        return None


def default_rules() -> list[WaterRule]:
    """In the order they run. Cheapest and most certain first."""
    return [
        RangeRule(),
        ProvenanceRule(),
        LockoutRule(),
        DoseRule(),
        InterlockRule(),
        MassBalanceRule(),
        CrossInstrumentRule(),
        ConsequenceRule(),
    ]
