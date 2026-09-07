"""The site rules, B1 to B8.

Each rule is a callable object that looks at one command plus the guard's
current belief about the site, and either objects or does not. They are the
storage-site analogue of the tank's R1..R5, and three of them exist in the shape
they do because of specific mistakes the tank version made and documented:

*The counterfactual test (B3, B5).* R3's lesson was that "does this command's
predicted trajectory violate the limit?" rejects the corrective command too,
because once a process is already heading out of bounds every trajectory looks
bad — including the one that saves it. A guard that blocks the recovery action
is worse than no guard at the moment it matters most. So B3 and B5 object only
when the candidate command is *strictly worse than continuing what is already
being done*.

*Directional lockout (B7).* R5's lesson was that a lockout phrased as "the
resulting equilibrium must be inside the envelope" refuses every recovery
action and strands the plant in the state that caused the trip. B7 latches
against the direction that tripped and leaves the opposite direction available.

*Detector, not tracker (B2).* R4's lesson, carried into
:mod:`~otguard.guard.site_estimator`.

B8 is not a physics rule and is labelled as such wherever it appears. It earns
its place because its authority has the same character: it comes from the site's
architecture, which the attacker on the operator station does not get to
renegotiate, rather than from recognising anything about the attack.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Protocol, Sequence

from ..bess.types import SiteCommand, SiteCommandKind, SiteObservation
from ..config import SiteGuardConfig, SiteConfig, SiteSafetyConfig
from ..site.topology import SiteTopology
from .site_estimator import PackEstimator, SourceVoter
from .types import RuleFinding


@dataclass
class SiteContext:
    """Everything a site rule may consult when judging a command."""

    estimators: dict[str, PackEstimator]
    voter: SourceVoter
    config: SiteGuardConfig
    site: SiteConfig
    safety: SiteSafetyConfig
    topology: SiteTopology
    now: float
    # Live site belief
    poi_limit_mw: float
    ramp_limit_mw_s: float
    site_power_mw: float = 0.0
    frequency_hz: float = 60.0
    breaker_closed: bool = True
    bus_live: bool = True
    fault_current_a: float = 0.0
    sync_ok: bool = True
    # Latches
    lockout_directions: frozenset[str] = frozenset()
    safety_trip_c: float = 52.0
    recent_power: Sequence[tuple[float, float]] = ()
    recent_command_mw: Sequence[tuple[float, float]] = ()
    observation: SiteObservation | None = None

    def commanded_pack_power(self, exclude: str = "") -> float:
        """Sum of the power set-points the guard has accepted so far."""
        return sum(
            est.estimate.p_mw
            for device, est in self.estimators.items()
            if device != exclude
        )

    def estimator(self, device: str) -> PackEstimator | None:
        return self.estimators.get(device)


class SiteRule(Protocol):
    rule_id: str
    name: str

    def check(self, command: SiteCommand, ctx: SiteContext) -> RuleFinding | None:
        ...


# ----------------------------------------------------------------------
# B1 — inverter capability envelope
# ----------------------------------------------------------------------


class CapabilityRule:
    """Reject set-points the unit physically cannot deliver in its state.

    The limit is not a configured number. It is the product of the SoC taper,
    the thermal derate and the inverter's apparent-power circle, all of which
    move as the plant runs. Commanding through it does not produce more power —
    it produces a clamped inverter, heat, and on real equipment a fault trip.

    Note what this rule does *not* do: it does not consult a configured maximum
    that an attacker could raise through the REST API. It recomputes capability
    from the estimated state every time.
    """

    rule_id = "B1"
    name = "capability"

    def check(self, command: SiteCommand, ctx: SiteContext) -> RuleFinding | None:
        if command.kind not in (SiteCommandKind.PACK_POWER, SiteCommandKind.PACK_REACTIVE):
            return None
        est = ctx.estimator(command.device)
        if est is None:
            return None

        model = ctx.config.model
        margin = ctx.config.capability
        soc = est.estimate.soc
        temp = est.estimate.temp_c

        if command.kind is SiteCommandKind.PACK_POWER:
            limit = _capability_mw(model, soc, temp, discharging=command.value >= 0.0)
            if abs(command.value) > limit + margin.margin_mw:
                direction = "discharge" if command.value >= 0 else "charge"
                return RuleFinding(
                    self.rule_id,
                    self.name,
                    f"{command.device} commanded to {direction} at "
                    f"{abs(command.value):.3f} MW but can sustain only {limit:.3f} MW at "
                    f"SoC {soc * 100:.1f}% and {temp:.1f} C",
                    margin=abs(command.value) - limit,
                )
            return None

        # Reactive: the circle, evaluated against the real power already set.
        p_mw = est.estimate.p_mw
        headroom_sq = model.apparent_mva**2 - p_mw**2
        headroom = math.sqrt(headroom_sq) if headroom_sq > 0 else 0.0
        if abs(command.value) > headroom + margin.margin_mvar:
            return RuleFinding(
                self.rule_id,
                self.name,
                f"{command.device} commanded to {abs(command.value):.3f} MVAr with "
                f"{p_mw:.3f} MW real power: apparent power would be "
                f"{math.hypot(p_mw, command.value):.3f} MVA against a "
                f"{model.apparent_mva:.2f} MVA inverter",
                margin=abs(command.value) - headroom,
            )
        return None


def _capability_mw(model, soc: float, temp_c: float, discharging: bool) -> float:
    """The guard's model of what one unit can do right now."""
    thermal = 1.0
    if temp_c > model.temp_derate_c:
        span = max(model.temp_max_c - model.temp_derate_c, 1e-6)
        thermal = max(0.0, min(1.0, (model.temp_max_c - temp_c) / span))
    if discharging:
        soc_factor = 1.0 if soc >= model.soc_derate_low else max(0.0, soc / max(model.soc_derate_low, 1e-6))
    else:
        span = max(1.0 - model.soc_derate_high, 1e-6)
        soc_factor = 1.0 if soc <= model.soc_derate_high else max(0.0, (1.0 - soc) / span)
    return model.power_mw * soc_factor * thermal


# ----------------------------------------------------------------------
# B2 — energy conservation
# ----------------------------------------------------------------------


class EnergyRule:
    """Raise the estimator's standing objection to a unit that is lying.

    The detection happens continuously in :class:`PackEstimator`; this rule is
    how that latched state reaches a command decision. A unit whose reported SoC
    has stopped matching its own energy balance is not a unit whose set-points
    should be honoured, because every other rule's view of its capability is
    computed from a number it is fabricating.
    """

    rule_id = "B2"
    name = "energy"

    def check(self, command: SiteCommand, ctx: SiteContext) -> RuleFinding | None:
        if not command.device:
            return None
        est = ctx.estimator(command.device)
        if est is None or not est.estimate.integrity_alarm:
            return None
        return RuleFinding(
            self.rule_id,
            self.name,
            est.estimate.alarm_detail,
            margin=est.estimate.soc_cusum,
        )


# ----------------------------------------------------------------------
# B3 — site power balance and the export limit
# ----------------------------------------------------------------------


class BalanceRule:
    """Keep the fleet's aggregate inside the interconnection.

    Two separate objections, and the second is the one that matters:

    *Absolute.* The commanded aggregate would put the POI beyond the
    transformer's rating. This is checked against ``poi_rating_mw`` — the
    nameplate — and not against the writable ``poi_limit_mw``, so raising the
    limit through the REST API does not buy the attacker anything.

    *Incremental.* The aggregate is already over the contractual limit and this
    command makes it worse. Phrased as the counterfactual — strictly worse than
    holding — so that a command *reducing* an existing excursion is allowed
    through. Without that, the guard blocks the operator's own attempt to fix
    the problem, which is exactly the failure the tank version's R3 was rewritten
    to avoid.

    The interesting case this catches is the distributed one: sixteen individually
    plausible set-points whose *sum* is not. No per-unit rule can see it.
    """

    rule_id = "B3"
    name = "balance"

    def check(self, command: SiteCommand, ctx: SiteContext) -> RuleFinding | None:
        if command.kind not in (
            SiteCommandKind.PACK_POWER,
            SiteCommandKind.SITE_POWER,
            SiteCommandKind.POI_LIMIT,
        ):
            return None

        cfg = ctx.config.balance

        # A limit is only meaningful up to the iron it is protecting.
        if command.kind is SiteCommandKind.POI_LIMIT:
            if command.value > ctx.site.poi_rating_mw:
                return RuleFinding(
                    self.rule_id,
                    self.name,
                    f"export limit raised to {command.value:.1f} MW, above the "
                    f"{ctx.site.poi_rating_mw:.1f} MW transformer rating: no "
                    f"authorisation makes this deliverable",
                    margin=command.value - ctx.site.poi_rating_mw,
                )
            return None

        if command.kind is SiteCommandKind.PACK_POWER:
            proposed = ctx.commanded_pack_power(exclude=command.device) + command.value
            held = ctx.commanded_pack_power()
        else:
            proposed = command.value
            held = ctx.site_power_mw

        projected_poi = _poi_from_bus(proposed, ctx.site)
        held_poi = _poi_from_bus(held, ctx.site)

        if abs(projected_poi) > ctx.site.poi_rating_mw:
            return RuleFinding(
                self.rule_id,
                self.name,
                f"aggregate set-point of {proposed:.2f} MW puts the point of "
                f"interconnection at {projected_poi:.2f} MW, past the "
                f"{ctx.site.poi_rating_mw:.1f} MW transformer rating",
                margin=abs(projected_poi) - ctx.site.poi_rating_mw,
            )

        limit = ctx.poi_limit_mw + cfg.limit_grace_mw
        if abs(projected_poi) > limit and abs(projected_poi) > abs(held_poi) + cfg.poi_margin_mw:
            return RuleFinding(
                self.rule_id,
                self.name,
                f"aggregate set-point of {proposed:.2f} MW takes the interconnection "
                f"to {projected_poi:.2f} MW against a {ctx.poi_limit_mw:.1f} MW export "
                f"limit, and is worse than the {held_poi:.2f} MW already commanded",
                margin=abs(projected_poi) - ctx.poi_limit_mw,
            )
        return None


def _poi_from_bus(p_bus_mw: float, site: SiteConfig) -> float:
    """Model the transformer between the LV bus and the meter."""
    rated = max(site.poi_rating_mw, 1e-9)
    loss = site.transformer_loss_mw * (p_bus_mw / rated) ** 2 + site.transformer_noload_mw
    aux = site.aux_base_mw
    return p_bus_mw - aux - loss


# ----------------------------------------------------------------------
# B4 — ramp, with the frequency exemption
# ----------------------------------------------------------------------


class RampRule:
    """Limit how fast the site changes output — unless the grid asked it to.

    A battery slamming from full charge to full discharge stresses the
    transformer and violates the interconnection agreement. But that same slam
    is precisely the correct, contracted behaviour during a frequency
    excursion — it is what fast frequency response *is*, and a guard that blocks
    it has broken the site's primary revenue service and its obligation to the
    grid.

    So the rule is not a threshold on ramp rate. It is a threshold conditioned on
    grid frequency: outside the normal band the allowance opens up by
    ``event_multiplier``. This is the clearest case in the project of physics
    supplying *context* rather than a limit — the same command is plausible or
    not depending on a measurement the attacker does not control.

    An attacker who wants the fast ramp must therefore also fake a frequency
    excursion, which means corrupting the relay and the meter's frequency
    channels rather than just writing a set-point.
    """

    rule_id = "B4"
    name = "ramp"

    def check(self, command: SiteCommand, ctx: SiteContext) -> RuleFinding | None:
        if command.kind not in (SiteCommandKind.PACK_POWER, SiteCommandKind.SITE_POWER):
            return None

        cfg = ctx.config.ramp
        if command.kind is SiteCommandKind.PACK_POWER:
            proposed = ctx.commanded_pack_power(exclude=command.device) + command.value
        else:
            proposed = command.value

        window = [(t, p) for t, p in ctx.recent_command_mw if ctx.now - t <= cfg.window_s]
        if not window:
            return None
        reference_t, reference_p = window[0]
        elapsed = max(ctx.now - reference_t, 1e-6)
        rate = abs(proposed - reference_p) / elapsed

        deviation_hz = abs(ctx.frequency_hz - ctx.site.nominal_frequency_hz)
        event = deviation_hz > cfg.deadband_hz
        allowance = ctx.ramp_limit_mw_s * (cfg.event_multiplier if event else 1.0)

        if rate <= allowance:
            return None

        context = (
            f"grid at {ctx.frequency_hz:.3f} Hz ({deviation_hz:.3f} Hz off nominal), "
            f"which does not call for a fast response"
            if not event
            else f"frequency excursion to {ctx.frequency_hz:.3f} Hz already allowed for"
        )
        return RuleFinding(
            self.rule_id,
            self.name,
            f"site power would move {abs(proposed - reference_p):.2f} MW in "
            f"{elapsed:.2f}s ({rate:.2f} MW/s) against a {allowance:.2f} MW/s "
            f"allowance: {context}",
            margin=rate - allowance,
        )


# ----------------------------------------------------------------------
# B5 — thermal lookahead
# ----------------------------------------------------------------------


class ThermalRule:
    """Object when a command drives a unit past its thermal trip.

    Counterfactual, like B3: the question is not "will this unit get hot?" but
    "does this command make the trajectory worse than what is already running?".
    A pack that is already climbing toward its limit needs its power *reduced*,
    and a rule phrased absolutely would reject the reduction along with
    everything else.

    Cooling state is part of the projection, which is what makes the
    thermal-management shutdown attack visible here: with the fans commanded off
    the same power set-point produces a completely different trajectory, and the
    lookahead sees it long before the temperature does.
    """

    rule_id = "B5"
    name = "thermal"

    def check(self, command: SiteCommand, ctx: SiteContext) -> RuleFinding | None:
        if command.kind not in (
            SiteCommandKind.PACK_POWER,
            SiteCommandKind.PACK_REACTIVE,
            SiteCommandKind.PACK_COOLING,
        ):
            return None
        est = ctx.estimator(command.device)
        if est is None:
            return None

        cfg = ctx.config.thermal
        trip_c = ctx.safety_trip_c
        held_power = est.estimate.p_mw
        held_cooling = est.estimate.cooling_enabled

        if command.kind is SiteCommandKind.PACK_POWER:
            candidate_power, candidate_cooling = command.value, held_cooling
        elif command.kind is SiteCommandKind.PACK_COOLING:
            candidate_power, candidate_cooling = held_power, bool(command.value)
        else:
            candidate_power, candidate_cooling = held_power, held_cooling

        _, held_peak = _project_temp(est, cfg.horizon_s, held_power, held_cooling)
        _, candidate_peak = _project_temp(est, cfg.horizon_s, candidate_power, candidate_cooling)

        # Where the commanded configuration *settles*, not just where it gets
        # to inside the horizon. With thermal management off the time constant
        # runs to hours, so a 300 s lookahead sees a couple of degrees and stays
        # quiet while the unit is on its way to well past the trip. The
        # equilibrium needs no horizon at all: it is the temperature at which
        # generated heat and removed heat balance, and if that is beyond the
        # trip the unit gets there eventually no matter how slowly.
        candidate_eq = _equilibrium_temp(est, candidate_power, candidate_cooling)
        held_eq = _equilibrium_temp(est, held_power, held_cooling)
        if candidate_eq > trip_c and candidate_eq > held_eq + 1e-6:
            detail = (
                f"{command.device} settles at {candidate_eq:.0f} C under the "
                f"commanded configuration against a {trip_c:.1f} C trip, versus "
                f"{held_eq:.0f} C for the command it currently holds"
            )
            if command.kind is SiteCommandKind.PACK_COOLING and not candidate_cooling:
                detail = (
                    f"{command.device} thermal management commanded off: with "
                    f"{held_power:.2f} MW held the unit settles at {candidate_eq:.0f} C "
                    f"against a {trip_c:.1f} C trip (it settles at {held_eq:.0f} C with "
                    f"cooling running). The approach is slow, so the horizon check "
                    f"cannot see it, but the destination is outside the envelope"
                )
            return RuleFinding(self.rule_id, self.name, detail, margin=candidate_eq - trip_c)

        if candidate_peak <= trip_c - cfg.margin_c:
            return None
        if candidate_peak <= held_peak + 1e-6:
            # Already heading there; this command is not what is doing it, and
            # refusing it would block the operator's way out.
            return None

        detail = (
            f"{command.device} would reach {candidate_peak:.1f} C within "
            f"{cfg.horizon_s:g}s against a {trip_c:.1f} C trip, worse than the "
            f"{held_peak:.1f} C implied by the command it currently holds"
        )
        if command.kind is SiteCommandKind.PACK_COOLING and not candidate_cooling:
            detail = (
                f"{command.device} thermal management commanded off: temperature "
                f"reaches {candidate_peak:.1f} C within {cfg.horizon_s:g}s against a "
                f"{trip_c:.1f} C trip, versus {held_peak:.1f} C with cooling running"
            )
        return RuleFinding(self.rule_id, self.name, detail, margin=candidate_peak - trip_c)


def _equilibrium_temp(est: PackEstimator, p_mw: float, cooling: bool) -> float:
    """Temperature at which conversion loss equals heat removal."""
    m = est.model
    rated = max(m.power_mw, 1e-9)
    loss_at_rated = rated * (1.0 - m.efficiency)
    delivered = est.deliverable_mw(p_mw, est.estimate.soc, est.estimate.temp_c)
    s = math.hypot(delivered, est.estimate.q_mvar)
    loss = loss_at_rated * (s / rated) ** 2
    coeff = m.cooling_mw_per_c if cooling else m.cooling_mw_per_c * 0.1
    return m.ambient_c + loss / max(coeff, 1e-12)


def _project_temp(est: PackEstimator, horizon_s: float, p_mw: float, cooling: bool):
    """Roll one unit's temperature forward under a hypothetical command."""
    e = est.estimate
    soc, temp = e.soc, e.temp_c
    actual = est._p_actual_mw
    peak = temp
    dt = 5.0
    for _ in range(max(1, int(horizon_s / dt))):
        target = est.deliverable_mw(p_mw, soc, temp)
        step = est.model.slew_mw_s * dt
        actual += max(-step, min(step, target - actual))
        soc = est.predict_soc(soc, actual, dt)
        temp = est.predict_temp(temp, actual, e.q_mvar, dt, cooling)
        peak = max(peak, temp)
    return soc, peak


# ----------------------------------------------------------------------
# B6 — cross-source agreement
# ----------------------------------------------------------------------


class CrossSourceRule:
    """Surface the voter's standing objection about a lying measurement.

    Like B2 this rule does not do the detection — :class:`SourceVoter` does,
    continuously — it carries the latched result into command decisions.

    Enforcement is ``alarm`` rather than ``block`` by default and that is a
    deliberate call. Knowing the revenue meter is lying does not by itself make
    any particular set-point wrong; what it does is tell the rest of the guard
    which number to believe, which it does through
    :meth:`SourceVoter.trusted_power_mw`. Blocking every command because a
    meter is suspect would take the site offline over an instrument fault.
    """

    rule_id = "B6"
    name = "crosssource"

    def check(self, command: SiteCommand, ctx: SiteContext) -> RuleFinding | None:
        if not ctx.config.crosssource.enabled:
            return None
        if ctx.voter.alarm is None:
            return None
        return RuleFinding(
            self.rule_id,
            self.name,
            ctx.voter.alarm_detail,
            margin=ctx.voter.cusum.get(ctx.voter.alarm, 0.0),
        )


# ----------------------------------------------------------------------
# B7 — switchgear interlocks
# ----------------------------------------------------------------------


class InterlockRule:
    """Refuse breaker operations the switchyard should not accept.

    Three objections:

    *Out of sync.* Closing onto a live bus that does not match in voltage,
    frequency and angle destroys machines in one cycle. This is what a 25 relay
    exists for, and it is one of the few OT actions with no recovery.

    *Latched lockout.* After a protective trip the breaker stays out until a
    human clears it. A trip the HMI can immediately undo is not a protection —
    the tank version learned this as R5 — so the latch holds against the
    direction that tripped and is cleared only by
    :meth:`SiteGuard.acknowledge`.

    *Uncorroborated trip.* A GOOSE trip message asserting a fault while the
    relay's own current measurement shows nothing near fault levels is a forged
    trip. This is the physics check on a protection signal: the frame can be
    faked, the current cannot.
    """

    rule_id = "B7"
    name = "interlock"

    def check(self, command: SiteCommand, ctx: SiteContext) -> RuleFinding | None:
        if command.kind is not SiteCommandKind.BREAKER:
            return None
        cfg = ctx.config.interlock
        closing = bool(command.value)

        if closing and "close" in ctx.lockout_directions:
            return RuleFinding(
                self.rule_id,
                self.name,
                "breaker close refused: a protective trip is latched and has not "
                "been acknowledged by an operator",
            )

        if closing and cfg.require_sync and not ctx.sync_ok:
            return RuleFinding(
                self.rule_id,
                self.name,
                f"breaker close with synchronism check failed: bus is live at "
                f"{ctx.frequency_hz:.3f} Hz and the site is not matched to it",
                margin=abs(ctx.frequency_hz - ctx.site.nominal_frequency_hz),
            )

        if not closing and ctx.fault_current_a < cfg.fault_corroboration_a:
            return RuleFinding(
                self.rule_id,
                self.name,
                f"trip asserted with only {ctx.fault_current_a:.0f} A measured, below "
                f"the {cfg.fault_corroboration_a:.0f} A that would indicate a real "
                f"fault: the protection signal is not corroborated by the current it "
                f"claims to be responding to",
                margin=cfg.fault_corroboration_a - ctx.fault_current_a,
            )
        return None


# ----------------------------------------------------------------------
# B8 — provenance (not a physics rule)
# ----------------------------------------------------------------------


class ProvenanceRule:
    """Check that a write arrived by a path the architecture permits.

    Explicitly *not* physics. It is included because it is the rule that makes
    the jump server and the firewall mean something operationally, and because
    its authority has the same character as the physics rules: the site's
    segmentation is not something an attacker on the operator station can
    renegotiate by sending a different value.

    The limitation is equally explicit: this trusts the provenance metadata on
    the command. In a real deployment that metadata comes from the firewall and
    the bastion's session records, and an attacker who can forge it defeats this
    rule completely. It is a check on the architecture being followed, not a
    cryptographic proof of origin.
    """

    rule_id = "B8"
    name = "provenance"

    def check(self, command: SiteCommand, ctx: SiteContext) -> RuleFinding | None:
        cfg = ctx.config.provenance
        if not cfg.enabled:
            return None

        # A conduit describes traffic *between* zones. The site controller
        # dispatching from within the control zone does not cross one, and
        # demanding a conduit for it would flag the site's own normal operation
        # — the single largest source of benign traffic there is.
        if command.zone in cfg.control_zones:
            return None

        conduit = ctx.topology.permitted(command.zone, "control", command.protocol)
        if conduit is None:
            levels = ctx.topology.crosses_levels(command.zone, "control")
            return RuleFinding(
                self.rule_id,
                self.name,
                f"{command.kind.value} arrived from the '{command.zone}' zone over "
                f"{command.protocol}, which no conduit permits into the control zone "
                f"({levels:g} Purdue levels away)",
                margin=levels,
            )

        if conduit.via and cfg.require_jump_server and command.source != conduit.via:
            return RuleFinding(
                self.rule_id,
                self.name,
                f"{command.kind.value} from '{command.zone}' reached the control zone "
                f"via '{command.source or 'an unrecorded host'}' rather than the "
                f"'{conduit.via}' bastion the '{conduit.name}' conduit requires",
            )

        if not command.kind.is_control and command.zone not in cfg.engineering_zones:
            return RuleFinding(
                self.rule_id,
                self.name,
                f"{command.kind.value} is an engineering change but arrived from the "
                f"'{command.zone}' zone, which is authorised for dispatch only",
            )
        return None


def default_site_rules() -> list[SiteRule]:
    """The rule set, in the order findings are reported."""
    return [
        CapabilityRule(),
        EnergyRule(),
        BalanceRule(),
        RampRule(),
        ThermalRule(),
        CrossSourceRule(),
        InterlockRule(),
        ProvenanceRule(),
    ]
