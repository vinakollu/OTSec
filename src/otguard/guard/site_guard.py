"""``SiteGuard`` — the bump-in-the-wire decision engine for a storage site.

Same shape as :class:`~otguard.guard.guard.PhysicsGuard`, and deliberately so:
``observe`` for telemetry flowing back, ``check`` for commands heading in,
protocol-agnostic in between. What differs is what it has to keep track of —
sixteen units instead of one actuator pair, three power measurements instead of
one level transmitter, and a switchyard.

The ordering inside ``observe`` matters and is worth stating, because getting it
wrong produces a guard that looks like it works:

1. **Vote first.** Decide which measurements to believe before using any of
   them. Everything downstream reads site power through
   :meth:`SourceVoter.trusted_power_mw`, so a meter that has been caught lying
   is out of the picture by the time the rules run.
2. **Then update the per-unit estimators**, driven by accepted commands and
   corrected — weakly — by what each unit reports about itself.
3. **Then supervise.** Re-check the standing orders against the envelope. This
   is what catches the attack that sends one legal command and waits, which the
   tank version found the hard way was invisible to a command-time-only guard.

The trip the guard can issue is a curtailment, not a shutdown. Dropping a
storage site to zero on a suspected instrument fault is itself an availability
incident, and on a site providing frequency response it is a grid event. So the
protective action reduces set-points to what the *trusted* measurements say is
inside the envelope, and latches so the HMI cannot immediately undo it.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Iterable, Sequence

from ..bess.types import BreakerState, SiteCommand, SiteCommandKind, SiteObservation
from ..config import Config
from ..site.topology import SiteTopology, default_site_topology
from .site_estimator import PackEstimator, SourceVoter, VoteResult
from .site_rules import SiteContext, SiteRule, default_site_rules
from .types import Decision, RuleFinding, Verdict

_POWER_HISTORY = 256


@dataclass(frozen=True)
class SiteProtectiveAction:
    """A curtailment the guard issues on its own authority."""

    t: float
    pack_power_mw: dict[str, float] = field(default_factory=dict)
    open_breaker: bool = False
    cooling_on: tuple[str, ...] = ()
    reason: str = ""

    def __str__(self) -> str:
        bits = []
        if self.pack_power_mw:
            total = sum(self.pack_power_mw.values())
            bits.append(f"curtail {len(self.pack_power_mw)} units to {total:.2f} MW")
        if self.cooling_on:
            bits.append(f"restore cooling on {', '.join(self.cooling_on)}")
        if self.open_breaker:
            bits.append("open main breaker")
        return f"TRIP t={self.t:7.2f}s {'; '.join(bits)}  <- {self.reason}"


@dataclass
class SiteSupervisionEvent:
    t: float
    findings: list[RuleFinding]
    action: SiteProtectiveAction | None = None


@dataclass
class SiteVerdict:
    """The guard's ruling on one site command.

    Structurally identical to :class:`~otguard.guard.types.Verdict` so that the
    existing metrics code scores both without a special case.
    """

    command: SiteCommand
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

    def __str__(self) -> str:
        head = f"{self.decision.value.upper():5s} {self.command}"
        if not self.findings:
            return head
        return head + "  <- " + "; ".join(str(f) for f in self.findings)


@dataclass
class SiteStats:
    commands_seen: int = 0
    allowed: int = 0
    alarmed: int = 0
    blocked: int = 0
    findings_by_rule: dict[str, int] = field(default_factory=dict)

    def record(self, verdict: SiteVerdict) -> None:
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


class SiteGuard:
    """Evaluates storage-site commands against the physics of the site."""

    def __init__(
        self,
        config: Config,
        rules: Sequence[SiteRule] | None = None,
        topology: SiteTopology | None = None,
        devices: Sequence[str] | None = None,
    ) -> None:
        self.config = config
        self.bess = config.bess
        self.rules: list[SiteRule] = list(rules) if rules is not None else default_site_rules()
        self.topology = topology or default_site_topology(self.bess.site.n_packs)

        device_ids = list(devices) if devices is not None else [
            f"MP{i + 1:02d}" for i in range(self.bess.site.n_packs)
        ]
        self.estimators: dict[str, PackEstimator] = {
            device: PackEstimator(
                device=device,
                model=self.bess.guard.model,
                energy=self.bess.guard.energy,
                initial_soc=self.bess.pack.initial_soc,
                initial_temp_c=self.bess.pack.ambient_c,
            )
            for device in device_ids
        }
        self.voter = SourceVoter(self.bess.guard.crosssource, self.bess.guard.model)

        # Live site belief, updated from telemetry and accepted commands.
        self.poi_limit_mw = self.bess.site.poi_limit_mw
        self.ramp_limit_mw_s = self.bess.site.ramp_limit_mw_s
        self.site_power_mw = 0.0
        self.frequency_hz = self.bess.site.nominal_frequency_hz
        self.breaker_closed = True
        self.bus_live = True
        self.fault_current_a = 0.0
        self.sync_ok = True

        self._power_history: deque[tuple[float, float]] = deque(maxlen=_POWER_HISTORY)
        self._now = 0.0
        self._last_trip_t: dict[str, float] = {}
        self.lockout_directions: set[str] = set()
        self.trip_latched = False

        self.stats = SiteStats()
        self.verdicts: list[SiteVerdict] = []
        self.supervision_events: list[SiteSupervisionEvent] = []
        self.votes: list[VoteResult] = []

    # ------------------------------------------------------------------
    # Telemetry
    # ------------------------------------------------------------------
    def observe(self, observation: SiteObservation) -> SiteSupervisionEvent | None:
        """Ingest one scan: vote, estimate, supervise."""
        dt = max(observation.t - self._now, 0.0) or self.bess.site.dt_s
        self._now = observation.t

        # 1. Decide what to believe before believing anything.
        vote = self.voter.vote(observation)
        self.votes.append(vote)

        # 2. Per-unit estimates, driven by commands and weakly corrected.
        for report in observation.packs:
            est = self.estimators.get(report.device)
            if est is not None:
                est.update(report.soc, report.temp_c, dt)

        # 3. Site belief from the sources still trusted.
        self.site_power_mw = self.voter.trusted_power_mw(observation)
        self.frequency_hz = observation.frequency_hz
        self.breaker_closed = observation.breaker is BreakerState.CLOSED
        self.bus_live = observation.bus_live
        self.fault_current_a = observation.fault_current_a
        self._power_history.append((observation.t, self.site_power_mw))

        return self._supervise(observation)

    def _supervise(self, observation: SiteObservation) -> SiteSupervisionEvent | None:
        """Re-check standing orders. Edge-triggered per direction."""
        cfg = self.bess.guard.supervision
        if not cfg.enabled:
            return None

        findings: list[RuleFinding] = []
        curtail: dict[str, float] = {}
        restore_cooling: list[str] = []
        direction = ""

        # --- POI excursion under the trusted measurement ---
        rating = self.bess.site.poi_rating_mw
        if abs(self.site_power_mw) > rating:
            direction = "export" if self.site_power_mw > 0 else "import"
            scale = (self.poi_limit_mw / abs(self.site_power_mw)) if self.site_power_mw else 0.0
            for device, est in self.estimators.items():
                curtail[device] = est.estimate.p_mw * scale
            findings.append(
                RuleFinding(
                    "B3",
                    "supervision",
                    f"interconnection at {self.site_power_mw:.2f} MW against a "
                    f"{rating:.1f} MW rating on the measurements still trusted; "
                    f"curtailing the fleet to {self.poi_limit_mw:.1f} MW",
                    margin=abs(self.site_power_mw) - rating,
                )
            )

        # --- thermal runaway on any unit ---
        trip_c = self.bess.guard.model.temp_trip_c
        horizon = self.bess.guard.thermal.horizon_s
        for device, est in self.estimators.items():
            _, peak = est.project(horizon)
            if peak <= trip_c:
                continue
            direction = direction or "thermal"
            if not est.estimate.cooling_enabled:
                restore_cooling.append(device)
            curtail.setdefault(device, 0.0)
            findings.append(
                RuleFinding(
                    "B5",
                    "supervision",
                    f"{device} reaches {peak:.1f} C within {horizon:g}s against a "
                    f"{trip_c:.1f} C trip while holding {est.estimate.p_mw:.2f} MW"
                    + ("" if est.estimate.cooling_enabled else " with cooling commanded off"),
                    margin=peak - trip_c,
                )
            )

        if not findings:
            return None

        previous = self._last_trip_t.get(direction)
        rearmed = previous is None or (observation.t - previous) >= cfg.rearm_after_s
        action = None
        if cfg.trip and rearmed:
            action = SiteProtectiveAction(
                t=observation.t,
                pack_power_mw=curtail,
                cooling_on=tuple(restore_cooling),
                reason="; ".join(f.detail for f in findings),
            )
            self._last_trip_t[direction] = observation.t
            for device, value in curtail.items():
                est = self.estimators.get(device)
                if est is not None:
                    est.note_power(value)
            for device in restore_cooling:
                est = self.estimators.get(device)
                if est is not None:
                    est.note_cooling(True)
            if cfg.latch_trip:
                self.trip_latched = True
                if direction:
                    self.lockout_directions.add(direction)

        event = SiteSupervisionEvent(t=observation.t, findings=findings, action=action)
        self.supervision_events.append(event)
        for finding in findings:
            self.stats.findings_by_rule[finding.rule_id] = (
                self.stats.findings_by_rule.get(finding.rule_id, 0) + 1
            )
        return event

    # ------------------------------------------------------------------
    # Commands
    # ------------------------------------------------------------------
    def check(self, command: SiteCommand) -> SiteVerdict:
        """Judge one command. This is the call on the real-time path."""
        started = time.perf_counter()
        self._now = max(self._now, command.t)

        ctx = SiteContext(
            estimators=self.estimators,
            voter=self.voter,
            config=self.bess.guard,
            site=self.bess.site,
            safety=self.bess.safety,
            topology=self.topology,
            now=command.t,
            poi_limit_mw=self.poi_limit_mw,
            ramp_limit_mw_s=self.ramp_limit_mw_s,
            site_power_mw=self.site_power_mw,
            frequency_hz=self.frequency_hz,
            breaker_closed=self.breaker_closed,
            bus_live=self.bus_live,
            fault_current_a=self.fault_current_a,
            sync_ok=self.sync_ok,
            lockout_directions=frozenset(self.lockout_directions),
            safety_trip_c=self.bess.guard.model.temp_trip_c,
            recent_power=tuple(self._power_history),
        )

        findings: list[RuleFinding] = []
        for rule in self.rules:
            finding = rule.check(command, ctx)
            if finding is not None:
                findings.append(finding)

        decision = self._decide(findings)
        if decision is not Decision.BLOCK:
            self._accept(command)

        latency_us = (time.perf_counter() - started) * 1e6
        verdict = SiteVerdict(
            command=command, decision=decision, findings=findings, latency_us=latency_us
        )
        self.stats.record(verdict)
        self.verdicts.append(verdict)
        return verdict

    def _accept(self, command: SiteCommand) -> None:
        """Fold an allowed command into the guard's belief."""
        est = self.estimators.get(command.device)
        if command.kind is SiteCommandKind.PACK_POWER and est is not None:
            est.note_power(command.value)
        elif command.kind is SiteCommandKind.PACK_REACTIVE and est is not None:
            est.note_reactive(command.value)
        elif command.kind is SiteCommandKind.PACK_COOLING and est is not None:
            est.note_cooling(bool(command.value))
        elif command.kind is SiteCommandKind.PACK_ENABLE and est is not None:
            if not command.value:
                est.note_power(0.0)
        elif command.kind is SiteCommandKind.POI_LIMIT:
            self.poi_limit_mw = command.value
        elif command.kind is SiteCommandKind.RAMP_LIMIT:
            self.ramp_limit_mw_s = command.value
        elif command.kind is SiteCommandKind.BREAKER:
            self.breaker_closed = bool(command.value)

    def _decide(self, findings: Iterable[RuleFinding]) -> Decision:
        decision = Decision.ALLOW
        for finding in findings:
            mode = self.bess.guard.enforcement.for_rule(finding.rule_id)
            if mode == "block":
                return Decision.BLOCK
            decision = Decision.ALARM
        return decision

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------
    @property
    def estimated_soc(self) -> dict[str, float]:
        return {d: e.estimate.soc for d, e in self.estimators.items()}

    @property
    def estimated_temp_c(self) -> dict[str, float]:
        return {d: e.estimate.temp_c for d, e in self.estimators.items()}

    @property
    def suspect_source(self):
        return self.voter.alarm

    def latencies_us(self) -> list[float]:
        return [v.latency_us for v in self.verdicts]

    def acknowledge(self) -> None:
        """Operator reset. Manual by design — see PhysicsGuard.acknowledge."""
        self.trip_latched = False
        self.lockout_directions.clear()
        self._last_trip_t.clear()
        self.voter.acknowledge()
        for est in self.estimators.values():
            est.acknowledge()

    def reset_log(self) -> None:
        self.verdicts.clear()
        self.supervision_events.clear()
        self.votes.clear()
        self.stats = SiteStats()
