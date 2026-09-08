"""Deterministic replay of one site scenario through the plant and the guard.

Mirrors :mod:`otguard.eval.harness` and for the same reasons. The loop is the
reference wiring for the site guard:

1. advance the site one scan,
2. read telemetry — all three power measurements and every unit's report, any of
   which the attacker may have rewritten,
3. hand it to the guard, which votes, estimates and supervises; a curtailment
   here is applied to the plant,
4. collect the writes due this scan from the dispatch controller and the
   attacker, run each past the guard, apply only what it allows.

Every scenario runs twice — once enforcing, once with the guard watching but
powerless. Without the second run, "the site did not over-export" is not a
result: it might have been the guard, or it might have been that nothing was
going to happen anyway. The tank version established this and it matters more
here, because several of these attacks do damage slowly enough that a short
scenario could exonerate the guard by accident.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..bess import BessSite
from ..bess.types import BreakerState, SiteCommand, SiteCommandKind, SiteObservation
from ..config import Config
from ..guard.site_guard import SiteGuard, SiteSupervisionEvent, SiteVerdict
from ..scenarios.site_base import ScheduledSiteCommand, SiteScenario

WARMUP_S = 20.0


@dataclass
class SiteSample:
    """One scan of recorded telemetry."""

    t: float
    p_poi_true_mw: float
    p_poi_reported_mw: float
    p_relay_mw: float
    p_telemetry_mw: float
    min_soc: float
    max_temp_c: float
    frequency_hz: float
    suspect_source: str = ""


@dataclass
class SiteRunResult:
    """Everything one scenario replay produced."""

    scenario: SiteScenario
    enforced: bool
    samples: list[SiteSample] = field(default_factory=list)
    verdicts: list[tuple[SiteVerdict, bool]] = field(default_factory=list)
    supervision_events: list[SiteSupervisionEvent] = field(default_factory=list)
    damage: list[str] = field(default_factory=list)
    peak_poi_mw: float = 0.0
    min_soc: float = 1.0
    peak_temp_c: float = 0.0
    first_detection_t: float | None = None
    first_damage_t: float | None = None
    named_source: str = ""

    @property
    def damaged(self) -> bool:
        return bool(self.damage)

    @property
    def detected(self) -> bool:
        return self.first_detection_t is not None

    @property
    def prevented(self) -> bool:
        return self.scenario.is_attack and self.detected and not self.damaged

    def latencies_us(self) -> list[float]:
        return [v.latency_us for v, _ in self.verdicts]

    @property
    def lead_time_s(self) -> float | None:
        if self.first_detection_t is None or self.first_damage_t is None:
            return None
        return self.first_damage_t - self.first_detection_t


def run_site_scenario(
    scenario: SiteScenario, config: Config, enforce: bool = True
) -> SiteRunResult:
    """Replay ``scenario`` once and return the full record."""
    bess = config.bess
    dt = scenario.dt_s or bess.site.dt_s

    site = BessSite(
        bess.site,
        bess.safety,
        bess.pack,
        seed=scenario.seed,
        initial_soc=scenario.initial_soc,
    )
    if scenario.initial_temp_c is not None:
        for unit in site.packs:
            unit.state.temp_c = scenario.initial_temp_c
    site.grid_events = list(scenario.grid_events)

    guard = SiteGuard(
        config,
        initial_soc=scenario.initial_soc,
        initial_temp_c=scenario.initial_temp_c,
    )
    controller = scenario.controller
    if controller is not None:
        controller.reset()

    result = SiteRunResult(scenario=scenario, enforced=enforce)
    pending = sorted(scenario.commands, key=lambda c: c.t)
    next_index = 0

    # -- warm-up: let the estimators lock on before scoring ---------------
    t = -WARMUP_S
    while t < 0.0:
        site.step(dt, t)
        t += dt
        guard.observe(site.observe(t))
    # Warm-up is not scored, and neither are the latches it sets while the
    # estimators converge. Leaving them set would carry a startup transient
    # into the results as a detection.
    guard.reset_log()
    guard.acknowledge()
    _clear_damage(site)

    # -- scored run -------------------------------------------------------
    t = 0.0
    steps = int(round(scenario.duration_s / dt))
    for _ in range(steps):
        site.step(dt, t)
        t = round(t + dt, 6)

        honest = site.observe(t)
        reported = honest
        if scenario.telemetry_attack is not None:
            reported = scenario.telemetry_attack(t, honest)

        guard.sync_ok = site.sync_ok()
        event = guard.observe(reported)
        if event is not None:
            result.supervision_events.append(event)
            _note_detection(result, t, scenario)
            if enforce and event.action is not None:
                for device, value in event.action.pack_power_mw.items():
                    unit = site.pack(device)
                    if unit is not None:
                        unit.set_power(value)
                for device in event.action.cooling_on:
                    unit = site.pack(device)
                    if unit is not None:
                        unit.set_cooling(True)
                if event.action.open_breaker:
                    site.set_breaker(False)

        due: list[ScheduledSiteCommand] = []
        while next_index < len(pending) and pending[next_index].t <= t:
            due.append(pending[next_index])
            next_index += 1
        stop_at = scenario.controller_stops_at
        if controller is not None and (stop_at is None or t < stop_at):
            due.extend(controller.update(t, reported))

        for scheduled in due:
            command = SiteCommand(
                t=t,
                kind=scheduled.kind,
                value=scheduled.value,
                device=scheduled.device,
                source=scheduled.source,
                zone=scheduled.zone,
                conduit=scheduled.conduit,
                protocol=scheduled.protocol,
            )
            verdict = guard.check(command)
            result.verdicts.append((verdict, scheduled.malicious))
            if verdict.flagged:
                _note_detection(result, t, scenario)
            if verdict.allowed or not enforce:
                _apply(site, command)

        # -- telemetry ----------------------------------------------------
        min_soc = min(u.state.soc for u in site.packs)
        max_temp = max(u.state.temp_c for u in site.packs)
        result.samples.append(
            SiteSample(
                t=t,
                p_poi_true_mw=site.state.p_poi_mw,
                p_poi_reported_mw=reported.poi_meter_mw,
                p_relay_mw=reported.relay_mw,
                p_telemetry_mw=reported.telemetry_mw,
                min_soc=min_soc,
                max_temp_c=max_temp,
                frequency_hz=site.state.frequency_hz,
                suspect_source=guard.voter.alarm.value if guard.voter.alarm else "",
            )
        )
        result.peak_poi_mw = max(result.peak_poi_mw, abs(site.state.p_poi_mw))
        result.min_soc = min(result.min_soc, min_soc)
        result.peak_temp_c = max(result.peak_temp_c, max_temp)

        if site.damaged and result.first_damage_t is None:
            result.first_damage_t = t

    result.damage = site.damage_summary()
    result.named_source = guard.voter.alarm.value if guard.voter.alarm else ""
    return result


def _apply(site: BessSite, command: SiteCommand) -> None:
    """Push an accepted command at the plant."""
    unit = site.pack(command.device) if command.device else None
    if command.kind is SiteCommandKind.PACK_POWER and unit is not None:
        unit.set_power(command.value)
    elif command.kind is SiteCommandKind.PACK_REACTIVE and unit is not None:
        unit.set_reactive(command.value)
    elif command.kind is SiteCommandKind.PACK_COOLING and unit is not None:
        unit.set_cooling(bool(command.value))
    elif command.kind is SiteCommandKind.PACK_ENABLE and unit is not None:
        unit.set_online(bool(command.value))
    elif command.kind is SiteCommandKind.BREAKER:
        site.set_breaker(bool(command.value))
    elif command.kind is SiteCommandKind.POI_LIMIT:
        site.poi_limit_mw = command.value
    elif command.kind is SiteCommandKind.RAMP_LIMIT:
        site.ramp_limit_mw_s = command.value


def _clear_damage(site: BessSite) -> None:
    site.state.poi_overloaded = False
    site.state.breaker_damaged = False
    for unit in site.packs:
        unit.state.overcharged = False
        unit.state.deep_discharged = False
        unit.state.overheated = False


def _note_detection(result: SiteRunResult, t: float, scenario: SiteScenario) -> None:
    if result.first_detection_t is not None:
        return
    if scenario.is_attack and not scenario.in_attack_window(t):
        return
    result.first_detection_t = t
