"""The storage site running live, with somebody able to interfere with it.

The same shape as :mod:`otguard.live.water_demo`, against a plant with a
different argument. The works is about a quantity nobody measures. This site is
about a quantity three people measure and what happens when two of them stop
telling the truth, or stop talking at all.

Two of the ten attacks here are in the list because the guard loses to them.
``stealth_creep`` walks the fleet past the export limit in steps too small for
the rule that judges whether a command makes an existing excursion worse, and
``cut_two_links`` takes the cross-check apart without touching a single meter.
Leaving them off the page would make the demonstration a sales pitch.

As with the works, the twenty-two devices and six zones are a model rather than
twenty-two listening servers. What is not modelled is the guard: every verdict
is the real B1 to B8 rule set deciding about the power the simulation is
actually moving.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import random
import time
from dataclasses import dataclass, field

from ..bess.metrics import HEADLINE, Area, assess, catalogue, read_site

from ..bess.site import BessSite, GridEvent
from ..bess.types import MeasurementSource, SiteCommand, SiteCommandKind as K
from ..clock import SimClock, SteppedClock
from ..config import Config, load_config
from ..guard.site_guard import SiteGuard
from ..guard.types import Decision
from ..site.topology import default_site_topology
from . import plain
from .bus import EventBus
from .events import Kind, LiveEvent

log = logging.getLogger(__name__)

#: What each writer is called here. A battery yard does not have "the plant's
#: automatic control system"; it has a site controller.
SITE_NAMES = {
    "scada": "the site controller",
    "hmi": "the operator's screen in the control room",
    "engineering": "the engineering workstation, through the jump server",
    "enterprise": "a machine on the corporate office network",
}

SOURCE_LABEL = {
    MeasurementSource.POI_METER: "revenue meter",
    MeasurementSource.TELEMETRY: "battery telemetry",
    MeasurementSource.RELAY: "protection relay",
}


@dataclass(frozen=True)
class Attack:
    """One thing somebody can do to the site from the page."""

    name: str
    title: str
    story: str
    source: str                 # which device it comes from
    zone: str
    conduit: str = "scada_to_control"
    #: (delay_s, command kind, value, device), device "" means site-wide,
    #: "*" means every unit.
    steps: tuple[tuple[float, K, float, str], ...] = ()
    hold_s: float = 240.0
    #: Things that are not commands: a meter bias, or links going dark.
    bias: tuple[MeasurementSource, float] | None = None   # source, MW per second
    cut_links: tuple[MeasurementSource, ...] = ()
    #: An exogenous grid condition: (delay_s, duration_s, frequency_hz).
    #: Closing a breaker is only dangerous when the two sides do not match,
    #: and nothing the attacker writes can make them differ. The grid has to.
    grid_slip: tuple[float, float, float] | None = None
    #: False when the damage is to what the guard knows rather than to the
    #: equipment. Biasing a meter moves no power; it moves the number
    #: everybody is reading, and the guard wins by naming which instrument is
    #: wrong rather than by preventing a breakage. Scoring that attack on
    #: damage would mark a success as a failure.
    harm_is_physical: bool = True
    beats_the_guard: bool = False

    @property
    def span_s(self) -> float:
        return max((d for d, _, _, _ in self.steps), default=0.0) + self.hold_s


_ALL = "*"

ATTACKS: tuple[Attack, ...] = (
    Attack(
        "export_over_limit", "Push past the export limit",
        "Every battery is dispatched to full power at once. The fleet can "
        "produce half as much again as the grid connection is allowed to "
        "carry, so the site ends up pushing more into the network than its "
        "connection agreement permits.",
        "scada", "control",
        steps=((0.0, K.PACK_POWER, 1.927, _ALL),),
    ),
    Attack(
        "rest_limit_tamper", "Move the limit, then fill it",
        "The export limit itself is raised from 20 MW to 40 MW over the site "
        "controller's web API, and only then is the fleet dispatched. The "
        "token was valid, the role was the one allowed to change limits, and "
        "the request came through the jump server exactly as designed.",
        "engineering", "operations", conduit="jump_to_control",
        steps=((0.0, K.POI_LIMIT, 40.0, ""), (8.0, K.PACK_POWER, 1.927, _ALL)),
    ),
    Attack(
        "capability_override", "Ask for more than the unit has",
        "Every battery is commanded above its own nameplate rating. No "
        "inverter can do it, so each one runs at its limit while the control "
        "system believes it is delivering more, and the fleet's real total "
        "still goes straight past what the grid connection can carry.",
        "scada", "control",
        steps=((0.0, K.PACK_POWER, 2.4, _ALL),),
    ),
    Attack(
        "ramp_slam", "Slam the output",
        "The site is driven from full charge to full export in one step. "
        "The grid code limits how fast a site may change what it sends, "
        "because a site that jumps around moves the frequency for everybody "
        "connected nearby.",
        "scada", "control",
        steps=((0.0, K.PACK_POWER, -1.9, _ALL), (30.0, K.PACK_POWER, 1.9, _ALL)),
    ),
    Attack(
        "cooling_shutdown", "Turn the cooling off",
        "Thermal management is switched off on half the fleet while it keeps "
        "working. Nothing changes for several minutes, and then the cells "
        "start to climb towards the temperature at which they are damaged.",
        "engineering", "operations", conduit="jump_to_control",
        steps=(tuple((0.0, K.PACK_COOLING, 0.0, f"MP{i:02d}")
                     for i in range(1, 9))
               + ((4.0, K.PACK_POWER, 1.8, _ALL),)),
        hold_s=900.0,
    ),
    Attack(
        "breaker_out_of_sync", "Close the breaker at the wrong moment",
        "The breaker is opened, the grid drifts half a hertz away while it is "
        "open, and then the breaker is closed again onto the mismatch. "
        "Closing out of step slams torque through the connection and is one "
        "of very few things in this project that wrecks equipment in a single "
        "cycle.",
        "hmi", "control",
        steps=((0.0, K.BREAKER, 0.0, ""), (90.0, K.BREAKER, 1.0, "")),
        grid_slip=(40.0, 400.0, 59.4), hold_s=300.0,
    ),
    Attack(
        "enterprise_write", "A command from the office network",
        "A dispatch command arrives from the corporate network, outside the "
        "jump server that everything from outside is supposed to pass "
        "through. No part of that network has any business writing to a "
        "battery.",
        "enterprise", "enterprise", conduit="enterprise_direct",
        steps=((0.0, K.PACK_POWER, 1.9, _ALL),),
    ),
    Attack(
        "meter_bias", "Lie to the revenue meter",
        "A slowly growing offset is added to the meter the utility bills "
        "against. Nothing jumps. The reading simply drifts away from what the "
        "other two instruments see, and the guard has to work out which of "
        "the three is wrong.",
        "scada", "control",
        bias=(MeasurementSource.POI_METER, 0.01), hold_s=900.0,
        steps=((0.0, K.PACK_POWER, 1.2, _ALL),), harm_is_physical=False,
    ),
    Attack(
        "cut_two_links", "Cut two of the three measurements",
        "The links carrying the revenue meter and the protection relay are "
        "dropped. Neither reading disappears: both freeze at their last "
        "value and go on agreeing with each other, so the majority is now "
        "two dead instruments against one live one.",
        "scada", "control",
        cut_links=(MeasurementSource.POI_METER, MeasurementSource.RELAY),
        steps=((0.0, K.PACK_POWER, 1.2, _ALL), (40.0, K.PACK_POWER, 0.0, _ALL)),
        hold_s=600.0, harm_is_physical=False, beats_the_guard=True,
    ),
    Attack(
        "stealth_creep", "Creep past the limit",
        "Each unit is nudged up by a few kilowatts at a time. Every single "
        "command is a small increase on the one before it, which is exactly "
        "the shape the rule is built not to object to, and the site ends up "
        "over its export limit without one refusal.",
        "scada", "control",
        steps=tuple((i * 18.0, K.PACK_POWER, 0.80 + i * 0.09, _ALL)
                    for i in range(14)),
        hold_s=420.0, beats_the_guard=True,
    ),
)

ATTACKS_BY_NAME = {a.name: a for a in ATTACKS}

#: What each writable point is called on screen, and where it sits.
_POINT_LABEL = {
    K.PACK_POWER: "power set-point", K.PACK_REACTIVE: "reactive set-point",
    K.PACK_ENABLE: "unit on or off", K.PACK_COOLING: "cooling on or off",
    K.SITE_POWER: "site power set-point", K.POI_LIMIT: "grid export limit",
    K.RAMP_LIMIT: "ramp limit", K.BREAKER: "main breaker", K.MODE: "control mode",
}
_POINT_AREA = {
    K.PACK_POWER: Area.FLEET, K.PACK_REACTIVE: Area.FLEET,
    K.PACK_ENABLE: Area.FLEET, K.PACK_COOLING: Area.FLEET,
    K.SITE_POWER: Area.COLLECTION, K.POI_LIMIT: Area.POI,
    K.RAMP_LIMIT: Area.POI, K.BREAKER: Area.TRANSFORMER, K.MODE: Area.COLLECTION,
}


def asked_for(kind: K, value: float, device: str) -> str:
    """One command, in words rather than register values."""
    where = f"unit {device}" if device else "the site"
    if kind is K.PACK_COOLING:
        return (f"turn the cooling on {where}" if value >= 0.5
                else f"turn the cooling off on {where}")
    if kind is K.PACK_ENABLE:
        return (f"bring {where} online" if value >= 0.5
                else f"take {where} offline")
    if kind is K.BREAKER:
        return ("close the main breaker" if value >= 0.5
                else "open the main breaker")
    if kind is K.MODE:
        return ("hand the site back to automatic dispatch" if value >= 0.5
                else "take the site off automatic dispatch")
    shown = f"{value:g}{(' ' + kind.unit) if kind.unit else ''}"
    if kind is K.POI_LIMIT:
        return f"change the grid export limit to {shown}"
    if kind is K.RAMP_LIMIT:
        return f"change the ramp limit to {shown}"
    if device:
        return f"set {where} to {shown}"
    return f"set the {_POINT_LABEL[kind]} to {shown}"


@dataclass
class _Stats:
    inspected: int = 0
    blocked: int = 0
    trips: int = 0
    attacks_run: int = 0
    latency_us: list[float] = field(default_factory=list)


class SiteDemo:
    """The site, the guard, the dispatch controller, and the controls."""

    def __init__(
        self,
        bus: EventBus,
        config: Config | None = None,
        speed: float = 10.0,
        enforce: bool = True,
        seed: int | None = None,
        clock: SimClock | SteppedClock | None = None,
    ) -> None:
        self.bus = bus
        self.config = config or load_config()
        #: A test passes a SteppedClock so the run is the same on any
        #: machine; a demonstration gets the wall-driven one.
        self.clock = clock if clock is not None else SimClock(speed=speed)
        self.stats = _Stats()
        # A run with no seed picks one, and says which. Starting every
        # demonstration from the same numbers makes a simulation look like a
        # recording, and sixteen units sharing one charge and one temperature
        # is not what a yard looks like at any hour of any day. A seed is
        # still accepted so a test can pin a run and so an interesting one can
        # be reproduced from what the page reports.
        self._seed = random.randrange(1, 1_000_000) if seed is None else seed
        self.attack: Attack | None = None
        self._attack_task: asyncio.Task | None = None
        self._tasks: list[asyncio.Task] = []
        self._health: dict[str, str] = {}
        self._seen_damage: set[str] = set()
        self._named: MeasurementSource | None = None
        self._control_enabled = True
        self._last_publish = 0.0
        #: Simulated seconds the plant has actually integrated. On a
        #: loaded machine this falls behind the clock, so anything
        #: waiting for the plant to get somewhere waits on this.
        self._sim_t = 0.0
        self._bias: dict[MeasurementSource, float] = {}
        self._bias_rate: dict[MeasurementSource, float] = {}
        self._target_mw = 0.0
        self._prev_poi = 0.0
        self._prev_t = 0.0
        self._ramp = 0.0
        self._build(enforce)

    def _build(self, enforce: bool) -> None:
        b = self.config.bess
        self.site = BessSite(b.site, b.safety, b.pack, seed=self._seed)
        self._vary(random.Random(self._seed))
        self.topology = default_site_topology(b.site.n_packs)
        self.guard = SiteGuard(self.config, topology=self.topology)
        self._anchor_guard()
        self.enforce = enforce
        self._live = set(MeasurementSource)
        self.guard.set_live_sources(self._live)

    def _vary(self, rng: random.Random) -> None:
        """Give the yard a plausible history before anybody is watching.

        Units are commissioned at different times, sit in different places in
        the yard, and have been cycled differently, so they do not share a
        charge or a temperature. The ranges here stay well inside every limit:
        the point is a site that looks alive, not one that starts half broken,
        because a demonstration that opens with a warning has spent the
        audience's attention before the attack arrives.
        """
        pk = self.config.bess.pack
        for unit in self.site.packs:
            unit.state.soc = min(0.80, max(0.25, rng.gauss(0.55, 0.075)))
            unit.state.temp_c = pk.ambient_c + rng.uniform(-2.5, 6.0)
        # What the site happens to be doing when the page opens: charging
        # overnight, idling, or exporting into the evening peak.
        self._target_mw = round(rng.choice([
            rng.uniform(-14.0, -6.0),      # charging
            rng.uniform(-1.0, 1.0),        # holding
            rng.uniform(4.0, 11.0),        # ordinary export
            rng.uniform(13.0, 18.0),       # into the peak
        ]), 2)

    def _anchor_guard(self) -> None:
        """Read each unit before judging any of it.

        A guard put in front of a running yard reads the telemetry and starts
        from it. Anchoring every estimator to the fleet average instead meant
        a unit sitting ten per cent below the mean looked, from the first
        scan, like a unit whose reported charge had drifted ten per cent from
        its own history, and the energy-balance rule said so: a protective
        trip on a site nobody had touched.

        Anchoring is not the same as trusting. From here on the estimator is
        driven by accepted commands alone and never corrected by the reported
        charge, which is the property that makes it independent evidence.
        """
        for unit in self.site.packs:
            est = self.guard.estimators.get(unit.state.device)
            if est is None:
                continue
            est.estimate.soc = unit.state.soc
            est.estimate.temp_c = unit.state.temp_c

    # ------------------------------------------------------------------
    def _now(self) -> float:
        return self.clock.now()

    @property
    def sim_t(self) -> float:
        """Simulated seconds the plant has integrated since the run began."""
        return self._sim_t

    async def advance(self, seconds: float) -> None:
        """Wait until the plant has actually advanced this far.

        Not the same as sleeping on the clock. Under load the loop falls
        behind, and a test that waited on the clock would cut an attack short
        and call the result a pass.
        """
        if isinstance(self.clock, SteppedClock):
            await self.clock.advance(seconds)
            return
        target = self._sim_t + seconds
        while self._sim_t < target:
            await self.clock.sleep(1.0)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    async def start(self) -> None:
        self.guard.observe(self._observe())
        self.bus.publish(self.describe())
        self._say(plain.guard_mode_line(self.enforce))
        self._say(plain.Line(
            self._opening_line(),
            f"{self.config.bess.site.n_packs} battery units are dispatched by "
            "the site controller, and three separate instruments are each "
            "measuring what leaves for the grid. Every command crosses OTGuard "
            "on the way.", "good", "start"))
        self._tasks.append(asyncio.create_task(self._process_loop()))
        self._tasks.append(asyncio.create_task(self._control_loop()))

    async def stop(self) -> None:
        await self._cancel_attack()
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        self._tasks.clear()

    def _opening_line(self) -> str:
        mw = self._target_mw
        if mw < -1.0:
            return f"The site is charging at about {abs(mw):.0f} MW."
        if mw > 1.0:
            return f"The site is exporting about {mw:.0f} MW to the grid."
        return "The site is sitting idle, neither charging nor exporting."

    # ------------------------------------------------------------------
    # The site
    # ------------------------------------------------------------------
    async def _process_loop(self) -> None:
        tick = self.config.bess.site.dt_s
        last = self._now()
        try:
            while True:
                await self.clock.sleep(tick)
                now = self._now()
                elapsed = min(max(now - last, 0.0), 120.0)
                last = now
                while elapsed > 0.0:
                    slice_s = min(elapsed, tick)
                    self.site.step(slice_s, now)
                    self._sim_t += slice_s
                    elapsed -= slice_s
                self._advance_bias(tick)
                poi = self.site.state.p_poi_mw
                step = max(now - self._prev_t, 1e-6)
                self._ramp = (poi - self._prev_poi) / step
                self._prev_poi, self._prev_t = poi, now
                event = self.guard.observe(self._observe())
                if event is not None:
                    self._on_supervision(event)
                self._check_damage()
                self._check_accusation()
                wall = time.monotonic()
                if wall - self._last_publish >= 0.22:
                    self._last_publish = wall
                    self._publish_state()
        except asyncio.CancelledError:
            raise

    def _advance_bias(self, dt: float) -> None:
        for source, rate in self._bias_rate.items():
            self._bias[source] = self._bias.get(source, 0.0) + rate * dt

    def _observe(self):
        """Telemetry as the guard receives it, bias and dead links included."""
        obs = self.site.observe(self._now())
        if not self._bias:
            return obs
        import dataclasses
        changes = {}
        for source, offset in self._bias.items():
            if source is MeasurementSource.POI_METER:
                changes["poi_meter_mw"] = obs.poi_meter_mw + offset
            elif source is MeasurementSource.RELAY:
                changes["relay_mw"] = obs.relay_mw + offset
        return dataclasses.replace(obs, **changes) if changes else obs

    # ------------------------------------------------------------------
    # The site's own dispatch
    # ------------------------------------------------------------------
    async def _control_loop(self) -> None:
        """What the site controller does when nobody is attacking it.

        It shares the target across the units that are online and writes a
        set-point to one of them each cycle, in rotation. This is the traffic
        that must never be refused: a guard that objects to a site following
        its own dispatch has taken the site off line.
        """
        turn = 0
        try:
            while True:
                await self.clock.sleep(6.0)
                if not self._control_enabled:
                    continue
                online = [p for p in self.site.packs if p.state.online]
                if not online:
                    continue
                share = self._target_mw / len(online)
                unit = online[turn % len(online)]
                turn += 1
                self._issue(K.PACK_POWER, round(share, 3), device=unit.state.device)
        except asyncio.CancelledError:
            raise

    def _issue(self, kind: K, value: float, *, device: str = "",
               source: str = "scada", zone: str = "control",
               conduit: str = "scada_to_control") -> bool:
        command = SiteCommand(self._now(), kind, value, device=device,
                              source=source, zone=zone, conduit=conduit)
        verdict = self.guard.check(command)
        self.stats.inspected += 1
        self.stats.latency_us.append(verdict.latency_us)
        allowed = verdict.allowed or not self.enforce
        if verdict.decision is Decision.BLOCK and self.enforce:
            self.stats.blocked += 1
        if allowed:
            self._apply(command)

        request = (f"{plain.who(source, SITE_NAMES).capitalize()} asked to "
                   f"{asked_for(kind, value, device)}.")
        line = plain.ruling(request, not allowed, verdict.findings,
                            subject="the site")
        self.bus.publish(LiveEvent(Kind.VERDICT, self._now(), {
            "decision": "block" if not allowed else (
                "alarm" if verdict.findings else "allow"),
            "source": source, "device": device or "site", "zone": zone,
            "conduit": conduit,
            "point": kind.value, "point_label": _POINT_LABEL[kind],
            "value": value, "unit": kind.unit,
            "area": _POINT_AREA[kind].value,
            "rules": verdict.rule_ids,
            "latency_us": round(verdict.latency_us, 1),
            **line.as_dict(),
        }))
        return allowed

    def _apply(self, command: SiteCommand) -> None:
        unit = self.site.pack(command.device) if command.device else None
        kind = command.kind
        if kind is K.PACK_POWER and unit is not None:
            unit.set_power(command.value)
        elif kind is K.PACK_REACTIVE and unit is not None:
            unit.set_reactive(command.value)
        elif kind is K.PACK_COOLING and unit is not None:
            unit.set_cooling(bool(command.value))
        elif kind is K.PACK_ENABLE and unit is not None:
            unit.set_online(bool(command.value))
        elif kind is K.BREAKER:
            self.site.set_breaker(bool(command.value))
        elif kind is K.POI_LIMIT:
            self.site.poi_limit_mw = command.value
        elif kind is K.RAMP_LIMIT:
            self.site.ramp_limit_mw_s = command.value

    # ------------------------------------------------------------------
    # Publishing
    # ------------------------------------------------------------------
    def _reading(self):
        """One pass over the site, with what only the demo knows folded in."""
        history = self.guard.voter.history
        spread = history[-1].spread_mw if history else 0.0
        return read_site(self.site, spread_mw=spread,
                         sources_live=len(self._live), ramp_mw_s=self._ramp)

    def _publish_state(self) -> None:
        b = self.config.bess
        reading = self._reading()
        rows = assess(reading, b.site, b.safety, b.pack)
        damage = sorted(self.site.damage_summary())
        self._track_health(rows)
        self.bus.publish(LiveEvent(Kind.STATE, self._now(), {
            "plant": "site",
            "metrics": rows,
            "headline": [r for r in rows if r["headline"]],
            "units": self._unit_rows(),
            "sources": self._source_rows(),
            "harms": damage,
            "summary": self._summary(rows, damage),
            "enforcing": self.enforce,
            "breaker": self.site.state.breaker.value,
            "poi_limit_mw": round(self.site.poi_limit_mw, 2),
            "attack": self.attack.name if self.attack else None,
            "attack_title": self.attack.title if self.attack else None,
            "counters": {
                "inspected": self.stats.inspected,
                "blocked": self.stats.blocked,
                "trips": self.stats.trips,
                "attacks": self.stats.attacks_run,
            },
        }))

    def _unit_rows(self) -> list[dict]:
        """One row per Megapack, which is what the page draws as the yard."""
        rows = []
        pk = self.config.bess.pack
        for unit in self.site.packs:
            s = unit.state
            if s.damaged:
                health = "breach"
            elif (s.temp_c > pk.temp_derate_c or not s.online
                  or not s.cooling_enabled):
                health = "watch"
            else:
                health = "good"
            rows.append({
                "device": unit.state.device,
                "p_mw": round(s.p_mw, 3),
                "soc": round(s.soc * 100.0, 1),
                "temp_c": round(s.temp_c, 1),
                "online": s.online,
                "cooling": s.cooling_enabled,
                "health": health,
                "damaged": sorted(
                    n for n, f in (("overcharged", s.overcharged),
                                   ("deep discharged", s.deep_discharged),
                                   ("overheated", s.overheated)) if f),
            })
        return rows

    def _source_rows(self) -> list[dict]:
        """The three instruments, what each says, and whether it is live."""
        history = self.guard.voter.history
        values = dict(history[-1].values) if history else {}
        truth = history[-1].consensus_mw if history else self.site.state.p_poi_mw
        rows = []
        for source in MeasurementSource:
            value = values.get(source, 0.0)
            live = source in self._live
            rows.append({
                "key": source.value,
                "label": SOURCE_LABEL[source],
                "mw": round(value, 3),
                "live": live,
                # The error is the demonstration's own honesty: the page can
                # show what the instrument says beside what is true, which is
                # exactly what nobody on a real site can see.
                "error_mw": round(value - truth, 3),
                "health": "good" if live and abs(value - truth) < 0.3
                          else ("watch" if live else "breach"),
            })
        return rows

    def _summary(self, rows: list[dict], damage: list[str]) -> str:
        if damage:
            return ("The site has been damaged: " + ", ".join(damage)
                    + ". That is permanent.")
        breaches = [r for r in rows if r["health"] == "breach"]
        if breaches:
            return (f"{breaches[0]['label']} is outside its limit at "
                    f"{breaches[0]['shown']} {breaches[0]['unit']}.")
        watch = [r for r in rows if r["health"] == "watch"]
        if watch:
            return (f"Everything is inside its limits, though "
                    f"{watch[0]['label'].lower()} is worth watching.")
        poi = next((r for r in rows if r["key"] == "p_poi"), None)
        where = f" sending {poi['shown']} MW to the grid" if poi else ""
        return (f"The site is running normally{where}, and every measurement "
                "is inside its limit.")

    def _track_health(self, rows: list[dict]) -> None:
        for row in rows:
            before, now = self._health.get(row["key"]), row["health"]
            if before is None or before == now:
                self._health[row["key"]] = now
                continue
            self._health[row["key"]] = now
            if now == "good" and before in ("watch", "breach"):
                self._say(plain.recovered_line(row))
            else:
                line = plain.metric_line(row)
                if line is not None:
                    self._say(line)

    def _check_damage(self) -> None:
        for item in sorted(self.site.damage_summary()):
            if item in self._seen_damage:
                continue
            self._seen_damage.add(item)
            self._say(plain.Line(
                "Something on the site has been damaged.",
                f"{item}. Unlike every other number on this page, this one "
                "does not come back when the attack stops.",
                "breach", "harm"))

    def _check_accusation(self) -> None:
        """The moment the vote picks one instrument out, said in words.

        This is the site's best result and the easiest one to miss, because
        nothing on the plant moves when it happens. Three instruments measure
        the same power by three different routes. When one drifts away from
        the other two, the guard can say which one rather than only that
        something is wrong. The number worth reading is how far the lie had
        got by then.
        """
        named = self.guard.voter.alarm
        if named is None or named is self._named:
            return
        self._named = named
        lie = self._bias.get(named)
        how_far = (f" By the time it was named, the reading had been shifted "
                   f"by {abs(lie):.2f} MW." if lie else "")
        self._say(plain.Line(
            f"OTGuard has named the {SOURCE_LABEL[named]} as the one that is wrong.",
            f"Three instruments measure the power leaving this site by three "
            f"different routes. The {SOURCE_LABEL[named]} has drifted away "
            f"from the other two, and because there are three of them the "
            f"guard can say which one to disbelieve rather than only that "
            f"they disagree.{how_far}", "watch", "vote"))

    def _on_supervision(self, event) -> None:
        action = getattr(event, "action", None)
        findings = list(getattr(event, "findings", []) or [])
        detail = findings[0].detail if findings else ""
        if action is not None and self.enforce:
            self.stats.trips += 1
            self._enact(action)
        self.bus.publish(LiveEvent(Kind.TRIP, self._now(), {
            "reason": getattr(action, "reason", "") if action else "",
            "rules": [f.rule_id for f in findings],
            "detail": detail,
            "enforced": self.enforce,
            **plain.trip_line(getattr(action, "reason", "") if action else "",
                              detail).as_dict(),
        }))

    def _enact(self, action) -> None:
        """Carry out a protective action the supervisor decided on."""
        for device, value in action.pack_power_mw.items():
            unit = self.site.pack(device)
            if unit is not None:
                unit.set_power(value)
        for device in action.cooling_on:
            unit = self.site.pack(device)
            if unit is not None:
                unit.set_cooling(True)
        if action.open_breaker:
            self.site.set_breaker(False)

    def _say(self, line: plain.Line) -> None:
        self.bus.publish(LiveEvent(Kind.NOTE, self._now(), line.as_dict()))

    # ------------------------------------------------------------------
    # What the page needs once
    # ------------------------------------------------------------------
    def describe(self) -> LiveEvent:
        b = self.config.bess
        return LiveEvent(Kind.SCENARIO, self._now(), {
            "plant": "site", "view": "site",
            "name": "grid storage site",
            "summary": f"{b.site.n_packs} battery units behind a "
                       f"{b.site.poi_rating_mw:.0f} MVA transformer, with a "
                       f"{b.site.poi_limit_mw:.0f} MW export limit.",
            "speed": self.clock.speed,
            "seed": self._seed,
            "n_packs": b.site.n_packs,
            "pack_mw": b.pack.power_mw,
            "pack_mwh": b.pack.energy_mwh,
            "poi_limit_mw": b.site.poi_limit_mw,
            "poi_rating_mw": b.site.poi_rating_mw,
            "topology": self.topology.summary() if hasattr(self.topology, "summary") else {},
            "metrics": [
                {"key": m.key, "label": m.label, "unit": m.unit,
                 "area": m.area.value, "plain": m.plain, "why": m.why,
                 "headline": m.key in HEADLINE,
                 "scale_min": m.scale_min, "scale_max": m.scale_max,
                 "limit_low": m.limit_low, "limit_high": m.limit_high}
                for m in catalogue(b.site, b.safety, b.pack)
            ],
            "areas": [{"key": a.value, "label": a.label} for a in Area],
            "attacks": [
                {"name": a.name, "title": a.title, "story": a.story,
                 "source": a.source, "zone": a.zone,
                 "harm_is_physical": a.harm_is_physical,
                 "beats_the_guard": a.beats_the_guard}
                for a in ATTACKS
            ],
        })

    # ------------------------------------------------------------------
    # Controls
    # ------------------------------------------------------------------
    async def launch_attack(self, name: str) -> dict:
        attack = ATTACKS_BY_NAME.get(name)
        if attack is None:
            return {"ok": False, "error": f"no attack called {name!r}"}
        await self._cancel_attack()
        self.attack = attack
        self.stats.attacks_run += 1
        self._say(plain.attack_line(attack.title, attack.story,
                                    SITE_NAMES.get(attack.source, attack.source)))
        if attack.beats_the_guard:
            self._say(plain.Line(
                "This is one the guard does not win.",
                "It is on the page because leaving it off would make this a "
                "sales pitch. Watch what happens with enforcement on.",
                "watch", "attack"))
        self._attack_task = asyncio.create_task(self._run_attack(attack))
        return {"ok": True, "attack": name}

    async def _run_attack(self, attack: Attack) -> None:
        try:
            self._control_enabled = False
            if attack.bias is not None:
                source, rate = attack.bias
                self._bias_rate[source] = rate
                self._say(plain.Line(
                    f"The {SOURCE_LABEL[source]} is being biased.",
                    f"Its reading will drift by {rate * 60:.2f} MW a minute. "
                    "Nothing jumps, so there is no single moment to notice.",
                    "watch", "spoof"))
            if attack.grid_slip is not None:
                delay, duration, hz = attack.grid_slip
                start = self._now() + delay
                self.site.grid_events.append(
                    GridEvent(start_s=start, end_s=start + duration,
                              frequency_hz=hz))
                self._say(plain.Line(
                    "The grid has drifted away from the site.",
                    f"It is now running at {hz:g} Hz while the site is still "
                    "at 60. While the breaker is open that is harmless. "
                    "Closing onto it is not.", "watch", "grid"))
            for source in attack.cut_links:
                self.site.set_link(source, False)
                self._live.discard(source)
                self._say(plain.device_line(SOURCE_LABEL[source], False,
                                            "its link has been cut"))
            if attack.cut_links:
                # The scanner is what would notice in a deployment. Here the
                # demonstration tells the guard directly, and whether it is
                # told is the switch the whole lesson turns on.
                self.guard.set_live_sources(self._live if self.enforce
                                            else set(MeasurementSource))
            last = 0.0
            for delay, kind, value, device in attack.steps:
                await self.clock.sleep(max(0.0, delay - last))
                last = delay
                targets = ([u.state.device for u in self.site.packs] if device == _ALL
                           else [device])
                for target in targets:
                    self._issue(kind, value, device=target,
                                source=attack.source, zone=attack.zone,
                                conduit=attack.conduit)
            await self.clock.sleep(attack.hold_s)
            self._say(plain.Line(f"The {attack.title.lower()} attempt has finished.",
                                 severity="info", tag="attack"))
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("attack %s failed", attack.name)
            self._say(plain.Line(
                "The attack script stopped early.",
                "Something went wrong running it. This is a fault in the "
                "demonstration, not a decision OTGuard made.", "watch", "error"))
        finally:
            self._restore()

    def _restore(self) -> None:
        self.site.grid_events = [e for e in self.site.grid_events
                                 if e.end_s < self._now()]
        self._bias_rate.clear()
        self._bias.clear()
        for source in MeasurementSource:
            self.site.set_link(source, True)
        self._live = set(MeasurementSource)
        self.guard.set_live_sources(self._live)
        self._control_enabled = True
        self.attack = None

    async def _cancel_attack(self) -> None:
        if self._attack_task is not None:
            self._attack_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._attack_task
            self._attack_task = None
        self._restore()

    async def set_enforce(self, enforce: bool) -> dict:
        self.enforce = enforce
        self._say(plain.guard_mode_line(enforce))
        return {"ok": True, "enforce": enforce}

    async def reset(self) -> dict:
        await self._cancel_attack()
        self._build(self.enforce)
        self.guard.observe(self._observe())
        self._health.clear()
        self._seen_damage.clear()
        self._named = None
        self.stats = _Stats()
        self._prev_poi = self._prev_t = self._ramp = 0.0
        self._say(plain.Line(
            "The site has been put back to where it started.",
            f"{self.config.bess.site.n_packs} units online, charged and warmed "
            "the way they were when the run began, and all three measurements "
            "arriving again.", "good", "reset"))
        return {"ok": True}

    async def command(self, action: str, params: dict[str, str]) -> dict:
        if action == "attack":
            return await self.launch_attack(params.get("name", ""))
        if action == "stop":
            await self._cancel_attack()
            self._say(plain.Line("The attack was stopped.", severity="info",
                                 tag="attack"))
            return {"ok": True}
        if action == "enforce":
            return await self.set_enforce(params.get("value", "true") == "true")
        if action == "reset":
            return await self.reset()
        if action == "dispatch":
            try:
                self._target_mw = max(-20.0, min(20.0, float(params.get("mw", "8"))))
            except ValueError:
                return {"ok": False, "error": "dispatch needs a number"}
            self._say(plain.Line(
                f"The site has been asked for {self._target_mw:g} MW.",
                "The site controller will share that across the units that "
                "are online, and every one of those writes crosses the guard.",
                "info", "dispatch"))
            return {"ok": True, "mw": self._target_mw}
        return {"ok": False, "error": f"unknown command {action!r}"}
