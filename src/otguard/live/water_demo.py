"""The treatment works running live, with somebody able to interfere with it.

The plant steps, the plant's own automatic control keeps it on target, and
every command that control issues goes through the guard exactly as an
operator's would. An attack is launched when somebody asks for one, the guard
can be switched to watch-only, and both of those are the demonstration rather
than a feature.

One honesty note that belongs at the top. The tank demonstration runs its
masters, its guard and its controller over real loopback sockets speaking real
Modbus. This one runs in process. The twenty-two devices, six zones and six
conduits in :mod:`otguard.water.topology` are a model of an OT environment,
not twenty-two listening servers, and the display says so. What is not
modelled is the guard: every verdict here is the real rule set reaching a real
decision on a real predicted plant state, and the plant it predicts over is the
same simulation the water is flowing through.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from dataclasses import dataclass, field

from ..clock import SimClock
from ..guard.water_guard import Decision, WaterGuard
from ..water.metrics import HEADLINE, assess, catalogue
from ..water.plant import WaterSafety, WaterWorks, WorksConfig
from ..water.topology import Topology
from ..water.types import (
    Analyser,
    Stage,
    WaterCommand,
    WaterCommandKind as K,
    WaterObservation,
)
from . import plain
from .bus import EventBus
from .events import Kind, LiveEvent

log = logging.getLogger(__name__)

#: How a command reaches the plant once the guard has allowed it.
APPLY = {
    K.INTAKE_PUMP: "set_intake_pump", K.RAW_VALVE: "set_raw_valve",
    K.COAGULANT_DOSE: "set_coagulant", K.POLYMER_DOSE: "set_polymer",
    K.FLOC_PADDLE: "set_floc_paddle", K.FILTER_VALVE: "set_filter_valve",
    K.BACKWASH: "set_backwash", K.CHLORINE_DOSE: "set_chlorine",
    K.CAUSTIC_DOSE: "set_caustic", K.HIGH_LIFT_PUMP: "set_high_lift_pump",
    K.CLEARWELL_OUTLET: "set_clearwell_outlet",
    K.MAX_CHLORINE_DOSE: "set_max_chlorine_dose",
    K.MAX_CAUSTIC_DOSE: "set_max_caustic_dose",
    K.TURBIDITY_ALARM: "set_turbidity_alarm",
}


@dataclass(frozen=True)
class Attack:
    """One thing somebody can do to the plant from the page."""

    name: str
    title: str
    story: str              # what it is, in plain English
    source: str             # which device it comes from
    zone: str
    device: str
    steps: tuple[tuple[float, K, float], ...]   # (delay_s, point, value)
    hold_s: float = 600.0    # how long it is left in place before standing down
    sensor_freeze: str = ""  # an analyser to stop updating, if any

    @property
    def span_s(self) -> float:
        return max((d for d, _, _ in self.steps), default=0.0) + self.hold_s


ATTACKS: tuple[Attack, ...] = (
    Attack(
        "oldsmar_overdose", "Chemical overdose",
        "Somebody on the operator's screen raises the chlorine dose ceiling and "
        "then doses far above it. This is the shape of what happened at a water "
        "plant in Florida in 2021, where a dosing set-point was raised about a "
        "hundredfold. Who sent that write is still disputed; what a write of "
        "this shape does to the water is not.",
        "hmi", "supervisory", "HMI-01",
        ((0.0, K.MAX_CHLORINE_DOSE, 11.0), (12.0, K.CHLORINE_DOSE, 9.5)), 600.0,
    ),
    Attack(
        "caustic_overdose", "Caustic overdose",
        "The caustic soda ceiling is raised and the dose pushed up with it. "
        "Caustic soda is the chemical the Florida case actually involved; too "
        "much of it makes the water burn and strips metal out of the pipes.",
        "hmi", "supervisory", "HMI-01",
        ((0.0, K.MAX_CAUSTIC_DOSE, 60.0), (12.0, K.CAUSTIC_DOSE, 48.0)), 600.0,
    ),
    Attack(
        "silent_underdose", "Quietly stop disinfecting",
        "The chlorine dose is turned down to almost nothing. Nothing moves, "
        "nothing alarms, and for several minutes every instrument still reads "
        "normal, because the water that was already dosed is still flowing past "
        "the analyser.",
        "scada", "supervisory", "SCADA-01",
        ((0.0, K.CHLORINE_DOSE, 0.15),), 900.0,
    ),
    Attack(
        "contact_time_theft", "Steal the contact time",
        "The pumps sending water to the town are opened right up. The chlorine "
        "reading barely changes, so the plant looks fine, but the water is now "
        "rushing through the contact tank too fast to be disinfected. No "
        "instrument on the site measures this.",
        "scada", "supervisory", "SCADA-01",
        ((0.0, K.HIGH_LIFT_PUMP, 100.0), (6.0, K.CLEARWELL_OUTLET, 100.0)), 5400.0,
    ),
    Attack(
        "turbidity_breakthrough", "Let the mud through",
        "The coagulant dose is cut. Without it the fine mud never clumps "
        "together, so it floats straight through the clarifier and the filters "
        "and out to the town, carrying bacteria with it where the chlorine "
        "cannot reach them.",
        "scada", "supervisory", "SCADA-01",
        ((0.0, K.COAGULANT_DOSE, 0.4), (10.0, K.FLOC_PADDLE, 5.0)), 1500.0,
    ),
    Attack(
        "drain_the_clearwell", "Empty the treated water tank",
        "The raw water pumps are stopped while the pumps to the town are left "
        "running. The treated water tank drains, and when it does the town "
        "loses pressure and dirty groundwater can be drawn into the mains.",
        "hmi", "supervisory", "HMI-01",
        ((0.0, K.INTAKE_PUMP, 0.0), (8.0, K.HIGH_LIFT_PUMP, 100.0)), 5400.0,
    ),
    Attack(
        "blind_the_alarms", "Blind the alarms first",
        "Before doing anything else, the turbidity alarm point is moved so far "
        "up that nothing will ever trigger it. On its own this moves no water "
        "at all, which is exactly why it is easy to miss.",
        "engineering", "operations", "ENG-01",
        ((0.0, K.TURBIDITY_ALARM, 0.95), (10.0, K.COAGULANT_DOSE, 0.6)), 1500.0,
    ),
    Attack(
        "freeze_the_analyser", "Freeze the chlorine reading",
        "The chlorine analyser is made to repeat its last good reading while "
        "the dose is cut underneath it. The screen in the control room shows a "
        "perfectly healthy plant the entire time.",
        "scada", "supervisory", "SCADA-01",
        ((8.0, K.CHLORINE_DOSE, 0.2),), 900.0,
        sensor_freeze="chlorine_residual_mg_l",
    ),
    Attack(
        "outsider", "A command from outside",
        "A command arrives from the vendor's remote support connection, out in "
        "the enterprise network. No part of that network has any business "
        "writing to the plant.",
        "vendor", "enterprise", "JUMP-01",
        ((0.0, K.MAX_CHLORINE_DOSE, 10.0), (5.0, K.CHLORINE_DOSE, 8.0)), 600.0,
    ),
)

ATTACKS_BY_NAME = {a.name: a for a in ATTACKS}

#: Which controller runs which stage. Sedimentation and flocculation have no
#: actuator of their own, so they are read by the controller that doses ahead
#: of them rather than being left unattributed.
STAGE_CONTROLLER = {
    Stage.INTAKE: "PLC-INTAKE", Stage.COAGULATION: "PLC-CHEM",
    Stage.FLOCCULATION: "PLC-CHEM", Stage.SEDIMENTATION: "PLC-CHEM",
    Stage.FILTRATION: "PLC-FILTER", Stage.DISINFECTION: "PLC-DISINFECT",
    Stage.CLEARWELL: "PLC-DISINFECT", Stage.DISTRIBUTION: "PLC-DIST",
}


@dataclass
class _Stats:
    inspected: int = 0
    blocked: int = 0
    trips: int = 0
    attacks_run: int = 0
    harms_prevented: int = 0
    latency_us: list[float] = field(default_factory=list)


class WaterDemo:
    """The works, the guard, the plant's own control loops, and the controls."""

    def __init__(
        self,
        bus: EventBus,
        speed: float = 30.0,
        enforce: bool = True,
        seed: int = 3,
    ) -> None:
        self.bus = bus
        self.clock = SimClock(speed=speed)
        self.works_cfg = WorksConfig()
        self.safety = WaterSafety()
        self.topology = Topology()
        self.plant = WaterWorks(self.works_cfg, self.safety, seed=seed)
        self.guard = WaterGuard(self.works_cfg, self.safety, self.topology,
                                enforce=enforce)
        self.stats = _Stats()
        self.attack: Attack | None = None
        self._attack_task: asyncio.Task | None = None
        self._tasks: list[asyncio.Task] = []
        self._frozen: dict[str, float] = {}
        self._health: dict[str, str] = {}
        self._seen_harms: set[str] = set()
        self._control_enabled = True
        self._turn = 0
        self._last_publish = 0.0
        self._seed = seed
        self._prime_guard()

    # ------------------------------------------------------------------
    def _now(self) -> float:
        return self.clock.now()

    def _prime_guard(self) -> None:
        """Tell the guard what the plant is already being held at.

        A guard inserted in front of a running plant does not know the standing
        orders until it sees one written. Starting it blind means its first
        prediction describes a works with every pump stopped, and it would
        object to the first ordinary command it saw.
        """
        s = self.plant.state
        for kind, value in (
            (K.INTAKE_PUMP, s.intake_pump_pct), (K.RAW_VALVE, s.raw_valve_pct),
            (K.COAGULANT_DOSE, s.coagulant_dose_mg_l), (K.FLOC_PADDLE, s.floc_paddle_pct),
            (K.FILTER_VALVE, s.filter_valve_pct), (K.CHLORINE_DOSE, s.chlorine_dose_mg_l),
            (K.CAUSTIC_DOSE, s.caustic_dose_mg_l), (K.HIGH_LIFT_PUMP, s.high_lift_pump_pct),
            (K.CLEARWELL_OUTLET, s.clearwell_outlet_pct),
        ):
            self.guard.estimator.note_accepted(kind, value)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    async def start(self) -> None:
        # Read the plant before anything is allowed to command it. A guard
        # inserted in front of a running works looks at it first; starting it
        # blind means the first command of the run is judged against defaults.
        self.guard.observe(self._observe())
        self.bus.publish(self.describe())
        self._say(plain.guard_mode_line(self.guard.enforce))
        self._say(plain.Line(
            "The works is running normally.",
            "Five controllers are running the process and the plant's automatic "
            "control is holding it on target. Every command it sends crosses "
            "OTGuard on the way.", "good", "start"))
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

    # ------------------------------------------------------------------
    # The plant
    # ------------------------------------------------------------------
    async def _process_loop(self) -> None:
        """Advance the works by however much time has actually passed.

        Stepping a fixed second per iteration is the obvious way to write this
        and it is wrong: the loop also has to observe, assess fourteen metrics
        and publish, so at any interesting speed it cannot complete an
        iteration in a scaled second. The plant then runs slower than the clock
        on the screen, and every rate shown beside it — a tank draining, a dose
        reaching an analyser — is understated by whatever the loop could not
        keep up with. Reading the elapsed time off the clock instead keeps the
        physics and the display on the same timeline at any speed.
        """
        tick = 1.0
        last = self._now()
        try:
            while True:
                await self.clock.sleep(tick)
                now = self._now()
                # Cap a long gap (a suspended laptop, a reset) rather than
                # integrating hours in one step.
                elapsed = min(max(now - last, 0.0), 120.0)
                last = now
                while elapsed > 0.0:
                    slice_s = min(elapsed, 2.0)
                    self.plant.step(slice_s)
                    elapsed -= slice_s
                observation = self._observe()
                event = self.guard.observe(observation)
                if event is not None:
                    self._on_supervision(event)
                self._check_harms()
                wall = time.monotonic()
                if wall - self._last_publish >= 0.22:
                    self._last_publish = wall
                    self._publish_state()
        except asyncio.CancelledError:
            raise

    def _observe(self) -> WaterObservation:
        m = self.plant.measure()
        s = self.plant.state
        # A frozen analyser goes on reporting its last good value, which is
        # what a lost link or a tampered reading actually looks like.
        for name, value in self._frozen.items():
            m[name] = value
        analysers = tuple(
            Analyser(d.name, m.get(d.reads[0] if d.reads else "", 0.0), "", 0.0, d.stage)
            for d in self.topology.analysers()
        )
        return WaterObservation(
            t=self._now(),
            raw_flow_m3h=m["raw_flow_m3h"],
            raw_turbidity_ntu=m["raw_turbidity_ntu"],
            settled_turbidity_ntu=m["settled_turbidity_ntu"],
            filtered_turbidity_ntu=m["filtered_turbidity_ntu"],
            coagulant_dose_mg_l=s.coagulant_dose_mg_l,
            chlorine_dose_mg_l=s.chlorine_dose_mg_l,
            caustic_dose_mg_l=s.caustic_dose_mg_l,
            chlorine_residual_mg_l=m["chlorine_residual_mg_l"],
            ph=m["ph"],
            clearwell_level_m=m["clearwell_level_m"],
            clearwell_outflow_m3h=m["clearwell_outflow_m3h"],
            distribution_pressure_bar=m["distribution_pressure_bar"],
            contact_time_min=s.contact_time_min,
            ct_value=s.ct_value,
            filter_headloss_m=s.filter_headloss_m,
            analysers=analysers,
        )

    # ------------------------------------------------------------------
    # The plant's own control
    # ------------------------------------------------------------------
    async def _control_loop(self) -> None:
        """What SCADA does when nobody is attacking it.

        Dosing paced to flow and turbidity, and the high-lift pumps trimmed to
        hold the clearwell. This is the traffic that must never be refused: if
        the guard objects to the plant running itself, nothing else it says
        means anything.
        """
        try:
            while True:
                await self.clock.sleep(15.0)
                if not self._control_enabled or self.guard.locked_out:
                    continue
                s = self.plant.state
                needed = self.works_cfg.coagulant_demand_per_ntu * s.raw_turbidity_ntu
                demand = self.guard.estimator.chlorine_demand()
                target_dose = round(demand + 0.95, 2)
                # Hold the clearwell near three and a half metres. The pump
                # speed is set from the flow coming in, with a small trim on
                # level, rather than from the level error alone. A pure level
                # controller re-reading every twenty seconds winds the pump
                # down faster than a tank this size can answer, and walks
                # itself into the pressure limit with nobody attacking it.
                balance = 100.0 * s.raw_flow_m3h / self.works_cfg.max_high_lift_flow_m3h
                trim = (s.clearwell_level_m - 3.5) * 5.0
                speed = max(30.0, min(92.0, balance + trim))

                # Write one setpoint per cycle, in rotation, whether or not it
                # has moved. SCADA refreshes its outputs rather than writing
                # only on change, and a guard that sees traffic only when
                # something changes has no idea whether it is still in the path.
                self._turn = (self._turn + 1) % 4
                point, value = (
                    (K.COAGULANT_DOSE, round(needed, 2)),
                    (K.CHLORINE_DOSE, target_dose),
                    (K.HIGH_LIFT_PUMP, round(speed, 1)),
                    (K.CAUSTIC_DOSE, round(s.caustic_dose_mg_l, 2)),
                )[self._turn]
                self._issue(point, value)
        except asyncio.CancelledError:
            raise

    def _issue(self, kind: K, value: float, *, source: str = "scada",
               zone: str = "supervisory", device: str = "SCADA-01") -> bool:
        """Put one command through the guard, and apply it if it survives."""
        command = WaterCommand(self._now(), kind, value, source, zone, device)
        verdict = self.guard.check(command)
        self.stats.inspected += 1
        self.stats.latency_us.append(verdict.latency_us)
        allowed = verdict.allowed or not self.guard.enforce
        if verdict.decision is Decision.BLOCK and self.guard.enforce:
            self.stats.blocked += 1
        if allowed:
            getattr(self.plant, APPLY[kind])(value)

        line = plain.verdict_line(command, not allowed, verdict.findings)
        self.bus.publish(LiveEvent(Kind.VERDICT, self._now(), {
            "decision": "block" if not allowed else ("alarm" if verdict.findings else "allow"),
            "source": source, "device": device, "zone": zone,
            "point": kind.value, "point_label": kind.label,
            "value": value, "unit": kind.unit,
            "stage": kind.stage.value, "role": kind.role.value,
            "rules": verdict.rule_ids,
            "latency_us": round(verdict.latency_us, 1),
            **line.as_dict(),
        }))
        return allowed

    # ------------------------------------------------------------------
    # Publishing
    # ------------------------------------------------------------------
    def _publish_state(self) -> None:
        rows = assess(self.plant.state, self.safety)
        harms = sorted(self.plant.state.harms)
        self._track_health(rows)
        self.bus.publish(LiveEvent(Kind.STATE, self._now(), {
            "plant": "water",
            "metrics": rows,
            "headline": [r for r in rows if r["headline"]],
            "stages": self._stage_values(),
            "harms": harms,
            "summary": plain.summary_sentence(rows, harms, self.guard.enforce),
            "enforcing": self.guard.enforce,
            "locked_out": self.guard.locked_out,
            "attack": self.attack.name if self.attack else None,
            "attack_title": self.attack.title if self.attack else None,
            "counters": {
                "inspected": self.stats.inspected,
                "blocked": self.stats.blocked,
                "trips": self.stats.trips,
                "attacks": self.stats.attacks_run,
            },
        }))

    def _stage_values(self) -> list[dict]:
        """One row per treatment stage, for the process diagram."""
        s = self.plant.state
        by_stage = {
            Stage.INTAKE: [("Flow", f"{s.raw_flow_m3h:.0f} m³/h"),
                           ("Cloudiness", f"{s.raw_turbidity_ntu:.1f} NTU")],
            Stage.COAGULATION: [("Coagulant", f"{s.coagulant_dose_mg_l:.1f} mg/L")],
            Stage.FLOCCULATION: [("Paddles", f"{s.floc_paddle_pct:.0f} %")],
            Stage.SEDIMENTATION: [("Cloudiness", f"{s.settled_turbidity_ntu:.2f} NTU")],
            Stage.FILTRATION: [("Cloudiness", f"{s.filtered_turbidity_ntu:.3f} NTU"),
                               ("Clogging", f"{s.filter_headloss_m:.2f} m")],
            Stage.DISINFECTION: [("Chlorine in", f"{s.chlorine_dose_mg_l:.2f} mg/L"),
                                 ("pH", f"{s.ph:.2f}")],
            Stage.CLEARWELL: [("Level", f"{s.clearwell_level_m:.2f} m"),
                              ("Contact", f"{s.contact_time_min:.0f} min"),
                              ("Chlorine out", f"{s.chlorine_residual_mg_l:.2f} mg/L")],
            Stage.DISTRIBUTION: [("To town", f"{s.clearwell_outflow_m3h:.0f} m³/h"),
                                 ("Pressure", f"{s.distribution_pressure_bar:.2f} bar")],
        }
        rows = []
        for stage in Stage:
            rows.append({
                "stage": stage.value, "label": stage.label,
                "values": [{"name": n, "shown": v} for n, v in by_stage.get(stage, [])],
                "controller": STAGE_CONTROLLER.get(stage, ""),
            })
        return rows

    def _track_health(self, rows: list[dict]) -> None:
        """Say something only when a measurement changes band."""
        for row in rows:
            before = self._health.get(row["key"])
            now = row["health"]
            if before is None:
                self._health[row["key"]] = now
                continue
            if before == now:
                continue
            self._health[row["key"]] = now
            if now == "good" and before in ("watch", "breach"):
                self._say(plain.recovered_line(row))
            else:
                line = plain.metric_line(row)
                if line is not None:
                    self._say(line)

    def _check_harms(self) -> None:
        for harm in sorted(self.plant.state.harms):
            if harm in self._seen_harms:
                continue
            self._seen_harms.add(harm)
            self._say(plain.harm_line(harm))

    def _on_supervision(self, event) -> None:
        action = event.action
        if action is None:
            return
        if self.guard.enforce:
            for kind, value in action.writes.items():
                getattr(self.plant, APPLY[kind])(value)
            self.stats.trips += 1
        self.bus.publish(LiveEvent(Kind.TRIP, self._now(), {
            "reason": action.reason,
            "rules": [f.rule_id for f in event.findings],
            "detail": event.findings[0].detail if event.findings else "",
            "enforced": self.guard.enforce,
            **plain.trip_line(action.reason, action.plain).as_dict(),
        }))

    def _say(self, line: plain.Line) -> None:
        self.bus.publish(LiveEvent(Kind.NOTE, self._now(), line.as_dict()))

    # ------------------------------------------------------------------
    # What the page needs once
    # ------------------------------------------------------------------
    def describe(self) -> LiveEvent:
        return LiveEvent(Kind.SCENARIO, self._now(), {
            "plant": "water", "view": "water",
            "name": "water treatment works",
            "summary": "A conventional surface-water treatment works, from river "
                       "intake to the mains.",
            "guarded": self.guard.enforce,
            "speed": self.clock.speed,
            "topology": self.topology.summary(),
            "metrics": [
                {"key": m.key, "label": m.label, "unit": m.unit, "stage": m.stage.value,
                 "plain": m.plain, "why": m.why, "headline": m.key in HEADLINE,
                 "scale_min": m.scale_min, "scale_max": m.scale_max,
                 "limit_low": m.limit_low, "limit_high": m.limit_high}
                for m in catalogue(self.safety)
            ],
            "attacks": [
                {"name": a.name, "title": a.title, "story": a.story,
                 "source": a.source, "zone": a.zone}
                for a in ATTACKS
            ],
            "stages": [{"stage": s.value, "label": s.label} for s in Stage],
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
        self._say(plain.attack_line(attack.title, attack.story, attack.source))
        self._attack_task = asyncio.create_task(self._run_attack(attack))
        return {"ok": True, "attack": name}

    async def _run_attack(self, attack: Attack) -> None:
        try:
            # The plant's own control stands down: the attacker has the station,
            # so the legitimate loop is not also using it. Leaving it running
            # would overwrite the attack and the guard would take credit for a
            # save its victim had already made.
            self._control_enabled = False
            if attack.sensor_freeze:
                m = self.plant.measure()
                self._frozen[attack.sensor_freeze] = m[attack.sensor_freeze]
                self._say(plain.Line(
                    "The chlorine analyser has been frozen.",
                    "It will keep reporting the same healthy number no matter what "
                    "the water actually does. The control room screen will look "
                    "completely normal.", "watch", "spoof"))
            last = 0.0
            for delay, kind, value in attack.steps:
                await self.clock.sleep(max(0.0, delay - last))
                last = delay
                self._issue(kind, value, source=attack.source, zone=attack.zone,
                            device=attack.device)
            await self.clock.sleep(attack.span_s)
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
            self._frozen.clear()
            self._control_enabled = True
            self.attack = None

    async def _cancel_attack(self) -> None:
        if self._attack_task is not None:
            self._attack_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._attack_task
            self._attack_task = None
        self._frozen.clear()
        self._control_enabled = True
        self.attack = None

    async def set_enforce(self, enforce: bool) -> dict:
        self.guard.enforce = enforce
        self._say(plain.guard_mode_line(enforce))
        return {"ok": True, "enforce": enforce}

    async def acknowledge(self) -> dict:
        self.guard.acknowledge()
        self._say(plain.Line(
            "An operator has acknowledged the alarm.",
            "The plant will take commands again. OTGuard keeps checking every one "
            "of them.", "good", "ack"))
        return {"ok": True}

    async def reset(self) -> dict:
        await self._cancel_attack()
        self.plant = WaterWorks(self.works_cfg, self.safety, seed=self._seed)
        self.guard = WaterGuard(self.works_cfg, self.safety, self.topology,
                                enforce=self.guard.enforce)
        self._prime_guard()
        self._health.clear()
        self._seen_harms.clear()
        self.stats = _Stats()
        self._say(plain.Line(
            "The works has been put back to where it started.",
            "Clean water, normal doses, tank half full.", "good", "reset"))
        return {"ok": True}

    async def command(self, action: str, params: dict[str, str]) -> dict:
        if action == "attack":
            return await self.launch_attack(params.get("name", ""))
        if action == "stop":
            await self._cancel_attack()
            self._say(plain.Line("The attack was stopped.", severity="info", tag="attack"))
            return {"ok": True}
        if action == "enforce":
            return await self.set_enforce(params.get("value", "true") == "true")
        if action == "ack":
            return await self.acknowledge()
        if action == "reset":
            return await self.reset()
        return {"ok": False, "error": f"unknown command {action!r}"}
