"""Scenario description for the storage site.

Same contract as :mod:`otguard.scenarios.base`: ground truth lives here and
nowhere else, and the guard never sees the ``malicious`` flag, the attack window
or the controller's internals.

The dispatch controller matters more here than the tank's PI loop did. A storage
site's benign traffic is not one operator nudging a set-point — it is a site
controller allocating a site-level target across sixteen units every few seconds,
all day. If that allocation is written naively the false-alarm rate measures the
controller's clumsiness rather than the guard's discrimination. So
:class:`SiteDispatchController` does what a real one does: respects the export
limit, distributes by available headroom rather than equally, honours derates,
and writes on change rather than every scan.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Protocol

from ..bess.site import GridEvent
from ..bess.types import SiteCommand, SiteCommandKind, SiteObservation

# Rewrites honest telemetry into what the guard is told.
TelemetryAttack = Callable[[float, SiteObservation], SiteObservation]


@dataclass(frozen=True)
class ScheduledSiteCommand:
    """One write, with the ground-truth label the guard may not see."""

    t: float
    kind: SiteCommandKind
    value: float
    device: str = ""
    malicious: bool = False
    zone: str = "control"
    conduit: str = "control_to_field"
    protocol: str = "modbus_tcp"
    source: str = "sitectrl"
    note: str = ""

    def to_command(self) -> SiteCommand:
        return SiteCommand(
            t=self.t,
            kind=self.kind,
            value=self.value,
            device=self.device,
            source=self.source,
            zone=self.zone,
            conduit=self.conduit,
            protocol=self.protocol,
        )


class SiteController(Protocol):
    def reset(self) -> None:
        ...

    def update(self, t: float, observation: SiteObservation) -> list[ScheduledSiteCommand]:
        ...


@dataclass
class SiteScenario:
    """One reproducible episode on the storage site."""

    name: str
    category: str                 # "attack" | "normal"
    description: str
    duration_s: float
    initial_soc: float = 0.55
    initial_temp_c: float | None = None
    commands: list[ScheduledSiteCommand] = field(default_factory=list)
    telemetry_attack: TelemetryAttack | None = None
    attack_window: tuple[float, float] | None = None
    controller: SiteController | None = None
    grid_events: list[GridEvent] = field(default_factory=list)
    expected_rules: tuple[str, ...] = ()
    seed: int = 0
    dt_s: float | None = None
    # When the attacker has taken over dispatch, the legitimate site
    # controller stops writing. Without this the scripted attack and the
    # honest controller overwrite each other every two seconds and the
    # attack is neutered by its victim rather than by the guard — which
    # silently flatters the results.
    controller_stops_at: float | None = None
    # Protocol-level events, replayed by the harness against the protocol
    # state machines rather than the physics.
    protocol_events: list[dict] = field(default_factory=list)

    @property
    def is_attack(self) -> bool:
        return self.category == "attack"

    def in_attack_window(self, t: float) -> bool:
        if self.attack_window is None:
            return self.is_attack
        start, end = self.attack_window
        return start <= t <= end

    def __str__(self) -> str:
        return f"{self.name} ({self.category}, {self.duration_s:g}s)"


class SiteDispatchController:
    """Allocates a site power target across the fleet, the way a real one does.

    Three behaviours that keep this honest as a source of *benign* traffic:

    ``write_period_s``
        A site controller writes on a cycle measured in seconds, not every scan.
        Emitting per-scan would trip the ramp rule and make the false-alarm
        number meaningless.

    Headroom-proportional allocation
        Units do not get an equal share. A unit near empty, or derated by heat,
        gets less, because that is what it can deliver. Allocating equally would
        produce set-points that exceed individual capability and the guard would
        be right to object — a false alarm caused by a bad controller, not a bad
        rule.

    ``deadband_mw``
        Write-on-change. Rewriting an unchanged set-point forever is not what
        real traffic looks like.

    ``ramp_mw_s`` defaults well below the grid-code limit B4 enforces. Routine
    dispatch on a storage site is not a race, and a controller that habitually
    ramps at three quarters of the legal limit leaves no headroom for the
    discretisation inherent in issuing a ramp as a series of set-point steps.
    The fast case has its own scenario, where the frequency exemption applies.
    """

    def __init__(
        self,
        target_schedule: list[tuple[float, float]],
        devices: list[str],
        pack_power_mw: float = 1.927,
        poi_limit_mw: float = 20.0,
        write_period_s: float = 2.0,
        deadband_mw: float = 0.05,
        ramp_mw_s: float = 0.8,
        meter_feedback: bool = True,
        trim_gain: float = 0.05,
        trim_limit_mw: float = 2.5,
    ) -> None:
        self.target_schedule = sorted(target_schedule)
        self.devices = list(devices)
        self.pack_power_mw = pack_power_mw
        self.poi_limit_mw = poi_limit_mw
        self.write_period_s = write_period_s
        self.deadband_mw = deadband_mw
        self.ramp_mw_s = ramp_mw_s
        self.meter_feedback = meter_feedback
        self.trim_gain = trim_gain
        self.trim_limit_mw = trim_limit_mw
        self.reset()

    def reset(self) -> None:
        self.target_mw = self.target_schedule[0][1] if self.target_schedule else 0.0
        self.commanded_mw = 0.0
        self._trim_mw = 0.0
        self._applied = 0
        self._last_write_t: float | None = None
        self._last_cmd: dict[str, float] = {}

    def _apply_schedule(self, t: float) -> None:
        while self._applied < len(self.target_schedule) and self.target_schedule[self._applied][0] <= t:
            self.target_mw = self.target_schedule[self._applied][1]
            self._applied += 1

    def update(self, t: float, observation: SiteObservation) -> list[ScheduledSiteCommand]:
        self._apply_schedule(t)
        if self._last_write_t is not None and (t - self._last_write_t) < self.write_period_s:
            return []
        dt = self.write_period_s if self._last_write_t is None else t - self._last_write_t
        self._last_write_t = t

        target = max(-self.poi_limit_mw, min(self.poi_limit_mw, self.target_mw))

        # Regulate against the revenue meter, the way a real site controller
        # does: the contracted quantity is power *at the point of
        # interconnection*, not at the LV bus, so the controller trims its bus
        # set-point until the meter reads the target.
        #
        # This is what makes a biased meter consequential rather than cosmetic.
        # A controller running open-loop on its schedule would ignore a spoofed
        # meter entirely and the attack would do nothing — which is precisely
        # what the first version of this did, and why the meter-bias scenario
        # initially registered no damage at all.
        # The clamp is the anti-windup. The trim exists only to cover house
        # load and transformer losses — about a megawatt — so bounding it
        # near that magnitude stops the integrator from winding the fleet up
        # past the transformer rating during a start-up transient. An
        # earlier bound of 8 MW did exactly that, and the guard was right to
        # block the result.
        if self.meter_feedback:
            error = target - observation.poi_meter_mw
            self._trim_mw += self.trim_gain * error * dt
            self._trim_mw = max(-self.trim_limit_mw, min(self.trim_limit_mw, self._trim_mw))

        # Rate-limit the *output*, after the trim, not just the schedule
        # tracking. A ramp limiter is the last block before the set-point
        # leaves the controller; putting it before the feedback trim lets the
        # trim add to the ramp and pushes the site past the grid-code limit
        # during every start-up.
        desired = target + self._trim_mw
        step = self.ramp_mw_s * dt
        self.commanded_mw += max(-step, min(step, desired - self.commanded_mw))
        commanded = self.commanded_mw

        online = [p for p in observation.packs if p.online]
        if not online:
            return []

        # Headroom-proportional split.
        discharging = commanded >= 0.0
        headroom = {}
        for report in online:
            if discharging:
                room = self.pack_power_mw * min(1.0, max(0.0, report.soc / 0.10))
            else:
                room = self.pack_power_mw * min(1.0, max(0.0, (1.0 - report.soc) / 0.10))
            if report.temp_c > 45.0:
                room *= max(0.0, (58.0 - report.temp_c) / 13.0)
            headroom[report.device] = max(room, 0.0)

        total_headroom = sum(headroom.values())
        out: list[ScheduledSiteCommand] = []
        if total_headroom <= 1e-9:
            return out

        for report in online:
            share = headroom[report.device] / total_headroom
            value = round(commanded * share, 3)
            previous = self._last_cmd.get(report.device)
            if previous is None or abs(value - previous) >= self.deadband_mw:
                self._last_cmd[report.device] = value
                out.append(
                    ScheduledSiteCommand(
                        t=t,
                        kind=SiteCommandKind.PACK_POWER,
                        value=value,
                        device=report.device,
                        zone="control",
                        protocol="modbus_tcp",
                        source="sitectrl",
                    )
                )
        return out
