"""Who is answering right now, and who stopped.

The scanner holds a list of devices, asks each of them the same question on a
fixed interval, and keeps one piece of state per device: is it answering. That
is all it does. The interesting decisions are in the two places where a naive
version gets it wrong.

**It debounces.** A single missed poll is not an outage. Networks drop packets,
an event loop under load misses a deadline, and a device busy with a scan cycle
answers late. A scanner that flips a device to DOWN on one timeout produces a
device table that flickers, and because this scanner's output reaches the
guard's cross-source vote, a flicker would drop a measurement source out of the
vote and put it back several times a second. So a device goes DOWN only after
``fail_threshold`` consecutive failures and comes back UP only after
``ok_threshold`` consecutive answers, and the thresholds are deliberately
asymmetric: be slow to condemn, slower to forgive.

**It probes concurrently.** Sixteen units, three meters and a switchyard at a
one-second timeout is twenty-seven seconds of sweep if the probes run in turn,
by which time the first answer is older than the interval. Every probe in a
sweep is launched together and the sweep takes as long as its slowest member.

Timestamps come from the simulation clock so that a device going quiet lines up
with the commands and verdicts around it. Timeouts do not: a socket that waits
one second waits one real second whatever speed the scenario is running at,
because that is a property of the network and not of the experiment.
"""

from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import dataclass, field
from enum import Enum

from ..bess.types import MeasurementSource
from ..clock import SimClock
from ..config import ScanConfig
from .probe import Evidence, Probe, ProbeResult

#: Round-trip times kept per device, for the display's sparkline and for
#: noticing a device that is answering but slowing down.
_RTT_HISTORY = 32


class Reachability(str, Enum):
    """What the scanner currently believes about one device."""

    UNKNOWN = "unknown"   # not probed yet, or not probed since a reset
    UP = "up"
    DOWN = "down"

    @property
    def label(self) -> str:
        return {"unknown": "--", "up": "UP", "down": "DOWN"}[self.value]


@dataclass(frozen=True)
class ScanTarget:
    """One device the scanner watches, and what losing it means.

    ``measurement_source`` is the load-bearing field. When it is set, this
    device is one of the independent measurements the site guard votes across,
    and the guard is told to stop counting it while the scanner cannot reach it.
    Leaving it unset makes the device observability only.

    ``min_evidence`` is what this device has to produce before it counts as
    answering. It defaults to :attr:`Evidence.ANSWERED` rather than to a bare
    socket, because the failure this scanner exists to catch is a device whose
    port still accepts while the device behind it has stopped.
    """

    name: str
    probe: Probe
    role: str = ""
    zone: str = ""
    protocol: str = ""
    address: str = ""
    measurement_source: MeasurementSource | None = None
    min_evidence: Evidence = Evidence.ANSWERED
    #: Losing this device is a process-safety condition rather than a
    #: monitoring nuisance. The scanner only records the flag; what to do about
    #: it belongs to the guard.
    critical: bool = False

    @property
    def networked(self) -> bool:
        """Is this device sensed over a socket, or read out of a model?

        Reported everywhere the device table is, because a table that mixes
        measurements with model reads and does not say which is worse than no
        table. Probes declare this themselves; anything that does not say is
        assumed to be a real network probe, since that is the stronger claim
        and a silent default should not be the flattering one.
        """
        return bool(getattr(self.probe, "networked", True))


@dataclass
class DeviceStatus:
    """Live state for one device."""

    target: ScanTarget
    state: Reachability = Reachability.UNKNOWN
    since: float = 0.0
    last_seen: float | None = None
    last_result: ProbeResult | None = None
    consecutive_ok: int = 0
    consecutive_fail: int = 0
    probes: int = 0
    failures: int = 0
    rtt_ms: deque[float] = field(default_factory=lambda: deque(maxlen=_RTT_HISTORY))

    @property
    def name(self) -> str:
        return self.target.name

    @property
    def up(self) -> bool:
        return self.state is Reachability.UP

    @property
    def last_rtt_ms(self) -> float:
        return self.rtt_ms[-1] if self.rtt_ms else 0.0

    @property
    def mean_rtt_ms(self) -> float:
        return sum(self.rtt_ms) / len(self.rtt_ms) if self.rtt_ms else 0.0

    @property
    def detail(self) -> str:
        return self.last_result.detail if self.last_result else "not probed yet"

    @property
    def evidence(self) -> Evidence:
        return self.last_result.evidence if self.last_result else Evidence.NONE


@dataclass(frozen=True)
class ScanTransition:
    """A device changed state. The only thing the scanner reports upward."""

    t: float
    name: str
    previous: Reachability
    current: Reachability
    evidence: Evidence
    detail: str
    measurement_source: MeasurementSource | None = None
    critical: bool = False

    @property
    def lost(self) -> bool:
        return self.current is Reachability.DOWN

    def __str__(self) -> str:
        verb = "went DOWN" if self.lost else f"is {self.current.label}"
        return f"t={self.t:7.2f}s {self.name} {verb}: {self.detail}"


class Scanner:
    """Polls a set of devices and keeps one up/down state for each."""

    def __init__(
        self,
        cfg: ScanConfig | None = None,
        clock: SimClock | None = None,
        targets: list[ScanTarget] | None = None,
    ) -> None:
        self.cfg = cfg or ScanConfig()
        self.clock = clock
        self.statuses: dict[str, DeviceStatus] = {}
        self.transitions: list[ScanTransition] = []
        self.sweeps = 0
        self._task: asyncio.Task | None = None
        self._stopping = asyncio.Event()
        for target in targets or []:
            self.add(target)

    # ------------------------------------------------------------------
    # Composition
    # ------------------------------------------------------------------
    def add(self, target: ScanTarget) -> DeviceStatus:
        if target.name in self.statuses:
            raise ValueError(f"device {target.name!r} is already being scanned")
        status = DeviceStatus(target=target, since=self._now())
        self.statuses[target.name] = status
        return status

    def _now(self) -> float:
        return self.clock.now() if self.clock is not None else 0.0

    # ------------------------------------------------------------------
    # Scanning
    # ------------------------------------------------------------------
    async def scan_once(self) -> list[ScanTransition]:
        """Probe every device once, concurrently, and return what changed."""
        if not self.statuses:
            return []
        names = list(self.statuses)
        results = await asyncio.gather(
            *(self._probe(self.statuses[name]) for name in names),
            return_exceptions=True,
        )
        now = self._now()
        self.sweeps += 1
        changes: list[ScanTransition] = []
        for name, result in zip(names, results):
            if isinstance(result, BaseException):
                # A probe that raises is a defect in the probe, not an outage,
                # but the device is also not answering, so it is recorded as a
                # failure with the exception as its reason rather than swallowed.
                result = ProbeResult.down(f"probe raised {result!r}")
            change = self._apply(self.statuses[name], result, now)
            if change is not None:
                changes.append(change)
        self.transitions.extend(changes)
        return changes

    async def _probe(self, status: DeviceStatus) -> ProbeResult:
        return await status.target.probe()

    def _apply(
        self, status: DeviceStatus, result: ProbeResult, now: float
    ) -> ScanTransition | None:
        """Fold one probe result into a device's state, debouncing both ways."""
        status.probes += 1
        status.last_result = result
        if result.rtt_ms:
            status.rtt_ms.append(result.rtt_ms)

        answered = result.reachable and result.evidence.at_least(status.target.min_evidence)
        if answered:
            status.consecutive_ok += 1
            status.consecutive_fail = 0
            status.last_seen = now
        else:
            status.consecutive_fail += 1
            status.consecutive_ok = 0
            status.failures += 1

        target_state = status.state
        if answered and status.consecutive_ok >= self.cfg.ok_threshold:
            target_state = Reachability.UP
        elif not answered and status.consecutive_fail >= self.cfg.fail_threshold:
            target_state = Reachability.DOWN

        if target_state is status.state:
            return None

        previous, status.state, status.since = status.state, target_state, now
        return ScanTransition(
            t=now,
            name=status.name,
            previous=previous,
            current=target_state,
            evidence=result.evidence,
            detail=result.detail,
            measurement_source=status.target.measurement_source,
            critical=status.target.critical,
        )

    async def run(self, on_change=None) -> None:
        """Sweep forever on the configured interval.

        ``on_change`` is called with each transition as it happens, which is how
        the live view and the guard hear about a device without polling the
        scanner themselves.
        """
        self._stopping.clear()
        while not self._stopping.is_set():
            changes = await self.scan_once()
            if on_change is not None:
                for change in changes:
                    on_change(change)
            if self.clock is not None:
                await self.clock.sleep(self.cfg.interval_s)
            else:
                await asyncio.sleep(self.cfg.interval_s)

    def start(self, on_change=None) -> asyncio.Task:
        if self._task is not None and not self._task.done():
            raise RuntimeError("scanner is already running")
        self._task = asyncio.create_task(self.run(on_change))
        return self._task

    async def stop(self) -> None:
        self._stopping.set()
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
            self._task = None

    # ------------------------------------------------------------------
    # What the rest of the system asks
    # ------------------------------------------------------------------
    def status(self, name: str) -> DeviceStatus | None:
        return self.statuses.get(name)

    def reachable(self, name: str) -> bool:
        """True unless the scanner has positively decided the device is down.

        UNKNOWN counts as reachable on purpose. At the start of a run nothing
        has been probed yet, and a scanner that answered "down" for a device it
        has not looked at would drop every measurement source out of the vote
        for the first few sweeps, which is a self-inflicted blind spot in
        exactly the window where the plant is starting up.
        """
        status = self.statuses.get(name)
        return status is None or status.state is not Reachability.DOWN

    def unreachable_sources(self) -> set[MeasurementSource]:
        """The measurement sources the guard should stop counting."""
        return {
            status.target.measurement_source
            for status in self.statuses.values()
            if status.target.measurement_source is not None
            and status.state is Reachability.DOWN
        }

    def live_sources(self) -> set[MeasurementSource]:
        configured = {
            s.target.measurement_source
            for s in self.statuses.values()
            if s.target.measurement_source is not None
        }
        return configured - self.unreachable_sources()

    def lost_critical(self) -> list[DeviceStatus]:
        return [
            s for s in self.statuses.values()
            if s.target.critical and s.state is Reachability.DOWN
        ]

    def snapshot(self) -> list[DeviceStatus]:
        """Every device, in the order they were added."""
        return list(self.statuses.values())

    def summary(self) -> str:
        up = sum(1 for s in self.statuses.values() if s.state is Reachability.UP)
        down = sum(1 for s in self.statuses.values() if s.state is Reachability.DOWN)
        unknown = len(self.statuses) - up - down
        parts = [f"{up} up", f"{down} down"]
        if unknown:
            parts.append(f"{unknown} not yet probed")
        return f"{self.sweeps} sweeps, " + ", ".join(parts)

    def reset(self) -> None:
        for status in self.statuses.values():
            status.state = Reachability.UNKNOWN
            status.consecutive_ok = 0
            status.consecutive_fail = 0
            status.last_result = None
            status.last_seen = None
            status.rtt_ms.clear()
        self.transitions.clear()
        self.sweeps = 0
