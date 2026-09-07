"""Datatypes for the battery-site guard.

The water-tank guard has one actuator pair and one sensor. A storage site has a
fleet of inverters, three independent ways of measuring the same power, and a
switchyard, so the command and observation types have to carry a *device* and a
*measurement source* alongside the value. Everything else — ``Decision``,
``RuleFinding``, ``Verdict`` — is reused unchanged from :mod:`otguard.guard`,
which is the payoff for having kept those protocol-agnostic.

Sign convention, fixed once here because getting it wrong silently inverts every
rule: **positive power is export** (discharging the battery, delivering to the
grid) and **negative power is import** (charging). Reactive power ``q`` is
positive when the inverter is supplying vars.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class SiteCommandKind(str, Enum):
    """Writable set-points and controls across the site."""

    PACK_POWER = "pack_power"        # per-Megapack real power set-point, MW
    PACK_REACTIVE = "pack_reactive"  # per-Megapack reactive power set-point, MVAr
    PACK_ENABLE = "pack_enable"      # 0 = offline, 1 = online
    PACK_COOLING = "pack_cooling"    # 0 = thermal management off, 1 = on
    SITE_POWER = "site_power"        # site-level real power set-point, MW
    POI_LIMIT = "poi_limit"          # interconnection export limit, MW
    RAMP_LIMIT = "ramp_limit"        # grid-code ramp limit, MW/s
    BREAKER = "breaker"              # 0 = open, 1 = close
    MODE = "mode"                    # 0 = manual, 1 = auto dispatch

    @property
    def unit(self) -> str:
        return {
            "pack_power": "MW",
            "pack_reactive": "MVAr",
            "pack_enable": "",
            "pack_cooling": "",
            "site_power": "MW",
            "poi_limit": "MW",
            "ramp_limit": "MW/s",
            "breaker": "",
            "mode": "",
        }[self.value]

    @property
    def is_control(self) -> bool:
        """Does this write actuate plant, as opposed to reconfiguring a limit?

        The distinction matters for the provenance rule (B8): raising a limit is
        an *engineering* action and has a different legitimate origin than a
        dispatch set-point, even though both arrive as register writes.
        """
        return self not in (SiteCommandKind.POI_LIMIT, SiteCommandKind.RAMP_LIMIT)


class MeasurementSource(str, Enum):
    """Where a power measurement came from.

    These three are physically independent: different current transformers,
    different cabling, different protocol stacks, different vendors. That
    independence is the whole basis of rule B6 — an attacker who compromises the
    revenue meter cannot also make the relay's CTs lie, so the disagreement is
    the tell.
    """

    POI_METER = "poi_meter"    # revenue meter at the point of interconnection (DNP3)
    TELEMETRY = "telemetry"    # sum of per-Megapack reports (Modbus TCP)
    RELAY = "relay"            # protection relay CT/PT measurement (GOOSE / MMS)

    @property
    def label(self) -> str:
        return {
            "poi_meter": "POI revenue meter",
            "telemetry": "Megapack telemetry sum",
            "relay": "protection relay CT",
        }[self.value]


class BreakerState(str, Enum):
    OPEN = "open"
    CLOSED = "closed"


@dataclass(frozen=True)
class SiteCommand:
    """One write heading for the site controller, a Megapack or the switchgear.

    ``device`` is the Megapack id for per-pack commands (``"MP03"``) and the
    empty string for site-wide ones. ``zone`` and ``conduit`` describe where the
    write entered from; they are what B8 adjudicates and what a firewall or jump
    server would populate in a real deployment.
    """

    t: float
    kind: SiteCommandKind
    value: float
    device: str = ""
    source: str = "scada"
    zone: str = "control"
    conduit: str = "scada_to_control"
    protocol: str = "modbus_tcp"

    def __str__(self) -> str:
        who = f" {self.device}" if self.device else ""
        return f"t={self.t:7.2f}s{who} {self.kind.value}={self.value:g}{self.kind.unit}"


@dataclass(frozen=True)
class PackReport:
    """What one Megapack says about itself.

    Under a false-data-injection attack this is what the *attacker* says the pack
    is doing; :class:`~otguard.bess.site.PackState` is what it is really doing.
    Telling those apart is rule B2's job.
    """

    device: str
    p_mw: float
    q_mvar: float
    soc: float
    temp_c: float
    online: bool = True
    cooling_enabled: bool = True


@dataclass(frozen=True)
class SiteObservation:
    """One scan of site telemetry flowing back toward SCADA.

    Carries all three power measurements so the guard can compare them. A real
    deployment collects these over three different protocols on three different
    conduits; the guard does not care which, only that they should agree.
    """

    t: float
    packs: tuple[PackReport, ...]
    poi_meter_mw: float
    relay_mw: float
    frequency_hz: float = 60.0
    voltage_pu: float = 1.0
    breaker: BreakerState = BreakerState.CLOSED
    bus_live: bool = True
    fault_current_a: float = 0.0

    @property
    def telemetry_mw(self) -> float:
        """Site power as the sum of what the packs report."""
        return sum(p.p_mw for p in self.packs if p.online)

    def measurement(self, source: MeasurementSource) -> float:
        if source is MeasurementSource.POI_METER:
            return self.poi_meter_mw
        if source is MeasurementSource.RELAY:
            return self.relay_mw
        return self.telemetry_mw

    def pack(self, device: str) -> PackReport | None:
        for report in self.packs:
            if report.device == device:
                return report
        return None


@dataclass
class SiteSnapshot:
    """Ground truth for scoring. The guard never sees this."""

    t: float
    p_poi_mw: float
    soc: dict[str, float] = field(default_factory=dict)
    temp_c: dict[str, float] = field(default_factory=dict)
    p_pack_mw: dict[str, float] = field(default_factory=dict)
    frequency_hz: float = 60.0
    breaker: BreakerState = BreakerState.CLOSED
