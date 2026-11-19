"""Every number the storage site is judged by, defined once, in one place.

The same treatment the treatment works got, applied backwards. The works had
its catalogue written before its guard. This site grew its numbers as the
evaluation needed them, and the denominators had to be reconstructed
afterwards. This file is that reconstruction, done properly: one definition of
each quantity, with the limit it has to stay inside, the range to draw it
over, and what it means to somebody who has never stood in a battery yard.

The site's hard numbers come from two different places and the difference
matters more here than anywhere else in the project. ``poi_rating_mw`` is the
transformer nameplate: iron, 25 MVA, not writable by anybody. ``poi_limit_mw``
is the connection agreement: 20 MW, a contractual figure held in a register
that an engineer is supposed to be able to change. The fleet can produce 30.8
MW, which is more than either. That gap is the whole reason an export limit is
something an attacker can violate rather than a physical impossibility, and it
is why the two are separate rows below rather than one.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable

from ..config import MegapackConfig, SiteConfig, SiteSafetyConfig
from .site import BessSite


class Health(str, Enum):
    """How a metric is doing. Never shown as colour alone."""

    GOOD = "good"        # inside the operating target
    WATCH = "watch"      # inside the limit, outside the target
    BREACH = "breach"    # outside the limit the site may run at

    @property
    def label(self) -> str:
        return {"good": "OK", "watch": "Watch", "breach": "Breach"}[self.value]


#: Where on the site a number is read. Drives the schematic's grouping.
class Area(str, Enum):
    FLEET = "fleet"            # the Megapacks themselves
    COLLECTION = "collection"  # the LV bus bringing them together
    TRANSFORMER = "transformer"
    POI = "poi"                # the point of interconnection, the grid edge
    MEASUREMENT = "measurement"  # the instruments, not the power

    @property
    def label(self) -> str:
        return {
            "fleet": "The batteries", "collection": "Collection bus",
            "transformer": "Transformer", "poi": "Grid connection",
            "measurement": "Instruments",
        }[self.value]


@dataclass(frozen=True)
class Metric:
    """One measured quantity, its limits, and what it means in English."""

    key: str
    label: str
    unit: str
    area: Area
    plain: str
    why: str
    read: Callable[["SiteReading"], float]
    scale_min: float = 0.0
    scale_max: float = 1.0
    limit_low: float | None = None
    limit_high: float | None = None
    target_low: float | None = None
    target_high: float | None = None
    decimals: int = 2
    direction: str = "band"

    def value(self, r: "SiteReading") -> float:
        return self.read(r)

    def health(self, value: float) -> Health:
        if self.limit_low is not None and value < self.limit_low:
            return Health.BREACH
        if self.limit_high is not None and value > self.limit_high:
            return Health.BREACH
        if self.target_low is not None and value < self.target_low:
            return Health.WATCH
        if self.target_high is not None and value > self.target_high:
            return Health.WATCH
        return Health.GOOD

    def fraction(self, value: float) -> float:
        span = self.scale_max - self.scale_min
        if span <= 0:
            return 0.0
        return max(0.0, min(1.0, (value - self.scale_min) / span))

    def limit_fractions(self) -> list[tuple[float, str]]:
        marks = []
        for limit, name in ((self.limit_low, "min"), (self.limit_high, "max")):
            if limit is not None:
                marks.append((self.fraction(limit), name))
        return marks

    def format(self, value: float) -> str:
        return f"{value:.{self.decimals}f}"

    def say(self, value: float) -> str:
        health = self.health(value)
        shown = f"{self.format(value)} {self.unit}".strip()
        if health is Health.GOOD:
            return f"{self.label} is {shown}, which is normal."
        if health is Health.WATCH:
            way = "up" if (self.target_high is not None
                           and value > self.target_high) else "down"
            moved = "risen" if way == "up" else "fallen"
            return (f"{self.label} has {moved} to {shown}. Still inside the limit, "
                    f"but it is heading the wrong way.")
        if self.limit_high is not None and value > self.limit_high:
            return (f"{self.label} is {shown}, above the limit of "
                    f"{self.format(self.limit_high)} {self.unit}. {self.why}")
        return (f"{self.label} is {shown}, below the minimum of "
                f"{self.format(self.limit_low or 0.0)} {self.unit}. {self.why}")


@dataclass
class SiteReading:
    """Everything the metrics need, read off the site in one pass.

    A flat record rather than the site object, because several of these are
    derived from more than one place and one of them, the spread between the
    three power measurements, is not a property of the site at all. It is a
    property of the instruments disagreeing, which is the thing this site
    exists to demonstrate.
    """

    p_poi_mw: float = 0.0
    p_site_mw: float = 0.0
    q_site_mvar: float = 0.0
    apparent_mva: float = 0.0
    fleet_soc: float = 0.0
    stored_mwh: float = 0.0
    hottest_c: float = 0.0
    coolest_c: float = 0.0
    packs_online: float = 0.0
    capability_mw: float = 0.0
    ramp_mw_s: float = 0.0
    frequency_hz: float = 60.0
    voltage_pu: float = 1.0
    sources_live: float = 3.0
    measurement_spread_mw: float = 0.0
    poi_limit_mw: float = 20.0


HEADLINE = ("p_poi", "apparent", "fleet_soc", "hottest", "measurement_spread",
            "sources_live")


def catalogue(
    site: SiteConfig | None = None,
    safety: SiteSafetyConfig | None = None,
    pack: MegapackConfig | None = None,
) -> list[Metric]:
    """The whole set, in the order power meets them on the way out."""
    s = site or SiteConfig()
    pk = pack or MegapackConfig()
    _ = safety or SiteSafetyConfig()
    n = s.n_packs
    fleet_mw = n * pk.power_mw
    fleet_mwh = n * pk.energy_mwh

    return [
        Metric(
            key="fleet_soc", label="Charge in the batteries", unit="%",
            area=Area.FLEET, decimals=1, scale_max=100.0, direction="band",
            plain="How full the battery fleet is, averaged across all "
                  f"{n} units.",
            why="Run a lithium battery flat or overfull and it is damaged "
                "permanently. These are the two ends nothing is allowed to "
                "cross.",
            read=lambda r: r.fleet_soc * 100.0,
            limit_low=pk.soc_min_hard * 100.0, limit_high=pk.soc_max_hard * 100.0,
            target_low=10.0, target_high=90.0,
        ),
        Metric(
            key="stored", label="Energy in store", unit="MWh",
            area=Area.FLEET, decimals=1, scale_max=round(fleet_mwh, 1),
            direction="band",
            plain="How much electricity the site is holding right now.",
            why="This is what the site has left to sell or to support the grid "
                "with. It falls as the site exports and rises as it charges.",
            read=lambda r: r.stored_mwh,
        ),
        Metric(
            key="hottest", label="Hottest battery", unit="°C",
            area=Area.FLEET, decimals=1, scale_min=0.0, scale_max=70.0,
            direction="lower",
            plain="The temperature of the warmest unit on the site.",
            why="Lithium cells degrade fast when hot and, far enough over, "
                "catch fire. This is the number a battery yard is designed "
                "around.",
            read=lambda r: r.hottest_c,
            limit_high=pk.temp_trip_c, target_high=pk.temp_derate_c,
        ),
        Metric(
            key="coolest", label="Coolest battery", unit="°C",
            area=Area.FLEET, decimals=1, scale_min=-20.0, scale_max=70.0,
            direction="band",
            plain="The temperature of the coldest unit on the site.",
            why="A cold battery cannot take charge quickly. Below freezing it "
                "has to be warmed before it can be used at all.",
            read=lambda r: r.coolest_c,
            target_low=pk.temp_cold_c,
        ),
        Metric(
            key="packs_online", label="Units online", unit="",
            area=Area.FLEET, decimals=0, scale_max=float(n), direction="higher",
            plain=f"How many of the {n} battery units are connected and "
                  "available.",
            why="Every unit taken offline is capacity the site cannot deliver, "
                "and a site that cannot meet its dispatch is in breach of its "
                "contract.",
            read=lambda r: r.packs_online,
            target_low=float(n) - 1.0,
        ),
        Metric(
            key="capability", label="Power the fleet could deliver", unit="MW",
            area=Area.FLEET, decimals=2, scale_max=round(fleet_mw, 1),
            direction="higher",
            plain="The most the batteries could export right now, given how "
                  "full and how warm they are.",
            why="A battery that is nearly empty or nearly too hot can do less "
                "than its nameplate. Asking for more than this is asking for "
                "something that cannot happen.",
            read=lambda r: r.capability_mw,
        ),
        Metric(
            key="p_site", label="Power leaving the batteries", unit="MW",
            area=Area.COLLECTION, decimals=2, scale_min=-round(fleet_mw, 1),
            scale_max=round(fleet_mw, 1), direction="band",
            plain="The total the units are putting onto the site's own "
                  "network, before the transformer.",
            why="This is the sum of what every unit is doing. It should match "
                "what the grid meter sees, less the transformer's losses.",
            read=lambda r: r.p_site_mw,
        ),
        Metric(
            key="q_site", label="Reactive power", unit="MVAr",
            area=Area.COLLECTION, decimals=2, scale_min=-12.0, scale_max=12.0,
            direction="band",
            plain="Power that supports grid voltage without delivering any "
                  "energy.",
            why="The grid operator asks for it, and it uses up inverter "
                "capacity that would otherwise carry real power.",
            read=lambda r: r.q_site_mvar,
        ),
        Metric(
            key="apparent", label="Load on the transformer", unit="MVA",
            area=Area.TRANSFORMER, decimals=2, scale_max=round(s.poi_rating_mw * 1.6, 1),
            direction="lower",
            plain="How hard the site transformer is working, counting real and "
                  "reactive power together.",
            why="The transformer is rated for "
                f"{s.poi_rating_mw:.0f} MVA. Past that it overheats, and a "
                "transformer is a twelve-month lead item.",
            read=lambda r: r.apparent_mva,
            limit_high=s.poi_rating_mw, target_high=s.poi_rating_mw * 0.92,
        ),
        Metric(
            key="p_poi", label="Power going to the grid", unit="MW",
            area=Area.POI, decimals=2, scale_min=-round(fleet_mw, 1),
            scale_max=round(fleet_mw, 1), direction="band",
            plain="What the grid actually receives from this site.",
            why="The connection agreement caps this. Exceeding it can overload "
                "the lines the site feeds and breaches the contract that lets "
                "the site connect at all.",
            read=lambda r: r.p_poi_mw,
            limit_high=s.poi_limit_mw, target_high=s.poi_limit_mw * 0.95,
        ),
        Metric(
            key="ramp", label="How fast output is changing", unit="MW/s",
            area=Area.POI, decimals=3, scale_max=round(s.ramp_limit_mw_s * 3, 1),
            direction="lower",
            plain="How quickly the site is increasing or decreasing what it "
                  "sends to the grid.",
            why="The grid code limits this. A site that slams its output "
                "around destabilises the frequency for everybody connected "
                "nearby.",
            read=lambda r: abs(r.ramp_mw_s),
            limit_high=s.ramp_limit_mw_s, target_high=s.ramp_limit_mw_s * 0.8,
        ),
        Metric(
            key="frequency", label="Grid frequency", unit="Hz",
            area=Area.POI, decimals=3, scale_min=59.0, scale_max=61.0,
            direction="band",
            plain="The frequency of the grid the site is connected to.",
            why="It is the grid's pulse. The site has to match it before it "
                "can close its breaker, and it responds to changes in it.",
            read=lambda r: r.frequency_hz,
            target_low=59.5, target_high=60.5,
        ),
        Metric(
            key="measurement_spread", label="Disagreement between the meters",
            unit="MW", area=Area.MEASUREMENT, decimals=3, scale_max=2.0,
            direction="lower",
            plain="How far apart the three independent measurements of the "
                  "site's output are.",
            why="Three instruments measure the same power by three different "
                "routes. When they stop agreeing, one of them is wrong, and "
                "the guard has to work out which.",
            read=lambda r: r.measurement_spread_mw,
            limit_high=1.0, target_high=0.3,
        ),
        Metric(
            key="sources_live", label="Measurements still arriving", unit="of 3",
            area=Area.MEASUREMENT, decimals=0, scale_max=3.0, direction="higher",
            plain="How many of the three power measurements are still being "
                  "refreshed.",
            why="A measurement whose link has dropped does not vanish. It "
                "freezes at its last value and keeps agreeing with itself, "
                "which is how two dead instruments can outvote a live one.",
            read=lambda r: r.sources_live,
            limit_low=2.0, target_low=3.0,
        ),
    ]


def read_site(site: BessSite, *, spread_mw: float = 0.0,
              sources_live: int = 3, ramp_mw_s: float = 0.0) -> SiteReading:
    """One pass over the site, producing everything the metrics need."""
    packs = list(site.packs)
    online = [p for p in packs if p.state.online]
    temps = [p.state.temp_c for p in packs] or [0.0]
    socs = [p.state.soc for p in packs] or [0.0]
    st = site.state
    return SiteReading(
        p_poi_mw=st.p_poi_mw,
        p_site_mw=st.p_site_mw,
        q_site_mvar=st.q_site_mvar,
        apparent_mva=(st.p_poi_mw ** 2 + st.q_site_mvar ** 2) ** 0.5,
        fleet_soc=sum(socs) / len(socs),
        stored_mwh=sum(p.state.soc * p.cfg.energy_mwh for p in packs),
        hottest_c=max(temps),
        coolest_c=min(temps),
        packs_online=float(len(online)),
        capability_mw=site.fleet_capability_mw,
        ramp_mw_s=ramp_mw_s,
        frequency_hz=st.frequency_hz,
        voltage_pu=st.voltage_pu,
        sources_live=float(sources_live),
        measurement_spread_mw=spread_mw,
        poi_limit_mw=site.poi_limit_mw,
    )


def assess(reading: SiteReading, site: SiteConfig | None = None,
           safety: SiteSafetyConfig | None = None,
           pack: MegapackConfig | None = None) -> list[dict]:
    """Every metric, read and judged, ready for a display or a report."""
    out = []
    for metric in catalogue(site, safety, pack):
        value = metric.value(reading)
        health = metric.health(value)
        out.append({
            "key": metric.key, "label": metric.label, "unit": metric.unit,
            "area": metric.area.value,
            "value": round(value, 4), "shown": metric.format(value),
            "health": health.value, "health_label": health.label,
            "fraction": round(metric.fraction(value), 4),
            "marks": [{"at": round(f, 4), "name": nm}
                      for f, nm in metric.limit_fractions()],
            "limit_low": metric.limit_low, "limit_high": metric.limit_high,
            "target_low": metric.target_low, "target_high": metric.target_high,
            "scale_min": metric.scale_min, "scale_max": metric.scale_max,
            "plain": metric.plain, "why": metric.why,
            "headline": metric.key in HEADLINE,
        })
    return out
