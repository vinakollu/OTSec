"""Every number this plant is judged by, defined once, in one place.

Written before the guard rather than after it, which is the opposite of how
the tank and the storage site were built. Both of those grew their metrics as
the evaluation needed them, and both ended up with numbers whose denominators
had to be reconstructed later. Here the catalogue comes first and everything
else reads from it: the rules check against these limits, the display draws
these bars, and the narration explains these words.

Each entry carries four things, and the fourth is the one that is usually
missing from an operator display.

``limits``   what the number must stay between, and where that came from
``scale``    the range to draw the bar over, so a reader sees the margin
``plain``    what the number is, for somebody who has never run a works
``why``      what happens to a person drinking the water if it goes wrong

The last two are not decoration. A dashboard that says "CT 4.1" to a room of
people who do not know what CT is has communicated nothing, and an audience
that cannot tell which numbers matter cannot tell whether the guard helped.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable

from .plant import WaterSafety
from .types import PlantState, Stage


class Health(str, Enum):
    """How a metric is doing. Never shown as colour alone."""

    GOOD = "good"        # inside the operating target
    WATCH = "watch"      # inside the legal limit, outside the target
    BREACH = "breach"    # outside the limit water may leave at

    @property
    def label(self) -> str:
        return {"good": "OK", "watch": "Watch", "breach": "Breach"}[self.value]


@dataclass(frozen=True)
class Metric:
    """One measured quantity, its limits, and what it means in English."""

    key: str
    label: str
    unit: str
    stage: Stage
    plain: str
    why: str
    read: Callable[[PlantState], float]
    scale_min: float = 0.0
    scale_max: float = 1.0
    limit_low: float | None = None     # below this, water is unsafe
    limit_high: float | None = None    # above this, water is unsafe
    target_low: float | None = None    # below this, somebody should look
    target_high: float | None = None   # above this, somebody should look
    decimals: int = 2
    #: Higher is better, lower is better, or a band is best. Drives the wording.
    direction: str = "band"

    def value(self, state: PlantState) -> float:
        return self.read(state)

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
        """Where this value sits on its own scale, 0 to 1, for a meter."""
        span = self.scale_max - self.scale_min
        if span <= 0:
            return 0.0
        return max(0.0, min(1.0, (value - self.scale_min) / span))

    def limit_fractions(self) -> list[tuple[float, str]]:
        """Where to draw the limit marks on the meter track."""
        marks = []
        for limit, name in ((self.limit_low, "min"), (self.limit_high, "max")):
            if limit is not None:
                marks.append((self.fraction(limit), name))
        return marks

    def format(self, value: float) -> str:
        return f"{value:.{self.decimals}f}"

    def say(self, value: float) -> str:
        """One sentence about where this number is, in plain English."""
        health = self.health(value)
        shown = f"{self.format(value)} {self.unit}".strip()
        if health is Health.GOOD:
            return f"{self.label} is {shown}, which is normal."
        if health is Health.WATCH:
            if self.target_high is not None and value > self.target_high:
                return (f"{self.label} has risen to {shown}. Still legal, but it is "
                        f"heading the wrong way.")
            return (f"{self.label} has fallen to {shown}. Still legal, but it is "
                    f"heading the wrong way.")
        if self.limit_high is not None and value > self.limit_high:
            return (f"{self.label} is {shown}, above the safe limit of "
                    f"{self.format(self.limit_high)} {self.unit}. {self.why}")
        return (f"{self.label} is {shown}, below the safe minimum of "
                f"{self.format(self.limit_low or 0.0)} {self.unit}. {self.why}")


def catalogue(safety: WaterSafety | None = None) -> list[Metric]:
    """The whole set, in the order water meets them."""
    s = safety or WaterSafety()
    return [
        Metric(
            key="raw_flow", label="Raw water coming in", unit="m³/h",
            stage=Stage.INTAKE, decimals=0, scale_max=1800.0, direction="band",
            plain="How much river water the plant is drawing per hour.",
            why="Everything else is dosed in proportion to this, so if it is "
                "wrong every chemical on the site is wrong with it.",
            read=lambda st: st.raw_flow_m3h,
            target_high=1700.0,
        ),
        Metric(
            key="raw_turbidity", label="Raw water cloudiness", unit="NTU",
            stage=Stage.INTAKE, decimals=2, scale_max=20.0, direction="lower",
            plain="How much mud and silt is in the river water arriving.",
            why="Dirty water needs more coagulant and more chlorine. It is the "
                "reason a fixed dose is never safe.",
            read=lambda st: st.raw_turbidity_ntu,
            target_high=12.0,
        ),
        Metric(
            key="coagulant", label="Coagulant dose", unit="mg/L",
            stage=Stage.COAGULATION, decimals=2, scale_max=40.0, direction="band",
            plain="The chemical that makes fine mud clump together so it can settle.",
            why="Too little and the mud goes straight through the filters. Far too "
                "much and it carries over and breaks through anyway.",
            read=lambda st: st.coagulant_dose_mg_l,
        ),
        Metric(
            key="settled_turbidity", label="Cloudiness after settling", unit="NTU",
            stage=Stage.SEDIMENTATION, decimals=2, scale_max=6.0, direction="lower",
            plain="How much mud is still in the water after the clarifier.",
            why="This is the load the filters have to catch. If it climbs, the "
                "filters blind faster and eventually stop catching anything.",
            read=lambda st: st.settled_turbidity_ntu,
            target_high=2.0,
        ),
        Metric(
            key="filtered_turbidity", label="Cloudiness leaving the filters", unit="NTU",
            stage=Stage.FILTRATION, decimals=3, scale_max=1.2, direction="lower",
            plain="How clear the water is once it has been through the sand filters.",
            why="Particles hide bacteria and viruses from the chlorine. This is a "
                "health limit, not a question of how the water looks.",
            read=lambda st: st.filtered_turbidity_ntu,
            target_high=s.turbidity_action_ntu, limit_high=s.turbidity_breach_ntu,
        ),
        Metric(
            key="filter_headloss", label="Filter clogging", unit="m",
            stage=Stage.FILTRATION, decimals=2, scale_max=2.4, direction="lower",
            plain="How blocked the sand filter has become since its last wash.",
            why="A blocked filter stops removing particles before it stops passing "
                "water, so it fails quietly.",
            read=lambda st: st.filter_headloss_m,
            target_high=1.9,
        ),
        Metric(
            key="chlorine_dose", label="Chlorine being added", unit="mg/L",
            stage=Stage.DISINFECTION, decimals=2, scale_max=12.0, direction="band",
            plain="How much chlorine the dosing pump is injecting.",
            why="This is the command. What matters is what survives to the far end "
                "of the contact tank, which is the next number down.",
            read=lambda st: st.chlorine_dose_mg_l,
            target_high=6.0,
        ),
        Metric(
            key="chlorine_residual", label="Chlorine leaving the works", unit="mg/L",
            stage=Stage.DISINFECTION, decimals=2, scale_max=6.0, direction="band",
            plain="How much chlorine is still in the water when it leaves.",
            why="Too little and the water is not disinfected. Too much and it is "
                "unpleasant and, far enough over, unsafe to drink.",
            read=lambda st: st.chlorine_residual_mg_l,
            limit_low=s.residual_min_mg_l, limit_high=s.residual_max_mg_l,
            target_low=0.40, target_high=2.50,
        ),
        Metric(
            key="contact_time", label="Time in the contact tank", unit="min",
            stage=Stage.CLEARWELL, decimals=0, scale_max=90.0, direction="higher",
            plain="How long the water sits with the chlorine before it is sent out.",
            why="Disinfection needs both chlorine and time. Pump the tank out "
                "faster and the water leaves before the chlorine has finished.",
            read=lambda st: st.contact_time_min,
            target_low=20.0,
        ),
        Metric(
            key="ct", label="Disinfection achieved (CT)", unit="mg·min/L",
            stage=Stage.CLEARWELL, decimals=1, scale_max=40.0, direction="higher",
            plain="Chlorine multiplied by contact time. The actual measure "
                  "of whether the bugs have been killed.",
            why="No instrument on the plant reads this. It has to be worked out "
                "from three of them, which is why it is the easiest thing to lose.",
            read=lambda st: st.ct_value,
            limit_low=s.ct_required, target_low=s.ct_required * 1.6,
        ),
        Metric(
            key="ph", label="pH of the final water", unit="",
            stage=Stage.DISINFECTION, decimals=2, scale_min=5.0, scale_max=10.0,
            direction="band",
            plain="How acidic or alkaline the treated water is.",
            why="Outside the safe band the water is unpleasant, chlorine stops "
                "working properly, and it starts dissolving metal out of the pipes.",
            read=lambda st: st.ph,
            limit_low=s.ph_min, limit_high=s.ph_max,
            target_low=6.9, target_high=8.1,
        ),
        Metric(
            key="clearwell_level", label="Treated water in store", unit="m",
            stage=Stage.CLEARWELL, decimals=2, scale_max=6.0, direction="band",
            plain="How full the treated water tank is.",
            why="Empty and the town loses supply and the pumps are damaged. "
                "Overflowing wastes treated water and can suck contamination back in.",
            read=lambda st: st.clearwell_level_m,
            limit_low=s.clearwell_min_m, limit_high=s.clearwell_max_m,
            target_low=1.8, target_high=5.0,
        ),
        Metric(
            key="final_flow", label="Water going to the town", unit="m³/h",
            stage=Stage.DISTRIBUTION, decimals=0, scale_max=2000.0, direction="band",
            plain="How much treated water is being pumped into the mains.",
            why="This is what divides into the contact tank to give contact time. "
                "Raising it quietly lowers disinfection.",
            read=lambda st: st.clearwell_outflow_m3h,
        ),
        Metric(
            key="pressure", label="Pressure in the mains", unit="bar",
            stage=Stage.DISTRIBUTION, decimals=2, scale_max=6.0, direction="band",
            plain="The pressure holding water in the pipes to people's homes.",
            why="If it falls far enough, dirty groundwater can be drawn in through "
                "any leak in the network.",
            read=lambda st: st.distribution_pressure_bar,
            limit_low=s.pressure_min_bar, limit_high=s.pressure_max_bar,
            target_low=1.9, target_high=5.2,
        ),
    ]


#: The handful a dashboard leads with. Everything else is below the fold.
HEADLINE = ("ct", "chlorine_residual", "filtered_turbidity", "ph",
            "clearwell_level", "pressure")


def by_key(safety: WaterSafety | None = None) -> dict[str, Metric]:
    return {m.key: m for m in catalogue(safety)}


def assess(state: PlantState, safety: WaterSafety | None = None) -> list[dict]:
    """Every metric, read and judged, ready for a display or a report."""
    out = []
    for metric in catalogue(safety):
        value = metric.value(state)
        health = metric.health(value)
        out.append({
            "key": metric.key,
            "label": metric.label,
            "unit": metric.unit,
            "stage": metric.stage.value,
            "value": round(value, 4),
            "shown": metric.format(value),
            "health": health.value,
            "health_label": health.label,
            "fraction": round(metric.fraction(value), 4),
            "marks": [{"at": round(f, 4), "name": n} for f, n in metric.limit_fractions()],
            "limit_low": metric.limit_low,
            "limit_high": metric.limit_high,
            "target_low": metric.target_low,
            "target_high": metric.target_high,
            "scale_min": metric.scale_min, "decimals": metric.decimals,
            "scale_max": metric.scale_max,
            "plain": metric.plain,
            "why": metric.why,
            "headline": metric.key in HEADLINE,
        })
    return out
