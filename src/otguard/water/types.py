"""What a water treatment plant is made of, as the guard sees it.

The tank and the storage site each had one quantity worth protecting: a level,
and a power. A treatment works has several, they are measured in different
units, and the dangerous ones are chemical rather than mechanical. Nothing here
can be reduced to "is the number too big", 11,100 ppm of sodium hydroxide is a
perfectly ordinary number for a chemical that is dosed in parts per million,
and it is the number that nearly poisoned Oldsmar.

Three groups of writable points, and the difference between them is the whole
reason this plant is worth modelling.

*Actuators* move water: pump speeds, valve positions. Their effects are
hydraulic, fast, and visible in a level or a flow within seconds.

*Doses* add chemicals: coagulant, chlorine, caustic. Their effects are chemical,
delayed by the time water takes to travel through the works, and invisible until
the water reaches an analyser several minutes downstream. A bad dose is already
in the clearwell by the time anything measures it.

*Limits* are configuration: the maximum dose a controller will accept, the
turbidity at which it alarms. Writing one moves nothing at all. It changes what
every later command is checked against, which is why it is the cheapest harmful
write on the plant and why it gets its own role here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Stage(str, Enum):
    """The treatment train, in the order water passes through it."""

    INTAKE = "intake"
    COAGULATION = "coagulation"
    FLOCCULATION = "flocculation"
    SEDIMENTATION = "sedimentation"
    FILTRATION = "filtration"
    DISINFECTION = "disinfection"
    CLEARWELL = "clearwell"
    DISTRIBUTION = "distribution"

    @property
    def label(self) -> str:
        return {
            "intake": "Raw water intake",
            "coagulation": "Coagulation",
            "flocculation": "Flocculation",
            "sedimentation": "Sedimentation",
            "filtration": "Filtration",
            "disinfection": "Disinfection",
            "clearwell": "Clearwell",
            "distribution": "Distribution",
        }[self.value]


class PointRole(str, Enum):
    """Why writing this point matters, which is not the same as what it is."""

    ACTUATOR = "actuator"     # moves water now
    DOSE = "dose"             # adds a chemical, felt minutes later
    LIMIT = "limit"           # moves nothing; changes what else is allowed
    MODE = "mode"             # hands control between loops


class WaterCommandKind(str, Enum):
    """Every point an operator, a controller or an attacker can write."""

    INTAKE_PUMP = "intake_pump"            # %
    RAW_VALVE = "raw_valve"                # %
    COAGULANT_DOSE = "coagulant_dose"      # mg/L
    POLYMER_DOSE = "polymer_dose"          # mg/L
    FLOC_PADDLE = "floc_paddle"            # %
    FILTER_VALVE = "filter_valve"          # %
    BACKWASH = "backwash"                  # 0/1
    CHLORINE_DOSE = "chlorine_dose"        # mg/L
    CAUSTIC_DOSE = "caustic_dose"          # mg/L
    HIGH_LIFT_PUMP = "high_lift_pump"      # %
    CLEARWELL_OUTLET = "clearwell_outlet"  # %
    MAX_CHLORINE_DOSE = "max_chlorine_dose"  # mg/L, a configured ceiling
    MAX_CAUSTIC_DOSE = "max_caustic_dose"    # mg/L, a configured ceiling
    TURBIDITY_ALARM = "turbidity_alarm"      # NTU, a configured alarm point
    MODE = "mode"                          # 0 manual, 1 auto

    @property
    def unit(self) -> str:
        return {
            "intake_pump": "%", "raw_valve": "%", "floc_paddle": "%",
            "filter_valve": "%", "high_lift_pump": "%", "clearwell_outlet": "%",
            "coagulant_dose": "mg/L", "polymer_dose": "mg/L",
            "chlorine_dose": "mg/L", "caustic_dose": "mg/L",
            "max_chlorine_dose": "mg/L", "max_caustic_dose": "mg/L",
            "turbidity_alarm": "NTU", "backwash": "", "mode": "",
        }[self.value]

    @property
    def role(self) -> PointRole:
        if self.value in ("max_chlorine_dose", "max_caustic_dose", "turbidity_alarm"):
            return PointRole.LIMIT
        if self.value in ("coagulant_dose", "polymer_dose", "chlorine_dose",
                          "caustic_dose"):
            return PointRole.DOSE
        if self.value == "mode":
            return PointRole.MODE
        return PointRole.ACTUATOR

    @property
    def stage(self) -> Stage:
        return {
            "intake_pump": Stage.INTAKE, "raw_valve": Stage.INTAKE,
            "coagulant_dose": Stage.COAGULATION,
            "polymer_dose": Stage.COAGULATION,
            "floc_paddle": Stage.FLOCCULATION,
            "filter_valve": Stage.FILTRATION, "backwash": Stage.FILTRATION,
            "turbidity_alarm": Stage.FILTRATION,
            "chlorine_dose": Stage.DISINFECTION,
            "max_chlorine_dose": Stage.DISINFECTION,
            "caustic_dose": Stage.DISINFECTION,
            "max_caustic_dose": Stage.DISINFECTION,
            "clearwell_outlet": Stage.CLEARWELL,
            "high_lift_pump": Stage.DISTRIBUTION,
            "mode": Stage.DISTRIBUTION,
        }[self.value]

    @property
    def label(self) -> str:
        """What to call this on a screen somebody is reading for the first time."""
        return {
            "intake_pump": "raw water pump speed",
            "raw_valve": "raw water valve",
            "coagulant_dose": "coagulant dose",
            "polymer_dose": "polymer dose",
            "floc_paddle": "flocculator paddle speed",
            "filter_valve": "filter outlet valve",
            "backwash": "filter backwash",
            "chlorine_dose": "chlorine dose",
            "caustic_dose": "caustic soda dose",
            "high_lift_pump": "high-lift pump speed",
            "clearwell_outlet": "clearwell outlet valve",
            "max_chlorine_dose": "chlorine dose ceiling",
            "max_caustic_dose": "caustic dose ceiling",
            "turbidity_alarm": "turbidity alarm point",
            "mode": "control mode",
        }[self.value]


@dataclass(frozen=True)
class WaterCommand:
    """One write heading for a controller."""

    t: float
    kind: WaterCommandKind
    value: float
    source: str = "hmi"
    zone: str = "control"
    device: str = ""

    def __str__(self) -> str:
        return f"t={self.t:7.2f}s {self.kind.value}={self.value:g}{self.kind.unit}"


@dataclass(frozen=True)
class Analyser:
    """One instrument's reading, and whether anybody has heard from it lately.

    ``age_s`` is the load-bearing field. An analyser whose link has dropped goes
    on reporting its last value to SCADA, and a stale reading looks exactly like
    a steady one. The storage site learned this the expensive way, where two
    frozen measurements outvoted the only honest instrument.
    """

    name: str
    value: float
    unit: str
    age_s: float = 0.0
    stage: Stage = Stage.FILTRATION

    @property
    def stale(self) -> bool:
        return self.age_s > 30.0


@dataclass(frozen=True)
class WaterObservation:
    """Everything the guard is told about the plant on one scan.

    These are *reported* numbers. Under a false-data attack they are not what
    the plant is doing, which is the distinction the whole project is built on.
    """

    t: float
    raw_flow_m3h: float
    raw_turbidity_ntu: float
    settled_turbidity_ntu: float
    filtered_turbidity_ntu: float
    coagulant_dose_mg_l: float
    chlorine_dose_mg_l: float
    caustic_dose_mg_l: float
    chlorine_residual_mg_l: float
    ph: float
    clearwell_level_m: float
    clearwell_outflow_m3h: float
    distribution_pressure_bar: float
    contact_time_min: float
    ct_value: float
    filter_headloss_m: float
    analysers: tuple[Analyser, ...] = ()

    def analyser(self, name: str) -> Analyser | None:
        for item in self.analysers:
            if item.name == name:
                return item
        return None


@dataclass
class PlantState:
    """Where the works actually is, which only the simulation knows."""

    t: float = 0.0
    raw_flow_m3h: float = 0.0
    raw_turbidity_ntu: float = 4.0
    raw_ph: float = 7.6
    coagulant_dose_mg_l: float = 0.0
    polymer_dose_mg_l: float = 0.0
    floc_paddle_pct: float = 0.0
    settled_turbidity_ntu: float = 4.0
    filtered_turbidity_ntu: float = 0.08
    filter_headloss_m: float = 0.3
    filter_in_backwash: bool = False
    chlorine_dose_mg_l: float = 0.0
    caustic_dose_mg_l: float = 0.0
    chlorine_residual_mg_l: float = 0.0
    ph: float = 7.6
    clearwell_level_m: float = 3.5
    clearwell_outflow_m3h: float = 0.0
    distribution_pressure_bar: float = 3.4
    contact_time_min: float = 0.0
    ct_value: float = 0.0

    # Commanded positions, latched from whatever reached the controllers.
    intake_pump_pct: float = 0.0
    raw_valve_pct: float = 0.0
    filter_valve_pct: float = 0.0
    high_lift_pump_pct: float = 0.0
    clearwell_outlet_pct: float = 0.0

    # Configured ceilings. Writable, which is the point.
    max_chlorine_dose_mg_l: float = 5.0
    max_caustic_dose_mg_l: float = 30.0
    turbidity_alarm_ntu: float = 0.30

    # What has gone wrong, and stays wrong.
    harms: set[str] = field(default_factory=set)

    @property
    def harmed(self) -> bool:
        return bool(self.harms)


#: What each harm means to somebody who does not work at a water utility.
HARM_MEANING: dict[str, str] = {
    "under_disinfected": (
        "Water left the plant without enough chlorine contact to kill "
        "bacteria and viruses. This is how a boil-water notice starts."
    ),
    "chemical_overdose": (
        "Water left the plant carrying far more chemical than is safe to "
        "drink. This is what nearly happened at Oldsmar in 2021."
    ),
    "turbidity_breach": (
        "Cloudy water got past the filters. The particles shield microbes "
        "from disinfection, so this is a health risk and not a cosmetic one."
    ),
    "ph_excursion": (
        "The water went acidic or caustic enough to be unsafe and to start "
        "dissolving metal out of the pipes on the way to people's taps."
    ),
    "clearwell_overflow": (
        "The treated water tank overflowed. Treated water is lost and the "
        "overflow can draw contamination back into the tank."
    ),
    "clearwell_empty": (
        "The treated water tank ran dry. The pumps downstream cavitate and "
        "the town loses supply."
    ),
    "pressure_loss": (
        "Pressure in the mains collapsed. Groundwater and whatever is in it "
        "can be drawn into the pipes through any leak."
    ),
}
