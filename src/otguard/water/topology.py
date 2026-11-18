"""The OT environment around the works: who talks to what, and across which line.

A treatment plant is not one controller. It is five or six of them spread
across a site, a remote intake that answers over a radio link, a rack of
analysers, and above all that the supervisory layer an operator actually
touches. The guard sits on one conduit inside that, and the point of writing
the rest down is to be honest about how much of the plant it is *not* on.

Levels follow the Purdue model, which is how a water utility's own drawings
would label them:

* **Level 0** instruments and final elements: analysers, flow meters, dose pumps
* **Level 1** controllers: the PLCs and the remote terminal unit
* **Level 2** supervisory: SCADA servers and the operator stations
* **Level 3** site operations: historian, engineering workstation
* **Level 3.5** a demilitarised zone: the jump server
* **Level 4** enterprise: billing, the vendor's remote support

The guard is installed on the conduit between Level 2 and Level 1, which is
where an operator's command crosses into the plant. Everything an attacker does
at Level 3 or above has to cross it to reach water. Everything they do by
standing in the chemical building does not.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .types import Stage, WaterCommandKind


@dataclass(frozen=True)
class Zone:
    name: str
    level: str
    purpose: str


@dataclass(frozen=True)
class Conduit:
    name: str
    source: str
    target: str
    protocol: str
    guarded: bool
    note: str = ""


@dataclass(frozen=True)
class Device:
    """One box on the network, and what it is allowed to do to the water."""

    name: str
    kind: str                 # plc | rtu | analyser | drive | server | workstation
    zone: str
    level: str
    stage: Stage
    protocol: str
    address: str
    writes: tuple[WaterCommandKind, ...] = ()
    reads: tuple[str, ...] = ()
    description: str = ""
    critical: bool = False

    @property
    def is_controller(self) -> bool:
        return self.kind in ("plc", "rtu")


ZONES: tuple[Zone, ...] = (
    Zone("enterprise", "Level 4", "Billing, email, the vendor's remote support"),
    Zone("dmz", "Level 3.5", "The jump server everything from outside must pass through"),
    Zone("operations", "Level 3", "Historian and the engineering workstation"),
    Zone("supervisory", "Level 2", "SCADA servers and the operator stations"),
    Zone("control", "Level 1", "The controllers that run the process"),
    Zone("field", "Level 0", "Analysers, meters and dose pumps"),
)

CONDUITS: tuple[Conduit, ...] = (
    Conduit("enterprise_to_dmz", "enterprise", "dmz", "https", False,
            "Vendor support and reporting. Not on the guard's path."),
    Conduit("dmz_to_operations", "dmz", "operations", "rdp/https", False,
            "Where a stolen jump-server session arrives."),
    Conduit("operations_to_supervisory", "operations", "supervisory", "opc_ua", False,
            "The historian's own feed. Reads only, and not guarded."),
    Conduit("supervisory_to_control", "supervisory", "control", "modbus_tcp", True,
            "Every operator command to the plant. This is where the guard is."),
    Conduit("control_to_field", "control", "field", "modbus_rtu/4-20mA", False,
            "Below the guard. An attacker here is out of its reach."),
    Conduit("intake_radio", "control", "field", "dnp3", False,
            "The licensed radio link to the remote intake."),
)

DEVICES: tuple[Device, ...] = (
    # ---- Level 1 controllers -----------------------------------------
    Device("PLC-INTAKE", "plc", "control", "Level 1", Stage.INTAKE, "modbus_tcp",
           "10.20.1.11",
           writes=(WaterCommandKind.INTAKE_PUMP, WaterCommandKind.RAW_VALVE),
           reads=("raw_flow", "raw_turbidity"),
           description="Runs the raw water pumps and the intake valve.",
           critical=True),
    Device("PLC-CHEM", "plc", "control", "Level 1", Stage.COAGULATION, "modbus_tcp",
           "10.20.1.12",
           writes=(WaterCommandKind.COAGULANT_DOSE, WaterCommandKind.POLYMER_DOSE,
                   WaterCommandKind.FLOC_PADDLE),
           reads=("coagulant_feed", "settled_turbidity"),
           description="Coagulant and polymer dosing, and the flocculator paddles.",
           critical=True),
    Device("PLC-FILTER", "plc", "control", "Level 1", Stage.FILTRATION, "modbus_tcp",
           "10.20.1.13",
           writes=(WaterCommandKind.FILTER_VALVE, WaterCommandKind.BACKWASH,
                   WaterCommandKind.TURBIDITY_ALARM),
           reads=("filtered_turbidity", "filter_headloss"),
           description="Filter outlet valves, backwash sequencing, turbidity alarms.",
           critical=True),
    Device("PLC-DISINFECT", "plc", "control", "Level 1", Stage.DISINFECTION, "modbus_tcp",
           "10.20.1.14",
           writes=(WaterCommandKind.CHLORINE_DOSE, WaterCommandKind.CAUSTIC_DOSE,
                   WaterCommandKind.MAX_CHLORINE_DOSE, WaterCommandKind.MAX_CAUSTIC_DOSE),
           reads=("chlorine_residual", "ph"),
           description="Chlorine and caustic dosing, and the ceilings they obey.",
           critical=True),
    Device("PLC-DIST", "plc", "control", "Level 1", Stage.DISTRIBUTION, "modbus_tcp",
           "10.20.1.15",
           writes=(WaterCommandKind.HIGH_LIFT_PUMP, WaterCommandKind.CLEARWELL_OUTLET,
                   WaterCommandKind.MODE),
           reads=("clearwell_level", "distribution_pressure"),
           description="High-lift pumps and the clearwell outlet to the town.",
           critical=True),
    Device("RTU-INTAKE", "rtu", "control", "Level 1", Stage.INTAKE, "dnp3",
           "10.20.1.30",
           reads=("river_level", "raw_flow"),
           description="Remote river intake, over a licensed radio link.",
           critical=False),

    # ---- Level 0 field devices ---------------------------------------
    Device("AIT-RAW-TURB", "analyser", "field", "Level 0", Stage.INTAKE, "4-20mA",
           "AI 1.01", reads=("raw_turbidity",),
           description="Raw water turbidity analyser."),
    Device("AIT-SETTLED-TURB", "analyser", "field", "Level 0", Stage.SEDIMENTATION,
           "4-20mA", "AI 2.04", reads=("settled_turbidity",),
           description="Settled water turbidity, after the clarifier."),
    Device("AIT-FILT-TURB", "analyser", "field", "Level 0", Stage.FILTRATION, "4-20mA",
           "AI 3.02", reads=("filtered_turbidity",),
           description="Filtered water turbidity. The compliance instrument.",
           critical=True),
    Device("AIT-CL2", "analyser", "field", "Level 0", Stage.DISINFECTION, "modbus_rtu",
           "unit 4", reads=("chlorine_residual",),
           description="Free chlorine residual leaving the contact tank.",
           critical=True),
    Device("AIT-PH", "analyser", "field", "Level 0", Stage.DISINFECTION, "modbus_rtu",
           "unit 5", reads=("ph",), description="Final pH."),
    Device("FIT-RAW", "analyser", "field", "Level 0", Stage.INTAKE, "4-20mA",
           "AI 1.02", reads=("raw_flow",), description="Raw water flow meter."),
    Device("FIT-FINAL", "analyser", "field", "Level 0", Stage.DISTRIBUTION, "4-20mA",
           "AI 5.01", reads=("clearwell_outflow",),
           description="Final water flow to the town.", critical=True),
    Device("LIT-CLEARWELL", "analyser", "field", "Level 0", Stage.CLEARWELL, "4-20mA",
           "AI 4.01", reads=("clearwell_level",),
           description="Treated water storage level.", critical=True),
    Device("PIT-DIST", "analyser", "field", "Level 0", Stage.DISTRIBUTION, "4-20mA",
           "AI 5.02", reads=("distribution_pressure",),
           description="Pressure in the main leaving the works.", critical=True),
    Device("VFD-HIGHLIFT-1", "drive", "field", "Level 0", Stage.DISTRIBUTION, "modbus_rtu",
           "unit 11", description="High-lift pump 1 variable-frequency drive."),
    Device("DOSE-CL2", "drive", "field", "Level 0", Stage.DISINFECTION, "modbus_rtu",
           "unit 21", description="Chlorine dosing pump.", critical=True),

    # ---- Level 2 and above -------------------------------------------
    Device("SCADA-01", "server", "supervisory", "Level 2", Stage.DISTRIBUTION, "modbus_tcp",
           "10.10.2.10",
           writes=tuple(WaterCommandKind),
           description="Supervisory control. Runs the plant's automatic loops."),
    Device("HMI-01", "workstation", "supervisory", "Level 2", Stage.DISTRIBUTION,
           "modbus_tcp", "10.10.2.21",
           writes=tuple(WaterCommandKind),
           description="The operator's screen in the control room."),
    Device("HIST-01", "server", "operations", "Level 3", Stage.DISTRIBUTION, "opc_ua",
           "10.10.3.10", reads=("everything",),
           description="Process historian. Reads continuously, writes nothing."),
    Device("ENG-01", "workstation", "operations", "Level 3", Stage.DISINFECTION,
           "modbus_tcp", "10.10.3.22",
           writes=(WaterCommandKind.MAX_CHLORINE_DOSE, WaterCommandKind.MAX_CAUSTIC_DOSE,
                   WaterCommandKind.TURBIDITY_ALARM),
           description="Engineering workstation. Changes configuration, rarely."),
    Device("JUMP-01", "server", "dmz", "Level 3.5", Stage.DISTRIBUTION, "rdp",
           "10.10.35.5",
           description="The jump server. Everything from outside arrives here."),
)


@dataclass
class Topology:
    """The site, assembled, with a few questions it can answer about itself."""

    zones: tuple[Zone, ...] = ZONES
    conduits: tuple[Conduit, ...] = CONDUITS
    devices: tuple[Device, ...] = DEVICES
    _by_name: dict[str, Device] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self._by_name = {d.name: d for d in self.devices}

    def device(self, name: str) -> Device | None:
        return self._by_name.get(name)

    def controllers(self) -> list[Device]:
        return [d for d in self.devices if d.is_controller]

    def analysers(self) -> list[Device]:
        return [d for d in self.devices if d.kind == "analyser"]

    def in_zone(self, zone: str) -> list[Device]:
        return [d for d in self.devices if d.zone == zone]

    def owner_of(self, kind: WaterCommandKind) -> Device | None:
        """Which controller is supposed to be driving this point."""
        for device in self.controllers():
            if kind in device.writes:
                return device
        return None

    def may_write(self, device_name: str, kind: WaterCommandKind) -> bool:
        """Is this device configured to write this point at all?

        Weak evidence and the code says so: it is a statement about what the
        plant's documentation records, not about who is really at the keyboard.
        An attacker on the operator station inherits the operator station's
        permissions, which is the threat model throughout this project.
        """
        device = self.device(device_name)
        if device is None:
            return False
        return kind in device.writes

    def guarded_conduit(self) -> Conduit:
        return next(c for c in self.conduits if c.guarded)

    def summary(self) -> dict:
        return {
            "zones": [{"name": z.name, "level": z.level, "purpose": z.purpose}
                      for z in self.zones],
            "conduits": [{"name": c.name, "source": c.source, "target": c.target,
                          "protocol": c.protocol, "guarded": c.guarded, "note": c.note}
                         for c in self.conduits],
            "devices": [{"name": d.name, "kind": d.kind, "zone": d.zone,
                         "level": d.level, "stage": d.stage.value,
                         "protocol": d.protocol, "address": d.address,
                         "writes": [w.value for w in d.writes],
                         "description": d.description, "critical": d.critical}
                        for d in self.devices],
        }
