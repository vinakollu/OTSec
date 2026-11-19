"""Site architecture as IEC 62443 zones and conduits.

The equipment on a storage site is not a flat network, and the segmentation is
not decoration, it is a security control that a command either respects or does
not. This module turns "there is a jump server and a firewall" into something a
rule can actually adjudicate.

The model is the Purdue reference architecture with 62443 zones layered on top:

    Level 4  enterprise      corporate IT, historians, market systems
    Level 3.5 dmz            jump server, firewall, the only way in
    Level 3  supervisory     SCADA front end, engineering workstation, HMI
    Level 2  control         site controller
    Level 1  field           Megapack controllers, protection relays, meter
    Level 0  process         cells, inverters, switchgear

A *conduit* is a permitted communication path between two zones, carrying named
protocols in a named direction. Anything not described by a conduit is not
supposed to happen, and rule B8 treats a write that arrives outside one as
implausible regardless of its content, the same move the physics rules make,
but with the site's architecture as the invariant instead of its dynamics.

Worth being explicit about what this is *not*: it is a model of the segmentation,
not an implementation of it. A real deployment gets these properties from the
firewall's rule set and the jump server's session records. Here they are fields
on a command that the harness populates, and the guard's job is to notice when
they are wrong. The distinction matters when reading the results, B8's
detections show the rule works given trustworthy provenance metadata, not that
the metadata is unforgeable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, IntEnum


class PurdueLevel(IntEnum):
    """Purdue model levels, coarse but universally understood in OT."""

    PROCESS = 0
    FIELD = 1
    CONTROL = 2
    SUPERVISORY = 3
    DMZ = 35          # conventionally "Level 3.5"; scaled to stay an int
    ENTERPRISE = 4

    @property
    def label(self) -> str:
        return {
            0: "Level 0 process",
            1: "Level 1 field",
            2: "Level 2 control",
            3: "Level 3 supervisory",
            35: "Level 3.5 DMZ",
            4: "Level 4 enterprise",
        }[int(self)]

    @property
    def rank(self) -> float:
        """Position in the hierarchy, for measuring how far a flow reaches.

        The enum values cannot be used directly: the DMZ is conventionally
        "Level 3.5" and is stored as 35 to keep the enum integral, which would
        make it read as thirty-one levels above the supervisory zone.
        """
        return 3.5 if self is PurdueLevel.DMZ else float(int(self))


class Role(str, Enum):
    """What a device is for. Drives the default conduit policy."""

    SITE_CONTROLLER = "site_controller"
    MEGAPACK = "megapack"
    RELAY = "relay"
    METER = "meter"
    SWITCH = "switch"
    SCADA = "scada"
    HMI = "hmi"
    JUMP_SERVER = "jump_server"
    FIREWALL = "firewall"
    HISTORIAN = "historian"
    ENGINEERING = "engineering_workstation"


@dataclass(frozen=True)
class Device:
    """One box on the site network."""

    name: str
    role: Role
    zone: str
    level: PurdueLevel
    protocols: tuple[str, ...] = ()
    address: str = ""

    def speaks(self, protocol: str) -> bool:
        return protocol in self.protocols


@dataclass(frozen=True)
class Conduit:
    """A permitted path between two zones.

    ``via`` names a device the traffic must actually traverse, the jump server
    on the engineering path. A conduit with a ``via`` that the command did not
    pass through is the modelled equivalent of someone reaching the control zone
    around the bastion rather than through it.
    """

    name: str
    source_zone: str
    dest_zone: str
    protocols: tuple[str, ...]
    via: str = ""
    bidirectional: bool = False

    def permits(self, source_zone: str, dest_zone: str, protocol: str) -> bool:
        if protocol not in self.protocols:
            return False
        if self.source_zone == source_zone and self.dest_zone == dest_zone:
            return True
        return (
            self.bidirectional
            and self.source_zone == dest_zone
            and self.dest_zone == source_zone
        )



#: What each zone is for, in the words the live page uses.
ZONE_PURPOSE = {
    "enterprise": "Corporate IT, billing and the utility's own reporting",
    "dmz": "The jump server every path from outside must pass through",
    "supervisory": "The dispatch SCADA and the operator screen",
    "engineering": "The engineering workstation, reaching in via the jump server",
    "control": "The site controller that splits dispatch across the fleet",
    "field": "The battery units, the relay, the meters and the switches",
}

#: Why a conduit exists, for the ones the guard does not sit on.
CONDUIT_NOTE = {
    "enterprise_to_dmz": "Reporting out of the site. Not on the guard's path.",
    "control_to_field": "Below the guard. An attacker here is out of its reach.",
    "field_to_control": "Telemetry coming back. Read by the guard, not judged.",
    "field_peer": "GOOSE and PRP between field devices. Never leaves Level 1.",
}

#: One line per role, for the device tooltips.
ROLE_NOTE = {
    Role.SITE_CONTROLLER: "Splits the dispatch set-point across the fleet",
    Role.MEGAPACK: "One battery unit with its own inverter and cooling",
    Role.RELAY: "Protection relay. One of the three power measurements",
    Role.METER: "Revenue meter. The measurement the utility bills against",
    Role.SWITCH: "Field network switch carrying the duplicated ring",
    Role.SCADA: "Dispatch from the control room",
    Role.HMI: "The operator's screen",
    Role.JUMP_SERVER: "The bastion every session from outside must cross",
    Role.FIREWALL: "The zone boundary itself",
    Role.HISTORIAN: "Reads the process feed. Writes nothing",
    Role.ENGINEERING: "Where limits are changed, under a work order",
}

@dataclass
class SiteTopology:
    """The devices, the zones they sit in and the conduits between them."""

    devices: list[Device] = field(default_factory=list)
    conduits: list[Conduit] = field(default_factory=list)

    # -- lookup ---------------------------------------------------------
    def device(self, name: str) -> Device | None:
        for d in self.devices:
            if d.name == name:
                return d
        return None

    def by_role(self, role: Role) -> list[Device]:
        return [d for d in self.devices if d.role is role]

    def zones(self) -> list[str]:
        seen: list[str] = []
        for d in self.devices:
            if d.zone not in seen:
                seen.append(d.zone)
        return seen

    def zone_level(self, zone: str) -> PurdueLevel | None:
        for d in self.devices:
            if d.zone == zone:
                return d.level
        return None

    # -- policy ---------------------------------------------------------
    def conduit(self, name: str) -> Conduit | None:
        for c in self.conduits:
            if c.name == name:
                return c
        return None

    def permitted(self, source_zone: str, dest_zone: str, protocol: str) -> Conduit | None:
        """Return the conduit that allows this flow, or ``None`` if none does."""
        for c in self.conduits:
            if c.permits(source_zone, dest_zone, protocol):
                return c
        return None

    def crosses_levels(self, source_zone: str, dest_zone: str) -> float:
        """How many Purdue levels a flow spans. Larger is more suspicious."""
        a = self.zone_level(source_zone)
        b = self.zone_level(dest_zone)
        if a is None or b is None:
            return 0.0
        return abs(a.rank - b.rank)

    def summary(self) -> dict:
        """The topology as the live page draws it.

        The guarded conduits are the ones that reach the control zone. That
        is where the guard sits, and it is the distinction the page exists to
        make: traffic below that line is out of its reach, and traffic that
        never leaves a zone never crosses it at all.
        """
        control = self.zone_level("control")
        control_rank = control.rank if control else 0.0

        def guards(c: Conduit) -> bool:
            """Does the guard adjudicate what crosses this conduit?

            It sits in front of the control zone on the way in, so a conduit
            counts only when it carries commands *down* into control. The
            return path from the field carries telemetry, which the guard
            reads to form its belief and never rules on.
            """
            if c.dest_zone != "control":
                return False
            src = self.zone_level(c.source_zone)
            return src is not None and src.rank > control_rank

        zones = []
        for zone in sorted(self.zones(),
                           key=lambda z: -(self.zone_level(z).rank
                                           if self.zone_level(z) else 0.0)):
            level = self.zone_level(zone)
            zones.append({
                "name": zone,
                "level": (level.label.split(" ", 2)[0] + " " + level.label.split(" ")[1]
                          if level else "?"),
                "purpose": ZONE_PURPOSE.get(zone, ""),
            })
        return {
            "zones": zones,
            "conduits": [{
                "name": c.name,
                "source": c.source_zone,
                "target": c.dest_zone,
                "protocol": "/".join(c.protocols),
                "guarded": guards(c),
                "note": (f"Must pass through {c.via}." if c.via
                         else CONDUIT_NOTE.get(c.name, "")),
            } for c in self.conduits],
            "devices": [{
                "name": d.name,
                "kind": d.role.value.replace("_", " "),
                "zone": d.zone,
                "level": d.level.label,
                "protocol": "/".join(d.protocols) or "-",
                "address": d.address or "-",
                "description": ROLE_NOTE.get(d.role, d.role.value.replace("_", " ")),
                "critical": d.role in (Role.MEGAPACK, Role.RELAY, Role.METER,
                                       Role.SITE_CONTROLLER),
            } for d in self.devices],
        }

    def describe(self) -> str:
        lines = ["Zones and devices:"]
        for zone in sorted(
            self.zones(),
            key=lambda z: -(self.zone_level(z).rank if self.zone_level(z) else 0.0),
        ):
            level = self.zone_level(zone)
            lines.append(f"  [{zone}] {level.label if level else '?'}")
            for d in self.devices:
                if d.zone == zone:
                    protos = ", ".join(d.protocols) if d.protocols else "-"
                    lines.append(f"      {d.name:<22s} {d.role.value:<24s} {protos}")
        lines.append("Conduits:")
        for c in self.conduits:
            via = f" via {c.via}" if c.via else ""
            arrow = "<->" if c.bidirectional else "-->"
            lines.append(
                f"  {c.name:<26s} {c.source_zone} {arrow} {c.dest_zone}{via}"
                f"  [{', '.join(c.protocols)}]"
            )
        return "\n".join(lines)


def default_site_topology(n_packs: int = 16) -> SiteTopology:
    """The reference site this project evaluates against.

    Modelled on the equipment list of a utility-scale Megapack installation: a
    site controller, per-unit controllers, protection relays, a revenue meter,
    redundant switching, SCADA, a jump server and a firewall, an HMI.
    """
    devices: list[Device] = [
        # Level 4, enterprise
        Device("historian", Role.HISTORIAN, "enterprise", PurdueLevel.ENTERPRISE, ("https",)),
        # Level 3.5, DMZ
        Device("firewall", Role.FIREWALL, "dmz", PurdueLevel.DMZ, ("https", "modbus_tcp", "dnp3")),
        Device("jump01", Role.JUMP_SERVER, "dmz", PurdueLevel.DMZ, ("ssh", "https")),
        # Level 3, supervisory
        Device("scada01", Role.SCADA, "supervisory", PurdueLevel.SUPERVISORY, ("dnp3", "rest")),
        Device("hmi01", Role.HMI, "supervisory", PurdueLevel.SUPERVISORY, ("rest", "modbus_tcp")),
        Device(
            "engws01",
            Role.ENGINEERING,
            "engineering",
            PurdueLevel.SUPERVISORY,
            ("ssh", "rest", "modbus_tcp"),
        ),
        # Level 2, control
        Device(
            "sitectrl",
            Role.SITE_CONTROLLER,
            "control",
            PurdueLevel.CONTROL,
            ("modbus_tcp", "dnp3", "rest", "goose"),
            address="10.10.2.10",
        ),
        # Level 1, field
        Device(
            "relay87",
            Role.RELAY,
            "field",
            PurdueLevel.FIELD,
            ("goose", "prp", "dnp3"),
            address="10.10.1.20",
        ),
        Device(
            "meter01",
            Role.METER,
            "field",
            PurdueLevel.FIELD,
            ("dnp3",),
            address="10.10.1.30",
        ),
        Device("switch_a", Role.SWITCH, "field", PurdueLevel.FIELD, ("prp",)),
        Device("switch_b", Role.SWITCH, "field", PurdueLevel.FIELD, ("prp",)),
    ]
    devices += [
        Device(
            f"MP{i + 1:02d}",
            Role.MEGAPACK,
            "field",
            PurdueLevel.FIELD,
            ("modbus_tcp", "goose"),
            address=f"10.10.1.{100 + i}",
        )
        for i in range(n_packs)
    ]

    conduits = [
        Conduit(
            "enterprise_to_dmz",
            "enterprise",
            "dmz",
            ("https",),
        ),
        # The only sanctioned way for a human to reach control: through the jump
        # server. B8 enforces the ``via``, which is what makes "the engineer
        # went around the bastion" a detectable event rather than a log entry
        # nobody reads.
        Conduit(
            "engineering_to_control",
            "engineering",
            "control",
            ("rest", "modbus_tcp"),
            via="jump01",
        ),
        Conduit(
            "scada_to_control",
            "supervisory",
            "control",
            ("dnp3", "rest"),
        ),
        Conduit(
            "control_to_field",
            "control",
            "field",
            ("modbus_tcp", "dnp3", "goose"),
        ),
        Conduit(
            "field_to_control",
            "field",
            "control",
            ("modbus_tcp", "dnp3", "goose", "prp"),
        ),
        Conduit(
            "field_peer",
            "field",
            "field",
            ("goose", "prp"),
            bidirectional=True,
        ),
    ]
    return SiteTopology(devices=devices, conduits=conduits)
