"""Attack episodes derived from publicly reported incidents, and what they cost.

The suite in :mod:`otguard.scenarios.attacks` was written from the design
outward: each scenario exists to exercise a rule. That is the right way to
build a test suite and the wrong way to argue the design matters, because the
attacks and the rules were written by the same person on the same afternoon.
This module works in the other direction. It starts from things that actually
happened to real plants and asks, for each one, whether this guard would have
been in a position to do anything about it.

The answer is often no, and the useful part is *why* not. Three reasons come up
repeatedly, and they divide the incidents more sharply than sector or severity
do.

**Where the commands came from.** A bump-in-the-wire sees one conduit. An
attacker who executes code on the controller is downstream of it and issues no
command the guard can read; an attacker stealing documents from an engineering
file share is off to one side of it entirely. Neither is a failure of the
rules. Both are a statement about where the device is installed, and a guard
evaluated only against attacks that happen to cross it will look far better
than it is.

**Whether there was a command at all.** Two of the campaigns most often cited
in OT security courses — Night Dragon and Havex — did not manipulate a process.
They inventoried and exfiltrated. A plausibility guard has nothing to
contribute, and the honest result is a row that says so rather than a scenario
bent until it scores.

**Whether the public account is specific enough to model.** The 2014 German
steel mill report says a blast furnace could not be brought to a controlled
shutdown. It does not say what was written, to what, or by whom. A scenario
built on that would be this project's invention wearing an incident's name.

Every account below is from public reporting as the author understood it, and
none of it has been checked against primary sources; the dates and mechanisms
are the parts to trust least. Every number in every scenario is this project's
own and is not an incident's measured parameter. Where reporting is disputed,
the row says so.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable

from ..guard.types import CommandKind
from .base import LevelController, Scenario, ScheduledCommand


# ----------------------------------------------------------------------
# Scenarios the existing suite did not already cover
# ----------------------------------------------------------------------
def stuxnet_overspeed_replay(
    burst_s: float = 30.0,
    rest_s: float = 30.0,
    bursts: int = 3,
    record_until_s: float = 40.0,
) -> Scenario:
    """Episodic overdrive behind a replayed process view.

    Two properties of the 2010 Stuxnet rotor-speed attack that
    :func:`~otguard.scenarios.attacks.replay_overflow` does not have.

    The first is that it ran in bursts with long quiet periods between them,
    rather than as one continuous push. That matters to anything edge-triggered
    or decaying: a CUSUM relaxes during the rest, a latched alarm may have been
    acknowledged, and no single burst is long enough on its own to do the
    damage. The damage accumulates across bursts.

    The second is that the process view was *replayed*, not frozen. A constant
    reading is a conspicuous thing for an operator to be shown. A recording of
    the plant's own recent behaviour, played back, has the right noise and the
    right small movements, and it defeats a detector looking for an
    implausibly quiet signal.

    What this is not: Stuxnet ran on the controller. Its commands never crossed
    a network conduit, so a bump-in-the-wire would have seen none of them. This
    scenario reproduces the command *pattern* over a conduit the guard can
    watch, which is a different thing and is worth saying out loud rather than
    leaving to be inferred from a table.
    """
    recorded: list[float] = []
    playback: list[list[float]] = []
    cursor = [0]

    def replay(t: float, true_level: float, honest_reading: float) -> float:
        if t < record_until_s:
            recorded.append(honest_reading)
            return honest_reading
        if not recorded:
            return honest_reading
        if not playback:
            # Played newest first and then ping-ponged. Starting at the oldest
            # sample would put a thirty-second step in the trace at the moment
            # the attack begins, which the consistency rule catches on the very
            # first sample — and then the scenario is measuring a discontinuity
            # rather than a replay. The seam has to be continuous for the
            # attack to be the attack.
            playback.append(recorded[::-1] + recorded)
        sequence = playback[0]
        value = sequence[cursor[0] % len(sequence)]
        cursor[0] += 1
        return value

    commands = [
        ScheduledCommand(2.0, CommandKind.VALVE, 30.0),
        ScheduledCommand(3.0, CommandKind.PUMP, 45.0),
    ]
    # The overdrive and the replayed view start together, which is the point of
    # the pairing: the operator's screen never shows the burst.
    t = record_until_s
    for _ in range(bursts):
        commands.append(ScheduledCommand(round(t, 2), CommandKind.VALVE, 0.0, malicious=True))
        commands.append(ScheduledCommand(round(t + 1.0, 2), CommandKind.PUMP, 100.0, malicious=True))
        commands.append(ScheduledCommand(round(t + burst_s, 2), CommandKind.PUMP, 45.0, malicious=True))
        commands.append(ScheduledCommand(round(t + burst_s + 1.0, 2), CommandKind.VALVE, 30.0, malicious=True))
        t += burst_s + rest_s
    duration = t + 20.0

    return Scenario(
        name="stuxnet_overspeed_replay",
        category="attack",
        description=(
            f"{bursts} overdrive bursts of {burst_s:g}s separated by {rest_s:g}s of normal "
            "operation, behind a level transmitter replaying its own earlier recording."
        ),
        duration_s=duration,
        initial_level_m=0.95,
        attack_window=(record_until_s, duration),
        expected_rules=("R3", "R4"),
        sensor_attack=replay,
        commands=commands,
        seed=19,
    )


def setpoint_overdose() -> Scenario:
    """One set-point write, far out of range, that the control loop then obeys.

    The Oldsmar shape. In February 2021 a remote-access session on a Florida
    water treatment plant's operator workstation raised a sodium hydroxide
    set-point by about a hundredfold — reported as roughly 100 ppm to roughly
    11,100 ppm — and an operator watching the screen put it back. Later
    reporting raised the possibility that the change was a plant employee's own
    action rather than an intrusion, so this is a scenario about a *shape* of
    command and not a reconstruction of an established attack.

    The shape is worth having on its own, because it is the cheapest harmful
    write there is. It moves no actuator. It is one number to one address, from
    an authenticated session, and everything harmful that follows is done by
    the plant's own control loop doing its job correctly against a target it
    was given. Authentication cannot catch it and neither can anything
    reasoning about rate, sequence or volume.

    What catches it is that 1.95 m is above the top of the tank, which is a
    fact about the equipment rather than about the request.
    """
    return Scenario(
        name="setpoint_overdose",
        category="attack",
        description=(
            "Level set-point raised to 1.95 m, above the tank, from an authenticated "
            "session; the control loop then fills to it."
        ),
        duration_s=200.0,
        initial_level_m=0.95,
        attack_window=(40.0, 200.0),
        expected_rules=("R1", "R3"),
        commands=[
            ScheduledCommand(
                40.0, CommandKind.SETPOINT, 1.95, malicious=True,
                note="single out-of-range set-point write",
            )
        ],
        # The loop has to actually act on the tampered target, or the scenario
        # measures a write nobody obeyed. This is how the benign set-point step
        # in ``normal.py`` is expressed too.
        controller=LevelController(
            setpoint_m=0.95, valve_pct=30.0, setpoint_schedule=[(40.0, 1.95)]
        ),
        seed=21,
    )


def all_incident_scenarios() -> list[Scenario]:
    return [stuxnet_overspeed_replay(), setpoint_overdose()]


# ----------------------------------------------------------------------
# The catalogue
# ----------------------------------------------------------------------
class Mechanism(str, Enum):
    """What the attacker did, which decides whether this guard is the control."""

    COMMAND = "process command"
    RECONNAISSANCE = "reconnaissance"
    ENTERPRISE = "enterprise intrusion"
    UNDISCLOSED = "not publicly disclosed"


class Vantage(str, Enum):
    """Where the activity sat relative to a bump-in-the-wire."""

    CROSSES = "crosses the guard"
    BELOW = "below the guard"
    BESIDE = "beside the guard"
    UNKNOWN = "not publicly established"


@dataclass(frozen=True)
class Evidence:
    """Which measured result in this project speaks to an incident.

    ``kind`` says which evaluation produced it, so the report can run the right
    one rather than quoting a number from a file that may be stale:

    ``tank``    a scenario for the in-process harness
    ``site``    a scenario for the storage site
    ``matrix``  a sender, receiver and attack from the device matrix
    ``opcua``   a scenario and security mode from the OPC UA experiment
    ``none``    nothing, deliberately
    """

    kind: str
    name: str
    note: str = ""


@dataclass(frozen=True)
class Incident:
    key: str
    name: str
    year: str
    sector: str
    mechanism: Mechanism
    vantage: Vantage
    account: str
    modelled: str
    unmodelled: str
    evidence: tuple[Evidence, ...]

    @property
    def in_scope(self) -> bool:
        """Is a physics-plausibility guard the right control for this at all?"""
        return (
            self.mechanism is Mechanism.COMMAND
            and self.vantage is Vantage.CROSSES
            and any(e.kind != "none" for e in self.evidence)
        )


INCIDENTS: tuple[Incident, ...] = (
    Incident(
        key="maroochy",
        name="Maroochy Water Services",
        year="2000",
        sector="water and sewage",
        mechanism=Mechanism.COMMAND,
        vantage=Vantage.CROSSES,
        account=(
            "A contractor who had worked on the installation used radio equipment and the "
            "utility's own SCADA software to issue commands to sewage pumping stations, "
            "causing repeated releases of sewage. The commands were indistinguishable from "
            "legitimate ones because they were sent with legitimate equipment."
        ),
        modelled=(
            "A write from a device that is not in the guard's inventory, driving an actuator "
            "to a position that spills the process. The matrix runs it against three receiver "
            "classes."
        ),
        unmodelled=(
            "The radio telemetry layer, the physical pumping-station network, and the fact "
            "that the attacker also suppressed alarms. This project's identity evidence is a "
            "source address, which is weaker than the problem Maroochy poses: an insider with "
            "the plant's own equipment has the plant's own identity."
        ),
        evidence=(
            Evidence("matrix", "unknown_source/hmi/plc"),
            Evidence("tank", "overflow", "the spill itself, from an authentic source"),
        ),
    ),
    Incident(
        key="stuxnet",
        name="Stuxnet",
        year="2010",
        sector="uranium enrichment",
        mechanism=Mechanism.COMMAND,
        vantage=Vantage.BELOW,
        account=(
            "Code resident on the controllers drove centrifuge rotor speeds outside their "
            "rated range in episodic bursts, while replaying recorded process values upstream "
            "so that the operators' view of the plant stayed plausible throughout."
        ),
        modelled=(
            "The command pattern: episodic overdrive bursts with quiet periods between them, "
            "behind a transmitter replaying its own earlier recording."
        ),
        unmodelled=(
            "The part that matters most. Stuxnet executed on the controller, below where a "
            "bump-in-the-wire sits, so none of its commands crossed a conduit this guard "
            "could read. Reproducing the pattern over a conduit measures whether the rules "
            "can recognise the shape, and says nothing about whether the guard would have "
            "been positioned to see it. It would not have been."
        ),
        evidence=(
            Evidence("tank", "stuxnet_overspeed_replay"),
            Evidence("tank", "replay_overflow", "the continuous version"),
        ),
    ),
    Incident(
        key="night_dragon",
        name="Night Dragon",
        year="2011",
        sector="oil, gas and petrochemical",
        mechanism=Mechanism.ENTERPRISE,
        vantage=Vantage.BESIDE,
        account=(
            "A campaign reported by McAfee in 2011 against energy companies, using "
            "spear-phishing, web-server compromise and remote-administration tools to reach "
            "internal systems and take operational and commercially sensitive documents."
        ),
        modelled="Nothing.",
        unmodelled=(
            "All of it. No process was manipulated, so there is no command for a "
            "plausibility rule to judge, and nothing a bump-in-the-wire between an operator "
            "station and a controller would have been on the path of. A guard that reported "
            "coverage here would be reporting a coincidence."
        ),
        evidence=(Evidence("none", "", "espionage; the wrong control entirely"),),
    ),
    Incident(
        key="havex",
        name="Havex / Dragonfly",
        year="2014",
        sector="energy and pharmaceutical",
        mechanism=Mechanism.RECONNAISSANCE,
        vantage=Vantage.CROSSES,
        account=(
            "A remote-access trojan distributed partly through trojanised installers on ICS "
            "vendor download sites. One of its modules enumerated OPC servers on the networks "
            "it reached and reported what it found, which amounts to building an inventory of "
            "the plant."
        ),
        modelled=(
            "The enumeration traffic, on the one protocol in this project that carries a "
            "self-describing address space. The OPC UA experiment's reconnaissance episode "
            "browses and reads everything and writes nothing."
        ),
        unmodelled=(
            "The delivery. Trojanised vendor installers arrive through a software supply "
            "chain, not through a control conduit."
        ),
        evidence=(
            Evidence("opcua", "recon_browse", "scored as traffic the guard must not refuse"),
        ),
    ),
    Incident(
        key="german_steel_mill",
        name="German steel mill",
        year="2014",
        sector="steel",
        mechanism=Mechanism.UNDISCLOSED,
        vantage=Vantage.UNKNOWN,
        account=(
            "Germany's federal information security office reported that a steel mill was "
            "reached through its office network and that a blast furnace could not be brought "
            "into a controlled shutdown, causing heavy damage."
        ),
        modelled="Nothing.",
        unmodelled=(
            "The public account does not say what was written, to which device, or whether "
            "the furnace failed to shut down because of a command, a suppressed command, or a "
            "disabled interlock. Each of those would need a different scenario and would "
            "produce a different result. Building one and labelling it with this incident's "
            "name would be presenting an invention as evidence."
        ),
        evidence=(Evidence("none", "", "public detail too thin to model faithfully"),),
    ),
    Incident(
        key="ukraine_2015",
        name="Ukraine distribution outage",
        year="2015",
        sector="electricity distribution",
        mechanism=Mechanism.COMMAND,
        vantage=Vantage.CROSSES,
        account=(
            "Operator workstations at Ukrainian distribution utilities were taken over through "
            "remote access and breakers were opened using the utilities' own HMI software. "
            "Firmware on serial-to-ethernet converters was overwritten and workstations were "
            "wiped, which is what made recovery slow."
        ),
        modelled=(
            "The core of this project's threat model: an authentic command from the operator "
            "station whose values are all legal and whose consequence is not."
        ),
        unmodelled=(
            "The destructive half. Wiping workstations and bricking converters is a "
            "recovery problem, and a guard that stops the breaker command does nothing about "
            "it."
        ),
        evidence=(
            Evidence("tank", "overflow", "legal values, illegal consequence"),
            Evidence("site", "jump_server_bypass", "the remote-access route"),
        ),
    ),
    Incident(
        key="industroyer",
        name="Industroyer / CrashOverride",
        year="2016",
        sector="electricity transmission",
        mechanism=Mechanism.COMMAND,
        vantage=Vantage.CROSSES,
        account=(
            "Malware that spoke substation protocols natively — IEC 60870-5-101 and -104, "
            "IEC 61850 and OPC — and issued breaker commands directly, with no operator "
            "console involved and at machine rate."
        ),
        modelled=(
            "Protocol-native command sequences at a rate no human or supervisory system "
            "produces, and a spoofed protection trip on the storage site."
        ),
        unmodelled=(
            "The substation itself: protection schemes, bus topology and the switching order "
            "that makes a breaker operation safe or not."
        ),
        evidence=(
            Evidence("tank", "command_flood"),
            Evidence("matrix", "write_flood/scada/plc"),
            Evidence("site", "goose_trip_spoof"),
        ),
    ),
    Incident(
        key="triton",
        name="Triton / Trisis",
        year="2017",
        sector="petrochemical",
        mechanism=Mechanism.COMMAND,
        vantage=Vantage.CROSSES,
        account=(
            "An implant was written to safety instrumented system controllers at a "
            "petrochemical plant, reached through an engineering workstation and the "
            "controllers' own engineering protocol. The plant tripped twice, which is how the "
            "intrusion was found: a flaw in the implant, not a control that caught it."
        ),
        modelled=(
            "A write whose whole purpose is to disable a protective function and which moves "
            "no actuator at all. In the matrix this is the RTU's own high-level interlock "
            "being switched off by a single coil write."
        ),
        unmodelled=(
            "Everything after the implant lands. Once resident on the safety controller the "
            "attacker is below the guard and nothing crosses the conduit. The modelled part "
            "is the delivery, which does cross it — and no physics rule can judge it, because "
            "'turn off the interlock' has no physical consequence to predict. It is refused "
            "by the wire policy, which is this project's one case of stopping an attack "
            "without understanding it."
        ),
        evidence=(
            Evidence("matrix", "interlock_disable/engineering/rtu"),
            Evidence("matrix", "coil_sweep/hmi/rtu", "the interlock and the pump together"),
        ),
    ),
    Incident(
        key="oldsmar",
        name="Oldsmar water treatment",
        year="2021",
        sector="water treatment",
        mechanism=Mechanism.COMMAND,
        vantage=Vantage.CROSSES,
        account=(
            "A remote-access session on an operator workstation at a Florida water treatment "
            "plant raised a sodium hydroxide dosing set-point by roughly a hundredfold, "
            "reported as about 100 ppm to about 11,100 ppm. An operator saw the change on "
            "screen and reverted it. Later reporting raised the possibility that it was a "
            "plant employee's own action rather than an intrusion, and the attribution is not "
            "settled."
        ),
        modelled=(
            "A single out-of-range set-point write from an authenticated session, with a "
            "control loop that then acts on it. On the storage site, the same shape against a "
            "configuration limit rather than a set-point."
        ),
        unmodelled=(
            "Chemical dosing, and the operator who noticed. This project's tank has no "
            "equivalent of a residual-chlorine measurement that would reveal a dose "
            "independently."
        ),
        evidence=(
            Evidence("tank", "setpoint_overdose"),
            Evidence("site", "rest_limit_tamper", "a limit raised, then obeyed"),
            Evidence("opcua", "setpoint_jump", "the same write under three security modes"),
        ),
    ),
    Incident(
        key="industroyer2",
        name="Industroyer2",
        year="2022",
        sector="electricity transmission",
        mechanism=Mechanism.COMMAND,
        vantage=Vantage.CROSSES,
        account=(
            "A successor to Industroyer, found in Ukraine in 2022, with its target "
            "configuration compiled into the executable rather than read from a file, and "
            "speaking IEC 60870-5-104 to issue breaker commands."
        ),
        modelled=(
            "A breaker command issued without regard to whether the system is in a state "
            "where closing or opening is safe."
        ),
        unmodelled=(
            "Synchrocheck and protection coordination as a transmission operator would model "
            "them. The storage site has a breaker and a bus, which is enough for an "
            "out-of-synchronism close and not enough for a substation."
        ),
        evidence=(
            Evidence("site", "breaker_close_out_of_sync"),
            Evidence("site", "goose_trip_spoof"),
        ),
    ),
    Incident(
        key="pipedream",
        name="Pipedream / Incontroller",
        year="2022",
        sector="multiple",
        mechanism=Mechanism.COMMAND,
        vantage=Vantage.CROSSES,
        account=(
            "A modular toolkit disclosed in 2022 in a joint advisory from United States "
            "government agencies, with components for specific controller families and a "
            "component for interacting with OPC UA servers: enumerating them, reading them "
            "and writing to them. No use against a plant was reported with it."
        ),
        modelled=(
            "A native OPC UA client writing to a device, which is the whole of the OPC UA "
            "experiment. The attacker is a protocol-conformant client holding valid "
            "credentials, so nothing about the session distinguishes it."
        ),
        unmodelled=(
            "The controller-specific components, and the toolkit's own capabilities, which "
            "are not public in enough detail to reproduce."
        ),
        evidence=(
            Evidence("opcua", "overflow", "a conformant client, all three security modes"),
            Evidence("opcua", "parameter_tamper"),
        ),
    ),
    Incident(
        key="unitronics_2023",
        name="Unitronics PLCs in water utilities",
        year="2023",
        sector="water",
        mechanism=Mechanism.COMMAND,
        vantage=Vantage.CROSSES,
        account=(
            "Internet-exposed Unitronics controllers at water utilities in several countries "
            "were reached and altered, in at least one case at a municipal water authority in "
            "Pennsylvania. Default credentials and direct exposure to the internet were the "
            "reported route."
        ),
        modelled=(
            "A write from a device the guard has never heard of. The matrix runs it against "
            "every receiver class."
        ),
        unmodelled=(
            "Internet exposure. Everything in this project sits on a conduit between two "
            "known networks, and the whole difficulty of this incident is that there was no "
            "such conduit."
        ),
        evidence=(
            Evidence("matrix", "unknown_source/hmi/plc"),
            Evidence("matrix", "unknown_source/hmi/rtu"),
        ),
    ),
)


def by_key(key: str) -> Incident:
    for incident in INCIDENTS:
        if incident.key == key:
            return incident
    raise KeyError(key)


#: The new scenarios, by the name the evaluation reports them under.
SCENARIO_FACTORIES: dict[str, Callable[[], Scenario]] = {
    "stuxnet_overspeed_replay": stuxnet_overspeed_replay,
    "setpoint_overdose": setpoint_overdose,
}
