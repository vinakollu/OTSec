"""Attack episodes, under a fixed threat model.

Threat model
------------
The attacker has taken the HMI or the engineering workstation. They can send any
Modbus write they like, at any rate, and they can tamper with what the operator's
screen displays. They do **not** have code execution on the PLC, they cannot
modify the guard, and they cannot reach the process instrumentation or the
actuators physically.

That is the standard "compromised operator station" position, and it is the one
where a bump-in-the-wire has authority: every command still has to cross the
guard on its way to the controller.

The attacks are ordered by how much they respect physics, which turns out to be
the same as ordering them by how hard they are to catch:

``out_of_envelope``   ignores the equipment's rating entirely
``overflow``          legal commands, illegal consequence
``dryout``            same, in the other direction
``water_hammer``      legal values, impossible sequence
``command_flood``     legal values, impossible rate
``replay_overflow``   hides the consequence by freezing the operator's view
``stealthy_bias``     hides it slowly enough to stay under the detector — the
                      one that is *expected* to partially succeed
"""

from __future__ import annotations

from ..guard.types import CommandKind
from .base import LevelController, Scenario, ScheduledCommand


def out_of_envelope() -> Scenario:
    """Raw out-of-range writes at the controller.

    The unsubtle case: a valve command of 250 % and a setpoint above the tank.
    A bare PLC accepts both because nothing ever told it the equipment's limits.
    """
    return Scenario(
        name="out_of_envelope",
        category="attack",
        description="Attacker writes values outside the equipment rating (valve 250%, setpoint 1.95 m).",
        duration_s=90.0,
        initial_level_m=0.90,
        attack_window=(30.0, 90.0),
        expected_rules=("R1",),
        commands=[
            ScheduledCommand(2.0, CommandKind.VALVE, 30.0),
            ScheduledCommand(3.0, CommandKind.PUMP, 50.0),
            ScheduledCommand(30.0, CommandKind.VALVE, 250.0, malicious=True),
            ScheduledCommand(32.0, CommandKind.SETPOINT, 1.95, malicious=True),
            ScheduledCommand(34.0, CommandKind.PUMP, -20.0, malicious=True),
            ScheduledCommand(36.0, CommandKind.VALVE, 180.0, malicious=True),
        ],
    )


def overflow() -> Scenario:
    """Overflow the tank with commands that are individually perfectly legal.

    ``pump = 100 %`` and ``valve = 0 %`` are both inside the equipment rating.
    Nothing about either write is anomalous. Only the *consequence* is, and only
    once you know where the level currently is and how fast it is moving — which
    is the entire argument for physics-based rules over value-based ones.
    """
    return Scenario(
        name="overflow",
        category="attack",
        description="Legal-valued commands (pump 100%, valve 0%) held until the tank overflows.",
        duration_s=150.0,
        initial_level_m=0.95,
        attack_window=(30.0, 150.0),
        expected_rules=("R3",),
        commands=[
            ScheduledCommand(2.0, CommandKind.VALVE, 30.0),
            ScheduledCommand(3.0, CommandKind.PUMP, 45.0),
            ScheduledCommand(30.0, CommandKind.VALVE, 0.0, malicious=True),
            ScheduledCommand(31.0, CommandKind.PUMP, 100.0, malicious=True),
        ],
    )


def dryout() -> Scenario:
    """Run the tank dry, damaging the pump. Same trick, opposite direction."""
    return Scenario(
        name="dryout",
        category="attack",
        description="Legal-valued commands (valve 100%, pump 0%) held until the pump runs dry.",
        duration_s=150.0,
        initial_level_m=0.85,
        attack_window=(30.0, 150.0),
        expected_rules=("R3",),
        commands=[
            ScheduledCommand(2.0, CommandKind.VALVE, 30.0),
            ScheduledCommand(3.0, CommandKind.PUMP, 45.0),
            ScheduledCommand(30.0, CommandKind.PUMP, 0.0, malicious=True),
            ScheduledCommand(31.0, CommandKind.VALVE, 100.0, malicious=True),
        ],
    )


def water_hammer() -> Scenario:
    """Cycle the outlet valve to generate destructive pressure transients.

    Every command is in range and the level barely moves, so neither a range
    check nor a level-based detector notices. The damage is mechanical and the
    signature is in the *sequence*.
    """
    commands = [
        ScheduledCommand(2.0, CommandKind.VALVE, 30.0),
        ScheduledCommand(3.0, CommandKind.PUMP, 50.0),
    ]
    t = 30.0
    for i in range(40):
        commands.append(
            ScheduledCommand(
                round(t, 2),
                CommandKind.VALVE,
                100.0 if i % 2 == 0 else 0.0,
                malicious=True,
            )
        )
        t += 0.2
    return Scenario(
        name="water_hammer",
        category="attack",
        description="Outlet valve cycled 0<->100% at 5 Hz to induce water hammer.",
        duration_s=90.0,
        initial_level_m=1.00,
        attack_window=(30.0, 90.0),
        expected_rules=("R2",),
        commands=commands,
    )


def command_flood() -> Scenario:
    """Hammer the controller with writes far faster than any HMI produces."""
    commands = [
        ScheduledCommand(2.0, CommandKind.VALVE, 30.0),
        ScheduledCommand(3.0, CommandKind.PUMP, 50.0),
    ]
    t = 30.0
    for i in range(200):
        commands.append(
            ScheduledCommand(round(t, 2), CommandKind.PUMP, 50.0 + (i % 5), malicious=True)
        )
        t += 0.05  # 20 Hz
    return Scenario(
        name="command_flood",
        category="attack",
        description="20 Hz write flood at the PLC, well above any human or supervisory rate.",
        duration_s=90.0,
        initial_level_m=1.00,
        attack_window=(30.0, 90.0),
        expected_rules=("R2",),
        commands=commands,
    )


def replay_overflow() -> Scenario:
    """Overflow the tank while freezing the operator's level display.

    The Stuxnet-shaped attack: drive the process somewhere dangerous and replay
    a recorded-normal reading so nobody upstream notices. It defeats any
    detector that reasons only from the reported process variable, because the
    reported process variable is the thing under the attacker's control.

    The guard's answer is that the level reading is not the only evidence
    available — the commands it has already forwarded imply a trajectory, and
    when the two stop agreeing, the reading is what gets demoted.
    """
    frozen_at = 0.95

    def freeze(t: float, true_level: float, honest_reading: float) -> float:
        return frozen_at if t >= 30.0 else honest_reading

    return Scenario(
        name="replay_overflow",
        category="attack",
        description="Tank driven to overflow while the level transmitter is replayed at 0.95 m.",
        duration_s=150.0,
        initial_level_m=0.95,
        attack_window=(30.0, 150.0),
        expected_rules=("R3", "R4"),
        sensor_attack=freeze,
        commands=[
            ScheduledCommand(2.0, CommandKind.VALVE, 30.0),
            ScheduledCommand(3.0, CommandKind.PUMP, 45.0),
            ScheduledCommand(31.0, CommandKind.VALVE, 0.0, malicious=True),
            ScheduledCommand(32.0, CommandKind.PUMP, 100.0, malicious=True),
        ],
    )


def stealthy_bias(rate_m_s: float = 0.002) -> Scenario:
    """Bias the level reading slowly enough to stay under the CUSUM.

    This is the attack the design is *expected* to struggle with, and it is in
    the suite on purpose. Any residual-based detector has a detection floor; an
    attacker who stays beneath it is invisible to R4 by construction. Reporting
    a suite where every attack is caught would mean the suite was chosen to
    flatter the defence.

    The sweep in ``scripts/run_eval.py --stealth-sweep`` maps the whole rate
    axis, and the shape of it is the interesting part. Fast ramps (>=10 mm/s)
    are caught early enough that the lockout still saves the tank. Slow ones
    (<=1 mm/s) stay invisible but are too slow to do damage in an episode. In
    between — around 2 mm/s, which is what this scenario uses — sits a band
    where the attack is both undetected and effective. That band is the honest
    headline limitation of the design, and no amount of tuning removes it: it
    is a property of thresholding a residual. Closing it needs a second,
    physically independent measurement, which is future work rather than
    something a threshold can fix.
    """
    def ramp(t: float, true_level: float, honest_reading: float) -> float:
        if t < 30.0:
            return honest_reading
        return honest_reading - rate_m_s * (t - 30.0)

    return Scenario(
        name="stealthy_bias",
        category="attack",
        description=(
            f"Level reading biased downward at {rate_m_s*1000:g} mm/s while the tank is filled "
            "— slow enough to stay under the residual detector."
        ),
        duration_s=400.0,
        initial_level_m=0.95,
        attack_window=(30.0, 300.0),
        expected_rules=("R3", "R4"),
        sensor_attack=ramp,
        controller=LevelController(setpoint_m=1.30, valve_pct=25.0),
    )


def all_attacks() -> list[Scenario]:
    return [
        out_of_envelope(),
        overflow(),
        dryout(),
        water_hammer(),
        command_flood(),
        replay_overflow(),
        stealthy_bias(),
    ]
