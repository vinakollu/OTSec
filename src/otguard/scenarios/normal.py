"""Benign episodes. Every alarm raised here is a false alarm.

These are the scenarios that decide whether the guard would survive contact with
a real control room. Detecting attacks is the easy half; a guard that also stops
a legitimate emergency drain gets bypassed within a week, and the operators will
be right to do it.

Each one is deliberately chosen to look like an attack in some superficial way:

``startup``            level climbing fast, pump wide open
``shutdown``           level falling toward the low trip point
``emergency_drain``    a large, abrupt, manual actuator move
``setpoint_change``    a big commanded step while the process is loaded
``pump_trip_restart``  an unannounced disturbance and recovery
"""

from __future__ import annotations

from ..guard.types import CommandKind
from .base import LevelController, Scenario, ScheduledCommand


def startup() -> Scenario:
    """Fill from near-empty to the normal operating level.

    The level rises at close to the maximum physical fill rate with the pump
    saturated — kinematically indistinguishable from the opening move of an
    overflow attack. What separates them is where the trajectory *ends*, which
    is exactly what R3's lookahead evaluates.
    """
    return Scenario(
        name="startup",
        category="normal",
        description="Cold start: fill from 0.35 m to a 1.20 m operating level.",
        duration_s=180.0,
        initial_level_m=0.35,
        controller=LevelController(setpoint_m=1.20, valve_pct=25.0),
    )


def shutdown() -> Scenario:
    """Controlled drain toward a low holding level.

    Approaches the 0.20 m low trip from above without crossing it. A guard whose
    dry-out rule is even slightly too eager fires here.
    """
    return Scenario(
        name="shutdown",
        category="normal",
        description="Planned shutdown: drain from 1.20 m to a 0.45 m holding level.",
        duration_s=180.0,
        initial_level_m=1.20,
        controller=LevelController(
            setpoint_m=1.20,
            valve_pct=25.0,
            setpoint_schedule=[(20.0, 0.45)],
            valve_schedule=[(20.0, 70.0)],
        ),
    )


def emergency_drain() -> Scenario:
    """Operator manually slams the valve open and kills the pump.

    A single large step on each actuator — abrupt, but monotonic and in the safe
    direction. This is the scenario that punishes a naive rate-of-change rule:
    the command jumps 25 % -> 100 % in one write, and blocking it would be a
    safety hazard in its own right.
    """
    return Scenario(
        name="emergency_drain",
        category="normal",
        description="Manual emergency drain: valve 25%->100%, pump ->0 in a single step, then restore.",
        duration_s=150.0,
        initial_level_m=1.40,
        controller=None,
        commands=[
            ScheduledCommand(2.0, CommandKind.VALVE, 25.0),
            ScheduledCommand(3.0, CommandKind.PUMP, 45.0),
            # --- operator hits the emergency drain ---
            ScheduledCommand(30.0, CommandKind.VALVE, 100.0, note="operator emergency drain"),
            ScheduledCommand(30.5, CommandKind.PUMP, 0.0, note="operator stops the pump"),
            # --- and restores normal operation once the level is down ---
            ScheduledCommand(55.0, CommandKind.VALVE, 30.0, note="restore"),
            ScheduledCommand(56.0, CommandKind.PUMP, 40.0, note="restore"),
        ],
    )


def setpoint_change() -> Scenario:
    """A large operator setpoint step while the plant is running."""
    return Scenario(
        name="setpoint_change",
        category="normal",
        description="Operator raises the level setpoint from 0.70 m to 1.45 m in one step.",
        duration_s=180.0,
        initial_level_m=0.70,
        controller=LevelController(
            setpoint_m=0.70,
            valve_pct=30.0,
            setpoint_schedule=[(25.0, 1.45)],
        ),
        commands=[
            ScheduledCommand(25.0, CommandKind.SETPOINT, 1.45, note="operator setpoint step"),
        ],
    )


def pump_trip_restart() -> Scenario:
    """An unannounced pump trip and manual restart.

    A real disturbance rather than a commanded one: the level sags while the
    pump is out, then recovers. Included because process upsets, not attacks,
    are what actually generate alarm fatigue.
    """
    # Valve 35 % passes 0.0175*sqrt(h) m^3/s, so pump 35 % balances it at h=1.0 m.
    # The recovery runs at 60 % — brisk, but it settles back to the balance point
    # rather than filling indefinitely. Getting this arithmetic wrong produces a
    # "benign" scenario that genuinely overflows, and then a correct trip gets
    # scored as a false alarm.
    return Scenario(
        name="pump_trip_restart",
        category="normal",
        description="Pump trips unexpectedly at t=30 s and is manually restarted at t=70 s.",
        duration_s=220.0,
        initial_level_m=1.00,
        controller=None,
        commands=[
            ScheduledCommand(2.0, CommandKind.VALVE, 35.0),
            ScheduledCommand(3.0, CommandKind.PUMP, 35.0),
            ScheduledCommand(30.0, CommandKind.PUMP, 0.0, note="pump trip"),
            ScheduledCommand(70.0, CommandKind.PUMP, 60.0, note="operator restart, brisk recovery"),
            ScheduledCommand(120.0, CommandKind.PUMP, 35.0, note="settle back to balance"),
        ],
    )


def all_normal() -> list[Scenario]:
    return [
        startup(),
        shutdown(),
        emergency_drain(),
        setpoint_change(),
        pump_trip_restart(),
    ]
