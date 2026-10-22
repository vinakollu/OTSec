"""Labelled scenarios: the ground truth the evaluation scores against."""

from .attacks import all_attacks
from .base import Controller, LevelController, Scenario, ScheduledCommand, SensorAttack
from .incidents import all_incident_scenarios
from .normal import all_normal

__all__ = [
    "all_incident_scenarios",
    "Controller",
    "LevelController",
    "Scenario",
    "ScheduledCommand",
    "SensorAttack",
    "all_attacks",
    "all_normal",
    "all_scenarios",
    "by_name",
]


def all_scenarios() -> list[Scenario]:
    """Every scenario the headline evaluation scores, attacks first.

    The incident-derived scenarios are deliberately not here. They are scored
    by ``scripts/run_incidents.py`` instead, so that the detection rate, the
    false-alarm rate and the latency figures quoted elsewhere in the project
    keep meaning the same thing they meant before the incident suite existed.
    Folding two more attacks into the denominator would move every published
    number for a reason that has nothing to do with the guard.
    """
    return all_attacks() + all_normal()


def by_name(name: str) -> Scenario:
    """Look a scenario up by name, incident-derived ones included."""
    pool = all_scenarios() + all_incident_scenarios()
    for scenario in pool:
        if scenario.name == name:
            return scenario
    known = ", ".join(s.name for s in pool)
    raise KeyError(f"unknown scenario {name!r}; available: {known}")
