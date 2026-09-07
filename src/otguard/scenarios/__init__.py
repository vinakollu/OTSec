"""Labelled scenarios: the ground truth the evaluation scores against."""

from .attacks import all_attacks
from .base import Controller, LevelController, Scenario, ScheduledCommand, SensorAttack
from .normal import all_normal

__all__ = [
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
    """Every scenario in the suite, attacks first."""
    return all_attacks() + all_normal()


def by_name(name: str) -> Scenario:
    for scenario in all_scenarios():
        if scenario.name == name:
            return scenario
    known = ", ".join(s.name for s in all_scenarios())
    raise KeyError(f"unknown scenario {name!r}; available: {known}")
