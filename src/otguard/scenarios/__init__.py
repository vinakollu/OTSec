"""Labelled scenarios: the ground truth the evaluation scores against.

The incident-derived scenarios are deliberately kept out of the headline
evaluation and scored by ``scripts/run_incidents.py`` instead, so that the
detection rate, the false-alarm rate and the latency figures quoted elsewhere
keep meaning what they meant before the incident suite existed. Folding two
more attacks into the denominator would move every published number for a
reason that has nothing to do with the guard.
"""

from .bess_attacks import all_attacks as all_site_attacks
from .bess_normal import all_normal as all_site_normal
from .incidents import INCIDENTS, Evidence, Incident, Mechanism, Vantage
from .site_base import SiteDispatchController, SiteScenario

__all__ = [
    "INCIDENTS",
    "Evidence",
    "Incident",
    "Mechanism",
    "SiteDispatchController",
    "SiteScenario",
    "Vantage",
    "all_site_attacks",
    "all_site_normal",
    "all_site_scenarios",
    "site_by_name",
]


def all_site_scenarios() -> list[SiteScenario]:
    """Every storage-site scenario the headline evaluation scores."""
    return all_site_attacks() + all_site_normal()


def site_by_name(name: str) -> SiteScenario:
    for scenario in all_site_scenarios():
        if scenario.name == name:
            return scenario
    raise KeyError(f"no site scenario called {name!r}")
