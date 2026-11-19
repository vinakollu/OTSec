"""Evaluation: replay scenarios, score them, render the results.

Each plant has its own harness because each plant has its own idea of what
damage is. What they share is the shape of the answer: a scenario run twice,
once with the guard enforcing and once with it watching and powerless, so that
"nothing went wrong" is a claim with a control behind it.
"""

from .site_harness import SiteRunResult, run_site_scenario
from .site_metrics import SiteReport, score_site

__all__ = [
    "SiteReport",
    "SiteRunResult",
    "run_site_scenario",
    "score_site",
]
