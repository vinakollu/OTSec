"""The physics-plausibility guard: estimators, rules and decision engines.

Two plants, two rule sets, one idea. The storage site's B1 to B8 judge power,
charge, temperature and provenance; the treatment works' W1 to W8 judge doses,
flows and the contact time nobody measures. Both reach a decision the same
way, against the same :class:`Verdict`, which is what lets one evaluation and
one display serve both.
"""

from .site_estimator import PackEstimate, PackEstimator, SourceVoter, VoteResult
from .site_guard import (
    SiteGuard,
    SiteProtectiveAction,
    SiteStats,
    SiteSupervisionEvent,
    SiteVerdict,
)
from .site_rules import SiteContext, SiteRule, default_site_rules
from .types import Decision, RuleFinding, Verdict
from .water_estimator import WaterEstimator
from .water_guard import ProtectiveAction, SupervisionEvent, WaterGuard, WaterVerdict
from .water_rules import WaterContext, default_rules
from .wire import PERMISSIVE_POLICY, PointRole, WireDecision, WirePolicy

__all__ = [
    "PERMISSIVE_POLICY",
    "Decision",
    "PackEstimate",
    "PackEstimator",
    "PointRole",
    "ProtectiveAction",
    "RuleFinding",
    "SiteContext",
    "SiteGuard",
    "SiteProtectiveAction",
    "SiteRule",
    "SiteStats",
    "SiteSupervisionEvent",
    "SiteVerdict",
    "SourceVoter",
    "SupervisionEvent",
    "Verdict",
    "VoteResult",
    "WaterContext",
    "WaterEstimator",
    "WaterGuard",
    "WaterVerdict",
    "WireDecision",
    "WirePolicy",
    "default_rules",
    "default_site_rules",
]
