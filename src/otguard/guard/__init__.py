"""The physics-plausibility guard: estimator, rules and decision engine."""

from .estimator import Prediction, TankEstimator
from .guard import GuardStats, PhysicsGuard, ProtectiveAction, SupervisionEvent
from .rules import (
    ConsistencyRule,
    DynamicsRule,
    GuardContext,
    PredictionRule,
    RangeRule,
    Rule,
    default_rules,
)
from .types import Command, CommandKind, Decision, Observation, RuleFinding, Verdict

__all__ = [
    "Command",
    "CommandKind",
    "ConsistencyRule",
    "Decision",
    "DynamicsRule",
    "GuardContext",
    "GuardStats",
    "Observation",
    "PhysicsGuard",
    "Prediction",
    "PredictionRule",
    "ProtectiveAction",
    "RangeRule",
    "Rule",
    "RuleFinding",
    "SupervisionEvent",
    "TankEstimator",
    "Verdict",
    "default_rules",
]
