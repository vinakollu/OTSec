"""What to do with a write the physics rules cannot evaluate.

Some writes are not physics questions. A write to a point the guard has no
description for, a write to a commissioning parameter that changes how an
actuator responds, a frame whose effect cannot be determined from the frame
itself: no rule about where the plant ends up can speak to any of them,
because the rules need to know what the command does before they can ask what
it would do.

A wire policy answers those before the rules run, and it refuses by default.
Keeping it separate from the rules is deliberate. An access check that stops
an attack is worth having and is not evidence for the claim this project
makes, so the two are reported apart and the policy can be switched off to
measure what the physics rules catch on their own.

This lives under ``guard`` rather than beside a protocol because it is not
about a protocol. The same three roles and the same refusal reasons apply to
an OPC UA node and to a Modbus register, and the policy was written once for
both.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class PointRole(str, Enum):
    """What writing to a point does, from the rules' point of view."""

    #: Moves the process. The physics rules judge it.
    COMMAND = "command"
    #: Changes how the process responds, which invalidates the model the rules
    #: reason about. No rule can judge it, so the policy decides.
    PARAMETER = "parameter"
    #: Not a write target. Forwarded.
    PASSTHROUGH = "passthrough"


class WireDecision(str, Enum):
    """Why a frame was stopped before the physics rules ever ran."""

    UNKNOWN_FUNCTION = "unknown_function"
    UNPARSEABLE = "unparseable"
    UNJUDGEABLE_WRITE = "unjudgeable_write"
    UNMAPPED_POINT = "unmapped_point"
    PARAMETER_WRITE = "parameter_write"
    UNAUTHORISED_SOURCE = "unauthorised_source"
    UNAUTHORISED_POINT = "unauthorised_point"


@dataclass(frozen=True)
class WirePolicy:
    """What to do with writes the physics rules cannot evaluate.

    Every flag defaults to refusing. ``allow_unknown_sources`` is the one worth
    arguing about: refusing it turns the guard into an access-control device as
    well as a physics one, which is a different claim than the project makes
    elsewhere. It is reported as its own column in the results so its
    contribution can be told apart from the rules'.
    """

    refuse_unknown_functions: bool = True
    refuse_unmapped_points: bool = True
    refuse_parameter_writes: bool = True
    enforce_source_scope: bool = True
    allow_unknown_sources: bool = False

    def permits(self, decision: WireDecision) -> bool:
        """True when the policy lets a frame with this defect through anyway."""
        return {
            WireDecision.UNKNOWN_FUNCTION: not self.refuse_unknown_functions,
            WireDecision.UNPARSEABLE: False,
            # A frame whose effect cannot be determined from the frame is never
            # forwarded, whatever the policy says. Permitting it would mean
            # vouching for a value the guard has not seen.
            WireDecision.UNJUDGEABLE_WRITE: False,
            WireDecision.UNMAPPED_POINT: not self.refuse_unmapped_points,
            WireDecision.PARAMETER_WRITE: not self.refuse_parameter_writes,
            WireDecision.UNAUTHORISED_SOURCE: self.allow_unknown_sources,
            WireDecision.UNAUTHORISED_POINT: not self.enforce_source_scope,
        }[decision]


#: Everything forwarded that the rules cannot judge. The ablation baseline:
#: it isolates what the physics rules catch on their own.
PERMISSIVE_POLICY = WirePolicy(
    refuse_unknown_functions=False,
    refuse_unmapped_points=False,
    refuse_parameter_writes=False,
    enforce_source_scope=False,
    allow_unknown_sources=True,
)
