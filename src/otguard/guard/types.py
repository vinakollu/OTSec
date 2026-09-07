"""Datatypes exchanged between the protocol layer, the rules and the evaluator.

Keeping these protocol-agnostic is what lets the same ``PhysicsGuard`` run
in-process under the evaluation harness and behind a real Modbus proxy without
a line of rule code changing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class CommandKind(str, Enum):
    """The writable process variables the guard understands."""

    PUMP = "pump"          # inlet pump speed, %
    VALVE = "valve"        # outlet valve position, %
    SETPOINT = "setpoint"  # level setpoint, m
    MODE = "mode"          # 0 = manual, 1 = auto

    @property
    def unit(self) -> str:
        return {"pump": "%", "valve": "%", "setpoint": "m", "mode": ""}[self.value]


class Decision(str, Enum):
    """What the guard did with a command."""

    ALLOW = "allow"   # forwarded, no rule fired
    ALARM = "alarm"   # forwarded, but a rule fired and raised an alert
    BLOCK = "block"   # not forwarded to the PLC


@dataclass(frozen=True)
class Command:
    """A single write from the HMI/engineering workstation toward the PLC."""

    t: float
    kind: CommandKind
    value: float
    source: str = "hmi"

    def __str__(self) -> str:
        return f"t={self.t:7.2f}s {self.kind.value}={self.value:g}{self.kind.unit}"


@dataclass(frozen=True)
class Observation:
    """A process-variable read flowing back from the PLC toward the HMI.

    ``level_m`` is what the *sensor reports*, which under a false-data-injection
    attack is not what the tank is actually doing. Telling those two apart is
    rule R4's entire job.
    """

    t: float
    level_m: float


@dataclass(frozen=True)
class RuleFinding:
    """One rule's objection to one command."""

    rule_id: str      # "R1" ... "R4"
    rule_name: str
    detail: str       # human-readable, shows up in the operator alarm
    margin: float = 0.0  # how far over the limit; 0 when not meaningful

    def __str__(self) -> str:
        return f"[{self.rule_id} {self.rule_name}] {self.detail}"


@dataclass
class Verdict:
    """The guard's ruling on one command, plus how long it took to decide."""

    command: Command
    decision: Decision
    findings: list[RuleFinding] = field(default_factory=list)
    latency_us: float = 0.0

    @property
    def allowed(self) -> bool:
        """Was the command forwarded to the PLC?"""
        return self.decision is not Decision.BLOCK

    @property
    def flagged(self) -> bool:
        """Did any rule object, whether or not the command was blocked?"""
        return bool(self.findings)

    @property
    def rule_ids(self) -> list[str]:
        return [f.rule_id for f in self.findings]

    def __str__(self) -> str:
        head = f"{self.decision.value.upper():5s} {self.command}"
        if not self.findings:
            return head
        return head + "  <- " + "; ".join(str(f) for f in self.findings)
