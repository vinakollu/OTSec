"""Scoring. The three numbers the project lives or dies by, plus their context.

Detection is scored at two levels, because each answers a different question and
either alone is misleading.

**Command level** — of the individual writes, which did the guard object to?
Gives precision/recall, and the false-positive rate that decides whether
operators would tolerate the thing. But it flatters a guard facing an attack
made of many writes (a 200-write flood scores 200 true positives for one idea)
and punishes one that catches a two-write attack via its consequence rather than
its commands.

**Scenario level** — of the attack episodes, how many were caught at all, and how
many were caught *early enough to prevent damage*? This is the number an asset
owner actually cares about. ``prevented`` is stricter than ``detected``: an
alarm raised as the tank tops out is not a save.

Latency is reported as a distribution, not a mean. A guard on a control loop is
judged by its tail: the p99 is what has to fit inside the scan period, and an
average hides exactly the excursions that would break real-time behaviour.
"""

from __future__ import annotations

import statistics
from dataclasses import asdict, dataclass, field

from .harness import RunResult


@dataclass
class CommandMetrics:
    """Per-write confusion matrix."""

    malicious_total: int = 0
    malicious_flagged: int = 0
    malicious_blocked: int = 0
    benign_total: int = 0
    benign_flagged: int = 0
    benign_blocked: int = 0

    @property
    def recall(self) -> float:
        """Share of malicious writes the guard objected to."""
        return _ratio(self.malicious_flagged, self.malicious_total)

    @property
    def false_positive_rate(self) -> float:
        """Share of benign writes the guard objected to. The headline FP number."""
        return _ratio(self.benign_flagged, self.benign_total)

    @property
    def precision(self) -> float:
        flagged = self.malicious_flagged + self.benign_flagged
        return _ratio(self.malicious_flagged, flagged)

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 0.0 if (p + r) == 0 else 2 * p * r / (p + r)

    def as_dict(self) -> dict:
        d = asdict(self)
        d.update(
            recall=self.recall,
            precision=self.precision,
            f1=self.f1,
            false_positive_rate=self.false_positive_rate,
        )
        return d


@dataclass
class ScenarioMetrics:
    """Per-episode outcomes."""

    attacks_total: int = 0
    attacks_detected: int = 0
    attacks_prevented: int = 0
    attacks_damaging_unguarded: int = 0
    damage_avoided: int = 0  # damaging-unguarded attacks that did no damage guarded
    normal_total: int = 0
    normal_clean: int = 0
    normal_with_false_alarm: int = 0
    normal_disrupted: int = 0  # a benign write was actually blocked

    @property
    def detection_rate(self) -> float:
        return _ratio(self.attacks_detected, self.attacks_total)

    @property
    def prevention_rate(self) -> float:
        return _ratio(self.attacks_prevented, self.attacks_total)

    @property
    def damage_avoidance_rate(self) -> float:
        """Of the attacks that actually caused damage with the guard removed,
        how many did the guard stop?

        This is the number worth quoting. ``prevention_rate`` gives credit for
        "preventing" attacks that were never going to break anything — a write
        flood of harmless values counts as a save under that definition, which
        flatters the result. Scoring only against attacks with a demonstrated
        physical consequence removes that free credit.
        """
        return _ratio(self.damage_avoided, self.attacks_damaging_unguarded)

    @property
    def false_alarm_rate(self) -> float:
        """Share of benign episodes in which the guard raised any objection."""
        return _ratio(self.normal_with_false_alarm, self.normal_total)

    def as_dict(self) -> dict:
        d = asdict(self)
        d.update(
            detection_rate=self.detection_rate,
            prevention_rate=self.prevention_rate,
            damage_avoidance_rate=self.damage_avoidance_rate,
            false_alarm_rate=self.false_alarm_rate,
        )
        return d


@dataclass
class LatencyMetrics:
    """Added per-command decision cost, in microseconds."""

    count: int = 0
    mean_us: float = 0.0
    p50_us: float = 0.0
    p95_us: float = 0.0
    p99_us: float = 0.0
    max_us: float = 0.0

    @classmethod
    def from_samples(cls, samples: list[float]) -> "LatencyMetrics":
        if not samples:
            return cls()
        ordered = sorted(samples)
        return cls(
            count=len(ordered),
            mean_us=statistics.fmean(ordered),
            p50_us=_percentile(ordered, 0.50),
            p95_us=_percentile(ordered, 0.95),
            p99_us=_percentile(ordered, 0.99),
            max_us=ordered[-1],
        )

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class Report:
    """The full evaluation result.

    ``commands`` covers every write in the suite. ``benign_traffic`` covers only
    the writes in benign episodes, and that is the one to quote as the
    false-positive rate: a benign-labelled write inside an *attack* scenario is
    usually the compromised controller being refused by the post-trip lockout,
    which is the guard working, not failing. Counting those as false positives
    would understate the design; excluding them from the whole-suite number
    would overstate it, so both are reported.
    """

    commands: CommandMetrics = field(default_factory=CommandMetrics)
    benign_traffic: CommandMetrics = field(default_factory=CommandMetrics)
    scenarios: ScenarioMetrics = field(default_factory=ScenarioMetrics)
    latency: LatencyMetrics = field(default_factory=LatencyMetrics)
    per_scenario: list[dict] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "commands": self.commands.as_dict(),
            "benign_traffic": self.benign_traffic.as_dict(),
            "scenarios": self.scenarios.as_dict(),
            "latency": self.latency.as_dict(),
            "per_scenario": self.per_scenario,
        }


def score(
    guarded: list[RunResult],
    unguarded: list[RunResult] | None = None,
) -> Report:
    """Aggregate runs into a report.

    ``unguarded`` is the matching set of counterfactual runs (same scenarios,
    guard disabled). It supplies the "would this have done damage anyway?"
    column, without which prevention counts are unfalsifiable.
    """
    report = Report()
    baseline = {r.scenario.name: r for r in (unguarded or [])}
    latencies: list[float] = []

    for run in guarded:
        latencies.extend(run.latencies_us())
        counterfactual = baseline.get(run.scenario.name)

        buckets = [report.commands]
        if not run.scenario.is_attack:
            buckets.append(report.benign_traffic)
        for verdict, malicious in run.verdicts:
            for bucket in buckets:
                if malicious:
                    bucket.malicious_total += 1
                    bucket.malicious_flagged += int(verdict.flagged)
                    bucket.malicious_blocked += int(not verdict.allowed)
                else:
                    bucket.benign_total += 1
                    bucket.benign_flagged += int(verdict.flagged)
                    bucket.benign_blocked += int(not verdict.allowed)

        entry = {
            "name": run.scenario.name,
            "category": run.scenario.category,
            "description": run.scenario.description,
            "expected_rules": list(run.scenario.expected_rules),
            "detected": run.detected,
            "first_detection_t": run.first_detection_t,
            "damaged": run.damaged,
            "overflowed": run.overflowed,
            "dried_out": run.dried_out,
            "min_level_m": round(run.min_level_m, 4),
            "max_level_m": round(run.max_level_m, 4),
            "lead_time_s": run.lead_time_s,
            "commands": len(run.verdicts),
            "blocked": sum(1 for v, _ in run.verdicts if not v.allowed),
            "supervision_trips": sum(1 for e in run.supervision_events if e.action is not None),
            "rules_fired": sorted({f.rule_id for v, _ in run.verdicts for f in v.findings}
                                  | {f.rule_id for e in run.supervision_events for f in e.findings}),
        }
        if counterfactual is not None:
            entry["unguarded_damaged"] = counterfactual.damaged
            entry["unguarded_max_level_m"] = round(counterfactual.max_level_m, 4)
            entry["unguarded_min_level_m"] = round(counterfactual.min_level_m, 4)

        if run.scenario.is_attack:
            report.scenarios.attacks_total += 1
            report.scenarios.attacks_detected += int(run.detected)
            report.scenarios.attacks_prevented += int(run.prevented)
            if counterfactual is not None and counterfactual.damaged:
                report.scenarios.attacks_damaging_unguarded += 1
                report.scenarios.damage_avoided += int(not run.damaged)
        else:
            report.scenarios.normal_total += 1
            flagged = any(v.flagged for v, _ in run.verdicts) or bool(run.supervision_events)
            blocked = any(not v.allowed for v, _ in run.verdicts)
            report.scenarios.normal_clean += int(not flagged)
            report.scenarios.normal_with_false_alarm += int(flagged)
            report.scenarios.normal_disrupted += int(blocked)

        report.per_scenario.append(entry)

    report.latency = LatencyMetrics.from_samples(latencies)
    return report


def _ratio(numerator: int, denominator: int) -> float:
    return 0.0 if denominator == 0 else numerator / denominator


def _percentile(ordered: list[float], q: float) -> float:
    """Nearest-rank percentile on an already-sorted list."""
    if not ordered:
        return 0.0
    index = max(0, min(len(ordered) - 1, int(round(q * (len(ordered) - 1)))))
    return ordered[index]
