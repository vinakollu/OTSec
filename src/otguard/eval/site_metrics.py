"""Scoring for the storage-site evaluation.

Same discipline as :mod:`otguard.eval.metrics`, with one addition the tank did
not need: because the site has three measurements and the vote *names* one as
the liar, "detected" is not the whole story. A guard that says "something is
wrong" and a guard that says "the revenue meter is lying, use the relay" differ
operationally, so source attribution is scored separately.

Two denominators are reported for the false-positive rate, for the reason the
tank version documented: a benign-labelled write inside an *attack* scenario is
usually the compromised controller being refused, which is the guard working.
Counting those as false positives understates the design; excluding them from
the whole-suite figure overstates it. Both appear.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .site_harness import SiteRunResult


def _ratio(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


@dataclass
class CommandCounts:
    malicious_total: int = 0
    malicious_flagged: int = 0
    malicious_blocked: int = 0
    benign_total: int = 0
    benign_flagged: int = 0
    benign_blocked: int = 0

    @property
    def recall(self) -> float:
        return _ratio(self.malicious_flagged, self.malicious_total)

    @property
    def false_positive_rate(self) -> float:
        return _ratio(self.benign_flagged, self.benign_total)

    @property
    def precision(self) -> float:
        return _ratio(
            self.malicious_flagged, self.malicious_flagged + self.benign_flagged
        )

    def as_dict(self) -> dict:
        return {
            "malicious_total": self.malicious_total,
            "malicious_flagged": self.malicious_flagged,
            "malicious_blocked": self.malicious_blocked,
            "benign_total": self.benign_total,
            "benign_flagged": self.benign_flagged,
            "benign_blocked": self.benign_blocked,
            "recall": self.recall,
            "false_positive_rate": self.false_positive_rate,
            "precision": self.precision,
        }


@dataclass
class ScenarioCounts:
    attacks: int = 0
    attacks_detected: int = 0
    attacks_damaging_unguarded: int = 0
    attacks_damage_avoided: int = 0
    benign: int = 0
    benign_with_any_flag: int = 0
    source_attributions: int = 0
    source_attributions_correct: int = 0

    @property
    def detection_rate(self) -> float:
        return _ratio(self.attacks_detected, self.attacks)

    @property
    def damage_avoidance(self) -> float:
        return _ratio(self.attacks_damage_avoided, self.attacks_damaging_unguarded)

    @property
    def benign_clean_rate(self) -> float:
        return _ratio(self.benign - self.benign_with_any_flag, self.benign)

    def as_dict(self) -> dict:
        return {
            "attacks": self.attacks,
            "attacks_detected": self.attacks_detected,
            "detection_rate": self.detection_rate,
            "attacks_damaging_unguarded": self.attacks_damaging_unguarded,
            "attacks_damage_avoided": self.attacks_damage_avoided,
            "damage_avoidance": self.damage_avoidance,
            "benign": self.benign,
            "benign_with_any_flag": self.benign_with_any_flag,
            "benign_clean_rate": self.benign_clean_rate,
            "source_attributions": self.source_attributions,
            "source_attributions_correct": self.source_attributions_correct,
        }


@dataclass
class LatencyCounts:
    samples: list[float] = field(default_factory=list)

    def add(self, values: list[float]) -> None:
        self.samples.extend(values)

    def percentile(self, p: float) -> float:
        if not self.samples:
            return 0.0
        ordered = sorted(self.samples)
        index = min(len(ordered) - 1, max(0, int(round(p / 100.0 * (len(ordered) - 1)))))
        return ordered[index]

    def as_dict(self) -> dict:
        return {
            "count": len(self.samples),
            "mean_us": sum(self.samples) / len(self.samples) if self.samples else 0.0,
            "p50_us": self.percentile(50),
            "p95_us": self.percentile(95),
            "p99_us": self.percentile(99),
            "max_us": max(self.samples) if self.samples else 0.0,
        }


@dataclass
class SiteReport:
    commands: CommandCounts = field(default_factory=CommandCounts)
    benign_traffic: CommandCounts = field(default_factory=CommandCounts)
    scenarios: ScenarioCounts = field(default_factory=ScenarioCounts)
    latency: LatencyCounts = field(default_factory=LatencyCounts)
    per_scenario: list[dict] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "commands": self.commands.as_dict(),
            "benign_traffic": self.benign_traffic.as_dict(),
            "scenarios": self.scenarios.as_dict(),
            "latency": self.latency.as_dict(),
            "per_scenario": self.per_scenario,
        }


# Which measurement each telemetry attack actually corrupts, so that a named
# outlier can be scored right or wrong rather than merely present.
EXPECTED_SOURCE = {
    "stealthy_meter_bias": "poi_meter",
}


def score_site(
    guarded: list[SiteRunResult], unguarded: list[SiteRunResult] | None = None
) -> SiteReport:
    """Aggregate runs into a report."""
    report = SiteReport()
    baseline = {r.scenario.name: r for r in (unguarded or [])}

    for run in guarded:
        scenario = run.scenario
        counterfactual = baseline.get(scenario.name)

        buckets = [report.commands]
        if not scenario.is_attack:
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

        report.latency.add(run.latencies_us())

        rules = sorted(
            {f.rule_id for v, _ in run.verdicts for f in v.findings}
            | {f.rule_id for e in run.supervision_events for f in e.findings}
        )
        row = {
            "name": scenario.name,
            "category": scenario.category,
            "description": scenario.description,
            "detected": run.detected,
            "first_detection_s": run.first_detection_t,
            "damaged": run.damaged,
            "damage": run.damage,
            "peak_poi_mw": run.peak_poi_mw,
            "min_soc": run.min_soc,
            "peak_temp_c": run.peak_temp_c,
            "rules_fired": rules,
            "expected_rules": list(scenario.expected_rules),
            "commands": len(run.verdicts),
            "blocked": sum(1 for v, _ in run.verdicts if not v.allowed),
            "supervision_events": len(run.supervision_events),
            "named_source": run.named_source,
        }
        if counterfactual is not None:
            row["unguarded_damaged"] = counterfactual.damaged
            row["unguarded_damage"] = counterfactual.damage
            row["unguarded_peak_poi_mw"] = counterfactual.peak_poi_mw
            row["unguarded_min_soc"] = counterfactual.min_soc
            row["unguarded_peak_temp_c"] = counterfactual.peak_temp_c
        report.per_scenario.append(row)

        if scenario.is_attack:
            report.scenarios.attacks += 1
            report.scenarios.attacks_detected += int(run.detected)
            if counterfactual is not None and counterfactual.damaged:
                report.scenarios.attacks_damaging_unguarded += 1
                if not run.damaged:
                    report.scenarios.attacks_damage_avoided += 1
            expected = EXPECTED_SOURCE.get(scenario.name)
            if expected is not None:
                report.scenarios.source_attributions += 1
                if run.named_source == expected:
                    report.scenarios.source_attributions_correct += 1
        else:
            report.scenarios.benign += 1
            flagged = any(v.flagged for v, _ in run.verdicts) or bool(
                run.supervision_events
            )
            report.scenarios.benign_with_any_flag += int(flagged)

    return report
