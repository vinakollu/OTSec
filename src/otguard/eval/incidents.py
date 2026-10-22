"""Running the incident catalogue against whatever evaluation covers each row.

This does not simulate anything of its own. Every incident in
:mod:`otguard.scenarios.incidents` points at evidence that already exists
somewhere in the project — a tank scenario, a storage-site scenario, a pair
from the device matrix, a cell of the OPC UA experiment — and this module runs
the right one and collects the answer.

Keeping it as a mapping rather than a parallel attack library is deliberate.
The alternative is a second copy of every attack with an incident's name on it,
which drifts from the first copy within a week and then reports two different
numbers for the same thing.

The rows that point at nothing are the point of the exercise as much as the
rows that do. A coverage table whose every row is a hit is a table of attacks
chosen to be hits.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from ..config import Config
from ..scenarios import by_name as tank_scenario
from ..scenarios.bess_attacks import all_attacks as site_attacks
from ..scenarios.bess_normal import all_normal as site_normal
from ..scenarios.incidents import INCIDENTS, Evidence, Incident, Mechanism, Vantage
from ..scenarios.site_base import SiteScenario
from .harness import run_scenario
from .site_harness import run_site_scenario


def site_scenario(name: str) -> SiteScenario:
    for scenario in site_attacks() + site_normal():
        if scenario.name == name:
            return scenario
    raise KeyError(f"unknown site scenario {name!r}")


@dataclass
class EvidenceResult:
    """What one piece of evidence turned out to say."""

    incident: str
    kind: str
    name: str
    note: str = ""
    ran: bool = False
    skipped: str = ""
    detected: bool = False
    first_detection_t: float | None = None
    damage_unguarded: bool = False
    damage_guarded: bool = False
    rules: tuple[str, ...] = ()
    wire_reasons: tuple[str, ...] = ()
    lead_time_s: float | None = None
    #: False when the incident issued no process commands. Detection is then
    #: the wrong thing to measure and a non-detection is the right answer.
    expect_detection: bool = True

    @property
    def damage_prevented(self) -> bool:
        return self.damage_unguarded and not self.damage_guarded

    @property
    def by_rules(self) -> bool:
        """Did a physics rule object, as opposed to the access policy?"""
        return bool(self.rules)

    @property
    def verdict(self) -> str:
        """One word for the table."""
        if not self.ran:
            return "not run"
        if not self.expect_detection:
            # Reconnaissance. Forwarding it is correct and claiming it is not.
            return "false alarm" if self.detected else "ignored"
        if not self.detected:
            return "missed"
        if self.damage_guarded:
            return "damaged"
        if self.damage_unguarded:
            return "prevented"
        return "detected"

    def as_dict(self) -> dict:
        return {
            "incident": self.incident,
            "kind": self.kind,
            "name": self.name,
            "note": self.note,
            "ran": self.ran,
            "skipped": self.skipped,
            "verdict": self.verdict,
            "by_rules": self.by_rules,
            "detected": self.detected,
            "first_detection_t": self.first_detection_t,
            "damage_unguarded": self.damage_unguarded,
            "damage_guarded": self.damage_guarded,
            "damage_prevented": self.damage_prevented,
            "rules": list(self.rules),
            "wire_reasons": list(self.wire_reasons),
            "lead_time_s": self.lead_time_s,
        }


@dataclass
class IncidentResult:
    incident: Incident
    evidence: list[EvidenceResult] = field(default_factory=list)

    @property
    def ran(self) -> list[EvidenceResult]:
        return [e for e in self.evidence if e.ran]

    @property
    def covered(self) -> bool:
        """Did at least one piece of evidence detect its attack?"""
        return any(e.detected for e in self.ran)

    @property
    def prevented(self) -> bool:
        return any(e.damage_prevented for e in self.ran)

    @property
    def had_damage_to_prevent(self) -> bool:
        return any(e.damage_unguarded for e in self.ran)

    @property
    def detected_by_rules(self) -> bool:
        """Did a physics rule object, rather than only the access policy?"""
        return any(e.detected and e.by_rules for e in self.ran)

    @property
    def summary(self) -> str:
        if not self.evidence:
            return "no evidence"
        if not self.ran:
            reasons = {e.skipped for e in self.evidence if e.skipped}
            return "; ".join(sorted(reasons)) or "not run"
        if not any(e.expect_detection for e in self.ran):
            objected = any(e.detected for e in self.ran)
            return ("objected to traffic it should have forwarded"
                    if objected else "forwarded, and nothing claimed")
        if self.prevented:
            return "detected, damage prevented"
        if self.covered and not self.had_damage_to_prevent:
            return "detected, no damage to prevent"
        if self.covered:
            return "detected, damage done anyway"
        return "not detected"


def _expects_detection(incident: Incident) -> bool:
    """Is detection even the right thing to measure for this incident?

    Night Dragon took documents and Havex inventoried servers. Neither issued a
    process command, so scoring them on detection asks a plausibility guard
    whether it caught something that was never there, and records the right
    answer as a miss.
    """
    return incident.mechanism is Mechanism.COMMAND


def _tank(evidence: Evidence, incident: Incident, config: Config) -> EvidenceResult:
    result = EvidenceResult(incident=incident.key, kind=evidence.kind,
                            name=evidence.name, note=evidence.note,
                            expect_detection=_expects_detection(incident))
    scenario = tank_scenario(evidence.name)
    guarded = run_scenario(scenario, config, enforce=True)
    unguarded = run_scenario(scenario, config, enforce=False)
    result.ran = True
    result.detected = guarded.detected
    result.first_detection_t = guarded.first_detection_t
    result.damage_guarded = guarded.damaged
    result.damage_unguarded = unguarded.damaged
    result.lead_time_s = unguarded.lead_time_s
    result.rules = tuple(sorted(
        {r for v, _ in guarded.verdicts for r in v.rule_ids}
        | {f.rule_id for e in guarded.supervision_events for f in e.findings}
    ))
    return result


def _site(evidence: Evidence, incident: Incident, config: Config) -> EvidenceResult:
    result = EvidenceResult(incident=incident.key, kind=evidence.kind,
                            name=evidence.name, note=evidence.note,
                            expect_detection=_expects_detection(incident))
    scenario = site_scenario(evidence.name)
    guarded = run_site_scenario(scenario, config, enforce=True)
    unguarded = run_site_scenario(scenario, config, enforce=False)
    result.ran = True
    result.detected = guarded.detected
    result.first_detection_t = guarded.first_detection_t
    result.damage_guarded = guarded.damaged
    result.damage_unguarded = unguarded.damaged
    result.lead_time_s = unguarded.lead_time_s
    result.rules = tuple(sorted(
        {r for v, _ in guarded.verdicts for r in v.rule_ids}
        | {f.rule_id for e in guarded.supervision_events for f in e.findings}
    ))
    return result


async def _matrix(evidence: Evidence, incident: Incident, config: Config,
                  speed: float = 20.0) -> EvidenceResult:
    from .matrix import all_scenarios as matrix_scenarios
    from .matrix import run_pair

    result = EvidenceResult(incident=incident.key, kind=evidence.kind,
                            name=evidence.name, note=evidence.note,
                            expect_detection=_expects_detection(incident))
    try:
        scenario_name, source, executor = evidence.name.split("/")
    except ValueError:
        result.skipped = f"malformed matrix reference {evidence.name!r}"
        return result
    match = next((s for s in matrix_scenarios() if s.name == scenario_name), None)
    if match is None:
        result.skipped = f"no matrix scenario named {scenario_name!r}"
        return result
    pair = await run_pair(match, source, executor, config, speed=speed)
    result.ran = True
    result.detected = pair.guarded.detected
    result.damage_guarded = pair.guarded.damaged
    result.damage_unguarded = pair.unguarded.damaged
    result.rules = tuple(pair.guarded.rules_fired)
    result.wire_reasons = tuple(pair.guarded.wire_reasons)
    return result


def _opcua(evidence: Evidence, incident: Incident, metrics: dict | None) -> EvidenceResult:
    """Read the OPC UA experiment's own output rather than re-running it.

    The OPC UA cells run over real sockets with a secure-channel handshake per
    episode, which costs minutes rather than milliseconds. Re-running them for
    every incident that points at one would make this report the slowest thing
    in the project. It reads ``opcua_metrics.json`` where it exists and says so
    plainly where it does not, rather than leaving a blank that reads like a
    miss.
    """
    result = EvidenceResult(incident=incident.key, kind=evidence.kind,
                            name=evidence.name, note=evidence.note,
                            expect_detection=_expects_detection(incident))
    if not metrics:
        result.skipped = "run scripts/run_opcua.py first"
        return result
    cells = [c for c in metrics.get("cells", [])
             if c.get("scenario") == evidence.name and c.get("enforced")]
    if not cells:
        result.skipped = f"no OPC UA cell for {evidence.name!r}"
        return result
    # The readable modes are the ones comparable with the rest of the project.
    # The encrypted one is the experiment's own finding and is reported there.
    readable = [c for c in cells if c.get("mode") != "SignAndEncrypt"]
    chosen = readable[0] if readable else cells[0]
    result.ran = True
    result.detected = bool(chosen.get("detected"))
    result.first_detection_t = chosen.get("first_detection_t")
    result.damage_guarded = bool(chosen.get("damaged"))
    result.damage_unguarded = bool(chosen.get("damaged_unguarded"))
    result.rules = tuple(chosen.get("rules_fired", ()))
    result.wire_reasons = tuple(chosen.get("wire_reasons", ()))
    result.note = (result.note + f" [mode {chosen.get('mode')}]").strip()
    return result


async def run_incidents(
    config: Config,
    incidents: tuple[Incident, ...] = INCIDENTS,
    *,
    include_matrix: bool = True,
    opcua_metrics_path: Path | None = None,
    speed: float = 20.0,
) -> list[IncidentResult]:
    """Run every piece of evidence every incident points at."""
    metrics = None
    if opcua_metrics_path is not None and opcua_metrics_path.exists():
        metrics = json.loads(opcua_metrics_path.read_text())

    out: list[IncidentResult] = []
    for incident in incidents:
        row = IncidentResult(incident=incident)
        for evidence in incident.evidence:
            if evidence.kind == "none":
                row.evidence.append(EvidenceResult(
                    incident=incident.key, kind="none", name="",
                    note=evidence.note, skipped=evidence.note or "out of scope",
                ))
            elif evidence.kind == "tank":
                row.evidence.append(_tank(evidence, incident, config))
            elif evidence.kind == "site":
                row.evidence.append(_site(evidence, incident, config))
            elif evidence.kind == "matrix":
                if include_matrix:
                    row.evidence.append(await _matrix(evidence, incident, config, speed))
                else:
                    row.evidence.append(EvidenceResult(
                        incident=incident.key, kind="matrix", name=evidence.name,
                        note=evidence.note, skipped="matrix pairs not requested",
                    ))
            elif evidence.kind == "opcua":
                row.evidence.append(_opcua(evidence, incident, metrics))
            else:
                row.evidence.append(EvidenceResult(
                    incident=incident.key, kind=evidence.kind, name=evidence.name,
                    skipped=f"unknown evidence kind {evidence.kind!r}",
                ))
        out.append(row)
    return out


def summarise(results: list[IncidentResult]) -> dict:
    """The counts worth quoting, each with its denominator stated."""
    in_scope = [r for r in results if r.incident.in_scope]
    out_of_scope = [r for r in results if not r.incident.in_scope]
    return {
        "incidents": len(results),
        "in_scope": len(in_scope),
        "out_of_scope": len(out_of_scope),
        "out_of_scope_reasons": {
            r.incident.key: _why_out(r.incident) for r in out_of_scope
        },
        "in_scope_detected": sum(1 for r in in_scope if r.covered),
        "in_scope_detected_by_rules": sum(1 for r in in_scope if r.detected_by_rules),
        "in_scope_detected_only_by_policy": sum(
            1 for r in in_scope if r.covered and not r.detected_by_rules
        ),
        "in_scope_with_damage_to_prevent": sum(1 for r in in_scope if r.had_damage_to_prevent),
        "in_scope_damage_prevented": sum(1 for r in in_scope if r.prevented),
        "evidence_run": sum(len(r.ran) for r in results),
        "evidence_skipped": sum(
            1 for r in results for e in r.evidence if not e.ran
        ),
    }


def _why_out(incident: Incident) -> str:
    if incident.mechanism is Mechanism.ENTERPRISE:
        return "no process command was issued; a plausibility rule has nothing to judge"
    if incident.mechanism is Mechanism.RECONNAISSANCE:
        return "reconnaissance only; the guard must not refuse it and cannot help against it"
    if incident.mechanism is Mechanism.UNDISCLOSED:
        return "the public account does not say what was written"
    if incident.vantage is Vantage.BELOW:
        return "the commands never crossed a conduit a bump-in-the-wire sits on"
    if incident.vantage is Vantage.BESIDE:
        return "the activity was not on a control conduit"
    return "no evidence in this project speaks to it"


def write_report(results: list[IncidentResult], out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "summary": summarise(results),
        "incidents": [
            {
                "key": r.incident.key,
                "name": r.incident.name,
                "year": r.incident.year,
                "sector": r.incident.sector,
                "mechanism": r.incident.mechanism.value,
                "vantage": r.incident.vantage.value,
                "in_scope": r.incident.in_scope,
                "summary": r.summary,
                "evidence": [e.as_dict() for e in r.evidence],
            }
            for r in results
        ],
    }
    path = out_dir / "incident_metrics.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True))
    return path
