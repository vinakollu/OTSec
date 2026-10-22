"""The incident catalogue, and the two scenarios it needed that did not exist.

Most of these are drift tests. The catalogue's value is that each row points at
a measured result somewhere else in the project, and the failure mode is that
someone renames a scenario and the row quietly starts pointing at nothing. A
coverage table full of silently broken references is worse than no table.

The rest pin the two scenarios, both of which were wrong on the first attempt
in ways that made them look like they worked.
"""

from __future__ import annotations

import pytest

from otguard.eval.harness import run_scenario
from otguard.eval.incidents import site_scenario
from otguard.scenarios import by_name
from otguard.scenarios.incidents import (
    INCIDENTS,
    Mechanism,
    Vantage,
    setpoint_overdose,
    stuxnet_overspeed_replay,
)

VALID_KINDS = {"tank", "site", "matrix", "opcua", "none"}


# ----------------------------------------------------------------------
# The catalogue holds together
# ----------------------------------------------------------------------
def test_every_incident_says_what_it_does_and_does_not_model():
    for incident in INCIDENTS:
        assert incident.account.strip(), incident.key
        assert incident.modelled.strip(), incident.key
        assert incident.unmodelled.strip(), incident.key
        assert incident.evidence, incident.key


def test_incident_keys_are_unique():
    keys = [i.key for i in INCIDENTS]
    assert len(keys) == len(set(keys))


def test_evidence_kinds_are_known():
    for incident in INCIDENTS:
        for evidence in incident.evidence:
            assert evidence.kind in VALID_KINDS, (incident.key, evidence.kind)


def test_an_incident_modelling_nothing_says_why():
    """A row pointing at nothing must carry its reason, or it reads as a miss."""
    for incident in INCIDENTS:
        for evidence in incident.evidence:
            if evidence.kind == "none":
                assert evidence.note.strip(), incident.key


@pytest.mark.parametrize(
    "name",
    sorted({e.name for i in INCIDENTS for e in i.evidence if e.kind == "tank"}),
)
def test_tank_evidence_resolves(name):
    assert by_name(name).name == name


@pytest.mark.parametrize(
    "name",
    sorted({e.name for i in INCIDENTS for e in i.evidence if e.kind == "site"}),
)
def test_site_evidence_resolves(name):
    assert site_scenario(name).name == name


@pytest.mark.parametrize(
    "reference",
    sorted({e.name for i in INCIDENTS for e in i.evidence if e.kind == "matrix"}),
)
def test_matrix_evidence_resolves(reference):
    from otguard.eval.matrix import all_scenarios

    scenario_name, source, executor = reference.split("/")
    match = next((s for s in all_scenarios() if s.name == scenario_name), None)
    assert match is not None, reference
    assert source in match.sources, reference
    assert executor in match.executors, reference


@pytest.mark.parametrize(
    "name",
    sorted({e.name for i in INCIDENTS for e in i.evidence if e.kind == "opcua"}),
)
def test_opcua_evidence_resolves(name):
    from otguard.eval.opcua_experiment import SCENARIOS

    assert name in SCENARIOS


# ----------------------------------------------------------------------
# What is in scope, and why the rest is not
# ----------------------------------------------------------------------
def test_espionage_and_reconnaissance_are_out_of_scope():
    """The guard judges commands. Two of the four cited campaigns issued none."""
    by_key = {i.key: i for i in INCIDENTS}
    assert by_key["night_dragon"].mechanism is Mechanism.ENTERPRISE
    assert not by_key["night_dragon"].in_scope
    assert by_key["havex"].mechanism is Mechanism.RECONNAISSANCE
    assert not by_key["havex"].in_scope


def test_stuxnet_is_out_of_scope_because_of_where_it_ran():
    """Not because the rules miss the pattern — they catch it. Because of vantage.

    This is the distinction the catalogue exists to make. The scenario derived
    from Stuxnet is detected and its damage is prevented, and the incident is
    still outside what a bump-in-the-wire could have done anything about,
    because the commands never crossed one.
    """
    stuxnet = next(i for i in INCIDENTS if i.key == "stuxnet")
    assert stuxnet.mechanism is Mechanism.COMMAND
    assert stuxnet.vantage is Vantage.BELOW
    assert not stuxnet.in_scope


def test_an_incident_with_no_public_detail_is_not_modelled():
    mill = next(i for i in INCIDENTS if i.key == "german_steel_mill")
    assert mill.mechanism is Mechanism.UNDISCLOSED
    assert all(e.kind == "none" for e in mill.evidence)


# ----------------------------------------------------------------------
# The replayed view
# ----------------------------------------------------------------------
def test_replay_is_continuous_where_it_starts(config):
    """The seam has to be smooth, or the scenario measures a step change.

    The first version replayed the recording from its oldest sample, so at the
    moment the attack began the reported level jumped back to where it had been
    half a minute earlier. The consistency rule caught that on the first sample
    and the episode scored as a detection — of a discontinuity, not of a
    replay.
    """
    scenario = stuxnet_overspeed_replay()
    start = 40.0
    readings: list[tuple[float, float]] = []
    attack = scenario.sensor_attack
    assert attack is not None

    # Feed it a rising honest trace, the way the plant would.
    level = 0.95
    t = 0.0
    while t < start + 2.0:
        level += 0.001
        readings.append((t, attack(t, level, level)))
        t = round(t + 0.1, 3)

    before = [v for t, v in readings if t < start][-1]
    after = [v for t, v in readings if t >= start][0]
    assert abs(after - before) < 0.01, (before, after)


def test_the_replayed_view_hides_a_rising_tank(config):
    """What the operator is shown must not follow the tank up."""
    scenario = stuxnet_overspeed_replay()
    result = run_scenario(scenario, config, enforce=False)
    during = [s for s in result.samples if s.t >= 60.0]
    assert max(s.true_level_m for s in during) > 1.5
    assert max(s.reported_level_m for s in during) < 1.3


def test_the_burst_attack_is_detected_and_prevented(config):
    guarded = run_scenario(stuxnet_overspeed_replay(), config, enforce=True)
    unguarded = run_scenario(stuxnet_overspeed_replay(), config, enforce=False)
    assert unguarded.damaged, "the scenario has to be able to do damage"
    assert guarded.detected
    assert not guarded.damaged
    assert "R4" in {f.rule_id for v, _ in guarded.verdicts for f in v.findings}


def test_detection_comes_after_the_attack_starts_not_on_the_first_sample(config):
    """A detection at the attack's first sample is the seam bug coming back."""
    result = run_scenario(stuxnet_overspeed_replay(), config, enforce=True)
    assert result.first_detection_t is not None
    assert result.first_detection_t > 40.5, result.first_detection_t


# ----------------------------------------------------------------------
# The tampered set-point
# ----------------------------------------------------------------------
def test_the_tampered_setpoint_is_actually_obeyed(config):
    """Without the guard, the plant's own loop has to do the damage.

    A set-point write that nothing acts on is a number in a register. If this
    assertion fails the scenario is measuring a write nobody obeyed, and the
    detection it reports is worthless.
    """
    unguarded = run_scenario(setpoint_overdose(), config, enforce=False)
    assert unguarded.damaged
    assert unguarded.max_level_m > 1.80


def test_the_tampered_setpoint_is_refused_on_its_range(config):
    guarded = run_scenario(setpoint_overdose(), config, enforce=True)
    assert guarded.detected
    assert not guarded.damaged
    rules = {f.rule_id for v, _ in guarded.verdicts for f in v.findings}
    assert "R1" in rules, rules


def test_the_incident_scenarios_stay_out_of_the_headline_suite():
    """Folding them in would move every published number in the project."""
    from otguard.scenarios import all_scenarios

    names = {s.name for s in all_scenarios()}
    assert "setpoint_overdose" not in names
    assert "stuxnet_overspeed_replay" not in names
    # and they still have to be findable by name
    assert by_name("setpoint_overdose").name == "setpoint_overdose"
