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

from otguard.eval.incidents import site_scenario
from otguard.scenarios import site_by_name as by_name
from otguard.scenarios.incidents import (
    INCIDENTS, Evidence, Incident, Mechanism, Vantage,
)

VALID_KINDS = {"water", "site", "opcua", "none"}


# ----------------------------------------------------------------------
# The catalogue holds together
# ----------------------------------------------------------------------


def test_every_incident_says_what_it_does_and_does_not_model():
    for incident in INCIDENTS:
        assert incident.account.strip(), incident.key
        assert incident.modelled.strip(), incident.key
        assert incident.unmodelled.strip(), incident.key
        # An incident with no evidence is a legitimate row: Stuxnet ran on the
        # controllers and Triton on a safety system, and neither is somewhere
        # a bump-in-the-wire sits. Those rows have to be out of scope rather
        # than quietly pointed at a scenario of a different shape.
        if not incident.evidence:
            assert not incident.in_scope, (
                f"{incident.key} claims to be in scope with nothing behind it")

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
    sorted({e.name for i in INCIDENTS for e in i.evidence if e.kind == "site"}),

)
def test_site_evidence_resolves(name):
    assert site_scenario(name).name == name


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
