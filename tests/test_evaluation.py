"""End-to-end properties of the scenario suite and the scoring.

These are the tests that would catch the evaluation quietly becoming
self-congratulatory: a benign scenario drifting into genuinely unsafe territory
(so a correct trip scores as a false alarm), or an attack losing its teeth (so
"prevented" stops meaning anything).
"""

from __future__ import annotations

import pytest

from otguard.eval import run_scenario, score
from otguard.scenarios import all_attacks, all_normal, all_scenarios, by_name


@pytest.mark.parametrize("scenario", all_normal(), ids=lambda s: s.name)
def test_benign_scenarios_raise_no_alarm(scenario, config):
    """The false-alarm bar: ordinary operations must pass unremarked."""
    run = run_scenario(scenario, config, enforce=True)
    flagged = [v for v, _ in run.verdicts if v.flagged]
    assert not flagged, f"{scenario.name}: {[str(v) for v in flagged[:3]]}"
    assert not run.supervision_events, (
        f"{scenario.name} tripped: {run.supervision_events[0].findings[0]}"
    )


@pytest.mark.parametrize("scenario", all_normal(), ids=lambda s: s.name)
def test_benign_scenarios_stay_inside_the_envelope(scenario, config):
    """A 'benign' scenario that actually breaks the plant is a broken scenario.

    Without this, a badly parameterised normal case (say, a pump/valve pair with
    no equilibrium below the tank top) fills forever, the guard correctly trips,
    and the correct trip is scored as a false alarm.
    """
    run = run_scenario(scenario, config, enforce=False)
    assert not run.damaged, (
        f"{scenario.name} leaves the safe envelope with no guard present "
        f"(min {run.min_level_m:.3f}, max {run.max_level_m:.3f}) — "
        "fix the scenario, not the guard"
    )


@pytest.mark.parametrize("scenario", all_attacks(), ids=lambda s: s.name)
def test_attacks_are_detected(scenario, config):
    """Every attack is caught, except the one documented as evading the design."""
    run = run_scenario(scenario, config, enforce=True)
    if scenario.name == "stealthy_bias":
        pytest.xfail(
            "documented limitation: a bias ramp under the residual detector's "
            "floor is invisible to R4 by construction (see --stealth-sweep)"
        )
    assert run.detected, f"{scenario.name} went undetected"


def test_attacks_that_do_damage_are_stopped(config):
    """Scored only against attacks with a demonstrated physical consequence."""
    scenarios = all_attacks()
    guarded = [run_scenario(s, config, enforce=True) for s in scenarios]
    unguarded = [run_scenario(s, config, enforce=False) for s in scenarios]
    report = score(guarded, unguarded)

    assert report.scenarios.attacks_damaging_unguarded >= 4, (
        "the suite has lost its teeth: too few attacks cause damage unguarded"
    )
    # stealthy_bias is expected to get through; everything else must not.
    assert report.scenarios.damage_avoided >= report.scenarios.attacks_damaging_unguarded - 1


def test_overflow_attack_is_prevented(config):
    """The headline case, with its counterfactual."""
    scenario = by_name("overflow")
    guarded = run_scenario(scenario, config, enforce=True)
    unguarded = run_scenario(scenario, config, enforce=False)

    assert unguarded.overflowed, "the attack should overflow the tank unguarded"
    assert not guarded.overflowed
    assert guarded.max_level_m < config.safety.level_max_m
    assert any(e.action is not None for e in guarded.supervision_events)


def test_replay_attack_is_caught_despite_a_lying_sensor(config):
    """The sensor says 0.95 m throughout; the guard must not believe it."""
    scenario = by_name("replay_overflow")
    guarded = run_scenario(scenario, config, enforce=True)
    unguarded = run_scenario(scenario, config, enforce=False)

    assert unguarded.overflowed
    assert not guarded.overflowed
    rules = {f.rule_id for v, _ in guarded.verdicts for f in v.findings}
    assert "R4" in rules, "the sensor-integrity rule should have fired"


def test_guard_disabled_run_never_intervenes(config):
    """The counterfactual has to actually be a counterfactual."""
    scenario = by_name("overflow")
    unguarded = run_scenario(scenario, config, enforce=False)
    # It still records what it *would* have done, but the plant must show the
    # attack running to completion.
    assert unguarded.overflowed
    assert unguarded.max_level_m >= config.safety.level_max_m


def test_latency_stays_within_a_control_scan(config):
    """The guard must not break the real-time property it is protecting."""
    scenarios = all_scenarios()
    runs = [run_scenario(s, config, enforce=True) for s in scenarios]
    report = score(runs, None)

    scan_period_us = config.plant.dt_s * 1e6
    assert report.latency.count > 100
    assert report.latency.p99_us < 0.05 * scan_period_us, (
        f"p99 {report.latency.p99_us:.0f} us is more than 5% of the "
        f"{scan_period_us:.0f} us scan period"
    )


def test_scoring_separates_benign_traffic_from_attack_episodes(config):
    """The headline FP number must be measured on benign episodes only."""
    scenarios = all_scenarios()
    guarded = [run_scenario(s, config, enforce=True) for s in scenarios]
    report = score(guarded, None)

    assert report.benign_traffic.benign_total > 0
    assert report.benign_traffic.benign_total <= report.commands.benign_total
    assert report.benign_traffic.benign_blocked == 0


def test_scenario_lookup():
    assert by_name("overflow").name == "overflow"
    with pytest.raises(KeyError):
        by_name("no_such_scenario")


def test_every_scenario_has_a_distinct_name():
    names = [s.name for s in all_scenarios()]
    assert len(names) == len(set(names))
