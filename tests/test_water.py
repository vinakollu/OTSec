"""The treatment works, its rules, and the live view that drives them.

Most of these pin a bug that was in the code and is not any more, because a
plant simulation is unusually good at hiding its own mistakes: a works that
quietly does nothing still produces plausible-looking numbers, and a guard
that objects to everything still blocks every attack. The two tests worth
reading first are the ones that would catch that.

``test_benign_traffic_is_never_refused`` is the one the project lives or dies
on. A guard that refuses the plant's own control loop has not made the works
safer, it has taken it off line, and every attack it then catches is beside
the point.

``test_every_attack_needs_the_guard`` is its mirror. For each of the nine
attacks it runs the works twice, and insists the harm appears with the guard
watching and does not appear with the guard enforcing. An attack that does no
damage unguarded proves nothing about the guard that blocked it.
"""

from __future__ import annotations

import asyncio
import math

import pytest

from otguard.guard.water_estimator import WaterEstimator
from otguard.guard.water_guard import Decision, WaterGuard
from otguard.guard.water_rules import ConsequenceRule, CrossInstrumentRule, WaterContext
from otguard.clock import SteppedClock
from otguard.live import EventBus
from otguard.live.bus import EventBus as Bus
from otguard.live.plain import Line, metric_line, verdict_line
from otguard.live.water_demo import ATTACKS, STAGE_CONTROLLER, WaterDemo
from otguard.live.water_page import WATER_PAGE
from otguard.water.metrics import HEADLINE, assess, catalogue
from otguard.water.plant import WaterSafety, WaterWorks, WorksConfig
from otguard.water.topology import Topology
from otguard.water.types import Stage, WaterCommand
from otguard.water.types import WaterCommandKind as K


#: Tests pin the river. The live demonstration picks one at random so no
#: two runs are alike; a test suite that did the same could not tell a
#: regression from a wet week upstream.
SEED = 3


def works() -> WaterWorks:
    return WaterWorks(WorksConfig(), WaterSafety(), seed=SEED)


def settled_guard(w: WaterWorks, enforce: bool = True) -> WaterGuard:
    """A guard that has been told the standing orders and has read the plant."""
    g = WaterGuard(WorksConfig(), WaterSafety(), Topology(), enforce=enforce)
    s = w.state
    for kind, value in ((K.INTAKE_PUMP, s.intake_pump_pct), (K.RAW_VALVE, s.raw_valve_pct),
                        (K.COAGULANT_DOSE, s.coagulant_dose_mg_l),
                        (K.FLOC_PADDLE, s.floc_paddle_pct),
                        (K.FILTER_VALVE, s.filter_valve_pct),
                        (K.CHLORINE_DOSE, s.chlorine_dose_mg_l),
                        (K.CAUSTIC_DOSE, s.caustic_dose_mg_l),
                        (K.HIGH_LIFT_PUMP, s.high_lift_pump_pct),
                        (K.CLEARWELL_OUTLET, s.clearwell_outlet_pct)):
        g.estimator.note_accepted(kind, value)
    g.observe(observation(w, 0.0))
    return g


def observation(w: WaterWorks, t: float):
    from otguard.water.types import WaterObservation
    m, s = w.measure(), w.state
    return WaterObservation(
        t=t, raw_flow_m3h=m["raw_flow_m3h"], raw_turbidity_ntu=m["raw_turbidity_ntu"],
        settled_turbidity_ntu=m["settled_turbidity_ntu"],
        filtered_turbidity_ntu=m["filtered_turbidity_ntu"],
        coagulant_dose_mg_l=s.coagulant_dose_mg_l, chlorine_dose_mg_l=s.chlorine_dose_mg_l,
        caustic_dose_mg_l=s.caustic_dose_mg_l,
        chlorine_residual_mg_l=m["chlorine_residual_mg_l"], ph=m["ph"],
        clearwell_level_m=m["clearwell_level_m"],
        clearwell_outflow_m3h=m["clearwell_outflow_m3h"],
        distribution_pressure_bar=m["distribution_pressure_bar"],
        contact_time_min=s.contact_time_min, ct_value=s.ct_value,
        filter_headloss_m=s.filter_headloss_m, analysers=())


def command(kind: K, value: float, *, source: str = "scada",
            zone: str = "supervisory", device: str = "SCADA-01") -> WaterCommand:
    return WaterCommand(0.0, kind, value, source, zone, device)


# ======================================================================
# The plant
# ======================================================================
class TestPlant:
    def test_settles_compliant(self):
        w = works()
        rows = assess(w.state, WaterSafety())
        assert w.state.harms == set()
        bad = [r["key"] for r in rows if r["health"] != "good"]
        assert bad == [], f"a settled works should be compliant, but {bad} are not"

    def test_fourteen_metrics_and_six_headlines(self):
        assert len(catalogue(WaterSafety())) == 14
        assert len(HEADLINE) == 6
        keys = {m.key for m in catalogue(WaterSafety())}
        assert set(HEADLINE) <= keys

    def test_every_stage_has_a_controller(self):
        for stage in Stage:
            assert STAGE_CONTROLLER.get(stage), f"{stage} has no named controller"

    def test_chlorine_takes_time_to_reach_the_analyser(self):
        """The transport delay is the thing that makes this hard to defend.

        If a dose change showed at the analyser immediately, under-dosing would
        be caught by the instrument that reads the residual and no rule about
        physics would be needed.
        """
        w = works()
        before = w.state.chlorine_residual_mg_l
        w.set_chlorine(4.0)
        for _ in range(60):
            w.step(1.0)
        assert abs(w.state.chlorine_residual_mg_l - before) < 0.05
        for _ in range(400):
            w.step(1.0)
        assert w.state.chlorine_residual_mg_l > before + 1.2

    def test_losing_the_coagulant_breaks_the_filters(self):
        """A sand filter is not a clarifier.

        The model used to let filter removal stay near its design figure
        however dirty the water arriving was, so cutting the coagulant produced
        0.26 NTU — untidy, legal, and survivable. A filter fed several times
        what it is sized for passes particles instead of catching them.
        """
        w = works()
        w.set_coagulant(0.4)
        w.set_floc_paddle(5.0)
        for _ in range(2400):
            w.step(1.0)
        assert w.state.settled_turbidity_ntu > 3.0
        assert w.state.filtered_turbidity_ntu > 1.0
        assert "turbidity_breach" in w.state.harms

    def test_pumps_cannot_send_water_that_is_not_there(self):
        """Regression: outflow was taken from pump speed alone.

        An empty clearwell went on reporting a steady flow to the town, which
        hid the consequence of draining it.
        """
        w = works()
        w.set_intake_pump(0.0)
        w.set_high_lift_pump(100.0)
        for _ in range(6000):
            w.step(1.0)
        assert w.state.clearwell_level_m == pytest.approx(0.0, abs=0.01)
        assert w.state.clearwell_outflow_m3h < 60.0

    def test_a_drained_clearwell_loses_the_mains(self):
        """Regression: pressure sagged gently towards a legal value.

        High-lift pumps draw from the clearwell. Below their suction the column
        breaks and they pass air, so the mains do not hold at two thirds of
        normal while the tank empties.
        """
        w = works()
        w.set_intake_pump(0.0)
        w.set_high_lift_pump(100.0)
        for _ in range(6000):
            w.step(1.0)
        assert w.state.distribution_pressure_bar < WaterSafety().pressure_min_bar
        assert "pressure_loss" in w.state.harms

    def test_harm_is_water_leaving_not_a_number(self):
        """A works with the outlet shut can be out of spec and harm nobody."""
        w = works()
        w.set_chlorine(0.0)
        w.set_clearwell_outlet(0.0)
        w.set_high_lift_pump(0.0)
        for _ in range(1500):
            w.step(1.0)
        assert w.state.chlorine_residual_mg_l < 0.2
        assert "under_disinfected" not in w.state.harms

    def test_the_dose_ceiling_is_writable_and_that_is_the_point(self):
        """Oldsmar's shape: the limit that stops the overdose can be moved."""
        w = works()
        w.set_chlorine(9.5)
        assert w.state.chlorine_dose_mg_l <= 5.0
        w.set_max_chlorine_dose(11.0)
        w.set_chlorine(9.5)
        assert w.state.chlorine_dose_mg_l == pytest.approx(9.5)


# ======================================================================
# The estimator
# ======================================================================
class TestEstimator:
    def test_healthy_plant_shows_no_instrument_disagreement(self):
        """Regression: the dose was compared with the residual as if the water
        went straight from the injector to the analyser. At a forty-minute
        contact time about four tenths of the free chlorine is gone by then, so
        a compliant works looked like a tampered one and every command it
        issued was refused.
        """
        w = works()
        g = settled_guard(w)
        for t in range(0, 120, 10):
            w.step(10.0)
            g.observe(observation(w, float(t)))
        gap, suspect = g.estimator.disagreement()
        assert suspect == "", f"a healthy works disagreed with itself by {gap:.2f} mg/L"
        assert gap < 0.1

    def test_a_guard_that_has_not_looked_accuses_nobody(self):
        """Regression: the belief starts at defaults, and the first command of
        a run was judged against them. Not having read the plant is not
        evidence that an instrument is lying.
        """
        e = WaterEstimator(WorksConfig(), WaterSafety())
        e.note_accepted(K.CHLORINE_DOSE, 1.5)
        assert not e.ready
        assert e.disagreement() == (0.0, "")

    def test_the_forward_model_agrees_with_the_plant(self):
        """The guard predicts over its own copy of the process. When the two
        drift apart the guard is reasoning about a different works, which is
        how cutting the coagulant came to read as harmless.
        """
        w = works()
        g = settled_guard(w)
        for t in range(0, 60, 10):
            w.step(10.0)
            g.observe(observation(w, float(t)))
        predicted = g.estimator.predict(2400.0, {K.COAGULANT_DOSE: 0.4})
        w.set_coagulant(0.4)
        for _ in range(2400):
            w.step(1.0)
        assert predicted.filtered_turbidity_ntu > 1.0
        assert predicted.filtered_turbidity_ntu == pytest.approx(
            w.state.filtered_turbidity_ntu, rel=0.45)

    def test_contact_time_is_computed_never_read(self):
        e = WaterEstimator(WorksConfig(), WaterSafety())
        slow = e.contact_time(3.5, 1100.0)
        fast = e.contact_time(3.5, 1900.0)
        assert slow > fast
        assert fast == pytest.approx(3.5 * 420.0 * 0.6 / 1900.0 * 60.0)


# ======================================================================
# The rules
# ======================================================================
class TestRules:
    def test_benign_traffic_is_never_refused(self):
        """The property the whole thing rests on.

        Nine hundred simulated seconds of the plant running itself: dosing
        paced to flow, pumps trimmed to hold the clearwell. Not one of those
        commands may be refused.
        """
        async def run():
            demo = WaterDemo(Bus(), enforce=True, seed=SEED, clock=SteppedClock())
            await demo.start()
            await demo.advance(900.0)
            await demo.stop()
            return demo
        demo = asyncio.run(run())
        assert demo.stats.inspected >= 20, "the control loop barely wrote anything"
        assert demo.stats.blocked == 0, (
            f"{demo.stats.blocked} of {demo.stats.inspected} ordinary commands refused")
        assert demo.plant.state.harms == set()

    def test_the_oldsmar_dose_is_refused(self):
        w = works()
        g = settled_guard(w)
        v = g.check(command(K.CHLORINE_DOSE, 9.5, source="hmi", device="HMI-01"))
        assert v.decision is Decision.BLOCK
        assert v.rule_ids

    def test_raising_the_ceiling_is_refused_on_its_own(self):
        """The ceiling moves no water, so a consequence rule cannot see it. W2
        judges it against what the chemical does to a person instead."""
        w = works()
        g = settled_guard(w)
        v = g.check(command(K.MAX_CHLORINE_DOSE, 11.0, source="hmi", device="HMI-01"))
        assert v.decision is Decision.BLOCK
        assert "W2" in v.rule_ids

    def test_a_write_from_the_enterprise_network_is_refused(self):
        w = works()
        g = settled_guard(w)
        v = g.check(command(K.CHLORINE_DOSE, 1.6, source="vendor",
                            zone="enterprise", device="JUMP-01"))
        assert v.decision is Decision.BLOCK
        assert "W8" in v.rule_ids

    def test_taking_more_out_than_goes_in_is_refused(self):
        """Regression: W3 predicted ten minutes ahead, and a clearwell this
        size takes over an hour to empty, so opening the high-lift pumps right
        up read as harmless. The balance is a rate, not a level at a horizon.
        """
        w = works()
        g = settled_guard(w)
        v = g.check(command(K.HIGH_LIFT_PUMP, 100.0))
        assert v.decision is Decision.BLOCK
        assert "W3" in v.rule_ids
        assert "empties the treated water tank" in v.findings[0].detail

    def test_stopping_the_intake_is_refused(self):
        w = works()
        g = settled_guard(w)
        v = g.check(command(K.INTAKE_PUMP, 0.0, source="hmi", device="HMI-01"))
        assert v.decision is Decision.BLOCK

    def test_instrument_disagreement_does_not_refuse_unrelated_commands(self):
        """Regression: W4 fired on whatever command happened to be passing.

        Every rule here blocks, so a rule that speaks only about the chlorine
        must not judge a filter valve or an alarm setting. It took the plant
        down on the strength of an instrument that had nothing to do with the
        command in front of it.
        """
        assert K.TURBIDITY_ALARM not in CrossInstrumentRule.bears_on
        assert K.COAGULANT_DOSE not in CrossInstrumentRule.bears_on
        assert K.CHLORINE_DOSE in CrossInstrumentRule.bears_on

        w = works()
        g = settled_guard(w)
        ctx = WaterContext(estimator=g.estimator, works=g.works, safety=g.safety,
                           topology=g.topology, now=0.0, history=(), locked_out=False)
        rule = CrossInstrumentRule()
        assert rule.check(command(K.TURBIDITY_ALARM, 0.5), ctx) is None

    def test_a_refused_command_never_reaches_the_belief(self):
        w = works()
        g = settled_guard(w)
        before = g.estimator.state.commanded.get(K.CHLORINE_DOSE.value)
        g.check(command(K.CHLORINE_DOSE, 9.5))
        assert g.estimator.state.commanded.get(K.CHLORINE_DOSE.value) == before

    def test_the_consequence_horizons_differ(self):
        """A dose reaches the analyser in minutes and a clearwell empties in
        hours. One horizon cannot serve both."""
        rule = ConsequenceRule()
        assert rule.balance_horizon_s > rule.horizon_s * 4


# ======================================================================
# The live view
# ======================================================================
class TestLiveView:
    @pytest.mark.parametrize("attack", [a.name for a in ATTACKS])
    def test_every_attack_needs_the_guard(self, attack):
        async def run(enforce: bool):
            demo = WaterDemo(Bus(), enforce=enforce, seed=SEED, clock=SteppedClock())
            spec = next(a for a in ATTACKS if a.name == attack)
            await demo.start()
            await demo.launch_attack(attack)
            seen: set[str] = set()
            end = demo.sim_t + spec.span_s + 200.0
            while demo.sim_t < end:
                await demo.advance(10.0)
                seen |= demo.plant.state.harms
            blocked = demo.stats.blocked
            await demo.stop()
            return seen, blocked

        watching, _ = asyncio.run(run(False))
        enforcing, blocked = asyncio.run(run(True))
        assert watching, f"{attack} did no damage even unguarded, so it proves nothing"
        assert not enforcing, f"{attack} got through the guard and caused {watching}"
        assert blocked >= 1, f"{attack} was stopped without the guard refusing anything"

    def test_the_plant_tracks_the_clock(self):
        """Regression: the loop stepped the plant one second per iteration
        while the clock ran at ``speed``. The physics fell behind the time on
        the screen, so every rate shown beside it was understated.
        """
        async def run():
            demo = WaterDemo(Bus(), enforce=False, seed=SEED, clock=SteppedClock())
            await demo.start()
            await demo.launch_attack("drain_the_clearwell")
            await demo.advance(3000.0)
            level = demo.plant.state.clearwell_level_m
            await demo.stop()
            return level
        # Nothing in, 1900 m3/h out, 420 m2 of clearwell: the tank is empty
        # well inside three thousand seconds. A plant stepping slower than its
        # own clock loses most of that.
        assert asyncio.run(run()) < 0.6

    def test_the_scenario_describes_everything_the_page_draws(self):
        demo = WaterDemo(Bus(), seed=SEED, clock=SteppedClock())
        p = demo.describe().payload
        assert len(p["attacks"]) == len(ATTACKS)
        assert len(p["metrics"]) == 14
        assert len(p["stages"]) == len(Stage)
        assert len(p["topology"]["devices"]) == 22
        assert len(p["topology"]["zones"]) == 6
        assert sum(1 for c in p["topology"]["conduits"] if c["guarded"]) == 1

    def test_the_page_knows_the_vocabulary_it_is_sent(self):
        for sev in ("good", "watch", "breach", "info"):
            assert '"' + sev + '"' in WATER_PAGE or sev in WATER_PAGE
        for key in ("chlorine_residual", "filtered_turbidity", "clearwell_level",
                    "pressure"):
            assert key in WATER_PAGE
        # Nothing on the page may carry a CDN dependency: it is served from
        # loopback and has to draw in a room with no network.
        assert "http://" not in WATER_PAGE.replace("http://www.w3.org/2000/svg", "")
        assert "https://" not in WATER_PAGE

    def test_narration_and_metrics_share_one_vocabulary(self):
        """Regression: the narrator said 'bad' where the metrics said 'breach',
        so a broken limit arrived on the page wearing the neutral icon."""
        row = {"key": "chlorine_residual", "label": "Chlorine leaving the works",
               "shown": "0.05", "unit": "mg/L", "health": "breach",
               "why": "x", "plain": "y"}
        line = metric_line(row)
        assert line is not None
        assert line.severity == "breach"
        assert Line("x").severity == "info"

    def test_a_refusal_is_explained_in_words_a_reader_knows(self):
        w = works()
        g = settled_guard(w)
        v = g.check(command(K.CHLORINE_DOSE, 9.5, source="hmi", device="HMI-01"))
        line = verdict_line(v.command, True, v.findings)
        assert "refused" in line.detail
        assert "mg/L" in line.detail
        assert line.severity == "breach"
        # No rule identifier leaks into the headline a visitor reads.
        assert "W1" not in line.headline and "W2" not in line.headline

    def test_the_guard_can_be_switched_off_and_back_on(self):
        async def run():
            demo = WaterDemo(Bus(), enforce=True, seed=SEED, clock=SteppedClock())
            await demo.start()
            assert (await demo.command("enforce", {"value": "false"}))["ok"]
            assert demo.guard.enforce is False
            assert (await demo.command("enforce", {"value": "true"}))["ok"]
            assert demo.guard.enforce is True
            assert (await demo.command("nonsense", {}))["ok"] is False
            await demo.stop()
        asyncio.run(run())

    def test_reset_puts_the_works_back(self):
        async def run():
            demo = WaterDemo(Bus(), enforce=False, seed=SEED, clock=SteppedClock())
            await demo.start()
            await demo.launch_attack("silent_underdose")
            await demo.advance(1400.0)
            assert demo.plant.state.harms
            await demo.command("reset", {})
            await demo.advance(30.0)
            harms = demo.plant.state.harms
            blocked = demo.stats.blocked
            await demo.stop()
            return harms, blocked
        harms, blocked = asyncio.run(run())
        assert harms == set()
        assert blocked == 0, "the counters should start again with the works"


def test_event_bus_import_is_the_same_object():
    assert EventBus is Bus


def test_no_nan_anywhere_in_a_long_run():
    w = works()
    w.set_coagulant(0.0)
    w.set_chlorine(0.0)
    w.set_high_lift_pump(0.0)
    for _ in range(4000):
        w.step(1.0)
    for name, value in vars(w.state).items():
        if isinstance(value, float):
            assert math.isfinite(value), f"{name} is {value}"


def test_a_running_works_is_compliant_whatever_river_it_got():
    """Across seeds, because the live run picks its river at random.

    A guard tuned to one set of opening numbers is a guard that works on the
    day it was written. The works meets a different river every run now, and
    none of them may produce a refusal.
    """
    async def once(seed: int):
        demo = WaterDemo(Bus(), seed=seed, clock=SteppedClock())
        await demo.start()
        await demo.advance(900.0)
        out = (demo.stats.blocked, demo.stats.inspected,
               sorted(demo.plant.state.harms))
        await demo.stop()
        return out
    for seed in (3, 11, 29, 47, 101):
        blocked, inspected, harms = asyncio.run(once(seed))
        assert inspected > 5, f"seed {seed} issued almost nothing"
        assert blocked == 0, (
            f"seed {seed}: {blocked} of {inspected} ordinary commands refused")
        assert harms == [], f"seed {seed} harmed the water with nobody attacking"


def test_no_two_unseeded_runs_meet_the_same_river():
    rivers = set()
    for _ in range(6):
        demo = WaterDemo(Bus(), clock=SteppedClock())
        s = demo.plant.state
        rivers.add((round(s.raw_turbidity_ntu, 4), round(s.raw_flow_m3h, 2),
                    round(s.clearwell_level_m, 4)))
    assert len(rivers) > 1, "every unseeded run started from the same river"
