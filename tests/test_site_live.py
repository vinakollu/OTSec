"""The storage site's live view: its metrics, its demo, and its page.

The two tests worth reading first are the same pair the works has.

``test_benign_dispatch_is_never_refused`` is the property the site lives on. A
guard that refuses the site controller's own dispatch has not made the yard
safer, it has stopped it earning.

``test_every_attack_needs_the_guard`` insists each attack does real damage
with the guard watching and none with it enforcing. Two attacks are excluded
from that and checked the other way round, because they are in the suite
precisely because they win: ``stealth_creep`` walks past the export limit in
steps too small for the rule that judges whether a command makes an existing
excursion worse, and ``cut_two_links`` takes the cross-check apart without
touching a meter. An attack list where the defence wins every row is a list
that was chosen to make the defence look good.
"""

from __future__ import annotations

import asyncio

import pytest

from otguard.bess.metrics import (
    HEADLINE, Area, Health, assess, catalogue, read_site,
)
from otguard.bess.site import BessSite
from otguard.bess.types import MeasurementSource
from otguard.config import load_config
from otguard.clock import SteppedClock
from otguard.live.bus import EventBus
from otguard.live.plain import RULE_MEANING, ruling
from otguard.live.site_demo import ATTACKS, SITE_NAMES, SiteDemo
from otguard.live.site_page import SITE_PAGE
from otguard.live.ui import BUILD_JS, CHART_JS, CORE_CSS, HEAD_JS, PARTS_CSS, TAIL_JS
from otguard.live.water_page import WATER_PAGE

CFG = load_config()

#: Tests pin the yard. The live demonstration randomises every unit's
#: charge and temperature and what the site is being dispatched to, so no
#: two runs look alike; a test cannot afford that.
SEED = 7


def settled_site() -> BessSite:
    b = CFG.bess
    site = BessSite(b.site, b.safety, b.pack, seed=SEED)
    for _ in range(200):
        site.step(b.site.dt_s)
    return site


# ======================================================================
# The catalogue
# ======================================================================
class TestMetrics:
    def test_fourteen_metrics_and_six_headlines(self):
        assert len(catalogue(CFG.bess.site, CFG.bess.safety, CFG.bess.pack)) == 14
        assert len(HEADLINE) == 6
        keys = {m.key for m in catalogue(CFG.bess.site, CFG.bess.safety, CFG.bess.pack)}
        assert set(HEADLINE) <= keys

    def test_a_settled_site_is_compliant(self):
        rows = assess(read_site(settled_site()), CFG.bess.site, CFG.bess.safety,
                      CFG.bess.pack)
        bad = [r["key"] for r in rows if r["health"] != "good"]
        assert bad == [], f"a settled site should be compliant, but {bad} are not"

    def test_the_contract_limit_and_the_iron_are_separate_rows(self):
        """The export limit is writable and the transformer rating is not.

        Collapsing them into one number would hide the gap that makes an
        export limit something an attacker can violate rather than a physical
        impossibility.
        """
        rows = {m.key: m for m in catalogue(CFG.bess.site, CFG.bess.safety,
                                            CFG.bess.pack)}
        assert rows["p_poi"].limit_high == CFG.bess.site.poi_limit_mw
        assert rows["apparent"].limit_high == CFG.bess.site.poi_rating_mw
        assert rows["p_poi"].limit_high < rows["apparent"].limit_high

    def test_every_metric_says_what_it_is_and_why_it_matters(self):
        for m in catalogue(CFG.bess.site, CFG.bess.safety, CFG.bess.pack):
            assert len(m.plain) > 25, m.key
            assert len(m.why) > 25, m.key
            assert m.area in Area

    def test_health_is_judged_against_the_limit_not_the_target(self):
        m = next(m for m in catalogue(CFG.bess.site, CFG.bess.safety, CFG.bess.pack)
                 if m.key == "p_poi")
        assert m.health(5.0) is Health.GOOD
        assert m.health(19.5) is Health.WATCH
        assert m.health(25.0) is Health.BREACH


# ======================================================================
# The demo
# ======================================================================
class TestDemo:
    def test_benign_dispatch_is_never_refused(self):
        async def run():
            demo = SiteDemo(EventBus(), enforce=True, seed=SEED, clock=SteppedClock())
            await demo.start()
            await demo.advance(400.0)
            await demo.stop()
            return demo
        demo = asyncio.run(run())
        assert demo.stats.inspected >= 20, "the dispatch controller barely wrote"
        assert demo.stats.blocked == 0, (
            f"{demo.stats.blocked} of {demo.stats.inspected} ordinary "
            f"dispatch commands refused")
        assert demo.site.damage_summary() == []

    @pytest.mark.parametrize("attack", [
        a.name for a in ATTACKS
        if not a.beats_the_guard and a.harm_is_physical])
    def test_every_attack_needs_the_guard(self, attack):
        async def run(enforce: bool):
            demo = SiteDemo(EventBus(), enforce=enforce, seed=SEED, clock=SteppedClock())
            spec = next(a for a in ATTACKS if a.name == attack)
            await demo.start()
            await demo.launch_attack(attack)
            worst_poi = 0.0
            end = demo.sim_t + spec.span_s + 120.0
            while demo.sim_t < end:
                await demo.advance(5.0)
                worst_poi = max(worst_poi, demo.site.state.p_poi_mw)
            damage = sorted(demo.site.damage_summary())
            blocked = demo.stats.blocked
            await demo.stop()
            return damage, blocked, worst_poi

        watching, _, loose_poi = asyncio.run(run(False))
        guarded, blocked, held_poi = asyncio.run(run(True))
        assert watching or loose_poi > CFG.bess.site.poi_limit_mw, (
            f"{attack} did no damage even unguarded, so it proves nothing")
        assert not guarded, f"{attack} got through the guard and caused {guarded}"
        assert blocked >= 1, f"{attack} was stopped without a single refusal"
        assert held_poi <= CFG.bess.site.poi_limit_mw + 0.5

    def test_the_attacks_that_harm_knowledge_rather_than_iron_are_marked(self):
        """Two attacks move no power at all.

        Biasing a meter and cutting its link both change what everybody is
        reading rather than what the site is doing, so scoring them on damage
        would mark a success as a failure. They are checked on whether the
        guard works out which instrument to disbelieve.
        """
        quiet = {a.name for a in ATTACKS if not a.harm_is_physical}
        assert quiet == {"meter_bias", "cut_two_links"}

    def test_the_two_that_beat_the_guard_say_so(self):
        """Both are declared on the page, not buried in a footnote."""
        losers = [a for a in ATTACKS if a.beats_the_guard]
        assert {a.name for a in losers} == {"stealth_creep", "cut_two_links"}

    def test_creeping_past_the_limit_is_not_stopped(self):
        """The documented failure, pinned so it cannot quietly start passing.

        B3 objects only when a command makes an existing excursion worse,
        which is what stops it blocking an operator's recovery and is also the
        way in. If this ever starts passing, the rule changed and the README
        is wrong.
        """
        async def run():
            demo = SiteDemo(EventBus(), enforce=True, seed=SEED, clock=SteppedClock())
            spec = next(a for a in ATTACKS if a.name == "stealth_creep")
            await demo.start()
            await demo.launch_attack("stealth_creep")
            worst = 0.0
            end = demo.sim_t + spec.span_s
            while demo.sim_t < end:
                await demo.advance(5.0)
                worst = max(worst, demo.site.state.p_poi_mw)
            await demo.stop()
            return worst
        assert asyncio.run(run()) > CFG.bess.site.poi_limit_mw

    def test_two_dead_links_outvote_the_live_one_unless_the_guard_is_told(self):
        """The site's headline result, reproduced live.

        A measurement whose link drops does not disappear: it freezes and goes
        on agreeing with itself. Told which sources are stale, the guard's
        belief stays right. Not told, it is wrong by most of the site's
        output and has formally accused the only honest instrument.
        """
        async def run(tell: bool):
            demo = SiteDemo(EventBus(), enforce=tell, seed=SEED, clock=SteppedClock())
            await demo.start()
            await demo.launch_attack("cut_two_links")
            worst = 0.0
            end = demo.sim_t + 500.0
            while demo.sim_t < end:
                await demo.advance(5.0)
                worst = max(worst, abs(demo.guard.site_power_mw
                                       - demo.site.state.p_poi_mw))
            await demo.stop()
            return worst
        told, not_told = asyncio.run(run(True)), asyncio.run(run(False))
        assert told < 1.0, f"informed guard was out by {told:.2f} MW"
        assert not_told > 10.0, (
            f"uninformed guard was only out by {not_told:.2f} MW; the "
            f"comparison this test exists for has stopped working")

    def test_the_vote_names_the_biased_meter_before_the_lie_gets_large(self):
        async def run():
            demo = SiteDemo(EventBus(), enforce=True, seed=SEED, clock=SteppedClock())
            await demo.start()
            await demo.launch_attack("meter_bias")
            end = demo.sim_t + 900.0
            lie = None
            while demo.sim_t < end:
                await demo.advance(5.0)
                if demo.guard.voter.alarm is not None and lie is None:
                    lie = abs(demo._bias.get(demo.guard.voter.alarm, 0.0))
                    named = demo.guard.voter.alarm
                    break
            await demo.stop()
            return named, lie
        named, lie = asyncio.run(run())
        assert named is MeasurementSource.POI_METER
        assert lie is not None and lie < 1.0, (
            f"the meter was named only after {lie} MW of lie had accumulated")

    def test_the_scenario_describes_everything_the_page_draws(self):
        demo = SiteDemo(EventBus(), seed=SEED, clock=SteppedClock())
        p = demo.describe().payload
        assert len(p["attacks"]) == len(ATTACKS) == 10
        assert len(p["metrics"]) == 14
        assert p["n_packs"] == CFG.bess.site.n_packs
        assert any(a["beats_the_guard"] for a in p["attacks"])

    def test_the_state_carries_a_row_per_unit_and_per_instrument(self):
        async def run():
            demo = SiteDemo(EventBus(), seed=SEED, clock=SteppedClock())
            seen = {}
            demo.bus.on(lambda e: seen.update(e.payload)
                        if e.kind.value == "state" else None)
            await demo.start()
            await demo.advance(20.0)
            await demo.stop()
            return seen
        state = asyncio.run(run())
        assert len(state["units"]) == CFG.bess.site.n_packs
        assert len(state["sources"]) == 3
        assert {s["key"] for s in state["sources"]} == {
            s.value for s in MeasurementSource}

    def test_controls_answer_and_a_bad_one_does_not_crash(self):
        async def run():
            demo = SiteDemo(EventBus(), seed=SEED, clock=SteppedClock())
            await demo.start()
            assert (await demo.command("enforce", {"value": "false"}))["ok"]
            assert demo.enforce is False
            assert (await demo.command("dispatch", {"mw": "14"}))["ok"]
            assert demo._target_mw == 14.0
            assert (await demo.command("dispatch", {"mw": "nonsense"}))["ok"] is False
            assert (await demo.command("attack", {"name": "nope"}))["ok"] is False
            assert (await demo.command("reset", {}))["ok"]
            await demo.stop()
        asyncio.run(run())


# ======================================================================
# The page
# ======================================================================
class TestPage:
    def test_both_plants_share_one_design_system(self):
        """Neither page carries its own copy of the tokens or the meter list.

        They did once, and the two drifted apart within a day.
        """
        for block in (CORE_CSS, PARTS_CSS, HEAD_JS, BUILD_JS, CHART_JS, TAIL_JS):
            assert block in SITE_PAGE
            assert block in WATER_PAGE

    def test_the_page_draws_what_the_demo_sends(self):
        for frag in ("buildYard", "paintUnit", "paintInstrument", "flyCommand",
                     "renderState", "renderScenario"):
            assert frag in SITE_PAGE, frag
        for key in ("p_poi", "apparent", "hottest", "measurement_spread"):
            assert key in SITE_PAGE, key

    def test_nothing_is_fetched_from_a_network(self):
        """A demonstration that needs a CDN fails in the room it matters in."""
        body = SITE_PAGE.replace("http://www.w3.org/2000/svg", "")
        assert "http://" not in body
        assert "https://" not in body

    def test_the_rules_are_explained_in_words(self):
        for rule in ("B1", "B2", "B3", "B4", "B5", "B6", "B7", "B8"):
            assert rule in RULE_MEANING
            assert RULE_MEANING[rule].endswith("?")

    def test_the_site_is_not_narrated_as_a_water_plant(self):
        assert SITE_NAMES["scada"] == "the site controller"
        line = ruling("The site controller asked to set unit MP04 to 3.4 MW.",
                      True, [], subject="the site")
        assert "the site" in line.detail
        assert "water" not in line.detail


# ======================================================================
# The harness itself
# ======================================================================
class TestDeterminism:
    def test_the_stepped_clock_gives_the_same_run_every_time(self):
        """The suite used to fail about one run in ten, on timing alone.

        Both demos are real asyncio systems whose process loop, control loop
        and attack script interleave however the machine happens to schedule
        them. Driven by the wall that interleaving changes under load, and an
        attack would occasionally be cut short or a control loop starved, so
        a run would fail for reasons that had nothing to do with the code.
        For a project whose subject is control timing, a harness whose own
        timing wanders proves very little.
        """
        async def once():
            demo = SiteDemo(EventBus(), seed=SEED, clock=SteppedClock())
            await demo.start()
            await demo.launch_attack("export_over_limit")
            await demo.advance(600.0)
            out = (demo.stats.inspected, demo.stats.blocked,
                   round(demo.site.state.p_poi_mw, 6),
                   round(demo._reading().fleet_soc, 9))
            await demo.stop()
            return out
        runs = [asyncio.run(once()) for _ in range(3)]
        assert runs[0] == runs[1] == runs[2], runs

    def test_an_unseeded_run_differs_from_the_next_one(self):
        """The other half: a demonstration must not be a recording."""
        starts = []
        for _ in range(6):
            demo = SiteDemo(EventBus(), clock=SteppedClock())
            starts.append((round(demo._target_mw, 3),
                           tuple(round(u.state.soc, 6) for u in demo.site.packs)))
        assert len(set(starts)) > 1, "every unseeded run started identically"

    def test_units_do_not_all_start_identical(self):
        demo = SiteDemo(EventBus(), seed=SEED, clock=SteppedClock())
        socs = {round(u.state.soc, 4) for u in demo.site.packs}
        temps = {round(u.state.temp_c, 3) for u in demo.site.packs}
        assert len(socs) > 8, "the yard starts with every unit at one charge"
        assert len(temps) > 8, "the yard starts with every unit at one temperature"

    def test_the_guard_reads_each_unit_before_it_judges_any_of_them(self):
        """Regression: every estimator was anchored to the fleet average.

        Once the yard stopped starting with all sixteen units at one charge, a
        unit ten per cent below the mean looked from the first scan like a
        unit whose reported charge had drifted ten per cent from its own
        history. B2 said so and the guard tripped protectively on a site
        nobody had touched, which is the worst failure this project has:
        not missing an attack, but stopping a plant that was fine.
        """
        async def once(seed: int):
            demo = SiteDemo(EventBus(), seed=seed, clock=SteppedClock())
            trips = []
            demo.bus.on(lambda e: trips.append(e.payload.get("rules"))
                        if e.kind.value == "trip" else None)
            await demo.start()
            await demo.advance(900.0)
            out = (demo.stats.trips, trips)
            await demo.stop()
            return out
        for seed in (3, 7, 11, 29, 47, 55, 101):
            count, rules = asyncio.run(once(seed))
            assert count == 0, f"seed {seed} tripped on a benign run: {rules}"

    def test_each_estimator_starts_from_its_own_unit(self):
        demo = SiteDemo(EventBus(), seed=SEED, clock=SteppedClock())
        for unit in demo.site.packs:
            est = demo.guard.estimators[unit.state.device]
            assert est.estimate.soc == pytest.approx(unit.state.soc)
            assert est.estimate.temp_c == pytest.approx(unit.state.temp_c)

    def test_a_dispatched_site_is_compliant_whatever_it_started_from(self):
        """Across seeds, because an opening state nobody chose is still an
        opening state the guard has to accept."""
        async def once(seed: int):
            demo = SiteDemo(EventBus(), seed=seed, clock=SteppedClock())
            await demo.start()
            await demo.advance(400.0)
            out = (demo.stats.blocked, demo.stats.inspected,
                   sorted(demo.site.damage_summary()))
            await demo.stop()
            return out
        for seed in (3, 11, 29, 47, 101):
            blocked, inspected, damage = asyncio.run(once(seed))
            assert inspected > 5, f"seed {seed} issued almost nothing"
            assert blocked == 0, (
                f"seed {seed}: {blocked} of {inspected} ordinary dispatch "
                f"commands refused")
            assert damage == [], f"seed {seed} damaged itself with nobody attacking"
