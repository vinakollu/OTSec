"""The two live pages, checked as the text they actually are.

Every other test in this suite runs Python. These run over the HTML, CSS and
JavaScript the server sends, because that is where a whole class of damage
hides: a page is a string until a browser parses it, and a string with a
comma missing from one ``rgba()`` still imports, still serves and still
passes every test that only calls Python.

That is not hypothetical. A sweep over the prose in this repository removed
a comma from eight colour values, one easing curve and two selectors, which
between them made the status pills render their own text in their own
background colour, stopped the phone layout collapsing to a single column,
and left the schematic's guard label stuck in its enforcing colour. Nothing
failed. The pages just quietly stopped working, and it took looking at them
to notice.

So these are deliberately dumb lexical checks. They do not know what a good
page looks like. They know what a broken one looks like.
"""

from __future__ import annotations

import re

import pytest

from otguard.live.site_page import SITE_PAGE
from otguard.live.ui import BUILD_JS, CHART_JS, CORE_CSS, HEAD_JS, PARTS_CSS, TAIL_JS
from otguard.live.water_page import WATER_PAGE

PAGES = {"water": WATER_PAGE, "site": SITE_PAGE}
SHARED = {"CORE_CSS": CORE_CSS, "PARTS_CSS": PARTS_CSS, "HEAD_JS": HEAD_JS,
          "BUILD_JS": BUILD_JS, "CHART_JS": CHART_JS, "TAIL_JS": TAIL_JS}


# ======================================================================
# CSS that a browser would reject
# ======================================================================
class TestColoursAndCurves:
    """Values a browser drops silently rather than complaining about."""

    @pytest.mark.parametrize("name", sorted(PAGES))
    def test_every_rgba_has_four_components(self, name):
        """``rgba(31,184,128.13)`` is not a parse error.

        It is a *valid* opaque colour, because three-argument ``rgba()`` is
        legacy ``rgb()``. So a tint meant to sit at 13% opacity behind dark
        text becomes the solid version of that same colour, the text on it
        becomes invisible, and the browser reports nothing at all.
        """
        bad = [m for m in re.findall(r"rgba\([^)]*\)", PAGES[name])
               if len(m[len("rgba("):-1].split(",")) != 4]
        assert bad == [], f"{name}: rgba() without an alpha: {bad}"

    @pytest.mark.parametrize("name", sorted(PAGES))
    def test_every_cubic_bezier_has_four_points(self, name):
        bad = [m for m in re.findall(r"cubic-bezier\([^)]*\)", PAGES[name])
               if len(m[len("cubic-bezier("):-1].split(",")) != 4]
        assert bad == [], f"{name}: malformed easing: {bad}"

    @pytest.mark.parametrize("name", sorted(PAGES))
    def test_braces_balance(self, name):
        """A dropped brace silently swallows every rule after it."""
        for block in re.findall(r"<style>(.*?)</style>", PAGES[name], re.S):
            assert block.count("{") == block.count("}")


# ======================================================================
# Selectors the sweep merged
# ======================================================================
class TestSelectors:
    """``a, b`` and ``a.b`` differ by one comma and mean opposite things."""

    def test_the_phone_layout_collapses_to_one_column(self):
        """``.g-main,.g-split`` became ``.g-main.g-split``, which no element
        carries, so both grids stayed two columns wide on a phone."""
        assert ".g-main,.g-split{grid-template-columns:1fr}" in PARTS_CSS

    def test_the_schematic_guard_label_follows_the_guard(self):
        """Two selectors, one for the label beside an off guard and one for
        the label itself. Merged, neither matches."""
        assert (".sv-guard.off + .sv-guard-t, .sv-guard-t.off"
                in PAGES["water"])

    @pytest.mark.parametrize("name", sorted(PAGES))
    def test_no_selector_runs_two_class_chains_together(self, name):
        """A descendant-free chain of four or more classes is almost always
        a comma that went missing, not a selector somebody meant."""
        for block in re.findall(r"<style>(.*?)</style>", PAGES[name], re.S):
            for sel in re.findall(r"(?m)^\s*([^{}@/\n][^{}\n]*)\{", block):
                for part in sel.split(","):
                    chain = part.strip().split()[-1] if part.strip() else ""
                    assert chain.count(".") < 4, f"{name}: suspect selector {sel!r}"


# ======================================================================
# Text the reader sees
# ======================================================================
class TestVisibleText:
    """The simulation's own prose, and the placeholders it starts from."""

    @pytest.mark.parametrize("name", sorted(PAGES))
    def test_no_em_dashes(self, name):
        assert "—" not in PAGES[name]

    @pytest.mark.parametrize("name", sorted(SHARED))
    def test_no_em_dashes_in_the_shared_parts(self, name):
        assert "—" not in SHARED[name]

    @pytest.mark.parametrize("name", sorted(PAGES))
    def test_no_stray_comma_space_placeholders(self, name):
        """The em-dash sweep turned four ``"—"`` placeholders into
        ``", "``, so a chip that had not been painted yet rendered a comma
        and a metric with no reading showed nothing at all."""
        assert 'el("span", null, ", ")' not in PAGES[name]
        assert 'el("b", null, ", ")' not in PAGES[name]

    @pytest.mark.parametrize("name", sorted(PAGES))
    def test_the_status_chip_carries_a_word(self, name):
        """Colour alone is not a status. Every chip ships a glyph and a
        label, and starts life saying which it is waiting for."""
        assert 'el("span", "glyph"' in PAGES[name]
        assert 'chip.appendChild(el("span", null, "waiting"))' in PAGES[name]

    @pytest.mark.parametrize("name", sorted(PAGES))
    def test_the_meter_explanations_are_not_cut_off(self, name):
        """The sentence under each meter name is the page's whole claim on a
        reader who does not know what an NTU is. It wraps, it does not get
        an ellipsis."""
        rule = re.search(r"\.meter \.nm i\{([^}]*)\}", PAGES[name])
        assert rule, f"{name}: no rule for the meter explanation"
        assert "nowrap" not in rule.group(1)
        assert "ellipsis" not in rule.group(1)


# ======================================================================
# What the page is handed
# ======================================================================
class TestTopologyPayload:
    """Both plants publish a topology, and both pages draw it."""

    @pytest.mark.parametrize("name", sorted(PAGES))
    def test_the_page_draws_the_network(self, name):
        assert 'id="zones"' in PAGES[name]
        assert 'id="conduits"' in PAGES[name]
        assert "buildNetwork(p.topology)" in PAGES[name]

    def test_the_site_topology_has_a_summary(self):
        """It did not, and the demo published ``{}`` behind a ``hasattr``
        guard, so the storage site's twenty-seven devices never reached a
        screen."""
        from otguard.site.topology import default_site_topology

        topo = default_site_topology(16).summary()
        assert len(topo["devices"]) == 27
        assert {z["name"] for z in topo["zones"]} == {
            "enterprise", "dmz", "supervisory", "engineering", "control", "field",
        }
        for zone in topo["zones"]:
            assert zone["purpose"], f"{zone['name']} has no description"

    def test_only_the_command_paths_into_control_are_guarded(self):
        """The guard sits in front of the control zone on the way in. The
        return path from the field carries telemetry it reads to form a
        belief and never rules on, so marking it guarded would claim a
        protection that is not there."""
        from otguard.site.topology import default_site_topology

        conduits = default_site_topology(16).summary()["conduits"]
        guarded = {c["name"] for c in conduits if c["guarded"]}
        assert guarded == {"engineering_to_control", "scada_to_control"}

    def test_every_conduit_says_something(self):
        from otguard.site.topology import default_site_topology

        for c in default_site_topology(16).summary()["conduits"]:
            assert c["guarded"] or c["note"], f"{c['name']} explains nothing"


# ======================================================================
# The charts
# ======================================================================
class TestCharts:
    """A chart that magnifies noise is a chart inventing an event."""

    def test_the_vertical_scale_is_floored(self):
        """Without a floor, a site holding 9.0351 MW against 9.0372 fills
        the frame with a two-kilowatt wobble and draws it as a cliff."""
        assert "var floor = Math.max(step * 6" in CHART_JS

    def test_the_axis_ends_are_told_apart(self):
        """Two labels reading the same number tell the reader nothing."""
        assert "function axisLabels(lo, hi)" in CHART_JS

    def test_the_metric_payload_carries_its_own_precision(self):
        from otguard.bess.metrics import assess as site_assess
        from otguard.bess.metrics import read_site
        from otguard.bess.site import BessSite
        from otguard.config import load_config

        b = load_config(None).bess
        site = BessSite(b.site, b.safety, b.pack, seed=1)
        for row in site_assess(read_site(site), b.site, b.safety, b.pack):
            assert isinstance(row["decimals"], int)

    def test_the_history_caption_does_not_promise_a_band_it_may_not_draw(self):
        """The chart scales to its trace, so a limit far outside that range
        is not drawn. The caption used to state the band unconditionally."""
        for page in PAGES.values():
            assert "shaded band is the allowed range" not in page
            assert "where it is in view" in page
