"""The interactive live view: the server route, the stand-down, and the page.

The expensive parts of this are covered elsewhere. The guard's decisions are
measured by the device matrix and the scanner by ``test_scan.py``; what is new
here is a tap on the guard, a control route on the server, and a page that has
to agree with the event schema it is fed. Those are what these pin.

The stand-down test is the one that matters. An attack launched while the
supervisory loop is still writing gets its set-point overwritten within a
second or two, never reaches the plant, and produces a demonstration in which
the guard appears to prevent damage that its own victim had already prevented.
"""

from __future__ import annotations

import asyncio
import json
import urllib.error
import urllib.request

import pytest

from otguard.live import EventBus, LiveServer
from otguard.live.demo import BACKGROUND, InteractiveDemo
from otguard.live.demo_page import DEMO_PAGE
from otguard.live.events import Kind
from otguard.live.page import PAGE


def _get(url: str) -> tuple[int, str]:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(url, timeout=5) as response:
            return response.status, response.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


# ----------------------------------------------------------------------
# The page
# ----------------------------------------------------------------------
def test_the_page_is_self_contained():
    """No CDN, no fonts, no framework: a lecture room has no network."""
    for forbidden in ("http://", "https://", "//cdn", "<script src"):
        assert forbidden not in DEMO_PAGE, forbidden


@pytest.mark.parametrize("kind", [k.value for k in (
    Kind.SCENARIO, Kind.STATE, Kind.VERDICT, Kind.TRIP, Kind.DEVICE, Kind.NOTE,
)])
def test_the_page_handles_every_kind_it_is_sent(kind):
    """The producer and the page drift apart silently otherwise.

    A kind the page does not branch on is an event that arrives, is parsed, and
    disappears, which looks exactly like a quiet plant.
    """
    assert f'"{kind}"' in DEMO_PAGE


def test_the_page_draws_the_things_it_claims_to():
    for element in ("topology", "levelChart", "actuatorChart",
                    "decisionChart", "deviceBody", "logBody"):
        assert f'id="{element}"' in DEMO_PAGE


# ----------------------------------------------------------------------
# The server's control route
# ----------------------------------------------------------------------
def test_a_server_without_commands_refuses_the_route():
    """``run_live.py`` builds one of these, and it must stay a read-only view."""
    async def check() -> tuple[int, str]:
        bus = EventBus()
        server = LiveServer(bus, port=0)
        await server.start()
        try:
            return await asyncio.to_thread(_get, f"{server.url}api/reset")
        finally:
            await server.stop()

    status, _ = asyncio.run(check())
    assert status == 404


def test_the_command_route_answers_and_survives_a_bad_command():
    seen: list[tuple[str, dict]] = []

    async def handler(action: str, params: dict) -> dict:
        seen.append((action, params))
        if action == "boom":
            raise RuntimeError("no")
        return {"ok": True, "action": action, "got": params.get("name", "")}

    async def check():
        bus = EventBus()
        server = LiveServer(bus, port=0, on_command=handler)
        await server.start()
        try:
            good = await asyncio.to_thread(
                _get, f"{server.url}api/attack?name=overflow")
            bad = await asyncio.to_thread(_get, f"{server.url}api/boom")
            return good, bad
        finally:
            await server.stop()

    (good_status, good_body), (bad_status, bad_body) = asyncio.run(check())
    assert good_status == 200
    assert json.loads(good_body) == {"ok": True, "action": "attack", "got": "overflow"}
    # A command that raises answers with the failure rather than killing the
    # server, because the server is holding the page an audience is watching.
    assert bad_status == 200
    assert json.loads(bad_body)["ok"] is False
    assert seen[0][0] == "attack"


def test_a_custom_page_replaces_the_default_one():
    async def check() -> str:
        bus = EventBus()
        server = LiveServer(bus, port=0, page="<!doctype html><p>mine</p>")
        await server.start()
        try:
            _, body = await asyncio.to_thread(_get, server.url)
            return body
        finally:
            await server.stop()

    assert "mine" in asyncio.run(check())


def test_the_default_page_is_still_the_default():
    async def check() -> str:
        bus = EventBus()
        server = LiveServer(bus, port=0)
        await server.start()
        try:
            _, body = await asyncio.to_thread(_get, server.url)
            return body
        finally:
            await server.stop()

    assert asyncio.run(check()) == PAGE


# ----------------------------------------------------------------------
# The running stack
# ----------------------------------------------------------------------
def test_the_guard_reports_every_write_it_judges(config):
    """The tap has to fire, or the page shows a wire with nothing on it."""
    async def run() -> list[dict]:
        bus = EventBus()
        demo = InteractiveDemo(config, bus, speed=20.0)
        seen: list[dict] = []
        bus.on(lambda e: seen.append(e.as_dict()))
        await demo.start()
        try:
            await demo.clock.sleep(6.0)
        finally:
            await demo.stop()
        return seen

    events = asyncio.run(run())
    verdicts = [e for e in events if e["kind"] == "verdict"]
    assert verdicts, "no write was reported"
    one = verdicts[0]
    for key in ("decision", "source", "point", "latency_us"):
        assert key in one
    assert {e["kind"] for e in events} >= {"scenario", "state", "verdict"}


def test_launching_an_attack_stands_the_writing_masters_down(config):
    """Otherwise the honest loop overwrites the attack and nothing happens.

    The device matrix runs its attacks alongside the read-only historian and
    nothing else. This asserts the live view does the same, and that the
    masters come back when the attack is called off.
    """
    async def run():
        bus = EventBus()
        demo = InteractiveDemo(config, bus, speed=20.0)
        await demo.start()
        try:
            await demo.clock.sleep(2.0)
            result = await demo.launch_attack("overflow")
            await demo.clock.sleep(1.0)
            during = set(demo.suspended)
            await demo.command("stop", {})
            await demo.clock.sleep(1.0)
            return result, during, set(demo.suspended)
        finally:
            await demo.stop()

    result, during, after = asyncio.run(run())
    assert result["ok"] is True
    assert result["source"] == "hmi"
    # Everything that writes stood down; the historian only reads, and the
    # matrix keeps it running, so it is the one that stays.
    assert "historian" not in during
    assert during == {m for m in BACKGROUND if m != "historian"}
    assert after == set()


def test_an_unknown_attack_is_refused_rather_than_raised(config):
    async def run() -> dict:
        bus = EventBus()
        demo = InteractiveDemo(config, bus, speed=20.0)
        await demo.start()
        try:
            return await demo.command("attack", {"name": "not_a_real_attack"})
        finally:
            await demo.stop()

    result = asyncio.run(run())
    assert result["ok"] is False
    assert "not_a_real_attack" in result["error"]


def test_cutting_the_link_is_a_real_probe_failure(config):
    """The scanner must fail for the reason a scanner would fail in a plant.

    A flag that said "down" would prove nothing about the scanner. Closing the
    listening socket means the probe genuinely cannot reach the device, and the
    plant carries on running behind it.
    """
    async def run():
        bus = EventBus()
        demo = InteractiveDemo(config, bus, speed=20.0)
        await demo.start()
        try:
            await demo.clock.sleep(4.0)
            up_before = demo.scanner.reachable("plc01")
            await demo.set_link(False)
            # Three failed sweeps are needed before the scanner calls it down.
            for _ in range(6):
                await demo.scanner.scan_once()
            down = demo.scanner.reachable("plc01")
            moving = demo.device.tank.state
            await demo.set_link(True)
            for _ in range(4):
                await demo.scanner.scan_once()
            return up_before, down, demo.scanner.reachable("plc01"), moving
        finally:
            await demo.stop()

    up_before, down, up_again, state = asyncio.run(run())
    assert up_before is True
    assert down is False, "the scanner did not notice the link was cut"
    assert up_again is True, "the scanner did not notice it come back"
    # The plant kept running while its link was down.
    assert state.level_m > 0.0
