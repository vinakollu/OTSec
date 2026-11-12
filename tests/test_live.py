"""The live view: the event stream, the bus, and the two renderers.

The properties worth testing here are the ones that would be silently wrong.
A display that disagrees with the plant is a bug nobody notices until they are
standing in front of an audience, and a bus that blocks when a browser falls
behind would change the timing of the thing it is displaying.

Async cases drive ``asyncio.run`` directly, as the rest of this suite does.
"""

from __future__ import annotations

import asyncio
import io
import json

from otguard.live import EventBus, LiveServer, TerminalView
from otguard.live import events as ev
from otguard.live.bus import _QUEUE_DEPTH
from otguard.live.events import Kind


def _tank(t: float = 1.0, **over):
    args = dict(
        level_m=1.4, reported_m=1.41, pump_pct=0.0, valve_pct=50.0, limit_m=1.8,
        floor_m=0.2, height_m=2.0, believed_m=1.39, overflowed=False, dried_out=False,
    )
    args.update(over)
    return ev.tank_state(t, **args)


# ----------------------------------------------------------------------
# Events
# ----------------------------------------------------------------------
def test_every_event_survives_json():
    """The browser needs it, and it keeps a live object out of a payload."""
    made = [
        ev.scenario(0.0, plant="tank", name="overflow", summary="s", guarded=True),
        _tank(),
        ev.site_state(2.0, poi_mw=1.0, believed_mw=1.1, limit_mw=20.0, rating_mw=25.0,
                      measurements={"m": 1.0}, counted=["m"], packs=[{"device": "MP01"}],
                      lying_source=None, damaged=False),
        ev.command(3.0, source="hmi", kind="pump", value=100.0, unit="%"),
        ev.verdict(4.0, decision="block", source="hmi", point="pump", value=100.0,
                   unit="%", rules=["R3"], detail="would overflow", latency_us=48.0),
        ev.trip(5.0, direction="overflow", rules=["R3"], detail="valve to 100 %"),
        ev.device(6.0, name="plc01", state="up", evidence="answered", networked=True),
        ev.note(7.0, "something happened"),
        ev.done(8.0, plant="tank", name="overflow", outcome="intact", lines=["a"]),
    ]
    for event in made:
        decoded = json.loads(event.to_json())
        assert decoded["kind"] == event.kind.value
        assert "t" in decoded


def test_a_device_row_always_says_whether_it_was_measured():
    """The one thing the device table must never get wrong."""
    probed = json.loads(ev.device(1.0, name="plc01", state="up", networked=True).to_json())
    modelled = json.loads(ev.device(1.0, name="MP01", state="up", networked=False).to_json())
    assert probed["networked"] is True
    assert modelled["networked"] is False


# ----------------------------------------------------------------------
# The bus
# ----------------------------------------------------------------------
def test_publish_numbers_events_and_reaches_every_watcher():
    async def scenario():
        bus = EventBus()
        seen = []
        bus.on(seen.append)
        queued = bus.subscribe()
        bus.publish(ev.note(1.0, "one"))
        bus.publish(ev.note(2.0, "two"))
        return seen, [await queued.get(), await queued.get()]

    seen, got = asyncio.run(scenario())
    assert [e.seq for e in seen] == [1, 2]
    assert [e.seq for e in got] == [1, 2]


def test_a_slow_watcher_never_blocks_the_plant():
    """Back-pressure from a display to a control loop would be an own goal.

    The alternative to dropping is making the simulation wait for a browser,
    which in a project about control timing would mean the display changed the
    thing it was displaying.
    """
    bus = EventBus()
    slow = bus.subscribe()
    total = _QUEUE_DEPTH + 120
    for i in range(total):
        bus.publish(ev.note(float(i), f"n{i}"))

    assert slow.queue.qsize() == _QUEUE_DEPTH
    assert slow.dropped == total - _QUEUE_DEPTH
    # The oldest went, not the newest: a watcher must never be left looking at
    # a frozen plant.
    oldest = asyncio.run(slow.get())
    assert oldest.payload["text"] == f"n{slow.dropped}"


def test_a_renderer_that_throws_does_not_take_the_run_with_it():
    bus = EventBus()
    survived = []
    bus.on(lambda e: (_ for _ in ()).throw(RuntimeError("formatting bug")))
    bus.on(survived.append)
    bus.publish(ev.note(1.0, "still here"))
    assert [e.payload["text"] for e in survived] == ["still here"]


def test_catch_up_briefs_a_late_watcher_with_a_whole_screen():
    bus = EventBus()
    bus.publish(ev.scenario(0.0, plant="tank", name="overflow", summary="s", guarded=True))
    bus.publish(ev.device(0.1, name="plc01", state="up", networked=True))
    bus.publish(_tank(1.0))
    bus.publish(ev.note(2.0, "a milestone"))
    bus.publish(_tank(3.0, level_m=1.5))

    brief = bus.catch_up()
    kinds = [e.kind for e in brief]
    assert Kind.SCENARIO in kinds and Kind.DEVICE in kinds and Kind.NOTE in kinds
    # One state event, the newest: replaying every frame of a long run would
    # make a page that opens late take as long to draw as the run took.
    states = [e for e in brief if e.kind is Kind.STATE]
    assert len(states) == 1 and states[0].payload["level_m"] == 1.5
    assert [e.seq for e in brief] == sorted(e.seq for e in brief)


def test_catch_up_after_a_sequence_number_returns_only_the_tail():
    bus = EventBus()
    for i in range(5):
        bus.publish(ev.note(float(i), f"n{i}"))
    assert [e.payload["text"] for e in bus.catch_up(after=3)] == ["n3", "n4"]


def test_a_new_scenario_clears_the_previous_plant():
    bus = EventBus()
    bus.publish(ev.scenario(0.0, plant="tank", name="a", summary="s", guarded=True))
    bus.publish(ev.device(0.1, name="plc01", state="up", networked=True))
    bus.publish(_tank(1.0))
    bus.publish(ev.scenario(0.0, plant="site", name="b", summary="s", guarded=True))
    assert bus.devices == {} and bus.latest_state == {}


# ----------------------------------------------------------------------
# The terminal renderer
# ----------------------------------------------------------------------
def test_terminal_falls_back_to_lines_when_it_is_not_a_terminal():
    """A pipe gets readable text, not a screenful of escape codes."""
    out = io.StringIO()
    view = TerminalView(stream=out)
    assert not view.tty
    view.start()
    view.on_event(ev.scenario(0.0, plant="tank", name="overflow", summary="s", guarded=True))
    view.on_event(ev.verdict(2.0, decision="block", source="hmi", point="pump",
                             value=100.0, unit="%", rules=["R3"], detail="would overflow"))
    view.stop()
    text = out.getvalue()
    assert "\x1b[" not in text, "no escape codes outside a terminal"
    assert "BLOCK" in text and "R3" in text


def test_each_run_gets_its_own_clock():
    """Without this the previous run's finishing time stamps the next one."""
    out = io.StringIO()
    view = TerminalView(stream=out)
    view.start()
    view.on_event(ev.scenario(0.0, plant="site", name="first", summary="s", guarded=True))
    view.on_event(ev.note(520.0, "end of the first run"))
    assert view.t == 520.0
    view.on_event(ev.scenario(0.0, plant="site", name="second", summary="s", guarded=True))
    assert view.t == 0.0


def test_the_frame_shows_both_plants_and_says_what_was_modelled():
    view = TerminalView(stream=io.StringIO())
    view.tty = True
    view._started = True

    view.on_event(ev.scenario(0.0, plant="tank", name="overflow", summary="s", guarded=True))
    view.on_event(ev.device(0.1, name="plc01", state="up", role="controller",
                            networked=True, critical=True, rtt_ms=0.4, detail="answered"))
    view.on_event(_tank(5.0, level_m=1.62))
    tank_frame = "\n".join(view._plain(line) for line in view._frame(100))
    assert "1.620 m" in tank_frame and "plc01" in tank_frame
    assert "0 of 1 read from the model" in tank_frame

    view.on_event(ev.scenario(0.0, plant="site", name="stale", summary="s", guarded=True))
    view.on_event(ev.device(1.0, name="meter01", state="down", role="meter",
                            networked=False, measurement_source="POI revenue meter",
                            detail="not refreshing"))
    view.on_event(ev.site_state(
        2.0, poi_mw=0.56, believed_mw=0.59, limit_mw=20.0, rating_mw=25.0,
        measurements={"POI revenue meter": 18.84, "Megapack telemetry sum": 0.59},
        counted=["Megapack telemetry sum"],
        packs=[{"device": "MP01", "online": True, "p_mw": 0.05, "soc": 0.5}],
        lying_source=None, damaged=False,
    ))
    site_frame = "\n".join(view._plain(line) for line in view._frame(100))
    assert "stale, not counted" in site_frame
    assert "quorum lost" in site_frame
    assert "1 of 1 read from the model" in site_frame


def test_long_lines_are_trimmed_without_counting_escape_codes():
    view = TerminalView(stream=io.StringIO())
    view.colour = True
    line = "\x1b[31m" + "x" * 200 + "\x1b[0m"
    assert view._visible(line) == 200
    assert view._visible(view._fit(line, 40)) == 40


# ----------------------------------------------------------------------
# The browser renderer
# ----------------------------------------------------------------------
async def _request(port: int, target: str, extra: str = "", method: str = "GET") -> str:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(f"{method} {target} HTTP/1.1\r\nHost: x\r\n{extra}\r\n".encode())
    await writer.drain()
    data = await asyncio.wait_for(reader.read(8192), timeout=5)
    writer.close()
    return data.decode("utf-8", "replace")


def test_the_server_serves_a_page_that_needs_nothing_from_the_network():
    """A control display that goes blank without internet is not a display."""
    async def scenario():
        bus = EventBus()
        server = LiveServer(bus, port=0)
        await server.start()
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
            writer.write(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            await writer.drain()
            chunks = b""
            while b"</html>" not in chunks:
                piece = await asyncio.wait_for(reader.read(65536), timeout=5)
                if not piece:
                    break
                chunks += piece
            writer.close()
            return chunks.decode("utf-8", "replace")
        finally:
            await server.stop()

    page = asyncio.run(scenario())
    assert page.startswith("HTTP/1.1 200 OK")
    assert "text/html" in page
    body = page.split("\r\n\r\n", 1)[1]
    assert "<script src" not in body and "//cdn" not in body
    assert "@import" not in body and "fonts.googleapis" not in body


def test_the_server_answers_only_what_it_means_to():
    async def scenario():
        bus = EventBus()
        server = LiveServer(bus, port=0)
        await server.start()
        try:
            return (
                await _status(server.port, "/healthz"),
                await _status(server.port, "/nope"),
                await _status(server.port, "/", method="POST"),
            )
        finally:
            await server.stop()

    async def _status(port, target, method="GET"):
        return (await _request(port, target, method=method)).split("\r\n")[0]

    health, missing, posted = asyncio.run(scenario())
    assert "200" in health
    assert "404" in missing
    assert "405" in posted


def test_a_browser_is_briefed_then_streamed_and_can_resume():
    async def scenario():
        bus = EventBus()
        server = LiveServer(bus, port=0)
        await server.start()
        try:
            bus.publish(ev.scenario(0.0, plant="tank", name="overflow",
                                    summary="s", guarded=True))
            bus.publish(_tank(1.0))

            reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
            writer.write(b"GET /events HTTP/1.1\r\nHost: x\r\n\r\n")
            await writer.drain()
            brief = (await asyncio.wait_for(reader.read(8192), timeout=5)).decode()

            bus.publish(ev.verdict(2.0, decision="block", source="hmi", point="pump",
                                   value=100.0, unit="%", rules=["R3"], detail="no"))
            pushed = (await asyncio.wait_for(reader.read(8192), timeout=5)).decode()
            writer.close()

            resumed = await _request(server.port, "/events", "Last-Event-ID: 2\r\n")
            return brief, pushed, resumed
        finally:
            await server.stop()

    brief, pushed, resumed = asyncio.run(scenario())
    assert "text/event-stream" in brief
    # Briefed before anything new, so the page draws a full screen at once.
    assert brief.count("data: ") == 2
    assert "id: 1" in brief, "ids are what make a reconnection cheap"
    assert '"decision":"block"' in pushed
    # Resuming from 2 replays only the third event.
    assert resumed.count("data: ") == 1
