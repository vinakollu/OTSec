"""One stream, several watchers, and nobody blocking the plant.

The bus is deliberately small, and two of its properties are load-bearing.

**A slow watcher cannot slow the plant down.** Publishing never awaits. Each
subscriber has a bounded queue, and when a queue is full the oldest event in it
is dropped rather than the producer being made to wait. A browser on a bad
connection therefore loses detail and the simulation keeps its timing. The
alternative — back-pressure all the way to the control loop — would mean the
display changed the thing it is displaying, which for a project whose whole
subject is control timing would be an unforced error. Drops are counted, and
the count is visible, because a display quietly missing events is worse than
one that says it missed them.

**A watcher that arrives late still gets a coherent picture.** The bus keeps
the most recent state event per plant, the current device table, and a bounded
tail of the stream. A browser opened halfway through a run is handed that
before it is handed anything new, so it starts with a full screen rather than
with whatever happens next.
"""

from __future__ import annotations

import asyncio
from collections import deque
from typing import Callable, Iterable

from .events import Kind, LiveEvent

#: Events kept for a late subscriber. Enough to fill the command feed on a
#: freshly opened page without replaying an entire run.
_BACKLOG = 400

#: Per-subscriber queue depth. A browser that falls this far behind is not
#: going to catch up by being given more memory.
_QUEUE_DEPTH = 256


class Subscription:
    """One watcher's queue, with its own drop count."""

    def __init__(self, depth: int = _QUEUE_DEPTH) -> None:
        self.queue: asyncio.Queue[LiveEvent] = asyncio.Queue(maxsize=depth)
        self.dropped = 0

    def offer(self, event: LiveEvent) -> None:
        """Hand over an event, discarding the oldest if the queue is full."""
        try:
            self.queue.put_nowait(event)
            return
        except asyncio.QueueFull:
            pass
        # Make room by dropping the stalest event this watcher has not read.
        # Dropping the newest instead would leave it looking at a frozen plant,
        # which is the one failure mode a live view must not have.
        try:
            self.queue.get_nowait()
            self.dropped += 1
        except asyncio.QueueEmpty:  # pragma: no cover - drained between the two calls
            pass
        try:
            self.queue.put_nowait(event)
        except asyncio.QueueFull:  # pragma: no cover - refilled between the two calls
            self.dropped += 1

    async def get(self) -> LiveEvent:
        return await self.queue.get()


class EventBus:
    """Fans events out to every watcher and remembers enough to brief a new one."""

    def __init__(self, backlog: int = _BACKLOG) -> None:
        self.seq = 0
        self.backlog: deque[LiveEvent] = deque(maxlen=backlog)
        self.subscribers: list[Subscription] = []
        self.callbacks: list[Callable[[LiveEvent], None]] = []
        # The picture a late watcher needs: the latest state per plant, every
        # device's current row, and the run in progress.
        self.latest_state: dict[str, LiveEvent] = {}
        self.devices: dict[str, LiveEvent] = {}
        self.current_scenario: LiveEvent | None = None

    # ------------------------------------------------------------------
    # Producing
    # ------------------------------------------------------------------
    def publish(self, event: LiveEvent) -> LiveEvent:
        """Number an event, remember it, and hand it to every watcher.

        Never awaits, so it is safe to call from inside a control loop.
        """
        self.seq += 1
        event = LiveEvent(kind=event.kind, t=event.t, payload=event.payload, seq=self.seq)
        self.backlog.append(event)

        if event.kind is Kind.STATE:
            self.latest_state[str(event.payload.get("plant", ""))] = event
        elif event.kind is Kind.DEVICE:
            self.devices[str(event.payload.get("name", ""))] = event
        elif event.kind is Kind.SCENARIO:
            # A new run starts from a clean screen: the previous run's devices
            # and plant state belong to a plant that is no longer running.
            self.current_scenario = event
            self.latest_state.clear()
            self.devices.clear()

        for subscription in self.subscribers:
            subscription.offer(event)
        for callback in self.callbacks:
            # A renderer that throws must not take the plant with it. The
            # terminal view runs in this process and a formatting mistake in it
            # is not a reason to stop a control loop.
            try:
                callback(event)
            except Exception:
                pass
        return event

    def publish_all(self, events: Iterable[LiveEvent]) -> None:
        for event in events:
            self.publish(event)

    # ------------------------------------------------------------------
    # Watching
    # ------------------------------------------------------------------
    def subscribe(self) -> Subscription:
        subscription = Subscription()
        self.subscribers.append(subscription)
        return subscription

    def unsubscribe(self, subscription: Subscription) -> None:
        if subscription in self.subscribers:
            self.subscribers.remove(subscription)

    def on(self, callback: Callable[[LiveEvent], None]) -> None:
        """Register a synchronous watcher, called inside :meth:`publish`."""
        self.callbacks.append(callback)

    # ------------------------------------------------------------------
    # Briefing a late arrival
    # ------------------------------------------------------------------
    def catch_up(self, after: int = 0) -> list[LiveEvent]:
        """What a watcher joining now needs to draw a full screen.

        With ``after`` set to a sequence number the watcher already has, this is
        the tail of the stream since then. Otherwise it is the current scenario,
        the current state, the device table and the recent feed, in that order,
        which is enough to render everything without waiting for the next tick.
        """
        if after:
            return [e for e in self.backlog if e.seq > after]
        brief: list[LiveEvent] = []
        if self.current_scenario is not None:
            brief.append(self.current_scenario)
        brief.extend(self.devices.values())
        brief.extend(self.latest_state.values())
        # The feed, minus anything already covered above, so a reconnecting
        # page does not show the same command twice.
        covered = {e.seq for e in brief}
        brief.extend(
            e for e in self.backlog
            if e.seq not in covered and e.kind in (Kind.COMMAND, Kind.VERDICT,
                                                   Kind.TRIP, Kind.NOTE, Kind.DONE)
        )
        return sorted(brief, key=lambda e: e.seq)

    @property
    def dropped(self) -> int:
        return sum(s.dropped for s in self.subscribers)
