"""A clock that can run faster than the wall.

Everything that runs over real sockets, the simulated field devices, the
guard's proxy, the masters sending commands, reads time from one of these
instead of ``time.perf_counter``. At ``speed=1`` it is the wall clock. At
``speed=20`` a two-minute scenario plays out in six seconds, and because every
party reads the same clock, a peer controller writing "every 100 ms" is still
seen by the guard as writing ten times a simulated second.

Decision latency is the one thing never measured on this clock. The guard's
cost is wall-clock microseconds whatever speed the scenario runs at.
"""

from __future__ import annotations

import asyncio
import time


class SimClock:
    """Scaled monotonic time, shared by every party in one experiment."""

    def __init__(self, speed: float = 1.0) -> None:
        if speed <= 0:
            raise ValueError(f"clock speed must be positive, got {speed}")
        self.speed = speed
        self._t0 = time.perf_counter()

    def now(self) -> float:
        """Simulated seconds since the clock started."""
        return (time.perf_counter() - self._t0) * self.speed

    async def sleep(self, seconds: float) -> None:
        """Sleep for ``seconds`` of simulated time."""
        await asyncio.sleep(max(seconds, 0.0) / self.speed)

    def reset(self) -> None:
        self._t0 = time.perf_counter()


class SteppedClock:
    """Simulated time that moves only when it is told to.

    :class:`SimClock` is driven by the wall, which is right for a
    demonstration and wrong for a test. A loaded machine changes how a
    process loop, a control loop and an attack script interleave, so a suite
    built on it fails every so often for reasons that have nothing to do with
    the code. For a project whose subject is control timing, a harness whose
    own timing wanders is weak evidence.

    This one exposes the same two methods every party already uses, so the
    plants, the guards and the attack scripts need no special case. The
    difference is that nothing happens until :meth:`advance` is called, and
    when it is, every sleeper due in that interval wakes in time order. The
    same run therefore produces the same interleaving on a quiet laptop and
    on a busy build machine.
    """

    def __init__(self, start: float = 0.0) -> None:
        #: Reported for the benefit of anything that displays a speed. A
        #: stepped clock has no relationship to the wall at all.
        self.speed = 0.0
        self._t = start
        self._waiters: list[tuple[float, asyncio.Future]] = []

    def now(self) -> float:
        return self._t

    async def sleep(self, seconds: float) -> None:
        if seconds <= 0:
            await asyncio.sleep(0)
            return
        future = asyncio.get_running_loop().create_future()
        self._waiters.append((self._t + seconds, future))
        await future

    async def advance(self, seconds: float) -> None:
        """Move time forward, waking everything due along the way.

        Time jumps to each waiter's deadline in turn rather than in fixed
        increments, so a loop sleeping a tenth of a second and one sleeping a
        minute both wake exactly when they asked to, and neither is skipped.
        """
        # Let anything just created reach its first sleep. A task made with
        # ``create_task`` has not run a line of its body until the loop
        # yields, so without this the first advance of a run sees no sleepers
        # at all, jumps straight to the target, and the plant never steps.
        for _ in range(12):
            await asyncio.sleep(0)
        target = self._t + max(seconds, 0.0)
        while True:
            pending = [(t, f) for t, f in self._waiters if not f.done()]
            self._waiters = pending
            upcoming = [t for t, _ in pending if t <= target]
            self._t = min(upcoming) if upcoming else target
            due = [f for t, f in pending if t <= self._t]
            self._waiters = [(t, f) for t, f in pending if t > self._t]
            for future in due:
                if not future.done():
                    future.set_result(None)
            # Let everything woken run until it sleeps again, including
            # anything it starts. Without this the next deadline is computed
            # from a half-finished scan.
            for _ in range(12):
                await asyncio.sleep(0)
            if not due and self._t >= target:
                return

    def reset(self) -> None:
        self._t = 0.0
