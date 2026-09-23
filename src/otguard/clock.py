"""A clock that can run faster than the wall.

Everything that runs over real sockets — the simulated field devices, the
guard's proxy, the masters sending commands — reads time from one of these
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
