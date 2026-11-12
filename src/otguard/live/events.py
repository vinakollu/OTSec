"""What a watcher is told, and the one shape it is told in.

Two displays read this stream: a terminal that redraws in place and a browser
page fed by server-sent events. They agree because neither of them is allowed
to ask the plant anything. Every number either of them shows arrived as an
event, so a disagreement between the two views is a rendering bug and never a
difference of opinion about the plant.

Events are JSON-safe by construction. The browser needs that, and it also
keeps the terminal honest: a payload that cannot be serialised is a payload
holding a live object, which is the first step toward one view reading state
the other cannot see.

The stream is not a log of everything. It is what somebody watching needs:
where the plant is, what was asked of it, what the guard said, which devices
are answering, and the moment something changes. Debug detail stays in the
logger.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Kind(str, Enum):
    """The kinds of thing a watcher is told."""

    SCENARIO = "scenario"   # a new run started
    STATE = "state"         # where the plant is now
    COMMAND = "command"     # a write arrived
    VERDICT = "verdict"     # what the guard did with it
    TRIP = "trip"           # the guard acted on its own
    DEVICE = "device"       # a device changed reachability
    NOTE = "note"           # a milestone worth a line
    DONE = "done"           # a run finished, with its outcome


@dataclass(frozen=True)
class LiveEvent:
    """One thing that happened, at one time, with a JSON-safe payload.

    ``seq`` is assigned by the bus. A browser that reconnects says which
    sequence number it already had, which is how it picks up without replaying
    the whole run or missing the middle of it.
    """

    kind: Kind
    t: float
    payload: dict[str, Any] = field(default_factory=dict)
    seq: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {"seq": self.seq, "kind": self.kind.value, "t": round(self.t, 3),
                **self.payload}

    def to_json(self) -> str:
        return json.dumps(self.as_dict(), separators=(",", ":"))


# ----------------------------------------------------------------------
# Constructors
# ----------------------------------------------------------------------
# Producers go through these rather than building payloads by hand, so a
# renderer can rely on a key being present instead of defending against every
# call site's idea of what to call it.


def scenario(t: float, *, plant: str, name: str, summary: str, guarded: bool) -> LiveEvent:
    return LiveEvent(Kind.SCENARIO, t, {
        "plant": plant, "name": name, "summary": summary, "guarded": guarded,
    })


def tank_state(
    t: float,
    *,
    level_m: float,
    reported_m: float,
    pump_pct: float,
    valve_pct: float,
    limit_m: float,
    floor_m: float,
    height_m: float,
    believed_m: float,
    overflowed: bool,
    dried_out: bool,
) -> LiveEvent:
    """Where the tank is.

    ``level_m`` is the truth, ``reported_m`` is what the sensor says and
    ``believed_m`` is the guard's estimate. Carrying all three is the point: in
    a false-data attack they come apart, and a display that showed one number
    would be showing the attacker's number.
    """
    return LiveEvent(Kind.STATE, t, {
        "plant": "tank",
        "level_m": round(level_m, 4),
        "reported_m": round(reported_m, 4),
        "believed_m": round(believed_m, 4),
        "pump_pct": round(pump_pct, 2),
        "valve_pct": round(valve_pct, 2),
        "limit_m": limit_m,
        "floor_m": floor_m,
        "height_m": height_m,
        "overflowed": bool(overflowed),
        "dried_out": bool(dried_out),
    })


def site_state(
    t: float,
    *,
    poi_mw: float,
    believed_mw: float,
    limit_mw: float,
    rating_mw: float,
    measurements: dict[str, float],
    counted: list[str],
    packs: list[dict[str, Any]],
    lying_source: str | None,
    damaged: bool,
) -> LiveEvent:
    """Where the site is, and which measurements the guard is still counting.

    ``measurements`` carries all three readings and ``counted`` says which of
    them the vote used. A view that showed only the consensus would hide the
    interesting case, where two readings are stale, agree with each other, and
    outvote the honest one.
    """
    return LiveEvent(Kind.STATE, t, {
        "plant": "site",
        "poi_mw": round(poi_mw, 4),
        "believed_mw": round(believed_mw, 4),
        "limit_mw": limit_mw,
        "rating_mw": rating_mw,
        "measurements": {k: round(v, 4) for k, v in measurements.items()},
        "counted": list(counted),
        "packs": packs,
        "lying_source": lying_source,
        "damaged": bool(damaged),
    })


def command(
    t: float, *, source: str, kind: str, value: float, unit: str = "", device: str = ""
) -> LiveEvent:
    return LiveEvent(Kind.COMMAND, t, {
        "source": source, "point": kind, "value": round(value, 4),
        "unit": unit, "device": device,
    })


def verdict(
    t: float,
    *,
    decision: str,
    source: str,
    point: str,
    value: float,
    unit: str = "",
    device: str = "",
    rules: list[str] | None = None,
    detail: str = "",
    latency_us: float = 0.0,
) -> LiveEvent:
    return LiveEvent(Kind.VERDICT, t, {
        "decision": decision,
        "source": source,
        "point": point,
        "value": round(value, 4),
        "unit": unit,
        "device": device,
        "rules": list(rules or []),
        "detail": detail,
        "latency_us": round(latency_us, 1),
    })


def trip(t: float, *, direction: str, rules: list[str], detail: str) -> LiveEvent:
    return LiveEvent(Kind.TRIP, t, {
        "direction": direction, "rules": list(rules), "detail": detail,
    })


def device(
    t: float,
    *,
    name: str,
    state: str,
    previous: str = "",
    role: str = "",
    zone: str = "",
    evidence: str = "",
    networked: bool = True,
    detail: str = "",
    measurement_source: str | None = None,
    critical: bool = False,
    rtt_ms: float = 0.0,
) -> LiveEvent:
    """A device's reachability, as the scanner sees it.

    ``networked`` travels with every row so no display can present a model read
    as a measurement, which is the one thing the device table must never do.
    """
    return LiveEvent(Kind.DEVICE, t, {
        "name": name,
        "state": state,
        "previous": previous,
        "role": role,
        "zone": zone,
        "evidence": evidence,
        "networked": bool(networked),
        "detail": detail,
        "measurement_source": measurement_source,
        "critical": bool(critical),
        "rtt_ms": round(rtt_ms, 3),
    })


def note(t: float, text: str, *, level: str = "info") -> LiveEvent:
    return LiveEvent(Kind.NOTE, t, {"text": text, "level": level})


def done(t: float, *, plant: str, name: str, outcome: str, lines: list[str]) -> LiveEvent:
    return LiveEvent(Kind.DONE, t, {
        "plant": plant, "name": name, "outcome": outcome, "lines": list(lines),
    })
