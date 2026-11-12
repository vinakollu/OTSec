"""The live view, drawn in a terminal and redrawn in place.

One screen, rebuilt from the event stream on every frame: where the plant is,
what was asked of it, what the guard said, and which devices are answering.
Nothing here reads the plant. If a number is on the screen, an event carried
it, which is what keeps this view and the browser view honest about each other.

Two practical points.

It redraws by homing the cursor and clearing each line rather than clearing the
whole screen, because clearing first and drawing second shows a blank frame for
one refresh and the result flickers on anything slower than a local terminal.

When stdout is not a terminal — a pipe, a CI log, a file — full-screen drawing
produces a few thousand lines of escape codes and nothing readable. So it
checks, and falls back to printing the events that matter one per line. The
fallback is not a lesser mode for the sake of having one: it is the mode that
makes the demo usable in a transcript, which is where most people will first
see it.
"""

from __future__ import annotations

import shutil
import sys
from collections import deque
from typing import TextIO

from .events import Kind, LiveEvent

HOME = "\x1b[H"
CLEAR_LINE = "\x1b[2K"
CLEAR_BELOW = "\x1b[J"
HIDE_CURSOR = "\x1b[?25l"
SHOW_CURSOR = "\x1b[?25h"

DIM = "\x1b[2m"
BOLD = "\x1b[1m"
RED = "\x1b[31m"
GREEN = "\x1b[32m"
YELLOW = "\x1b[33m"
BLUE = "\x1b[34m"
RESET = "\x1b[0m"

#: Lines of command and verdict history on screen. Enough to see a burst of
#: writes as a burst rather than as one line that changes too fast to read.
_FEED = 8


def _bar(fraction: float, width: int, *, marks: dict[int, str] | None = None) -> str:
    """A filled bar with optional marker characters at fixed positions."""
    fraction = max(0.0, min(1.0, fraction))
    filled = int(round(fraction * width))
    cells = ["#" if i < filled else "." for i in range(width)]
    for position, char in (marks or {}).items():
        if 0 <= position < width:
            cells[position] = char
    return "".join(cells)


class TerminalView:
    """Renders the event stream onto one screen."""

    def __init__(self, stream: TextIO | None = None, colour: bool | None = None) -> None:
        self.stream = stream or sys.stdout
        self.tty = bool(getattr(self.stream, "isatty", lambda: False)())
        self.colour = self.tty if colour is None else colour
        self.scenario: dict | None = None
        self.state: dict | None = None
        self.devices: dict[str, dict] = {}
        self.feed: deque[str] = deque(maxlen=_FEED)
        self.outcome: list[str] = []
        self.t = 0.0
        self.blocked = 0
        self.trips = 0
        self.lost: set[str] = set()
        self._started = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def start(self) -> None:
        if self.tty:
            self.stream.write(HIDE_CURSOR + "\x1b[2J")
            self.stream.flush()
        self._started = True

    def stop(self) -> None:
        if self.tty:
            self.stream.write(SHOW_CURSOR + "\n")
            self.stream.flush()
        self._started = False

    def __enter__(self) -> "TerminalView":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()

    # ------------------------------------------------------------------
    # Consuming events
    # ------------------------------------------------------------------
    def on_event(self, event: LiveEvent) -> None:
        payload = event.payload
        if event.kind is Kind.SCENARIO:
            # Each run has its own clock starting at zero. Without this the
            # previous run's finishing time sticks and every line in the next
            # one is stamped with it.
            self.t = event.t
        self.t = max(self.t, event.t)

        if event.kind is Kind.SCENARIO:
            self.scenario = dict(payload)
            self.state = None
            self.devices.clear()
            self.feed.clear()
            self.outcome.clear()
            self.blocked = 0
            self.trips = 0
            self.lost.clear()
            self._line(f"{BOLD}{payload['name']}{RESET} on the "
                       f"{payload['plant']}: {payload['summary']}")
        elif event.kind is Kind.STATE:
            self.state = dict(payload)
        elif event.kind is Kind.DEVICE:
            first_sighting = payload["name"] not in self.devices
            self.devices[payload["name"]] = dict(payload)
            if payload["state"] == "down":
                self.lost.add(payload["name"])
                self._line(f"{RED}{payload['name']} went down{RESET}: {payload['detail']}")
            else:
                self.lost.discard(payload["name"])
                if payload.get("previous") == "down":
                    self._line(f"{GREEN}{payload['name']} is back{RESET}: "
                               f"{payload['detail']}")
                elif first_sighting and not self.tty and (
                    payload["critical"] or payload["measurement_source"]
                ):
                    # On a screen the device panel carries this. A transcript
                    # has no panel, so the devices whose loss would matter are
                    # named once when they are first seen answering; listing
                    # all twenty-seven would bury the run.
                    tag = "" if payload["networked"] else " (model)"
                    self._line(f"{GREEN}{payload['name']} answering{RESET}{tag}: "
                               f"{payload['detail']}")
        elif event.kind is Kind.COMMAND:
            where = f" {payload['device']}" if payload["device"] else ""
            self._line(f"{DIM}{payload['source']:<9s}{RESET} ->{where} "
                       f"{payload['point']}={payload['value']:g}{payload['unit']}")
        elif event.kind is Kind.VERDICT:
            self._verdict(payload)
        elif event.kind is Kind.TRIP:
            self.trips += 1
            self._line(f"{YELLOW}GUARD acts{RESET} [{','.join(payload['rules'])}] "
                       f"{payload['detail']}")
        elif event.kind is Kind.NOTE:
            tint = {"warn": YELLOW, "bad": RED, "good": GREEN}.get(payload.get("level", ""), BLUE)
            self._line(f"{tint}{payload['text']}{RESET}")
        elif event.kind is Kind.DONE:
            self.outcome = [payload["outcome"], *payload["lines"]]

        self.draw()

    def _verdict(self, payload: dict) -> None:
        decision = payload["decision"]
        if decision == "block":
            self.blocked += 1
            tint, word = RED, "BLOCK"
        elif decision == "alarm":
            tint, word = YELLOW, "ALARM"
        else:
            tint, word = GREEN, "allow"
        rules = ",".join(payload["rules"])
        tail = f"  {DIM}[{rules}] {payload['detail']}{RESET}" if rules else ""
        where = f" {payload['device']}" if payload["device"] else ""
        self._line(
            f"{tint}{word:<6s}{RESET}{payload['source']:<9s}->{where} "
            f"{payload['point']}={payload['value']:g}{payload['unit']}{tail}"
        )

    def _line(self, text: str) -> None:
        stamped = f"{DIM}{self.t:7.1f}s{RESET} {text}"
        if self.tty:
            self.feed.append(stamped)
        else:
            # Transcript mode: the feed *is* the output, so it goes out now.
            self.stream.write(self._plain(stamped) + "\n")
            self.stream.flush()

    # ------------------------------------------------------------------
    # Drawing
    # ------------------------------------------------------------------
    def draw(self) -> None:
        if not self.tty or not self._started:
            return
        width = max(60, min(shutil.get_terminal_size((100, 30)).columns, 120))
        lines = self._frame(width)
        out = [HOME]
        for line in lines:
            out.append(CLEAR_LINE + self._fit(line, width) + "\n")
        out.append(CLEAR_BELOW)
        self.stream.write("".join(out))
        self.stream.flush()

    def _frame(self, width: int) -> list[str]:
        lines = [self._header(width), ""]
        if self.state is None:
            lines.append(f"{DIM}  waiting for the plant to report{RESET}")
        elif self.state.get("plant") == "tank":
            lines += self._tank_panel(width)
        else:
            lines += self._site_panel(width)
        lines += ["", self._rule("devices", width)]
        lines += self._device_panel(width)
        lines += ["", self._rule("commands and verdicts", width)]
        lines += list(self.feed) or [f"{DIM}  nothing yet{RESET}"]
        if self.outcome:
            lines += ["", self._rule("result", width)]
            lines += [f"  {BOLD}{self.outcome[0]}{RESET}"]
            lines += [f"  {DIM}{line}{RESET}" for line in self.outcome[1:]]
        return lines

    def _header(self, width: int) -> str:
        if self.scenario is None:
            return f"{BOLD}OTGuard live{RESET}"
        mode = "guard enforcing" if self.scenario["guarded"] else "guard powerless (control run)"
        left = (f"{BOLD}OTGuard live{RESET}  {self.scenario['plant']}  "
                f"{self.scenario['name']}  {DIM}{mode}{RESET}")
        right = f"t={self.t:7.1f}s"
        pad = max(1, width - self._visible(left) - len(right))
        return left + " " * pad + right

    def _rule(self, label: str, width: int) -> str:
        dashes = max(0, width - len(label) - 4)
        return f"{DIM}-- {label} {'-' * dashes}{RESET}"

    # -- tank -----------------------------------------------------------
    def _tank_panel(self, width: int) -> list[str]:
        s = self.state or {}
        height = s.get("height_m", 2.0) or 2.0
        bar_width = max(20, width - 34)
        marks = {
            int(round(s.get("floor_m", 0.2) / height * bar_width)): "|",
            min(bar_width - 1, int(round(s.get("limit_m", 1.8) / height * bar_width))): "|",
        }
        level = s.get("level_m", 0.0)
        tint = RED if (s.get("overflowed") or s.get("dried_out")) else (
            YELLOW if level > s.get("limit_m", 1.8) - 0.15 else GREEN
        )
        lines = [
            f"  level    {tint}{level:5.3f} m{RESET}  "
            f"[{_bar(level / height, bar_width, marks=marks)}]  {DIM}0-{height:g} m{RESET}",
            f"  {DIM}sensor says {s.get('reported_m', 0.0):5.3f} m, guard believes "
            f"{s.get('believed_m', 0.0):5.3f} m, overflow at "
            f"{s.get('limit_m', 0.0):g} m, dry at {s.get('floor_m', 0.0):g} m{RESET}",
            "",
            f"  pump     {s.get('pump_pct', 0.0):5.1f} %  "
            f"[{_bar(s.get('pump_pct', 0.0) / 100.0, 24)}]",
            f"  valve    {s.get('valve_pct', 0.0):5.1f} %  "
            f"[{_bar(s.get('valve_pct', 0.0) / 100.0, 24)}]",
        ]
        if s.get("overflowed"):
            lines.append(f"  {RED}{BOLD}the tank has overflowed{RESET}")
        if s.get("dried_out"):
            lines.append(f"  {RED}{BOLD}the pump has run dry{RESET}")
        return lines

    # -- site -----------------------------------------------------------
    def _site_panel(self, width: int) -> list[str]:
        s = self.state or {}
        rating = s.get("rating_mw", 25.0) or 25.0
        poi = s.get("poi_mw", 0.0)
        limit = s.get("limit_mw", 20.0)
        over = abs(poi) > limit
        tint = RED if abs(poi) > rating else (YELLOW if over else GREEN)
        bar_width = max(20, width - 48)
        marks = {min(bar_width - 1, int(round(limit / rating * bar_width))): "|"}
        lines = [
            f"  export   {tint}{poi:+7.3f} MW{RESET} "
            f"[{_bar(abs(poi) / rating, bar_width, marks=marks)}] "
            f"{DIM}| = {limit:g} MW limit{RESET}",
            f"  {DIM}guard believes {s.get('believed_mw', 0.0):+7.3f} MW{RESET}",
            "",
        ]
        counted = set(s.get("counted", []))
        for name, value in (s.get("measurements") or {}).items():
            if name in counted:
                flag = f"{GREEN}counted{RESET}"
            else:
                flag = f"{RED}stale, not counted{RESET}"
            accused = s.get("lying_source") == name
            lines.append(
                f"  {name:<26s} {value:+7.3f} MW   {flag}"
                + (f"  {RED}named as lying{RESET}" if accused else "")
            )
        if len(counted) < 3:
            lines.append(
                f"  {YELLOW}quorum lost: {len(counted)} of 3 measurements arriving, so "
                f"a disagreement can no longer be attributed{RESET}"
            )
        packs = s.get("packs") or []
        if packs:
            # Labelled, because a fleet sitting near zero draws as a row of
            # blanks and an unlabelled blank row reads as a broken display.
            lines += [
                "",
                f"  {DIM}{len(packs)} units, one cell each, ' ' to '@'{RESET}",
                f"  power    [{self._pack_row(packs, 'p_mw')}]  {DIM}of 2 MW each{RESET}",
                f"  charge   [{self._pack_row(packs, 'soc')}]  {DIM}0 to 100 %{RESET}",
            ]
        if s.get("damaged"):
            lines.append(f"  {RED}{BOLD}the site has been damaged{RESET}")
        return lines

    def _pack_row(self, packs: list[dict], field: str) -> str:
        """One character per unit, so sixteen of them fit on a line.

        Not a precise read-out and not meant to be: it is there to show the
        fleet moving together, and an outlier as a cell that does not match its
        neighbours.
        """
        ramp = " .:-=+*#%@"
        cells = []
        for pack in packs:
            if not pack.get("online", True):
                cells.append(f"{RED}x{RESET}")
                continue
            if field == "soc":
                fraction = max(0.0, min(1.0, pack.get("soc", 0.0)))
            else:
                fraction = min(1.0, abs(pack.get("p_mw", 0.0)) / 2.0)
            cells.append(ramp[min(len(ramp) - 1, int(fraction * len(ramp)))])
        return "".join(cells)

    # -- devices --------------------------------------------------------
    def _device_panel(self, width: int) -> list[str]:
        if not self.devices:
            return [f"{DIM}  no devices being scanned{RESET}"]
        rows = sorted(
            self.devices.values(),
            key=lambda d: (d["state"] != "down", not d["critical"], d["name"]),
        )
        up = sum(1 for d in rows if d["state"] == "up")
        down = [d for d in rows if d["state"] == "down"]
        modelled = sum(1 for d in rows if not d["networked"])

        lines = [
            f"  {GREEN}{up} answering{RESET}"
            + (f", {RED}{len(down)} not{RESET}" if down else "")
            + f"  {DIM}({modelled} of {len(rows)} read from the model rather than "
              f"probed over a socket){RESET}"
        ]
        # Only the interesting rows: everything that is down, plus the devices
        # whose loss would matter. A full 27-row table pushes the command feed
        # off the screen and is unreadable anyway.
        shown = [d for d in rows if d["state"] == "down" or d["critical"]
                 or d["measurement_source"]][:7]
        for d in shown:
            tint = RED if d["state"] == "down" else GREEN
            tag = "" if d["networked"] else f" {DIM}(model){RESET}"
            extra = f" {DIM}{d['rtt_ms']:.1f}ms{RESET}" if d["state"] == "up" and d["rtt_ms"] else ""
            lines.append(
                f"    {d['name']:<10s} {tint}{d['state'].upper():<5s}{RESET}"
                f"{d['role']:<18s}{tag}{extra}"
            )
        return lines

    # ------------------------------------------------------------------
    # Width handling
    # ------------------------------------------------------------------
    def _fit(self, line: str, width: int) -> str:
        """Trim to the terminal width, counting only visible characters."""
        if self._visible(line) <= width:
            return line
        out, seen = [], 0
        i = 0
        while i < len(line) and seen < width:
            if line[i] == "\x1b":
                end = line.find("m", i)
                if end == -1:
                    break
                out.append(line[i:end + 1])
                i = end + 1
                continue
            out.append(line[i])
            seen += 1
            i += 1
        return "".join(out) + RESET

    @staticmethod
    def _visible(line: str) -> int:
        count, i = 0, 0
        while i < len(line):
            if line[i] == "\x1b":
                end = line.find("m", i)
                if end == -1:
                    break
                i = end + 1
                continue
            count += 1
            i += 1
        return count

    @staticmethod
    def _plain(line: str) -> str:
        out, i = [], 0
        while i < len(line):
            if line[i] == "\x1b":
                end = line.find("m", i)
                if end == -1:
                    break
                i = end + 1
                continue
            out.append(line[i])
            i += 1
        return "".join(out)
