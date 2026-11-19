"""Turning what the guard did into sentences anybody can read.

Every other display in this project writes for somebody who already knows what
R3 is. A room watching a demonstration does not, and a feed of
``[W2 dose proportioning] margin 8.91`` tells them nothing except that
something technical happened. They cannot tell whether the guard helped,
which is the only question they came to have answered.

So each event gets three things: what was asked for, what it would have done
to the water, and what the guard did about it. No rule identifiers without the
rule's meaning next to them, no units left unexplained, and no sentence that
needs a water engineer to parse.

The hard part is the second one. "A chlorine dose of 9.5 mg/L" means nothing
to a reader. "more than ten times what this water needs, enough to leave the
mains carrying twice the safe limit" means something to anybody. The numbers
come from the guard's own finding, so nothing here invents a consequence the
rules did not actually compute.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..water.metrics import Health
from ..water.types import HARM_MEANING, PointRole, WaterCommand, WaterCommandKind

#: What each rule is actually asking, said once, in words.
RULE_MEANING: dict[str, str] = {
    "W1": "is this something the equipment can even do?",
    "W2": "is this dose sensible for the amount and quality of water?",
    "W3": "where does the water end up if this command sticks?",
    "W4": "do the instruments agree with each other?",
    "W5": "does the water coming in match the water going out?",
    "W6": "are the orders already in force taking the water somewhere unsafe?",
    "W7": "is this a safe thing to do in the order it is being done?",
    "W8": "should this device, in this part of the network, be writing this?",
    "B1": "can this unit actually deliver what is being asked of it?",
    "B2": "does the charge reported add up with the power that has flowed?",
    "B3": "where does the power at the grid connection end up?",
    "B4": "is the site changing its output faster than the grid code allows?",
    "B5": "will this leave a battery hotter than it may safely get?",
    "B6": "do the three instruments measuring this agree with each other?",
    "B7": "is the switchgear in a state where this is a safe thing to do?",
    "B8": "should this device, in this part of the network, be writing this?",
    "B3b": "is the site's output heading out of its envelope on its own?",
}

#: Who is on the other end, said the way an operator would say it.
SOURCE_NAME: dict[str, str] = {
    "scada": "the plant's automatic control system",
    "hmi": "the operator's screen in the control room",
    "engineering": "the engineering workstation",
    "historian": "the historian, which should only ever read",
    "jump": "a session coming in through the jump server",
    "vendor": "the vendor's remote support connection",
    "unknown": "a device the plant has no record of",
    "enterprise": "a machine on the corporate office network",
    "relay": "the protection relay",
    "meter": "the revenue meter the utility bills against",
}


@dataclass(frozen=True)
class Line:
    """One thing to put on the screen."""

    headline: str
    detail: str = ""
    #: The same four words the metric rows use. Two vocabularies for one
    #: idea meant the page had a rule for one of them and a default for the
    #: other, so a broken limit arrived wearing the neutral icon.
    severity: str = "info"     # info | good | watch | breach
    tag: str = ""              # a short word for the left gutter

    def as_dict(self) -> dict:
        return {"headline": self.headline, "detail": self.detail,
                "severity": self.severity, "tag": self.tag}


def who(source: str, names: dict[str, str] | None = None) -> str:
    if names and source in names:
        return names[source]
    return SOURCE_NAME.get(source, f"the device called {source}")


def asked_for(command: WaterCommand) -> str:
    """What the command is, in words rather than register values."""
    kind = command.kind
    value = f"{command.value:g}{(' ' + kind.unit) if kind.unit else ''}"
    if kind is WaterCommandKind.BACKWASH:
        return ("start washing the filter" if command.value >= 0.5
                else "stop washing the filter")
    if kind is WaterCommandKind.MODE:
        return ("hand the plant back to automatic control" if command.value >= 0.5
                else "take the plant off automatic control")
    if kind.role is PointRole.LIMIT:
        # "set", not "raise". A limit write that re-asserts the value already
        # configured is the commonest honest traffic on this point, and it is
        # also the exact shape an attack on it takes, so the narration has to
        # describe both without calling either one of them the other.
        return f"set the {kind.label} to {value}"
    return f"set the {kind.label} to {value}"


def verdict_line(command: WaterCommand, blocked: bool, findings: list) -> Line:
    """The headline event: somebody asked for something and the guard ruled."""
    return ruling(f"{who(command.source).capitalize()} asked to "
                  f"{asked_for(command)}.", blocked, findings)


def ruling(request: str, blocked: bool, findings: list,
           *, subject: str = "the water") -> Line:
    """One verdict, narrated. Shared by every plant in the project."""
    if not blocked and not findings:
        return Line(
            headline=request,
            detail=f"OTGuard let it through. Nothing about it would take "
                   f"{subject} outside safe limits.",
            severity="good", tag="allowed",
        )
    reasons = [_explain(f) for f in findings]
    first = (reasons[0] if reasons
             else f"It would have taken {subject} outside safe limits.")
    if len(reasons) > 1:
        first += " " + _also(reasons[1:])
    if blocked:
        return Line(headline=request,
                    detail="OTGuard refused it. " + first,
                    severity="breach", tag="refused")
    return Line(headline=request,
                detail="OTGuard let it through but objected. " + first,
                severity="watch", tag="warned")


def _explain(finding) -> str:
    """One finding, as a sentence, with the rule's question attached."""
    question = RULE_MEANING.get(finding.rule_id, "")
    detail = finding.detail.strip()
    if detail:
        detail = detail[0].upper() + detail[1:]
        if not detail.endswith("."):
            detail += "."
    if question:
        return f"{detail} (The check that caught it asks: {question})"
    return detail


def _also(rest: list[str]) -> str:
    if len(rest) == 1:
        return "One other check objected as well."
    return f"{len(rest)} other checks objected as well."


def trip_line(reason: str, plain: str) -> Line:
    """The guard acting on its own, which is the moment worth narrating well."""
    return Line(
        headline="OTGuard stepped in and changed the plant itself.",
        detail=(plain or reason)
        + " It will hold the plant there until an operator acknowledges,"
          " because letting it recover on its own would hand the decision"
          " back to whoever sent the bad command.",
        severity="breach", tag="acted",
    )


def metric_line(row: dict) -> Line | None:
    """A measurement crossing out of, or back into, its safe band."""
    health = row.get("health")
    label = row["label"]
    shown = f"{row['shown']} {row['unit']}".strip()
    if health == Health.BREACH.value:
        return Line(
            headline=f"{label} is outside its safe limit, at {shown}.",
            detail=row.get("why", ""), severity="breach", tag="limit",
        )
    if health == Health.WATCH.value:
        return Line(
            headline=f"{label} has moved to {shown}, which is still legal but worth watching.",
            detail=row.get("plain", ""), severity="watch", tag="drift",
        )
    return None


def recovered_line(row: dict) -> Line:
    return Line(
        headline=f"{row['label']} is back to normal, at "
                 f"{row['shown']} {row['unit']}".strip() + ".",
        severity="good", tag="clear",
    )


def harm_line(harm: str) -> Line:
    return Line(
        headline="Water left the plant in a state it should not have.",
        detail=HARM_MEANING.get(harm, harm), severity="breach", tag="harm",
    )


def attack_line(name: str, story: str, source: str) -> Line:
    return Line(
        headline=f"Attack started: {name.replace('_', ' ')}.",
        detail=f"{story} It is being sent from {who(source)}.",
        severity="watch", tag="attack",
    )


def guard_mode_line(enforcing: bool) -> Line:
    if enforcing:
        return Line(
            headline="OTGuard is enforcing.",
            detail="Commands that would take the water outside safe limits will be "
                   "refused before they reach the plant.",
            severity="good", tag="guard",
        )
    return Line(
        headline="OTGuard has been switched to watch-only.",
        detail="It will still judge every command and say what it thinks, and it "
               "will not stop anything. This is the comparison: the same attack, "
               "the same plant, with nothing standing in the way.",
        severity="watch", tag="guard",
    )


def device_line(name: str, up: bool, detail: str) -> Line:
    if up:
        return Line(headline=f"{name} is answering again.", severity="good", tag="device")
    return Line(
        headline=f"{name} has stopped answering.",
        detail=(detail or "") + " While it is down the plant is running on the "
                                "last reading it sent, which can look exactly like a steady one.",
        severity="watch", tag="device",
    )


def summary_sentence(metrics: list[dict], harms: list[str], enforcing: bool) -> str:
    """One line for the top of the screen: is the water all right?"""
    breaches = [m for m in metrics if m["health"] == Health.BREACH.value]
    if harms:
        return ("Water has already left the plant in an unsafe state. "
                + HARM_MEANING.get(harms[0], ""))
    if breaches:
        names = ", ".join(m["label"].lower() for m in breaches[:2])
        return (f"The water is outside its safe limits on {names}. "
                "Nothing has reached the town yet.")
    watching = [m for m in metrics if m["health"] == Health.WATCH.value]
    if watching:
        return (f"The water is safe to drink. {watching[0]['label']} is drifting and "
                "worth keeping an eye on.")
    if not enforcing:
        return ("The water is safe to drink, and OTGuard is only watching. "
                "Nothing is being stopped.")
    return "The water leaving the plant is safe to drink, on every measure."
