"""Tables and a figure for the incident catalogue.

The figure is the hard part, and the form matters more than usual here, because
the obvious chart would be dishonest. Twelve incidents with a tick or a cross
against each reads as a score out of twelve, and this guard is not in a
position to be scored against four of them: a campaign that stole documents and
an implant that ran on the controller are not misses, they are different
problems. Putting them in the same column as a prevented overflow invents a
denominator.

So the figure has three bands and they are not comparable with each other on
purpose. The first carries a real number — how much warning there was before
the process left its envelope. The second holds the incidents whose shape the
rules recognise in a plant this model cannot damage. The third holds the ones
the guard would never have seen, each with the reason, which is the band a
reader should look at first.
"""

from __future__ import annotations

from pathlib import Path

from . import figstyle as fs
from .incidents import IncidentResult, summarise


def _best(row: IncidentResult) -> object | None:
    """The piece of evidence that says the most about this incident."""
    ran = row.ran
    if not ran:
        return None
    with_lead = [e for e in ran if e.lead_time_s is not None]
    if with_lead:
        return min(with_lead, key=lambda e: e.lead_time_s)
    prevented = [e for e in ran if e.damage_prevented]
    if prevented:
        return prevented[0]
    detected = [e for e in ran if e.detected]
    return detected[0] if detected else ran[0]


def format_catalogue(results: list[IncidentResult]) -> str:
    lines = [
        "Incidents and what this project can say about them",
        "=" * 100,
        f"{'incident':<30}{'year':<7}{'mechanism':<24}{'vantage':<27}{'in scope'}",
        "-" * 100,
    ]
    for row in results:
        inc = row.incident
        lines.append(
            f"{inc.name[:29]:<30}{inc.year:<7}{inc.mechanism.value:<24}"
            f"{inc.vantage.value:<27}{'yes' if inc.in_scope else 'no'}"
        )
    return "\n".join(lines)


def format_results(results: list[IncidentResult]) -> str:
    lines = ["", "What each one did when it was run", "-" * 100]
    for row in results:
        inc = row.incident
        lines.append("")
        lines.append(f"{inc.name} ({inc.year}) — {row.summary}")
        if not inc.in_scope:
            lines.append(f"    out of scope: {_scope_note(row)}")
        for ev in row.evidence:
            if not ev.ran:
                where = f"{ev.kind}/{ev.name}" if ev.name else ev.kind
                lines.append(f"    {where:<42} not run: {ev.skipped}")
                continue
            detail = []
            if ev.rules:
                detail.append("rules " + ",".join(ev.rules))
            if ev.wire_reasons:
                detail.append("wire " + ",".join(ev.wire_reasons))
            if ev.first_detection_t is not None:
                detail.append(f"first objection t={ev.first_detection_t:.1f}s")
            if ev.lead_time_s is not None:
                detail.append(f"warning {ev.lead_time_s:.1f}s")
            if not ev.damage_unguarded:
                detail.append("no damage to prevent")
            lines.append(
                f"    {ev.kind}/{ev.name:<36} {ev.verdict:<10} " + "; ".join(detail)
            )
    return "\n".join(lines)


def _scope_note(row: IncidentResult) -> str:
    from .incidents import _why_out

    return _why_out(row.incident)


def format_summary(results: list[IncidentResult]) -> str:
    s = summarise(results)
    lines = [
        "",
        "Counts, with what each is out of",
        "-" * 100,
        f"  Incidents in the catalogue                        {s['incidents']}",
        f"  A plausibility guard is the right control for     {s['in_scope']}",
        f"  Of those, an attack of that shape was objected to  {s['in_scope_detected']}/{s['in_scope']}",
        f"    by a physics rule                               {s['in_scope_detected_by_rules']}",
        f"    by the access policy alone                      {s['in_scope_detected_only_by_policy']}",
        f"  Of those, damage occurred without the guard       {s['in_scope_with_damage_to_prevent']}",
        f"  Of those, the guard prevented it                  "
        f"{s['in_scope_damage_prevented']}/{s['in_scope_with_damage_to_prevent']}",
        f"  Pieces of evidence run                            {s['evidence_run']}",
        f"  Pieces of evidence not run                        {s['evidence_skipped']}",
        "",
        "  Outside what this guard can see:",
    ]
    for key, reason in sorted(s["out_of_scope_reasons"].items()):
        lines.append(f"    {key:<22}{reason}")
    lines.append("")
    lines.append(
        "  The last two lines are kept apart for the reason docs/devices.md gives: an"
    )
    lines.append(
        "  access check that stops an attack is worth having and is not evidence for the"
    )
    lines.append(
        "  claim this project makes. Reporting them together inflates the number that"
    )
    lines.append("  matters.")
    lines.append("")
    lines.append(
        "  Detection counted here means an attack of that shape was objected to on a"
    )
    lines.append(
        "  conduit the guard sits on. It is not a claim that the incident would have"
    )
    lines.append(
        "  been stopped: the scenarios carry this project's parameters, not the"
    )
    lines.append("  incidents' own.")
    return "\n".join(lines)


def plot_coverage(results: list[IncidentResult], path: Path) -> Path:
    """Bands that are deliberately not comparable with one another.

    Four of them, because three was wrong. The first version put the incidents
    that were simply not run in this report into the same band as the ones the
    guard could never have seen, under a heading saying it would not have been
    in a position to see them. Triton and the Unitronics intrusions are both
    squarely in scope and both have matrix pairs waiting to be run; filing them
    beside Night Dragon claimed something about them that is not true.
    """
    import matplotlib.pyplot as plt

    fs.apply()

    warned: list[tuple[str, float, str]] = []
    prevented: list[tuple[str, str]] = []
    recognised: list[tuple[str, str]] = []
    unrun: list[tuple[str, str]] = []
    unseen: list[tuple[str, str]] = []

    for row in results:
        inc = row.incident
        label = f"{inc.name} ({inc.year})"
        if not inc.in_scope:
            unseen.append((label, _why_out_short(row)))
            continue
        best = _best(row)
        where = f"{best.kind}/{best.name}" if best is not None else ""
        if best is None:
            unrun.append((label, _how_to_run(row)))
        elif best.lead_time_s is not None:
            warned.append((label, best.lead_time_s, where))
        elif best.damage_prevented:
            # Prevented, but the device matrix and the OPC UA experiment do not
            # record a warning time, so there is no bar to draw. Filing these
            # under "nothing to damage" would say the opposite of what happened.
            prevented.append((label, where))
        elif best.detected:
            recognised.append((label, where))
        else:
            unseen.append((label, "not detected"))

    warned.sort(key=lambda r: r[1])
    bands: list[tuple[str, list, str, bool]] = []
    if warned:
        bands.append(("Warning before the process left its envelope, in seconds",
                      warned, fs.SERIES["estimate"], True))
    if prevented:
        bands.append(("Damage prevented, by an evaluation that records no warning time",
                      prevented, fs.STATUS["safe"], False))
    if recognised:
        bands.append(("Shape recognised, in a plant this model cannot damage",
                      recognised, fs.STATUS["warn"], False))
    if unrun:
        bands.append(("In scope, and not run in this report",
                      unrun, fs.STATUS["inert"], False))
    if unseen:
        bands.append(("The guard would not have been in a position to see it",
                      unseen, fs.STATUS["inert"], False))

    ratios = [max(len(entries), 1) for _, entries, _, _ in bands]
    height = 1.2 + 0.38 * sum(ratios) + 0.45 * len(bands)
    fig, axes = plt.subplots(
        len(bands), 1, figsize=(9.6, height),
        gridspec_kw={"height_ratios": ratios, "hspace": 0.85},
    )
    if len(bands) == 1:
        axes = [axes]

    for ax, (title, entries, colour, numeric) in zip(axes, bands):
        if numeric:
            _bars(ax, entries, colour, title)
        else:
            _chips(ax, entries, colour, title)

    in_scope = sum(1 for r in results if r.incident.in_scope)
    fs.titles(
        fig,
        f"{len(results)} incidents, and which of them this guard could speak to",
        f"Bands are not comparable. {len(results) - in_scope} of the "
        f"{len(results)} are a different problem, not a miss.",
    )
    fs.footnote(
        fig,
        "Warning times are from the counterfactual run, in simulated seconds, with this "
        "project's parameters and not the incidents' own.",
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path)
    plt.close(fig)
    return path


def _bars(ax, entries: list[tuple[str, float, str]], colour: str, title: str) -> None:
    # The unit goes in the band title rather than on an axis label, which would
    # otherwise sit directly on top of the next band's heading.
    fs.style(ax, grid="x")
    ys = list(range(len(entries)))
    ax.barh(ys, [e[1] for e in entries], height=0.55, color=colour, zorder=2)
    ax.set_yticks(ys)
    ax.set_yticklabels([e[0] for e in entries])
    ax.invert_yaxis()
    ax.tick_params(length=0)
    for y, (_, lead, _) in zip(ys, entries):
        fs.value(ax, lead, y, f"{lead:.0f}s", offset=(6, -3), ha="left")
    ax.set_xlim(0, max(e[1] for e in entries) * 1.3)
    ax.set_title(title, loc="left", fontsize=fs.TYPE.subtitle, color=fs.INK, pad=6)


def _how_to_run(row: IncidentResult) -> str:
    """Which evaluation would fill this row in."""
    kinds = {e.kind for e in row.evidence if not e.ran and e.kind != "none"}
    if kinds == {"matrix"}:
        return "run scripts/run_matrix.py, or run_incidents.py --matrix"
    if kinds == {"opcua"}:
        return "run scripts/run_opcua.py"
    return "evidence available; not run here"


def _chips(ax, entries: list[tuple[str, str]], colour: str, title: str) -> None:
    """One row per entry: a dot, the name, and the reason set beside it."""
    fs.style(ax, grid="")
    ax.set_xlim(0, 1)
    ax.set_ylim(-0.6, max(len(entries) - 0.4, 0.6))
    for side in ("left", "bottom"):
        ax.spines[side].set_visible(False)
    ax.set_xticks([])
    if not entries:
        ax.set_yticks([])
        ax.annotate("none", xy=(0.0, 0.0), fontsize=fs.TYPE.note, color=fs.INK_3,
                    va="center")
    else:
        ys = list(range(len(entries)))
        ax.set_yticks(ys)
        ax.set_yticklabels([e[0] for e in entries])
        ax.invert_yaxis()
        ax.tick_params(length=0)
        for y, (_, reason) in zip(ys, entries):
            ax.plot([0.005], [y], marker="o", ms=5, color=colour, zorder=3)
            ax.annotate(reason, xy=(0.028, y), fontsize=fs.TYPE.note,
                        color=fs.INK_2, va="center")
    ax.set_title(title, loc="left", fontsize=fs.TYPE.subtitle, color=fs.INK, pad=6)


def _why_out_short(row: IncidentResult) -> str:
    from .incidents import Mechanism, Vantage

    inc = row.incident
    if inc.mechanism is Mechanism.ENTERPRISE:
        return "no process command to judge"
    if inc.mechanism is Mechanism.RECONNAISSANCE:
        return "reconnaissance; must not be refused"
    if inc.mechanism is Mechanism.UNDISCLOSED:
        return "public account does not say what was written"
    if inc.vantage is Vantage.BELOW:
        return "ran on the controller, below the guard"
    if inc.vantage is Vantage.BESIDE:
        return "not on a control conduit"
    return "no evidence speaks to it"


def render(results: list[IncidentResult]) -> str:
    return "\n".join([
        format_catalogue(results),
        format_results(results),
        format_summary(results),
    ])
