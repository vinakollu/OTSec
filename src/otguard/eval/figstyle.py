"""One visual system for every figure the project produces.

Before this module the two halves of the project drew in two different styles,
and the tank half drew in matplotlib's default one: the tab10 cycle, a boxed
legend floating over the data, a full rectangle of spines, and a grid at the
same weight as the traces. That look is instantly recognisable as "nobody chose
this", and it costs the figures their authority in a report where the argument
is that the measurements were made carefully.

The parameters here are chosen once and consumed everywhere.

Colour
    Three categorical hues, validated for colour-vision deficiency separation
    against a white surface (worst adjacent pair dE 9.2 protan, 25.6 normal).
    Ground truth is drawn in ink rather than a hue, because it is the reference
    every other trace is judged against and should read as the authority. A
    counterfactual, being a might-have-been rather than a measurement, is drawn
    in muted grey. Status colours are reserved for outcomes and never reused as
    a fourth series.

Type
    Liberation Sans throughout, with Liberation Mono for numbers that a reader
    compares: peaks, thresholds, and annotated values line up in columns when
    the digits are monospaced.

Layout
    No top or right spine, no vertical grid, horizontal gridlines under the
    data in a colour close to the page. Series are labelled at the end of their
    own line wherever four or fewer of them fit, because a legend box asks the
    reader to hold a colour in memory and walk back to the data.

These figures are drawn for paper and for a light README. That is a deliberate
single-mode choice rather than an omission: every colour is picked against a
white surface, and a dark variant would need its own steps and its own
validation run rather than an inversion.
"""

from __future__ import annotations

from dataclasses import dataclass

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.axes import Axes  # noqa: E402
from matplotlib.figure import Figure  # noqa: E402

# ----------------------------------------------------------------------
# Tokens
# ----------------------------------------------------------------------
SURFACE = "#ffffff"
INK = "#14202b"          # primary text, and the ground-truth trace
INK_2 = "#54656f"        # axis labels, secondary annotation
INK_3 = "#8a99a3"        # tick labels, units
GRID = "#e6eaec"
RULE = "#cfd6da"

#: Categorical series, in fixed order. Never cycled, never extended by
#: generating a hue: a fifth co-occurring series means the chart is wrong.
SERIES = {
    "estimate": "#1d4ed8",     # what the guard believes
    "sensor": "#c2410c",       # what the instrument reports, which may be a lie
    "third": "#047857",        # an independent third measurement
    "extra": "#6d28d9",        # protective action, interventions
}

#: Reserved for outcomes. These carry a label or a shape as well as a colour.
STATUS = {
    "safe": "#047857",
    "warn": "#a16207",
    "danger": "#b42318",
    "inert": "#94a3b8",
}

TRUTH = INK              # ground truth: the reference, not a category
COUNTERFACTUAL = "#97a6af"   # what would have happened; never a measurement

SANS = ["Liberation Sans", "FreeSans", "DejaVu Sans"]
MONO = ["Liberation Mono", "DejaVu Sans Mono", "monospace"]


@dataclass(frozen=True)
class Type:
    title = 12.0
    subtitle = 9.0
    axis = 9.0
    tick = 8.5
    label = 8.5      # direct labels on marks
    note = 8.0


TYPE = Type()


def apply() -> None:
    """Set the rcParams every figure in this project inherits."""
    plt.rcParams.update({
        "figure.facecolor": SURFACE,
        "axes.facecolor": SURFACE,
        "savefig.facecolor": SURFACE,
        "font.family": "sans-serif",
        "font.sans-serif": SANS,
        "font.size": TYPE.tick,
        "text.color": INK,
        "axes.edgecolor": RULE,
        "axes.labelcolor": INK_2,
        "axes.labelsize": TYPE.axis,
        "axes.titlesize": TYPE.title,
        "axes.linewidth": 0.8,
        "xtick.color": INK_3,
        "ytick.color": INK_3,
        "xtick.labelsize": TYPE.tick,
        "ytick.labelsize": TYPE.tick,
        "xtick.direction": "out",
        "ytick.direction": "out",
        "legend.frameon": False,
        "legend.fontsize": TYPE.note,
        "lines.solid_capstyle": "round",
        "lines.dash_capstyle": "round",
        "figure.dpi": 150,
        "savefig.dpi": 150,
        "savefig.bbox": "tight",
        "savefig.pad_inches": 0.25,
    })


def style(ax: Axes, *, xlabel: str = "", ylabel: str = "", grid: str = "y") -> Axes:
    """Strip the frame to the two spines that carry information."""
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(RULE)
    ax.tick_params(length=3, width=0.8, pad=3)
    if grid in ("y", "both"):
        ax.grid(axis="y", color=GRID, lw=0.9, zorder=0)
    if grid in ("x", "both"):
        ax.grid(axis="x", color=GRID, lw=0.9, zorder=0)
    ax.set_axisbelow(True)
    if xlabel:
        ax.set_xlabel(xlabel)
    if ylabel:
        ax.set_ylabel(ylabel)
    return ax


def titles(fig: Figure, title: str, subtitle: str = "", x: float = 0.0) -> None:
    """A left-aligned title and one line of subtitle, set on the figure.

    Left-aligned because a centred title over an axis whose left margin is set
    by tick labels is never actually centred on anything the reader can see.
    """
    fig.suptitle("", y=1.0)  # clear any default
    fig.text(x, 1.0, title, ha="left", va="bottom",
             fontsize=TYPE.title, color=INK, fontweight=600)
    if subtitle:
        fig.text(x, 0.972, subtitle, ha="left", va="bottom",
                 fontsize=TYPE.subtitle, color=INK_2)


def direct_labels(ax: Axes, entries: list[tuple[float, str, str]],
                  *, pad: float = 0.012, fontsize: float | None = None) -> None:
    """Label series at the right edge of the axes instead of in a legend box.

    ``entries`` is ``(y_value, text, colour)``. Labels are nudged apart when
    they would collide, which is the whole reason this is a function and not
    three calls to ``ax.text``.
    """
    if not entries:
        return
    lo, hi = ax.get_ylim()
    span = hi - lo or 1.0

    # The gap has to be a *typographic* distance, not a fraction of the data
    # range. Four series that converge to nearly the same value produce four
    # labels a few hundredths of a unit apart, which is several lines of text
    # stacked in the same place however large the axis happens to be.
    fig = ax.get_figure()
    axes_height_pt = ax.get_position().height * fig.get_figheight() * 72.0
    line_pt = (fontsize or TYPE.label) * 1.45
    gap = span * (line_pt / axes_height_pt) if axes_height_pt else span * pad

    ordered = sorted(entries, key=lambda e: e[0])
    placed: list[float] = []
    for y, _, _ in ordered:
        if placed and y - placed[-1] < gap:
            y = placed[-1] + gap
        placed.append(y)
    # If nudging pushed the stack past the top, slide the whole run down.
    overshoot = placed[-1] - (hi - span * pad)
    if overshoot > 0:
        placed = [p - overshoot for p in placed]

    for (_, text, colour), y in zip(ordered, placed):
        ax.annotate(
            text,
            xy=(1.0, y), xycoords=("axes fraction", "data"),
            xytext=(6, 0), textcoords="offset points",
            va="center", ha="left", fontsize=fontsize or TYPE.label,
            color=colour, annotation_clip=False,
        )


def danger_band(ax: Axes, threshold: float, *, above: bool = True,
                label: str = "", colour: str | None = None) -> None:
    """Shade the region a value must not enter, rather than ruling a line at it.

    A dashed line says "here is a number". A band says "this region is the
    failure", which is what a safety limit actually means.
    """
    colour = colour or STATUS["danger"]
    lo, hi = ax.get_ylim()
    if above:
        ax.axhspan(threshold, max(hi, threshold), color=colour, alpha=0.055, zorder=0)
    else:
        ax.axhspan(min(lo, threshold), threshold, color=colour, alpha=0.055, zorder=0)
    ax.axhline(threshold, color=colour, lw=0.9, alpha=0.5, zorder=1)
    if label:
        ax.annotate(
            label,
            xy=(0.0, threshold), xycoords=("axes fraction", "data"),
            xytext=(2, 3 if above else -11), textcoords="offset points",
            fontsize=TYPE.note, color=colour, ha="left",
        )
    ax.set_ylim(lo, hi)


def span(ax: Axes, start: float, end: float, *, label: str = "",
         colour: str | None = None, alpha: float = 0.06) -> None:
    """Shade a stretch of the x axis: an attack window, a blind band."""
    colour = colour or STATUS["danger"]
    ax.axvspan(start, end, color=colour, alpha=alpha, zorder=0, lw=0)
    if label:
        ax.annotate(
            label,
            xy=((start + end) / 2, 1.0), xycoords=("data", "axes fraction"),
            xytext=(0, 4), textcoords="offset points",
            ha="center", va="bottom", fontsize=TYPE.note, color=colour,
        )


def callout(ax: Axes, xy: tuple[float, float], text: str, *,
            offset: tuple[float, float] = (12, 12), colour: str | None = None,
            mono: bool = False) -> None:
    """Point at one value and say what it means."""
    colour = colour or INK_2
    ax.annotate(
        text, xy=xy, xytext=offset, textcoords="offset points",
        fontsize=TYPE.note, color=colour,
        family=MONO if mono else None,
        arrowprops=dict(arrowstyle="-", color=colour, lw=0.8,
                        shrinkA=0, shrinkB=3, alpha=0.7),
    )


def value(ax: Axes, x: float, y: float, text: str, *,
          colour: str | None = None, offset: tuple[float, float] = (0, 6),
          ha: str = "center") -> None:
    """A number set on the mark it belongs to, in tabular figures."""
    ax.annotate(
        text, xy=(x, y), xytext=offset, textcoords="offset points",
        ha=ha, va="bottom", fontsize=TYPE.note, color=colour or INK_2,
        family=MONO,
    )


def footnote(fig: Figure, text: str, x: float = 0.0) -> None:
    """One line under the figure for the caveat a reader needs to have."""
    fig.text(x, -0.02, text, ha="left", va="top",
             fontsize=TYPE.note, color=INK_3)
