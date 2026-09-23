"""Scoring and tables for the device matrix.

Three numbers are reported separately on purpose.

*Detected* counts an attack the guard objected to at all, by a physics rule or
by the wire policy. *Damage prevented* counts only the pairs where the attack
actually damaged the plant with the guard removed, which is the only place the
phrase means anything. *Stopped at the wire* separates refusals that came from
the policy rather than the rules, so the rules' contribution can be read on its
own rather than inflated by an access check.

The fourth column exists because of what the RTU does. Some executors protect
themselves: the RTU opens its pump contactor above 1.70 m whatever it was told.
On those pairs an attack can be harmless without the guard doing anything, and
counting it as a save would credit the guard for the device's own interlock.
Those pairs are reported as "no damage to prevent".
"""

from __future__ import annotations

import json
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Iterable

from .matrix import PairResult


def _pct(n: int, d: int) -> str:
    return f"{100.0 * n / d:.0f}%" if d else "n/a"


def summarise(results: list[PairResult]) -> dict:
    detected = [r for r in results if r.guarded.detected]
    damaging = [r for r in results if r.unguarded.damaged]
    prevented = [r for r in damaging if not r.guarded.damaged]
    wire_only = [r for r in results if r.stopped_at_wire]
    latencies = [v for r in results for v in r.guarded.latency_us]

    return {
        "pairs": len(results),
        "detected": len(detected),
        "damaging_unguarded": len(damaging),
        "damage_prevented": len(prevented),
        "stopped_at_wire_only": len(wire_only),
        "still_damaged": [
            f"{r.scenario}/{r.source}/{r.executor}" for r in damaging if r.guarded.damaged
        ],
        "undetected": [
            f"{r.scenario}/{r.source}/{r.executor}" for r in results if not r.guarded.detected
        ],
        "wire_latency_us": {
            "count": len(latencies),
            "p50": statistics.median(latencies) if latencies else 0.0,
            "p95": (sorted(latencies)[int(0.95 * (len(latencies) - 1))] if latencies else 0.0),
            "p99": (sorted(latencies)[int(0.99 * (len(latencies) - 1))] if latencies else 0.0),
        },
    }


def format_summary(results: list[PairResult]) -> str:
    s = summarise(results)
    lat = s["wire_latency_us"]
    lines = [
        "Device matrix",
        "=" * 78,
        f"  Sender/receiver pairs run     {s['pairs']}",
        f"  Attacks the guard objected to {s['detected']}/{s['pairs']}  "
        f"({_pct(s['detected'], s['pairs'])})",
        f"  Damaged the plant unguarded   {s['damaging_unguarded']}",
        f"  Of those, damage prevented    {s['damage_prevented']}/{s['damaging_unguarded']}  "
        f"({_pct(s['damage_prevented'], s['damaging_unguarded'])})",
        f"  Stopped at the wire first     {s['stopped_at_wire_only']}  "
        f"(run --ablation to see how many of those the rules also catch)",
        f"  Added round trip              p50 {lat['p50']:.0f} us, p95 {lat['p95']:.0f} us, "
        f"p99 {lat['p99']:.0f} us  (n={lat['count']})",
    ]
    if s["still_damaged"]:
        lines.append("  Damaged even with the guard   " + ", ".join(s["still_damaged"]))
    if s["undetected"]:
        lines.append("  Not objected to at all        " + ", ".join(s["undetected"]))
    return "\n".join(lines)


def format_matrix(results: list[PairResult]) -> str:
    """One row per scenario, one column per executor, cells listing sources."""
    executors = sorted({r.executor for r in results})
    by_scenario: dict[str, dict[str, list[PairResult]]] = defaultdict(lambda: defaultdict(list))
    for r in results:
        by_scenario[r.scenario][r.executor].append(r)

    width = 16
    head = "scenario".ljust(22) + "".join(e.ljust(width) for e in executors)
    lines = ["", "Detection by sender and receiver", "-" * 78, head, "-" * 78]
    for scenario in sorted(by_scenario):
        row = scenario.ljust(22)
        for executor in executors:
            pairs = by_scenario[scenario].get(executor)
            if not pairs:
                row += "-".ljust(width)
                continue
            hit = sum(1 for p in pairs if p.guarded.detected)
            row += f"{hit}/{len(pairs)}".ljust(width)
        lines.append(row)
    lines.append("")
    lines.append("Cells are: pairs where the guard objected / sender types tried.")
    return "\n".join(lines)


def format_pairs(results: list[PairResult]) -> str:
    lines = [
        "",
        "Every pair",
        "-" * 110,
        f"{'scenario':<22}{'sender':<17}{'receiver':<9}{'detected':<10}"
        f"{'peak m':>8}{'unguard':>9}  {'stopped by'}",
        "-" * 110,
    ]
    for r in sorted(results, key=lambda x: (x.scenario, x.executor, x.source)):
        g, u = r.guarded, r.unguarded
        if g.rules_fired and g.wire_reasons:
            stopped = ",".join(g.rules_fired) + " + " + ",".join(g.wire_reasons)
        elif g.rules_fired:
            stopped = ",".join(g.rules_fired)
        elif g.wire_reasons:
            stopped = ",".join(g.wire_reasons)
            stopped += " (policy, not a rule)"
        else:
            stopped = "nothing"
        note = ""
        if not u.damaged:
            note = "  [no damage to prevent]"
            if u.interlock_trips:
                note = "  [device interlock held it]"
        lines.append(
            f"{r.scenario:<22}{r.source:<17}{r.executor:<9}"
            f"{('yes' if g.detected else 'NO'):<10}"
            f"{g.peak_level_m:>8.2f}{u.peak_level_m:>9.2f}  {stopped}{note}"
        )
    return "\n".join(lines)


def format_benign(results: list[PairResult]) -> str:
    lines = [
        "",
        "Ordinary traffic, every sender at once",
        "-" * 78,
        f"{'receiver':<12}{'writes':>8}{'refused':>9}{'flagged by':>14}",
        "-" * 78,
    ]
    for r in sorted(results, key=lambda x: x.executor):
        g = r.guarded
        flagged = ",".join(g.rules_fired + g.wire_reasons) or "-"
        lines.append(
            f"{r.executor:<12}{g.benign_writes:>8}{g.benign_refused:>9}{flagged:>14}"
        )
    return "\n".join(lines)


def format_ablation(on: list[PairResult], off: list[PairResult]) -> str:
    """What the physics rules catch once the wire policy stops helping."""
    off_by_key = {(r.scenario, r.source, r.executor): r for r in off}

    # The number worth reporting: the policy runs first, so it takes credit for
    # everything it stops. Disabling it says how much of that the rules would
    # have caught anyway, and how much the policy is actually carrying.
    stopped_first = [r for r in on if r.stopped_at_wire]
    still_needed, rules_cover = [], []
    for r in stopped_first:
        other = off_by_key.get((r.scenario, r.source, r.executor))
        if other is None:
            continue
        (rules_cover if other.guarded.rules_fired else still_needed).append(r)
    missed = [r for r in off if not r.guarded.detected]
    damaged = [r for r in off if r.unguarded.damaged and r.guarded.damaged]

    lines = [
        "",
        "Wire policy on and off",
        "-" * 92,
        "With the policy off, every frame the rules cannot judge is forwarded, so",
        "what remains is what the physics rules catch on their own.",
        "",
        f"  Stopped at the wire with the policy on   {len(stopped_first)}",
        f"  Of those, a physics rule catches anyway  {len(rules_cover)}",
        f"  Of those, the policy is load-bearing     {len(still_needed)}"
        + (f"  ({', '.join(sorted({r.scenario for r in still_needed}))})"
           if still_needed else ""),
        f"  Undetected with the policy off           {len(missed)}",
        f"  Damaged with the policy off              {len(damaged)}",
        "",
        f"{'scenario':<22}{'sender':<17}{'receiver':<9}{'policy on':<24}{'policy off'}",
        "-" * 92,
    ]
    for r in sorted(on, key=lambda x: (x.scenario, x.executor, x.source)):
        other = off_by_key.get((r.scenario, r.source, r.executor))
        if other is None:
            continue

        def describe(pair: PairResult) -> str:
            g = pair.guarded
            parts = list(g.rules_fired) + [f"{w}*" for w in g.wire_reasons]
            label = ",".join(parts) if parts else "not detected"
            return f"{label}{'' if not g.damaged else ' (damaged)'}"

        lines.append(
            f"{r.scenario:<22}{r.source:<17}{r.executor:<9}"
            f"{describe(r):<24}{describe(other)}"
        )
    lines.append("")
    lines.append("* refused by the wire policy rather than by a physics rule.")
    return "\n".join(lines)


def write_report(
    results: list[PairResult],
    benign: list[PairResult],
    out_dir: Path,
    ablation: list[PairResult] | None = None,
) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "summary": summarise(results),
        "benign": summarise(benign),
        "pairs": [
            {
                "scenario": r.scenario,
                "source": r.source,
                "executor": r.executor,
                "detected": r.guarded.detected,
                "rules": list(r.guarded.rules_fired),
                "wire_reasons": list(r.guarded.wire_reasons),
                "guarded_damaged": r.guarded.damaged,
                "unguarded_damaged": r.unguarded.damaged,
                "guarded_peak_m": round(r.guarded.peak_level_m, 3),
                "unguarded_peak_m": round(r.unguarded.peak_level_m, 3),
                "attack_accepted": r.guarded.attack.accepted,
                "attack_attempted": r.guarded.attack.attempted,
                "trips": r.guarded.trips,
                "device_interlock_trips": r.unguarded.interlock_trips,
            }
            for r in results
        ],
    }
    if ablation is not None:
        payload["ablation_policy_off"] = summarise(ablation)
    path = out_dir / "matrix_metrics.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True))
    return path
