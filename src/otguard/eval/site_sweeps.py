"""Boundary experiments: where the site guard stops working.

A scenario suite the author wrote scoring 13/13 is not evidence that a design
generalises. It is evidence that the design handles the thirteen cases its
author thought of. What tells you something is a sweep — vary one attacker
parameter continuously and find the value at which detection fails — because
the boundary is a property of the mechanism rather than of the example.

Three sweeps here, chosen because each targets a different rule's claim.

``sweep_meter_bias``
    The headline claim. The tank version's stealthy-bias result was that a
    residual detector bounds an attacker's *rate*: ramp slowly enough and the
    CUSUM never accumulates, so the attack succeeds outright. Cross-source
    voting should bound *displacement* instead — the slow attacker still gets
    caught, just later. The sweep reports bias-at-detection against ramp rate;
    if the claim holds, that column is roughly flat over orders of magnitude.
    Run with voting disabled it reproduces the tank's blind spot, which is the
    control that makes the comparison mean anything.

``sweep_soc_offset``
    B2's discriminator between a battery-management re-anchor and a spoof.
    Both are a step followed by a constant offset, so the question is what
    actually separates them and at what magnitude.

``sweep_dispatch_creep``
    The adversarial case for B3. Its incremental test fires only when a command
    makes an existing excursion worse, which is what keeps it from blocking a
    recovery — and is also an escape hatch. An attacker who creeps upward in
    small enough steps stays under the margin on every individual write. The
    sweep finds the step size at which that stops working and, more usefully,
    how far over the export limit the site gets before it does.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass

from ..bess import BessSite
from ..bess.types import PackReport, SiteCommand, SiteCommandKind, SiteObservation
from ..config import Config
from ..guard.site_guard import SiteGuard

DEVICES = [f"MP{i + 1:02d}" for i in range(16)]


@dataclass
class SweepPoint:
    """One (parameter, outcome) pair."""

    parameter: float
    detected_at_s: float | None = None
    displacement_at_detection: float = 0.0
    peak_excursion: float = 0.0
    damaged: bool = False
    named_source: str = ""
    rules: tuple[str, ...] = ()

    @property
    def detected(self) -> bool:
        return self.detected_at_s is not None


def _with_crosssource(config: Config, enabled: bool) -> Config:
    bess = config.bess
    return dataclasses.replace(
        config,
        bess=dataclasses.replace(
            bess,
            guard=dataclasses.replace(
                bess.guard,
                crosssource=dataclasses.replace(bess.guard.crosssource, enabled=enabled),
            ),
        ),
    )


def sweep_meter_bias(
    config: Config,
    rates_mw_s: list[float],
    duration_s: float = 2400.0,
    voting: bool = True,
    hold_mw: float = 1.0,
) -> list[SweepPoint]:
    """Bias the revenue meter at a range of ramp rates.

    Reports where the vote catches it and how much bias had accumulated by
    then. The interesting column is the displacement, not the time.
    """
    cfg = _with_crosssource(config, voting)
    out: list[SweepPoint] = []

    for rate in rates_mw_s:
        site = BessSite(cfg.bess.site, cfg.bess.safety, cfg.bess.pack, seed=5)
        guard = SiteGuard(cfg)
        for unit in site.packs:
            unit.set_power(hold_mw)
        for est in guard.estimators.values():
            est.note_power(hold_mw)

        point = SweepPoint(parameter=rate)
        t = 0.0
        dt = cfg.bess.site.dt_s
        while t < duration_s:
            site.step(dt, t)
            t += dt
            honest = site.observe(t)
            bias = rate * t
            reported = SiteObservation(
                t=honest.t,
                packs=honest.packs,
                poi_meter_mw=honest.poi_meter_mw - bias,
                relay_mw=honest.relay_mw,
                frequency_hz=honest.frequency_hz,
                voltage_pu=honest.voltage_pu,
                breaker=honest.breaker,
                bus_live=honest.bus_live,
                fault_current_a=honest.fault_current_a,
            )
            guard.observe(reported)
            point.peak_excursion = bias
            if guard.voter.alarm is not None and not point.detected:
                point.detected_at_s = t
                point.displacement_at_detection = bias
                point.named_source = guard.voter.alarm.value
        out.append(point)
    return out


def sweep_soc_offset(
    config: Config,
    offsets: list[float],
    transient: bool = False,
    duration_s: float = 1500.0,
) -> list[SweepPoint]:
    """Offset reported state of charge, held or as a single-sample step."""
    out: list[SweepPoint] = []
    dt = config.bess.site.dt_s

    for offset in offsets:
        site = BessSite(config.bess.site, config.bess.safety, config.bess.pack, seed=9, initial_soc=0.55)
        guard = SiteGuard(config, initial_soc=0.55)
        for unit in site.packs:
            unit.set_power(0.5)
        for est in guard.estimators.values():
            est.note_power(0.5)

        point = SweepPoint(parameter=offset)
        t = 0.0
        while t < duration_s:
            site.step(dt, t)
            t += dt
            obs = site.observe(t)
            active = (600.0 <= t < 600.0 + dt) if transient else (t >= 200.0)
            if active:
                packs = tuple(
                    PackReport(
                        device=p.device,
                        p_mw=p.p_mw,
                        q_mvar=p.q_mvar,
                        soc=min(1.0, p.soc + offset),
                        temp_c=p.temp_c,
                        online=p.online,
                        cooling_enabled=p.cooling_enabled,
                    )
                    for p in obs.packs
                )
                obs = SiteObservation(
                    t=obs.t,
                    packs=packs,
                    poi_meter_mw=obs.poi_meter_mw,
                    relay_mw=obs.relay_mw,
                    frequency_hz=obs.frequency_hz,
                    voltage_pu=obs.voltage_pu,
                    breaker=obs.breaker,
                    bus_live=obs.bus_live,
                    fault_current_a=obs.fault_current_a,
                )
            guard.observe(obs)
            est = guard.estimators["MP01"].estimate
            point.peak_excursion = max(point.peak_excursion, est.soc_cusum)
            if est.integrity_alarm and not point.detected:
                point.detected_at_s = t
        out.append(point)
    return out


def sweep_dispatch_creep(
    config: Config,
    step_sizes_mw: list[float],
    interval_s: float = 20.0,
    duration_s: float = 2000.0,
) -> list[SweepPoint]:
    """Creep every unit's set-point upward and see how far the site gets.

    ``peak_excursion`` is megawatts over the *export limit* at the point of
    interconnection, which is the number that matters commercially, and
    ``damaged`` records whether the transformer rating was passed.
    """
    out: list[SweepPoint] = []
    dt = config.bess.site.dt_s
    limit = config.bess.site.poi_limit_mw

    for step in step_sizes_mw:
        site = BessSite(config.bess.site, config.bess.safety, config.bess.pack, seed=23)
        guard = SiteGuard(config)
        point = SweepPoint(parameter=step)

        value = 1.00
        t = 0.0
        next_write = 0.0
        fired: set[str] = set()

        # Establish the baseline the creep starts from, gently enough that the
        # ramp rule has nothing to say about it. Without this the sweep measures
        # B4 catching the step from zero on the first write — which it does, at
        # every step size, making the result look like a uniform detection and
        # telling you nothing about B3.
        baseline_until = 120.0
        while t < baseline_until:
            site.step(dt, t)
            t += dt
            guard.observe(site.observe(t))
            if t >= next_write:
                next_write += 4.0
                ramped = min(value, 0.05 * next_write / 4.0)
                for device in DEVICES:
                    command = SiteCommand(
                        t=t, kind=SiteCommandKind.PACK_POWER, value=round(ramped, 4),
                        device=device, source="sitectrl", zone="control",
                        protocol="modbus_tcp",
                    )
                    if guard.check(command).allowed:
                        unit = site.pack(device)
                        if unit is not None:
                            unit.set_power(round(ramped, 4))
        guard.reset_log()
        guard.acknowledge()

        next_write = t + interval_s
        while t < duration_s:
            site.step(dt, t)
            t += dt
            guard.observe(site.observe(t))

            if t >= next_write:
                next_write += interval_s
                value = round(value + step, 4)
                for device in DEVICES:
                    command = SiteCommand(
                        t=t,
                        kind=SiteCommandKind.PACK_POWER,
                        value=value,
                        device=device,
                        source="scada01",
                        zone="control",
                        protocol="modbus_tcp",
                    )
                    verdict = guard.check(command)
                    if verdict.flagged:
                        fired.update(verdict.rule_ids)
                        if not point.detected:
                            point.detected_at_s = t
                    if verdict.allowed:
                        unit = site.pack(device)
                        if unit is not None:
                            unit.set_power(value)

            over = abs(site.state.p_poi_mw) - limit
            point.peak_excursion = max(point.peak_excursion, over)
            if site.damaged:
                point.damaged = True
        point.rules = tuple(sorted(fired))
        point.displacement_at_detection = point.peak_excursion
        out.append(point)
    return out
