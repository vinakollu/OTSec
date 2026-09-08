"""Benign operation of the storage site.

These decide whether the guard is deployable. A storage site does things every
day that look, at the wire, exactly like the attacks in the neighbouring module:
it slams from charge to discharge, it runs units hard enough to derate them, it
takes packs offline, and its state-of-charge estimate jumps discontinuously. A
guard that objects to any of those gets removed within a week, and its detection
rate stops mattering.

Two of these are adversarial by design, chosen because they are the mirror
images of specific attacks:

``frequency_response`` is command-for-command the same shape as ``ramp_slam``.
The only thing separating them is grid frequency, which is what B4 conditions
on. If B4 is wrong in either direction, one of this pair is scored incorrectly.

``soc_recalibration`` is a legitimate discontinuity in reported state of charge
— real battery management systems re-anchor their estimate when a pack reaches a
known point, and the correction can be several percent in a single sample. It
looks precisely like the opening move of ``soc_spoof``.
"""

from __future__ import annotations

from ..bess.site import GridEvent
from ..bess.types import PackReport, SiteCommandKind, SiteObservation
from .site_base import ScheduledSiteCommand as Cmd
from .site_base import SiteDispatchController, SiteScenario

DEVICES = [f"MP{i + 1:02d}" for i in range(16)]


def _controller(schedule, poi_limit_mw: float = 20.0, ramp_mw_s: float = 0.8):
    return SiteDispatchController(
        target_schedule=schedule,
        devices=DEVICES,
        poi_limit_mw=poi_limit_mw,
        ramp_mw_s=ramp_mw_s,
    )


def scheduled_dispatch() -> SiteScenario:
    """An ordinary arbitrage day: charge overnight, discharge on peak.

    The bulk of benign traffic. If the guard raises anything here it is not
    deployable, full stop.
    """
    return SiteScenario(
        name="scheduled_dispatch",
        category="normal",
        description="Routine energy arbitrage: charge, idle, discharge on the peak.",
        duration_s=1200.0,
        initial_soc=0.45,
        controller=_controller(
            [(0.0, -12.0), (300.0, 0.0), (500.0, 15.0), (900.0, 5.0)]
        ),
        seed=31,
    )


def frequency_response() -> SiteScenario:
    """A real under-frequency event and the fast response it calls for.

    Deliberately the same command shape as the ``ramp_slam`` attack. The grid
    drops to 59.65 Hz and the site swings from charging to near-full discharge
    in a few seconds, which is exactly what it is contracted to do and what the
    grid needs. B4's frequency exemption is the only thing that keeps this from
    being scored as an attack.
    """
    commands = [
        Cmd(t=200.0 + i * 0.05, kind=SiteCommandKind.PACK_POWER, value=1.15, device=dev)
        for i, dev in enumerate(DEVICES)
    ]
    return SiteScenario(
        name="frequency_response",
        category="normal",
        description=(
            "Under-frequency event at 59.65 Hz and the contracted fast response: "
            "charge to 18.4 MW export in under a second, inside the export limit."
        ),
        duration_s=600.0,
        initial_soc=0.60,
        commands=commands,
        controller=_controller([(0.0, -8.0), (260.0, 6.0)]),
        grid_events=[GridEvent(start_s=198.0, end_s=280.0, frequency_hz=59.65)],
        seed=32,
    )


def thermal_derate_day() -> SiteScenario:
    """A hot day: units heat up and the controller correctly backs them off.

    The temperatures climb into the derate band and the dispatch controller
    reduces set-points accordingly. Everything here is the system working as
    designed, and B5 must stay quiet through all of it — the trajectory never
    reaches the trip, and the commands that reduce power are improvements on what
    is held, not degradations.
    """
    return SiteScenario(
        name="thermal_derate_day",
        category="normal",
        description=(
            "Sustained high output on a hot day; units enter thermal derate and the "
            "controller reduces set-points in response."
        ),
        duration_s=1800.0,
        initial_soc=0.85,
        initial_temp_c=38.0,
        controller=_controller([(0.0, 19.0), (1200.0, 12.0)]),
        seed=33,
        dt_s=1.0,
    )


def pack_maintenance() -> SiteScenario:
    """Three units taken out of service; the rest pick up the load.

    The aggregate changes for an entirely legitimate reason, and the remaining
    units' set-points all rise at once. A balance rule that reasoned about
    individual increases without accounting for the units leaving service would
    object to every one of them.
    """
    commands = [
        Cmd(t=300.0 + i * 5.0, kind=SiteCommandKind.PACK_ENABLE, value=0.0, device=dev)
        for i, dev in enumerate(DEVICES[:3])
    ] + [
        Cmd(t=900.0 + i * 5.0, kind=SiteCommandKind.PACK_ENABLE, value=1.0, device=dev)
        for i, dev in enumerate(DEVICES[:3])
    ]
    return SiteScenario(
        name="pack_maintenance",
        category="normal",
        description=(
            "Three units taken offline for maintenance and returned, with the fleet "
            "rebalancing around them."
        ),
        duration_s=1200.0,
        initial_soc=0.55,
        commands=commands,
        controller=_controller([(0.0, 14.0)]),
        seed=34,
    )


def soc_recalibration() -> SiteScenario:
    """A legitimate step change in reported state of charge.

    Battery management systems re-anchor their SoC estimate at known points —
    typically at the top of a charge, where the cell voltage curve is steep
    enough to be informative. The correction lands in one sample and can be
    several percent.

    This is the false-positive test for B2. The energy-balance detector is
    looking for exactly this signature, and the thing that separates it from
    ``soc_spoof`` is that the correction happens once and the reported value
    then tracks the energy balance again, rather than holding an offset.
    """

    def recalibrate(t: float, obs: SiteObservation) -> SiteObservation:
        if not 600.0 <= t < 601.0:
            return obs
        packs = tuple(
            PackReport(
                device=p.device,
                p_mw=p.p_mw,
                q_mvar=p.q_mvar,
                soc=min(1.0, p.soc + 0.04),
                temp_c=p.temp_c,
                online=p.online,
                cooling_enabled=p.cooling_enabled,
            )
            for p in obs.packs
        )
        return SiteObservation(
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

    return SiteScenario(
        name="soc_recalibration",
        category="normal",
        description=(
            "Battery management re-anchors its state-of-charge estimate at the top "
            "of charge: a legitimate 4-point step in one sample."
        ),
        duration_s=1000.0,
        initial_soc=0.80,
        controller=_controller([(0.0, -6.0), (700.0, 8.0)]),
        telemetry_attack=recalibrate,
        seed=35,
    )


def planned_black_start() -> SiteScenario:
    """A synchronised close onto a dead bus, then normal ramp-up.

    Closing a breaker is the highest-consequence routine action on the site, and
    it is legitimate here: the bus is dead, so there is nothing to synchronise
    against and the close is safe. B7 must permit it. A rule that demanded a
    synchronism check unconditionally would make black start impossible, which
    is the state a site is in after exactly the kind of event it exists to help
    with.
    """
    return SiteScenario(
        name="planned_black_start",
        category="normal",
        description=(
            "Planned energisation: breaker closed onto a dead bus, then the fleet "
            "ramps up normally."
        ),
        duration_s=600.0,
        initial_soc=0.70,
        commands=[
            Cmd(t=60.0, kind=SiteCommandKind.BREAKER, value=1.0,
                zone="control", protocol="dnp3", source="sitectrl"),
        ],
        controller=_controller([(0.0, 0.0), (120.0, 12.0)]),
        seed=36,
    )


def curtailment_recovery() -> SiteScenario:
    """The export limit is cut, and the operator walks the site back down.

    The counterfactual test's reason for existing, and the realistic way a site
    ends up over its limit: not by someone commanding it, but by the limit
    moving. The site is dispatched to 20 MW, which is legal; the utility then
    issues a curtailment order reducing the export limit to 16 MW, and the site
    is instantly non-compliant without a single new set-point.

    Every command after that is issued while over the limit, and every one
    *reduces* the excursion. A guard that asked "does this command leave the
    site over the limit?" would block the entire recovery and strand the site
    outside its new limit — the failure the tank version's R3 was rewritten to
    avoid.

    Note what this scenario cannot do: reach the over-limit state by commanding
    it. With the guard enforcing, that path is blocked, correctly. An earlier
    draft tried it anyway and scored the guard's correct refusal as a false
    alarm.
    """
    commands = [
        Cmd(t=20.0 + i * 4.0, kind=SiteCommandKind.PACK_POWER, value=1.25, device=dev)
        for i, dev in enumerate(DEVICES)
    ] + [
        Cmd(t=200.0, kind=SiteCommandKind.POI_LIMIT, value=16.0,
            zone="engineering", conduit="engineering_to_control",
            protocol="rest", source="jump01"),
    ] + [
        Cmd(t=240.0 + i * 0.5, kind=SiteCommandKind.PACK_POWER, value=1.05, device=dev)
        for i, dev in enumerate(DEVICES)
    ] + [
        Cmd(t=300.0 + i * 0.5, kind=SiteCommandKind.PACK_POWER, value=0.92, device=dev)
        for i, dev in enumerate(DEVICES)
    ]
    return SiteScenario(
        name="curtailment_recovery",
        category="normal",
        description=(
            "Utility cuts the export limit from 20 MW to 16 MW; the operator walks "
            "the fleet down in two steps. Every command is issued while over the "
            "limit and every one improves it."
        ),
        duration_s=420.0,
        initial_soc=0.60,
        commands=commands,
        controller=None,
        seed=37,
    )


def all_normal() -> list[SiteScenario]:
    return [
        scheduled_dispatch(),
        frequency_response(),
        thermal_derate_day(),
        pack_maintenance(),
        soc_recalibration(),
        planned_black_start(),
        curtailment_recovery(),
    ]
