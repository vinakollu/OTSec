"""Attacks against the storage site.

The threat model is the same one the tank version fixed in week two, moved up a
layer: **the attacker owns the SCADA front end or the engineering workstation.**
They can send any command the site controller could send, read all telemetry,
and — where noted — modify what the field devices report on their way back. They
do not have code execution on the Megapack controllers themselves, and they
cannot alter the cells, the transformer or the CTs.

That boundary is what makes the whole approach work and it is worth being blunt
about: an attacker who *does* own the field devices can make all three power
measurements agree on a lie, and rule B6 fails completely. What the guard buys
is that compromising three independent measurement chains simultaneously is a
much larger operation than writing a set-point.

Each scenario is labelled with the rules expected to object. That is
documentation, not an assertion — the evaluation scores what actually fires, and
one scenario (``stealth_dispatch_creep``) is in the suite specifically because
it is hard.
"""

from __future__ import annotations

from ..bess.site import GridEvent
from ..bess.types import SiteCommandKind, SiteObservation, PackReport
from .site_base import ScheduledSiteCommand as Cmd
from .site_base import SiteDispatchController, SiteScenario

DEVICES = [f"MP{i + 1:02d}" for i in range(16)]


def _bias_source(source: str, ramp_mw_s: float, start_s: float = 60.0):
    """Telemetry attack: slowly bias one measurement chain."""

    def attack(t: float, obs: SiteObservation) -> SiteObservation:
        if t < start_s:
            return obs
        bias = ramp_mw_s * (t - start_s)
        return SiteObservation(
            t=obs.t,
            packs=obs.packs,
            poi_meter_mw=obs.poi_meter_mw - (bias if source == "meter" else 0.0),
            relay_mw=obs.relay_mw - (bias if source == "relay" else 0.0),
            frequency_hz=obs.frequency_hz,
            voltage_pu=obs.voltage_pu,
            breaker=obs.breaker,
            bus_live=obs.bus_live,
            fault_current_a=obs.fault_current_a,
        )

    return attack


def _spoof_soc(devices: list[str], offset: float, start_s: float = 60.0, ramp: float = 0.0):
    """Telemetry attack: report a healthier state of charge than is real."""

    def attack(t: float, obs: SiteObservation) -> SiteObservation:
        if t < start_s:
            return obs
        delta = offset + ramp * (t - start_s)
        packs = tuple(
            PackReport(
                device=p.device,
                p_mw=p.p_mw,
                q_mvar=p.q_mvar,
                soc=min(1.0, p.soc + delta) if p.device in devices else p.soc,
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

    return attack


def _spoof_temperature(devices: list[str], hold_c: float, start_s: float = 30.0):
    """Telemetry attack: pin reported temperature so the derate never engages."""

    def attack(t: float, obs: SiteObservation) -> SiteObservation:
        if t < start_s:
            return obs
        packs = tuple(
            PackReport(
                device=p.device,
                p_mw=p.p_mw,
                q_mvar=p.q_mvar,
                soc=p.soc,
                temp_c=hold_c if p.device in devices else p.temp_c,
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

    return attack


def _baseline_controller(target: float = 8.0) -> SiteDispatchController:
    return SiteDispatchController(
        target_schedule=[(0.0, target)], devices=DEVICES, poi_limit_mw=20.0
    )


# ----------------------------------------------------------------------
# 1. Straightforward export violation
# ----------------------------------------------------------------------


def poi_export_violation() -> SiteScenario:
    """Drive every unit to rated power, well past the interconnection limit.

    The unsubtle version, and the one that does real damage fastest: sixteen
    units at 1.927 MW is 30.8 MW through a 25 MVA transformer.
    """
    commands = [
        Cmd(t=120.0 + i * 0.2, kind=SiteCommandKind.PACK_POWER, value=1.9, device=dev, malicious=True)
        for i, dev in enumerate(DEVICES)
    ]
    return SiteScenario(
        name="poi_export_violation",
        category="attack",
        description=(
            "Attacker writes rated power to all sixteen units, taking the point of "
            "interconnection past the transformer rating."
        ),
        duration_s=400.0,
        commands=commands,
        controller=_baseline_controller(),
        attack_window=(120.0, 400.0),
        expected_rules=("B3",),
        controller_stops_at=115.0,
        seed=11,
    )


# ----------------------------------------------------------------------
# 2. The distributed version — individually plausible, collectively not
# ----------------------------------------------------------------------


def aggregate_stealth() -> SiteScenario:
    """Spread the excess across the fleet so no single set-point looks wrong.

    This is the scenario that justifies reasoning at the site level. Each unit is
    asked for 1.45 MW — comfortably inside its 1.927 MW capability, unremarkable
    on its own, and exactly the kind of value a per-device rule waves through.
    The sum is 23.2 MW against a 20 MW limit and a 25 MVA transformer.

    No per-unit rule can see this. Only the conservation law across the fleet
    can, which is why B3 evaluates the *aggregate* implied by each command rather
    than the command in isolation.
    """
    commands = [
        Cmd(t=150.0 + i * 1.5, kind=SiteCommandKind.PACK_POWER, value=1.45, device=dev, malicious=True)
        for i, dev in enumerate(DEVICES)
    ]
    return SiteScenario(
        name="aggregate_stealth",
        category="attack",
        description=(
            "Sixteen individually plausible set-points of 1.45 MW whose aggregate "
            "exceeds the export limit. Invisible to any per-device check."
        ),
        duration_s=500.0,
        commands=commands,
        controller=_baseline_controller(6.0),
        attack_window=(150.0, 500.0),
        expected_rules=("B3",),
        controller_stops_at=145.0,
        seed=12,
    )


# ----------------------------------------------------------------------
# 3. Limit tampering through the REST API
# ----------------------------------------------------------------------


def rest_limit_tamper() -> SiteScenario:
    """Raise the export limit, then dispatch legally against the new one.

    The attacker never sends a command that violates a limit. They change the
    limit first, with a valid engineer token, and then every subsequent dispatch
    is compliant by the site controller's own reckoning.

    The guard's answer is that a limit is only meaningful up to the iron it
    protects: 40 MW through a 25 MVA transformer is not authorisable by anyone.
    """
    commands = [
        Cmd(
            t=100.0,
            kind=SiteCommandKind.POI_LIMIT,
            value=40.0,
            malicious=True,
            zone="engineering",
            conduit="engineering_to_control",
            protocol="rest",
            source="jump01",
            note="valid engineer token, stolen from the jump server",
        )
    ] + [
        Cmd(t=130.0 + i * 0.5, kind=SiteCommandKind.PACK_POWER, value=1.8, device=dev, malicious=True)
        for i, dev in enumerate(DEVICES)
    ]
    return SiteScenario(
        name="rest_limit_tamper",
        category="attack",
        description=(
            "Export limit raised to 40 MW over REST with a valid engineer token, "
            "then the fleet is dispatched 'legally' against the tampered limit."
        ),
        duration_s=400.0,
        commands=commands,
        controller=_baseline_controller(),
        attack_window=(100.0, 400.0),
        expected_rules=("B3",),
        controller_stops_at=125.0,
        seed=13,
    )


# ----------------------------------------------------------------------
# 4. Capability override at low state of charge
# ----------------------------------------------------------------------


def capability_override() -> SiteScenario:
    """Command rated discharge from units that are nearly empty.

    Starts the fleet at 8% SoC, below the derate knee. The units cannot deliver
    rated power and commanding it produces heat and a fault trip rather than
    megawatts. The capability the guard checks against is recomputed from state,
    not read from a register the attacker could raise.
    """
    commands = [
        Cmd(t=60.0 + i * 0.2, kind=SiteCommandKind.PACK_POWER, value=1.9, device=dev, malicious=True)
        for i, dev in enumerate(DEVICES[:8])
    ]
    return SiteScenario(
        name="capability_override",
        category="attack",
        description=(
            "Rated discharge commanded from units at 8% state of charge, below the "
            "capability knee."
        ),
        duration_s=300.0,
        initial_soc=0.08,
        commands=commands,
        attack_window=(60.0, 300.0),
        expected_rules=("B1",),
        seed=14,
    )


# ----------------------------------------------------------------------
# 5. Ramp slam with no grid event to justify it
# ----------------------------------------------------------------------


def ramp_slam() -> SiteScenario:
    """Full charge to full discharge with the grid sitting at nominal.

    The mirror image of ``frequency_response`` in the benign set. Physically the
    same command sequence; the difference is entirely in whether the grid asked
    for it. If the guard cannot tell these two apart it has either broken the
    site's revenue service or missed the attack.
    """
    commands = [
        Cmd(t=100.0 + i * 0.1, kind=SiteCommandKind.PACK_POWER, value=-1.8, device=dev, malicious=True)
        for i, dev in enumerate(DEVICES)
    ] + [
        Cmd(t=104.0 + i * 0.1, kind=SiteCommandKind.PACK_POWER, value=1.8, device=dev, malicious=True)
        for i, dev in enumerate(DEVICES)
    ]
    return SiteScenario(
        name="ramp_slam",
        category="attack",
        description=(
            "Fleet slammed from full charge to full discharge in four seconds with "
            "grid frequency at nominal — no fast-response event to justify it."
        ),
        duration_s=300.0,
        commands=commands,
        controller=_baseline_controller(4.0),
        attack_window=(100.0, 300.0),
        expected_rules=("B4", "B3"),
        controller_stops_at=95.0,
        seed=15,
    )


# ----------------------------------------------------------------------
# 6. Thermal management shutdown
# ----------------------------------------------------------------------


def cooling_shutdown() -> SiteScenario:
    """Switch off thermal management and hold the units at power.

    No set-point exceeds any limit. The packs keep reporting legal power and a
    plausible state of charge. What changes is a boolean nobody watches, and the
    temperature does the rest — full power with cooling off leaves the envelope
    in about half an hour.

    Caught by the lookahead rather than by a threshold: B5 projects the thermal
    trajectory under the commanded cooling state, so the objection lands when the
    fans are commanded off, not when the pack is already hot.
    """
    commands = [
        Cmd(t=90.0 + i * 0.2, kind=SiteCommandKind.PACK_COOLING, value=0.0, device=dev, malicious=True)
        for i, dev in enumerate(DEVICES[:6])
    ]
    return SiteScenario(
        name="cooling_shutdown",
        category="attack",
        description=(
            "Thermal management commanded off on six units while they hold rated "
            "power. Every power set-point remains legal."
        ),
        duration_s=2400.0,
        commands=commands,
        controller=SiteDispatchController(
            target_schedule=[(0.0, 18.0)], devices=DEVICES, poi_limit_mw=20.0
        ),
        attack_window=(90.0, 2400.0),
        expected_rules=("B5",),
        seed=16,
        dt_s=1.0,
    )


# ----------------------------------------------------------------------
# 7. State-of-charge spoofing to force over-discharge
# ----------------------------------------------------------------------


def soc_spoof() -> SiteScenario:
    """Report a healthy SoC while the units are actually being emptied.

    The site controller keeps dispatching because the fleet looks half full. The
    real cells go to deep discharge. Detection comes from the energy balance:
    the guard integrates the power it has *accepted* and knows how much charge
    should have left, regardless of what the units claim.
    """
    return SiteScenario(
        name="soc_spoof",
        category="attack",
        description=(
            "Reported state of charge held 25 points above reality while the fleet "
            "discharges, to keep dispatch running into deep discharge."
        ),
        duration_s=3000.0,
        initial_soc=0.30,
        controller=SiteDispatchController(
            target_schedule=[(0.0, 16.0)], devices=DEVICES, poi_limit_mw=20.0
        ),
        telemetry_attack=_spoof_soc(DEVICES, offset=0.25, start_s=60.0),
        attack_window=(60.0, 3000.0),
        expected_rules=("B2",),
        seed=17,
        dt_s=1.0,
    )


# ----------------------------------------------------------------------
# 8. Stealthy meter bias — the tank version's unsolved case
# ----------------------------------------------------------------------


def stealthy_meter_bias() -> SiteScenario:
    """Slowly bias the revenue meter so the site over-exports without knowing.

    This is deliberately the same attack shape that defeated the water-tank
    guard, ported to a site that has redundancy. There the only defence was a
    residual against a model the attacker was slowly dragging, and a slow enough
    ramp was never caught. Here two other measurements of the same power are
    sitting right there.
    """
    return SiteScenario(
        name="stealthy_meter_bias",
        category="attack",
        description=(
            "Revenue meter biased at 2 mW/s so the site believes it is inside its "
            "export limit while it is not. The tank project's unsolved case."
        ),
        duration_s=1200.0,
        controller=SiteDispatchController(
            target_schedule=[(0.0, 19.0)], devices=DEVICES, poi_limit_mw=20.0
        ),
        telemetry_attack=_bias_source("meter", ramp_mw_s=0.002, start_s=60.0),
        attack_window=(60.0, 1200.0),
        expected_rules=("B6",),
        seed=18,
    )


# ----------------------------------------------------------------------
# 9. Forged protection trip
# ----------------------------------------------------------------------


def goose_trip_spoof() -> SiteScenario:
    """A forged GOOSE trip opens the main breaker with no fault present.

    Availability attack: the site stops earning and stops supporting the grid.
    The frame is well-formed and correctly addressed. What it cannot fake is the
    relay's own current measurement, which shows nothing near fault levels — so
    B7 refuses to act on a protection signal the physics does not corroborate.
    """
    return SiteScenario(
        name="goose_trip_spoof",
        category="attack",
        description=(
            "Forged GOOSE trip asserted at the main breaker while measured current "
            "is nowhere near fault levels."
        ),
        duration_s=300.0,
        commands=[
            Cmd(
                t=120.0,
                kind=SiteCommandKind.BREAKER,
                value=0.0,
                malicious=True,
                zone="field",
                conduit="field_to_control",
                protocol="goose",
                source="relay87",
            )
        ],
        controller=_baseline_controller(10.0),
        attack_window=(120.0, 300.0),
        expected_rules=("B7",),
        seed=19,
        protocol_events=[
            {"kind": "goose_replay", "t": 120.0, "gocb": "SITE/LLN0$GO$gcbTrip"},
        ],
    )


# ----------------------------------------------------------------------
# 10. Out-of-sync breaker close
# ----------------------------------------------------------------------


def breaker_close_out_of_sync() -> SiteScenario:
    """Close the main breaker onto a live bus that does not match.

    One of very few OT actions that destroys equipment in a single cycle, and
    the reason a synchronism-check relay exists. The attacker opens the breaker,
    waits for the site to drift, and closes it against a 0.6 Hz slip.
    """
    return SiteScenario(
        name="breaker_close_out_of_sync",
        category="attack",
        description=(
            "Main breaker closed against a 0.6 Hz slip with the bus live — an "
            "out-of-synchronism close."
        ),
        duration_s=300.0,
        commands=[
            Cmd(t=100.0, kind=SiteCommandKind.BREAKER, value=0.0, malicious=True,
                zone="field", conduit="field_to_control", protocol="goose", source="relay87"),
            Cmd(t=160.0, kind=SiteCommandKind.BREAKER, value=1.0, malicious=True,
                zone="field", conduit="field_to_control", protocol="goose", source="relay87"),
        ],
        controller=_baseline_controller(6.0),
        grid_events=[GridEvent(start_s=140.0, end_s=300.0, frequency_hz=59.4)],
        attack_window=(100.0, 300.0),
        expected_rules=("B7",),
        seed=20,
    )


# ----------------------------------------------------------------------
# 11. Provenance: control write from the wrong zone
# ----------------------------------------------------------------------


def enterprise_origin_write() -> SiteScenario:
    """Dispatch commands arriving straight from the enterprise zone.

    Not a physics failure — the values are all deliverable. It is an
    architectural one: nothing in the enterprise zone has any business writing
    set-points into control, and no conduit describes that path.
    """
    return SiteScenario(
        name="enterprise_origin_write",
        category="attack",
        description=(
            "Set-points written into the control zone directly from enterprise, "
            "bypassing the DMZ and the jump server entirely."
        ),
        duration_s=300.0,
        commands=[
            Cmd(
                t=120.0 + i * 2.0,
                kind=SiteCommandKind.PACK_POWER,
                value=1.2,
                device=dev,
                malicious=True,
                zone="enterprise",
                conduit="",
                protocol="modbus_tcp",
                source="historian",
            )
            for i, dev in enumerate(DEVICES[:6])
        ],
        controller=_baseline_controller(6.0),
        attack_window=(120.0, 300.0),
        expected_rules=("B8",),
        controller_stops_at=115.0,
        seed=21,
    )


# ----------------------------------------------------------------------
# 12. Bastion bypass
# ----------------------------------------------------------------------


def jump_server_bypass() -> SiteScenario:
    """An engineering change that did not go through the bastion.

    The conduit from engineering to control exists and permits REST — but only
    ``via`` the jump server. A change arriving on that path from an unrecorded
    host is the modelled equivalent of someone reaching around the bastion.
    """
    return SiteScenario(
        name="jump_server_bypass",
        category="attack",
        description=(
            "Ramp limit raised over REST from the engineering zone without "
            "traversing the jump server the conduit requires."
        ),
        duration_s=300.0,
        commands=[
            Cmd(
                t=110.0,
                kind=SiteCommandKind.RAMP_LIMIT,
                value=30.0,
                malicious=True,
                zone="engineering",
                conduit="engineering_to_control",
                protocol="rest",
                source="engws01",
            )
        ],
        controller=_baseline_controller(6.0),
        attack_window=(110.0, 300.0),
        expected_rules=("B8",),
        seed=22,
    )


# ----------------------------------------------------------------------
# 13. The one that is meant to be hard
# ----------------------------------------------------------------------


def stealth_dispatch_creep() -> SiteScenario:
    """Creep the aggregate over the limit slowly enough to stay under the margins.

    In the suite because it is the hardest case for this design, in the same way
    ``stealthy_bias`` was for the tank. The attacker raises every unit by 0.02 MW
    every twenty seconds. No single write is a meaningful change, the ramp rate
    stays far inside the grid-code allowance, and the aggregate crosses the
    export limit so gradually that B3's incremental test — which fires only when
    a command makes an existing excursion *worse* — sees each step as marginal.

    What eventually catches it is the transformer rating rather than the
    contractual limit: the absolute test has no incremental escape hatch. The
    interesting question the evaluation answers is how much the site over-exports
    before that happens.
    """
    commands = []
    t = 200.0
    value = 1.20
    while t < 1400.0:
        value = round(value + 0.02, 3)
        for i, dev in enumerate(DEVICES):
            commands.append(
                Cmd(t=t + i * 0.1, kind=SiteCommandKind.PACK_POWER, value=value,
                    device=dev, malicious=True)
            )
        t += 20.0
    return SiteScenario(
        name="stealth_dispatch_creep",
        category="attack",
        description=(
            "Aggregate set-point crept over the export limit in 0.02 MW steps per "
            "unit every 20 s, staying inside every incremental margin."
        ),
        duration_s=1500.0,
        commands=commands,
        controller=None,
        attack_window=(200.0, 1500.0),
        expected_rules=("B3",),
        seed=23,
    )


def all_attacks() -> list[SiteScenario]:
    return [
        poi_export_violation(),
        aggregate_stealth(),
        rest_limit_tamper(),
        capability_override(),
        ramp_slam(),
        cooling_shutdown(),
        soc_spoof(),
        stealthy_meter_bias(),
        goose_trip_spoof(),
        breaker_close_out_of_sync(),
        enterprise_origin_write(),
        jump_server_bypass(),
        stealth_dispatch_creep(),
    ]
