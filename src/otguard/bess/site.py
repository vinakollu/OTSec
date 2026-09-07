"""The battery site: a fleet of Megapacks behind one point of interconnection.

Layout modelled here, matching a utility-scale storage site:

    Megapacks (N)  ──►  LV bus  ──►  main transformer  ──►  POI breaker  ──► grid
                                          │                     │
                                    protection relay      revenue meter

Two site-level facts drive most of the rules:

*The fleet can out-produce the interconnection.* Sixteen 1.927 MW units is about
30.8 MW of inverter behind a 20 MW export limit and a 25 MVA transformer. That
is the normal way these sites are built — the limit binds, the site controller
enforces it, and an attacker who can move set-points can exceed it. The
transformer, not the contract, is what fails.

*The same power is measured three ways.* The revenue meter, the sum of the
Megapacks' own reports, and the protection relay's current transformers each see
site power through different hardware, different cabling and different
protocols. Absent an attack they agree to within their error bands. That
redundancy is the thing the water-tank version of this project did not have and
explicitly named as the reason its stealthy-bias attack could not be caught.

Grid frequency and fault current are exogenous here: a 20 MW site does not move
a synchronous grid, so treating frequency as an input rather than a state is the
honest simplification. It also gives the guard a piece of *context* — a fast
ramp is plausible during a frequency excursion and suspicious without one.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field

from ..config import SiteConfig, SiteSafetyConfig
from .megapack import Megapack
from .types import BreakerState, MeasurementSource, PackReport, SiteObservation, SiteSnapshot


@dataclass
class GridEvent:
    """An exogenous grid condition over a time window."""

    start_s: float
    end_s: float
    frequency_hz: float | None = None
    voltage_pu: float | None = None
    fault_current_a: float | None = None

    def active(self, t: float) -> bool:
        return self.start_s <= t <= self.end_s


@dataclass
class SiteState:
    """Ground truth for the site as a whole."""

    p_site_mw: float = 0.0       # aggregate at the LV bus
    p_poi_mw: float = 0.0        # after transformer losses, what the grid sees
    q_site_mvar: float = 0.0
    frequency_hz: float = 60.0
    voltage_pu: float = 1.0
    breaker: BreakerState = BreakerState.CLOSED
    bus_live: bool = True
    fault_current_a: float = 0.0
    sync_angle_deg: float = 0.0
    # Latched damage
    poi_overloaded: bool = False
    breaker_damaged: bool = False

    @property
    def damaged(self) -> bool:
        return self.poi_overloaded or self.breaker_damaged


class BessSite:
    """Fleet of Megapacks, a transformer, a breaker and three power meters."""

    def __init__(
        self,
        cfg: SiteConfig,
        safety: SiteSafetyConfig,
        pack_cfg,
        seed: int = 0,
        initial_soc: float | None = None,
    ) -> None:
        self.cfg = cfg
        self.safety = safety
        self.packs: list[Megapack] = [
            Megapack(
                device=f"MP{i + 1:02d}",
                cfg=pack_cfg,
                initial_soc=pack_cfg.initial_soc if initial_soc is None else initial_soc,
            )
            for i in range(cfg.n_packs)
        ]
        self.state = SiteState(frequency_hz=cfg.nominal_frequency_hz)
        self.grid_events: list[GridEvent] = []
        self._rng = random.Random(seed)
        # The contractual export limit. Distinct from ``poi_rating_mw``, which is
        # the transformer's nameplate and cannot be edited by anyone on the
        # network — that gap is what rule B3 uses to catch limit tampering.
        self.poi_limit_mw = cfg.poi_limit_mw
        self.ramp_limit_mw_s = cfg.ramp_limit_mw_s

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------
    def pack(self, device: str) -> Megapack | None:
        for unit in self.packs:
            if unit.state.device == device:
                return unit
        return None

    @property
    def device_ids(self) -> list[str]:
        return [p.state.device for p in self.packs]

    # ------------------------------------------------------------------
    # Integration
    # ------------------------------------------------------------------
    def step(self, dt: float, t: float = 0.0) -> None:
        self._apply_grid_events(t)

        if self.state.breaker is BreakerState.OPEN:
            # Islanded with no load: the inverters have nowhere to push power.
            for unit in self.packs:
                unit.set_power(0.0)

        for unit in self.packs:
            unit.step(dt)

        p_bus = sum(u.state.p_mw for u in self.packs if u.state.online)
        q_bus = sum(u.state.q_mvar for u in self.packs if u.state.online)
        aux = self.cfg.aux_base_mw + sum(
            self.cfg.aux_thermal_mw_per_c * max(0.0, u.state.temp_c - self.cfg.ambient_ref_c)
            for u in self.packs
        )
        # Auxiliary load is a house load: it always consumes, so it subtracts
        # from an export and deepens an import.
        self.state.p_site_mw = p_bus - aux
        self.state.q_site_mvar = q_bus

        if self.state.breaker is BreakerState.OPEN:
            self.state.p_poi_mw = 0.0
        else:
            self.state.p_poi_mw = self.state.p_site_mw - self._transformer_loss_mw(
                self.state.p_site_mw
            )

        self._latch_damage()

    def _transformer_loss_mw(self, p_site_mw: float) -> float:
        rated = max(self.cfg.poi_rating_mw, 1e-9)
        copper = self.cfg.transformer_loss_mw * (p_site_mw / rated) ** 2
        return copper + self.cfg.transformer_noload_mw

    def _apply_grid_events(self, t: float) -> None:
        st = self.state
        st.frequency_hz = self.cfg.nominal_frequency_hz
        st.voltage_pu = 1.0
        st.fault_current_a = 0.0
        for event in self.grid_events:
            if not event.active(t):
                continue
            if event.frequency_hz is not None:
                st.frequency_hz = event.frequency_hz
            if event.voltage_pu is not None:
                st.voltage_pu = event.voltage_pu
            if event.fault_current_a is not None:
                st.fault_current_a = event.fault_current_a

    def _latch_damage(self) -> None:
        """Record the outcomes the evaluation scores as physical damage."""
        st = self.state
        if abs(st.p_poi_mw) > self.cfg.poi_rating_mw * self.safety.poi_overload_factor:
            st.poi_overloaded = True

    # ------------------------------------------------------------------
    # Switchgear
    # ------------------------------------------------------------------
    def sync_ok(self) -> bool:
        """Is it safe to close the main breaker right now?

        Either the far side is dead (nothing to synchronise against) or the two
        systems match in voltage, frequency and phase angle. Closing out of sync
        slams the machines together; on a real site this is what the 25 relay
        exists to prevent, and it is one of the few OT actions that destroys
        equipment in a single cycle.
        """
        st = self.state
        if not st.bus_live:
            return True
        return (
            abs(st.frequency_hz - self.cfg.nominal_frequency_hz) <= self.safety.sync_freq_hz
            and abs(st.voltage_pu - 1.0) <= self.safety.sync_voltage_pu
            and abs(st.sync_angle_deg) <= self.safety.sync_angle_deg
        )

    def set_breaker(self, close: bool) -> None:
        """Operate the main breaker, recording damage on an unsynchronised close."""
        st = self.state
        if close:
            if st.breaker is BreakerState.OPEN and not self.sync_ok():
                st.breaker_damaged = True
            st.breaker = BreakerState.CLOSED
        else:
            st.breaker = BreakerState.OPEN

    # ------------------------------------------------------------------
    # Measurement
    # ------------------------------------------------------------------
    def observe(self, t: float) -> SiteObservation:
        """Produce one honest scan of telemetry.

        Each of the three power measurements carries its own independent noise,
        which is what sets the agreement tolerance rule B6 has to live with: too
        tight and honest measurement scatter raises alarms, too loose and a small
        injected bias hides inside the band.
        """
        reports = tuple(
            PackReport(
                device=u.state.device,
                p_mw=u.state.p_mw + self._noise(self.cfg.pack_power_noise_mw),
                q_mvar=u.state.q_mvar,
                soc=max(0.0, min(1.0, u.state.soc + self._noise(self.cfg.soc_noise))),
                temp_c=u.state.temp_c + self._noise(self.cfg.temp_noise_c),
                online=u.state.online,
                cooling_enabled=u.state.cooling_enabled,
            )
            for u in self.packs
        )
        return SiteObservation(
            t=t,
            packs=reports,
            poi_meter_mw=self.state.p_poi_mw + self._noise(self.cfg.meter_noise_mw),
            relay_mw=self.state.p_poi_mw + self._noise(self.cfg.relay_noise_mw),
            frequency_hz=self.state.frequency_hz,
            voltage_pu=self.state.voltage_pu,
            breaker=self.state.breaker,
            bus_live=self.state.bus_live,
            fault_current_a=self.state.fault_current_a,
        )

    def snapshot(self, t: float) -> SiteSnapshot:
        return SiteSnapshot(
            t=t,
            p_poi_mw=self.state.p_poi_mw,
            soc={u.state.device: u.state.soc for u in self.packs},
            temp_c={u.state.device: u.state.temp_c for u in self.packs},
            p_pack_mw={u.state.device: u.state.p_mw for u in self.packs},
            frequency_hz=self.state.frequency_hz,
            breaker=self.state.breaker,
        )

    def _noise(self, std: float) -> float:
        return self._rng.gauss(0.0, std) if std > 0.0 else 0.0

    # ------------------------------------------------------------------
    # Aggregate helpers
    # ------------------------------------------------------------------
    @property
    def fleet_capability_mw(self) -> float:
        """Total export the fleet could deliver right now."""
        return sum(u.max_discharge_mw() for u in self.packs if u.state.online)

    @property
    def any_pack_damaged(self) -> bool:
        return any(u.state.damaged for u in self.packs)

    @property
    def damaged(self) -> bool:
        return self.state.damaged or self.any_pack_damaged

    def damage_summary(self) -> list[str]:
        out: list[str] = []
        if self.state.poi_overloaded:
            out.append("POI overload")
        if self.state.breaker_damaged:
            out.append("out-of-sync close")
        for unit in self.packs:
            st = unit.state
            if st.deep_discharged:
                out.append(f"{st.device} deep discharge")
            if st.overcharged:
                out.append(f"{st.device} overcharge")
            if st.overheated:
                out.append(f"{st.device} overheat")
        return out
