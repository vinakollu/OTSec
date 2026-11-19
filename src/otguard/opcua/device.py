"""A simulated field device that speaks OPC UA, with the storage site behind it.

A server answering requests, and a scan loop that latches the commanded
set-points, advances the site, and publishes the measurements back. The device
has no notion of a safety envelope and obeys any value of the right type, which
is the premise of the whole project rather than an omission.

The site controller's own sharing of a fleet set-point across the units that
are online lives here rather than in the guard, because that is where it lives
on a real site. The guard sees one write of one number and has to work out
what that number does to thirty megawatts of battery, which is the position a
bump-in-the-wire is actually in.

What changes against the Modbus version is the security configuration, and that
is the only reason this exists. A Modbus device has none, so a guard in front of
one can always read the wire. An OPC UA device is configured with a security
policy, and that configuration decides how much of the traffic a guard is able
to see. The experiment runs the identical device three times under the three
modes and measures the difference.

The device is deliberately *correctly* configured in the secure modes: a
certificate on each end, a policy of Basic256Sha256, no anonymous endpoint left
open beside it. The problem the experiment demonstrates is not a
misconfiguration.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging

from ..clock import SimClock
from ..config import Config
from ..bess.site import BessSite
from .certs import CertSet
from .framing import SecurityMode
from .nodes import ENDPOINT_PATH, NAMESPACE_URI, SITE_POINTS, NodeMap

log = logging.getLogger(__name__)

_MAX_CATCHUP_STEPS = 400


def endpoint_url(host: str, port: int) -> str:
    return f"opc.tcp://{host}:{port}{ENDPOINT_PATH}"


class SimulatedOpcUaDevice:
    """OPC UA server whose nodes are backed by the storage site simulation."""

    def __init__(
        self,
        config: Config,
        host: str = "127.0.0.1",
        port: int = 4842,
        mode: SecurityMode = SecurityMode.NONE,
        certs: CertSet | None = None,
        seed: int = 0,
        clock: SimClock | None = None,
        initial_dispatch_mw: float = 0.0,
    ) -> None:
        self.config = config
        self.host = host
        self.port = port
        self.mode = mode
        self.certs = certs
        self.clock = clock or SimClock()
        b = config.bess
        self.site = BessSite(b.site, b.safety, b.pack, seed=seed)
        self.initial_dispatch_mw = initial_dispatch_mw
        self.map = NodeMap()
        self.writes_latched = 0
        self.peak_poi_mw = self.site.state.p_poi_mw
        self.min_poi_mw = self.site.state.p_poi_mw
        self.peak_mva = 0.0

        self._server = None
        self._nodes: dict[str, object] = {}
        self._scan_task: asyncio.Task | None = None
        self._plant_t = 0.0
        self._ramp_limit = b.site.ramp_limit_mw_s
        #: Simulated time after which the plant stops advancing.
        #:
        #: The episode's clock is shared with the clients and the guard, and it
        #: keeps running while a client unwinds a channel the guard has cut.
        #: Without a boundary the plant goes on being driven after the episode
        #: is over and the extra seconds are scored as though they were part of
        #: it; a severed write-flood episode drained to 0.00 m this way, long
        #: after anybody was writing to it.
        self.run_until: float | None = None

    # ------------------------------------------------------------------
    # Address space
    # ------------------------------------------------------------------
    async def _build(self) -> None:
        from asyncua import Server, ua

        server = Server()
        await server.init()
        server.set_endpoint(endpoint_url(self.host, self.port))
        server.set_server_name("OTGuard storage site")

        if self.mode is SecurityMode.NONE:
            server.set_security_policy([ua.SecurityPolicyType.NoSecurity])
        else:
            if self.certs is None:
                raise ValueError(f"security mode {self.mode.value} needs certificates")
            await server.load_certificate(self.certs.device.cert_str)
            await server.load_private_key(self.certs.device.key_str)
            policy = (
                ua.SecurityPolicyType.Basic256Sha256_Sign
                if self.mode is SecurityMode.SIGN
                else ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt
            )
            # Only the secure policy. Leaving an unauthenticated endpoint open
            # beside it would make the result an argument about configuration
            # rather than about encryption.
            server.set_security_policy([policy])

        index = await server.register_namespace(NAMESPACE_URI)
        if index != self.map.namespace_index:
            self.map = NodeMap(SITE_POINTS, namespace_index=index)
        folder = await server.nodes.objects.add_object(
            ua.NodeId("Site", index), "Site"
        )
        for point in SITE_POINTS:
            initial = point.initial
            if point.identifier == "Site.DispatchSetpoint":
                initial = self.initial_dispatch_mw
            node = await folder.add_variable(
                ua.NodeId(point.identifier, index),
                point.browse_name,
                ua.Variant(float(initial), ua.VariantType.Double),
            )
            if point.writable:
                await node.set_writable()
            self._nodes[point.identifier] = node
        self._server = server

    # ------------------------------------------------------------------
    # Process loop
    # ------------------------------------------------------------------
    async def _latch(self) -> None:
        """Read the command nodes, apply them, publish the measurements."""
        dispatch = float(await self._nodes["Site.DispatchSetpoint"].read_value())
        limit = float(await self._nodes["Site.ExportLimit"].read_value())
        breaker = float(await self._nodes["Site.Breaker"].read_value())
        # The parameter is what a dispatch is allowed to move *through*, so
        # raising it changes what every subsequent set-point does to the site.
        # The device obeys it without comment, which is the point of having it.
        self._ramp_limit = max(0.01, float(
            await self._nodes["Site.RampLimit"].read_value()))
        self.site.poi_limit_mw = limit
        self.site.ramp_limit_mw_s = self._ramp_limit
        self.site.set_breaker(breaker >= 0.5)
        # A fleet set-point is shared across whatever is online. That sharing
        # is the site controller's job on a real site, so it belongs to the
        # device rather than to the guard watching it.
        online = [u for u in self.site.packs if u.state.online]
        if online:
            share = dispatch / len(online)
            for unit in online:
                unit.set_power(share)
        self.writes_latched += 1

    async def _publish(self) -> None:
        from asyncua import ua

        state = self.site.state
        packs = list(self.site.packs)
        socs = [u.state.soc for u in packs] or [0.0]
        temps = [u.state.temp_c for u in packs] or [0.0]
        mva = (state.p_poi_mw ** 2 + state.q_site_mvar ** 2) ** 0.5
        for identifier, value in (
            ("Site.PoiPowerMw", self.site.observe(self.clock.now()).poi_meter_mw),
            ("Site.FleetSoc", 100.0 * sum(socs) / len(socs)),
            ("Site.HottestTempC", max(temps)),
            ("Site.TransformerMva", mva),
        ):
            await self._nodes[identifier].write_value(
                ua.DataValue(ua.Variant(float(value), ua.VariantType.Double))
            )

    async def _run_scan_loop(self) -> None:
        dt = self.config.bess.site.dt_s
        self._plant_t = self.clock.now()
        try:
            while True:
                target = self.clock.now()
                if self.run_until is not None:
                    target = min(target, self.run_until)
                steps = 0
                while self._plant_t + dt <= target and steps < _MAX_CATCHUP_STEPS:
                    await self._latch()
                    self.site.step(dt, self._plant_t)
                    self._plant_t += dt
                    steps += 1
                    s = self.site.state
                    self.peak_poi_mw = max(self.peak_poi_mw, s.p_poi_mw)
                    self.min_poi_mw = min(self.min_poi_mw, s.p_poi_mw)
                    self.peak_mva = max(
                        self.peak_mva,
                        (s.p_poi_mw ** 2 + s.q_site_mvar ** 2) ** 0.5)
                await self._publish()
                await self.clock.sleep(dt)
        except asyncio.CancelledError:
            raise
        except Exception:  # pragma: no cover - a dead scan loop must be visible
            log.exception("opc ua device scan loop failed")
            raise

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    @property
    def url(self) -> str:
        return endpoint_url(self.host, self.port)

    @property
    def damaged(self) -> bool:
        return self.site.damaged

    @property
    def damage_summary(self) -> list[str]:
        return sorted(self.site.damage_summary())

    async def start(self) -> None:
        await self._build()
        await self._server.start()
        self._scan_task = asyncio.create_task(self._run_scan_loop())

    async def stop(self) -> None:
        if self._scan_task is not None:
            self._scan_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._scan_task
            self._scan_task = None
        if self._server is not None:
            with contextlib.suppress(Exception):
                await self._server.stop()
            self._server = None

    async def __aenter__(self) -> "SimulatedOpcUaDevice":
        await self.start()
        return self

    async def __aexit__(self, *exc) -> None:
        await self.stop()
