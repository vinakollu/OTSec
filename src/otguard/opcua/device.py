"""A simulated field device that speaks OPC UA, with the tank behind it.

The same shape as :class:`~otguard.modbus.plc_server.SimulatedPLC`: a server
answering requests, and a scan loop that latches the commanded actuator
positions, advances the plant, and publishes the measurements back. The device
has no notion of a safety envelope and obeys any value of the right type, which
is the premise of the whole project rather than an omission.

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
from ..sim import WaterTank
from .certs import CertSet
from .framing import SecurityMode
from .nodes import ENDPOINT_PATH, NAMESPACE_URI, TANK_POINTS, NodeMap

log = logging.getLogger(__name__)

_MAX_CATCHUP_STEPS = 400


def endpoint_url(host: str, port: int) -> str:
    return f"opc.tcp://{host}:{port}{ENDPOINT_PATH}"


class SimulatedOpcUaDevice:
    """OPC UA server whose nodes are backed by the tank simulation."""

    def __init__(
        self,
        config: Config,
        host: str = "127.0.0.1",
        port: int = 4842,
        mode: SecurityMode = SecurityMode.NONE,
        certs: CertSet | None = None,
        seed: int = 0,
        clock: SimClock | None = None,
        initial_level_m: float | None = None,
    ) -> None:
        self.config = config
        self.host = host
        self.port = port
        self.mode = mode
        self.certs = certs
        self.clock = clock or SimClock()
        self.tank = WaterTank(config.plant, config.safety, seed=seed)
        if initial_level_m is not None:
            self.tank.state.level_m = initial_level_m
        self.map = NodeMap()
        self.writes_latched = 0
        self.peak_level_m = self.tank.state.level_m
        self.min_level_m = self.tank.state.level_m

        self._server = None
        self._nodes: dict[str, object] = {}
        self._scan_task: asyncio.Task | None = None
        self._plant_t = 0.0
        self._max_pump_pct = 100.0
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
        server.set_server_name("OTGuard tank device")

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
            self.map = NodeMap(TANK_POINTS, namespace_index=index)
        folder = await server.nodes.objects.add_object(
            ua.NodeId("Tank", index), "Tank"
        )
        for point in TANK_POINTS:
            node = await folder.add_variable(
                ua.NodeId(point.identifier, index),
                point.browse_name,
                ua.Variant(float(point.initial), ua.VariantType.Double),
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
        pump = float(await self._nodes["Tank.PumpCommand"].read_value())
        valve = float(await self._nodes["Tank.ValveCommand"].read_value())
        self._max_pump_pct = float(await self._nodes["Tank.PumpMaxSpeed"].read_value())
        # The parameter is what a speed command is a fraction *of*, so raising
        # it changes what every subsequent pump command means. The device obeys
        # it without comment, which is the whole point of having it here.
        self.tank.set_pump(pump * self._max_pump_pct / 100.0)
        self.tank.set_valve(valve)
        self.writes_latched += 1

    async def _publish(self) -> None:
        from asyncua import ua

        state = self.tank.state
        for identifier, value in (
            ("Tank.Level", self.tank.measure()),
            ("Tank.PumpFeedback", state.pump_pos_pct),
            ("Tank.ValveFeedback", state.valve_pos_pct),
        ):
            await self._nodes[identifier].write_value(
                ua.DataValue(ua.Variant(float(value), ua.VariantType.Double))
            )

    async def _run_scan_loop(self) -> None:
        dt = self.config.plant.dt_s
        self._plant_t = self.clock.now()
        try:
            while True:
                target = self.clock.now()
                if self.run_until is not None:
                    target = min(target, self.run_until)
                steps = 0
                while self._plant_t + dt <= target and steps < _MAX_CATCHUP_STEPS:
                    await self._latch()
                    self.tank.step(dt)
                    self._plant_t += dt
                    steps += 1
                    self.peak_level_m = max(self.peak_level_m, self.tank.state.level_m)
                    self.min_level_m = min(self.min_level_m, self.tank.state.level_m)
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
        return self.tank.state.overflowed or self.tank.state.dried_out

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
