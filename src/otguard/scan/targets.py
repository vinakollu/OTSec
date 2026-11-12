"""The device lists the scanner watches, for each of the two plants.

Two plants, two honesty problems.

The tank runs on real sockets. Its controller and its guard are listening
processes, so they are probed for real and the results are evidence about a
real listener.

The battery site is sixteen objects in one process. Probing the addresses in
its topology would report twenty-seven devices down, which is worse than
reporting nothing. So the site's devices are sensed through a model of their
network links, and every one of those rows is stamped
:attr:`~otguard.scan.probe.Evidence.MODEL` so no table can present a model read
as a measurement. :class:`ModelledNetwork` is the thing the demo pulls a cable
out of.

What runs on a real socket and what does not is a property of this project's
test rig rather than of the design. A deployment would probe all of them the
same way; nothing here measures whether that works against real hardware.
"""

from __future__ import annotations

from ..bess.site import BessSite
from ..bess.types import MeasurementSource
from ..modbus.registers import IR_LEVEL
from ..site.topology import Role, SiteTopology, default_site_topology
from .probe import CallbackProbe, Evidence, ModbusProbe
from .scanner import ScanTarget

#: Which measurement each of the three independent power readings comes in on.
#: The telemetry sum arrives through the site controller, which is what polls
#: the fleet over Modbus, so losing the controller loses that measurement as
#: surely as losing the meter loses the meter's.
_MEASUREMENT_DEVICE = {
    "meter01": MeasurementSource.POI_METER,
    "relay87": MeasurementSource.RELAY,
    "sitectrl": MeasurementSource.TELEMETRY,
}

#: Devices whose loss is a process-safety condition rather than a monitoring
#: nuisance: without the site controller nothing is dispatching the fleet, and
#: without the relay nothing is protecting the switchyard.
_CRITICAL = frozenset({"sitectrl", "relay87"})


class ModelledNetwork:
    """Up/down state for devices that exist as objects rather than listeners.

    Every device starts up. ``cut`` and ``restore`` are what a scenario uses to
    take a link away, which is the only way to show what losing a measurement
    costs the guard: the alternative is waiting for a real cable to fail.
    """

    def __init__(self) -> None:
        self._down: set[str] = set()

    def up(self, name: str) -> bool:
        return name not in self._down

    def cut(self, name: str) -> None:
        self._down.add(name)

    def restore(self, name: str) -> None:
        self._down.discard(name)

    def restore_all(self) -> None:
        self._down.clear()

    @property
    def severed(self) -> frozenset[str]:
        return frozenset(self._down)


def tank_targets(
    *,
    plc_host: str = "127.0.0.1",
    plc_port: int,
    proxy_host: str = "127.0.0.1",
    proxy_port: int | None = None,
    timeout_s: float = 1.0,
) -> list[ScanTarget]:
    """The water-tank stack: the controller, and the guard in front of it.

    Both are probed by reading the level input register rather than by opening
    a socket, because the failure worth catching is a controller whose port
    still accepts while its scan loop has stopped. The two probes answer
    different questions: the controller's says the controller is alive, and the
    guard's says the whole path through the guard to the controller is. A guard
    that is up in front of a controller that is not shows as one row up and one
    row down, which is the picture an engineer needs.
    """
    targets = [
        ScanTarget(
            name="plc01",
            probe=ModbusProbe(plc_host, plc_port, address=IR_LEVEL, timeout_s=timeout_s),
            role="controller",
            zone="control",
            protocol="modbus_tcp",
            address=f"{plc_host}:{plc_port}",
            critical=True,
        )
    ]
    if proxy_port is not None:
        targets.append(
            ScanTarget(
                name="guard01",
                probe=ModbusProbe(
                    proxy_host, proxy_port, address=IR_LEVEL, timeout_s=timeout_s
                ),
                role="guard",
                zone="control",
                protocol="modbus_tcp",
                address=f"{proxy_host}:{proxy_port}",
                critical=True,
            )
        )
    return targets


def site_targets(
    site: BessSite,
    *,
    network: ModelledNetwork | None = None,
    topology: SiteTopology | None = None,
) -> tuple[list[ScanTarget], ModelledNetwork]:
    """Every box in the site topology, sensed through the model.

    A Megapack counts as answering when its link is up *and* the unit reports
    itself online. Those are two different failures that look the same from
    SCADA — a unit that has tripped still answers, a unit behind a dead switch
    does not — and the detail string says which one happened, because the
    remedy is a different person in a different building.
    """
    network = network or ModelledNetwork()
    topology = topology or default_site_topology(n_packs=len(site.packs))
    targets: list[ScanTarget] = []

    for device in topology.devices:
        name = device.name
        source = _MEASUREMENT_DEVICE.get(name)
        if device.role is Role.MEGAPACK:
            probe = CallbackProbe(
                _pack_liveness(site, network, name),
                label=name,
                detail=_pack_detail(site, network, name),
            )
        elif source is not None:
            probe = CallbackProbe(
                _measurement_liveness(site, network, name, source),
                label=name,
                detail=_measurement_detail(site, network, name, source),
            )
        else:
            probe = CallbackProbe(
                (lambda n=name: network.up(n)),
                label=name,
                detail=(
                    lambda n=name, d=device: f"{n} ({d.role.value}) link "
                    + ("up" if network.up(n) else "down")
                ),
            )
        targets.append(
            ScanTarget(
                name=name,
                probe=probe,
                role=device.role.value,
                zone=device.zone,
                protocol=device.protocols[0] if device.protocols else "",
                address=device.address,
                measurement_source=source,
                # A model read is authoritative about the model, so there is no
                # weaker rung to insist on here.
                min_evidence=Evidence.MODEL,
                critical=name in _CRITICAL,
            )
        )
    return targets, network


def _pack_liveness(site: BessSite, network: ModelledNetwork, name: str):
    def answering() -> bool:
        unit = site.pack(name)
        return network.up(name) and unit is not None and unit.state.online
    return answering


def _pack_detail(site: BessSite, network: ModelledNetwork, name: str):
    def detail() -> str:
        unit = site.pack(name)
        if not network.up(name):
            return f"{name} is not reachable: its Modbus link is down"
        if unit is None:
            return f"{name} is not in the fleet"
        if not unit.state.online:
            return f"{name} answers and reports itself offline"
        return (
            f"{name} online at {unit.state.p_mw:+.3f} MW, "
            f"SoC {unit.state.soc * 100:.0f}%, {unit.state.temp_c:.1f} C"
        )
    return detail


def _measurement_liveness(
    site: BessSite, network: ModelledNetwork, name: str, source: MeasurementSource
):
    def answering() -> bool:
        return network.up(name) and site.link_up(source)
    return answering


def _measurement_detail(
    site: BessSite, network: ModelledNetwork, name: str, source: MeasurementSource
):
    def detail() -> str:
        if not network.up(name):
            return f"{name} is not reachable: its link is down"
        if not site.link_up(source):
            # The number has not gone away, it has stopped moving, and a median
            # of three cannot tell a frozen reading from an agreeing one.
            return (
                f"{name} is not refreshing {source.label}: the last value is "
                f"still being served"
            )
        return f"{name} is refreshing {source.label}"
    return detail
