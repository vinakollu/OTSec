"""Device reachability: who is answering, who stopped, and what that costs.

The scanner is observability that the guard acts on. A measurement source the
scanner cannot reach stops counting as a vote in cross-source agreement, which
takes the site back toward the blind spot the three-meter design exists to
close. That consequence is the point: losing a meter is not only a monitoring
event, it is a reduction in what the guard can prove.
"""

from .probe import CallbackProbe, Evidence, Probe, ProbeResult, ModbusProbe, TcpProbe
from .scanner import DeviceStatus, Reachability, ScanTarget, ScanTransition, Scanner
from .targets import site_targets, tank_targets

__all__ = [
    "CallbackProbe",
    "DeviceStatus",
    "Evidence",
    "ModbusProbe",
    "Probe",
    "ProbeResult",
    "Reachability",
    "ScanTarget",
    "ScanTransition",
    "Scanner",
    "TcpProbe",
    "site_targets",
    "tank_targets",
]
