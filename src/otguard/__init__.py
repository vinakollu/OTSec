"""OTGuard — a physics-plausibility guard for OT/ICS command streams.

Instead of trying to recognise malicious traffic, the guard enforces the
physics of the controlled process as an admission policy on commands. Its
authority comes from the plant's dynamics, which an attacker on the operator
station cannot renegotiate.

Typical use::

    from otguard.config import load_config
    from otguard.guard import PhysicsGuard, Command, CommandKind, Observation

    guard = PhysicsGuard(load_config())
    guard.observe(Observation(t, level_m))          # every process read
    verdict = guard.check(Command(t, CommandKind.PUMP, 100.0))
    if verdict.allowed:
        forward_to_plc(...)

See ``docs/design.md`` for the threat model and rule rationale.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
