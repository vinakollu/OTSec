"""OTGuard — a physics-plausibility guard for OT/ICS command streams.

Instead of trying to recognise malicious traffic, the guard enforces the
physics of the controlled process as an admission policy on commands. Its
authority comes from the plant's dynamics, which an attacker on the operator
station cannot renegotiate.

Two plants are modelled. A grid storage site, where the quantity that matters
is measured three times by three different instruments, and a water treatment
works, where the quantity that decides whether the water is safe is not
measured at all.

Typical use::

    from otguard.config import load_config
    from otguard.guard import SiteGuard
    from otguard.bess.types import SiteCommand, SiteCommandKind

    guard = SiteGuard(load_config())
    guard.observe(observation)                      # every scan of telemetry
    verdict = guard.check(SiteCommand(t, SiteCommandKind.SITE_POWER, 30.0))
    if verdict.allowed:
        forward_to_controller(...)

See ``docs/design.md`` for the threat model and rule rationale.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
