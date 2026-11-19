"""Shared fixtures."""

from __future__ import annotations

import pytest

from otguard.config import Config, load_config


@pytest.fixture
def config() -> Config:
    return load_config()


@pytest.fixture
def config_without_supervision() -> Config:
    """Config with continuous supervision off.

    Needed to test a rule's *command-time* behaviour in isolation. With
    supervision running, a plant parked near a limit trips before the command
    under test is ever issued, and the assertion ends up measuring the trip
    rather than the rule.
    """
    return load_config(overrides={"guard": {"supervision": {"enabled": False}}})
