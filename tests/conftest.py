"""Shared fixtures for the DELM test suite."""
from __future__ import annotations

import pytest


def toy_units() -> list[tuple[str, str]]:
    """A tiny corpus: u3 carries the load-bearing constraint."""
    return [
        ("u1", "This system processes events in order; no constraint here."),
        ("u2", "The scheduler retries failed jobs three times; a policy."),
        ("u3", ("CONSTRAINT: a transaction must be journaled before it is "
               "acked to the client; acking before journaling is forbidden "
               "under all failure modes.")),
        ("u4", "The API returns JSON and error codes follow RFC 9457."),
    ]
