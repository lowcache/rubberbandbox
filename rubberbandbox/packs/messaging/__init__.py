"""Messaging workflow pack."""

from __future__ import annotations

import random

from rubberbandbox.core import LaneConfig, ManualClock, Mount, Sandbox

from .clerk import KeywordClerk
from .pack import CLERK_GUIDE, DEFAULT_PUBLISHED, KINDS, RULES, SCHEMA, TOOLS, MessagingConfig, MessagingPack
from .sim import ProviderRefused, SimChannel


def build(
    clock: ManualClock | None = None,
    *,
    seed: int = 0,
    channel: SimChannel | None = None,
    config: MessagingConfig | None = None,
    lane: LaneConfig = LaneConfig(),
    clerk=None,
) -> tuple[Sandbox, SimChannel, ManualClock]:
    """A messaging sandbox with the demo's owner-published scripts installed."""
    clock = clock or ManualClock()
    channel = channel or SimChannel()
    sb = Sandbox(
        [Mount(MessagingPack(config), clerk or KeywordClerk())],
        {kind: channel for kind in KINDS},
        clock=clock,
        rng=random.Random(seed),
        lane=lane,
    )
    for name, data in DEFAULT_PUBLISHED.items():
        sb.owner_publish(name, data)
    return sb, channel, clock


__all__ = ["build", "MessagingPack", "MessagingConfig", "KeywordClerk", "SimChannel", "ProviderRefused",
           "KINDS", "TOOLS", "RULES", "SCHEMA", "DEFAULT_PUBLISHED", "CLERK_GUIDE"]
