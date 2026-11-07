"""Coding workflow pack."""

from __future__ import annotations

import random

from rubberbandbox.core import Hands, ManualClock, Mount, Sandbox

from .clerk import KeywordClerk
from .hands import InjectedHands, ScriptedHands
from .pack import KINDS, RULES, SCHEMA, TOOLS, CodingPack
from .sim import SimTools


def build(
    clock: ManualClock | None = None,
    *,
    seed: int = 0,
    hands: Hands | None = None,
    tools: SimTools | None = None,
) -> tuple[Sandbox, SimTools, ManualClock]:
    """A coding sandbox with simulated tools and issue-hijacked hands by default."""
    clock = clock if clock is not None else ManualClock()
    tools = tools if tools is not None else SimTools()
    sb = Sandbox(
        [Mount(CodingPack(), KeywordClerk())],
        {kind: tools for kind in KINDS},
        hands=hands if hands is not None else InjectedHands(),
        clock=clock,
        rng=random.Random(seed),
    )
    return sb, tools, clock


__all__ = ["build", "CodingPack", "KeywordClerk", "InjectedHands", "ScriptedHands", "SimTools",
           "KINDS", "TOOLS", "RULES", "SCHEMA"]
