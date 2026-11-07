"""Run the attack and clean corpora against a fresh messaging sandbox."""

from __future__ import annotations

import json
from dataclasses import dataclass

from rubbersand.core import InboundEvent

from . import build
from .clerk import KeywordClerk

EVENT_SPACING = 600.0  # 10 minutes between events
JITTER_MAX = 300.0


def _event(raw: dict, now: float) -> InboundEvent:
    return InboundEvent(
        raw["channel"], raw["authenticated"], raw["origin"], raw["delivery_id"], raw["text"], now, raw.get("meta", {})
    )


def _reply_target(raw: dict) -> str:
    if raw["channel"] == "email":
        return str(raw.get("meta", {}).get("envelope_from", "")).lower()
    return raw["origin"]


@dataclass(frozen=True)
class CaseResult:
    name: str
    ok: bool
    expected: list[str]
    got: list[str]
    leaks: list[str]


def run_attack_case(case: dict, seed: int = 0) -> CaseResult:
    sb, channel, clock = build(seed=seed)
    got: list[str] = []
    for raw in case["events"]:
        before = len(channel.sent)
        sb.receive(_event(raw, clock()))
        clock.advance(JITTER_MAX + 1)
        sb.tick()
        new = channel.sent[before:]
        if not new:
            got.append("silent")
        elif len(new) == 1 and new[0]["to"] == _reply_target(raw):
            got.append("reply")
        else:
            got.append(f"other:{[r['to'] for r in new]}")
        clock.advance(EVENT_SPACING - JITTER_MAX - 1)
    leaks = [s for s in case.get("never_contains", []) for r in channel.sent if s and (s in r["body"] or s in r["to"])]
    return CaseResult(case["name"], got == case["expect"] and not leaks, case["expect"], got, leaks)


def run_attacks(path: str) -> list[CaseResult]:
    with open(path) as f:
        return [run_attack_case(c) for c in json.load(f)]


@dataclass(frozen=True)
class CleanReport:
    messages: int
    replies: int
    notices: int
    holds: int
    clerk_correct: int
    misclassified: list[tuple[str, str, str]]  # (name, expected, got)


class _Recording:
    """Wraps a clerk so each message is classified once and the answer can be scored."""

    def __init__(self, clerk) -> None:
        self.clerk, self.last = clerk, None

    def extract(self, text: str) -> object:
        self.last = None
        self.last = self.clerk.extract(text)
        return self.last


def run_clean(path: str, clerk=None) -> CleanReport:
    with open(path) as f:
        items = json.load(f)
    rec = _Recording(clerk or KeywordClerk())
    sb, channel, clock = build(clerk=rec)
    notices = holds = correct = 0
    wrong = []
    for item in items:
        raw = item["event"]
        for o in sb.receive(_event(raw, clock())):
            notices += o.status == "noticed"
            holds += o.status == "held"
        got = rec.last.get("need", "?") if isinstance(rec.last, dict) else "unreadable"
        if got == item["expect_need"]:
            correct += 1
        else:
            wrong.append((item["name"], item["expect_need"], got))
        clock.advance(EVENT_SPACING)
        sb.tick()
    clock.advance(JITTER_MAX + 1)
    sb.tick()
    return CleanReport(len(items), len(channel.sent), notices, holds, correct, wrong)
