"""Simulated SMS/email provider. Enforces a provider-level hard spending cap that holds even if
the sandbox's own budgets fail."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Sequence


class ProviderRefused(RuntimeError):
    pass


@dataclass
class SimChannel:
    hard_cap: float = 10.0
    sms_cost: Mapping[str, float] = field(default_factory=lambda: {"+1": 0.0079})
    sent: list[dict] = field(default_factory=list)
    spent: float = 0.0

    def execute(self, kind: str, destination: str, payload: Sequence[str]) -> dict:
        channel, _, addr = destination.partition(":")
        if channel == "sms":
            prefixes = [p for p in self.sms_cost if addr.startswith(p)]
            if not prefixes:
                raise ProviderRefused(f"no route to {addr}")
            cost = self.sms_cost[max(prefixes, key=len)]
        elif channel == "email":
            cost = 0.0
        else:
            raise ProviderRefused(f"unknown channel {channel!r}")
        if self.spent + cost > self.hard_cap:
            raise ProviderRefused("provider hard cap reached")
        self.spent += cost
        headers = {}
        if channel == "email" and kind == "msg.reply":
            headers = {"Auto-Submitted": "auto-replied", "envelope_from": ""}
        record = {"kind": kind, "channel": channel, "to": addr, "body": "\n".join(payload), "headers": headers}
        self.sent.append(record)
        return record
