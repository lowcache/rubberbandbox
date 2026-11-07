"""Simulated adapter shared by every coding egress kind."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence


@dataclass
class SimTools:
    log: list[dict] = field(default_factory=list)

    def execute(self, kind: str, destination: str, payload: Sequence[str]) -> dict:
        record = {"kind": kind, "destination": destination, "payload": list(payload)}
        self.log.append(record)
        return record
