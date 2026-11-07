"""The public lane (the spec's mail slot): owner-published replies to a constrained route,
without the owner's tap. Blind to suspicion by construction: no score or hold state is an input."""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Mapping

from .labels import OWNER_PUBLIC
from .store import Store
from .types import Authorization, Egress, KindSpec, RouteReceipt


@dataclass(frozen=True)
class LaneConfig:
    window_seconds: float = 86_400.0
    per_destination: int = 1  # auto-replies per destination per window
    service_budget: float = 5.0  # total lane spend per window, in provider currency
    jitter: tuple[float, float] = (120.0, 300.0)  # seconds added to arrival time
    slot_grace: float = 600.0  # a reply not dispatched by send_at + grace is cancelled, never caught up


class PublicLane:
    def __init__(self, store: Store, config: LaneConfig, rng: random.Random) -> None:
        self.store = store
        self.config = config
        self.rng = rng

    def admit(
        self,
        egress: Egress,
        route: RouteReceipt,
        kinds: Mapping[str, KindSpec],
        now: float,
    ) -> tuple[Authorization | None, float, str]:
        """Return (authorization, send_at, reason). Reserves the delivery id and budget atomically."""
        spec = kinds.get(egress.kind)
        if spec is None or not spec.public_lane:
            return None, 0.0, "kind not eligible"
        if not egress.payload or any(v.label != OWNER_PUBLIC for v in egress.payload):
            return None, 0.0, "payload not owner-published"
        if egress.control:
            return None, 0.0, "control args not allowed"
        if route.destination != egress.destination.data:
            return None, 0.0, "destination is not the route's return address"
        cfg = self.config
        since = now - cfg.window_seconds
        with self.store.tx() as db:
            if db.execute("SELECT 1 FROM delivery_ids WHERE id=?", (route.delivery_id,)).fetchone():
                return None, 0.0, "delivery id already seen"
            db.execute("INSERT INTO delivery_ids (id) VALUES (?)", (route.delivery_id,))
            if route.cost is None:
                return None, 0.0, "route cost unknown"
            send_at = route.arrived_at + self.rng.uniform(*cfg.jitter)
            latest = send_at + cfg.slot_grace
            # window is measured between delivery times as the recipient sees them
            (n,) = db.execute(
                "SELECT COUNT(*) FROM sends WHERE lane='public' AND dest=? AND at>?",
                (route.destination, send_at - cfg.window_seconds),
            ).fetchone()
            if n >= cfg.per_destination:
                return None, 0.0, "destination window exhausted"
            (spent,) = db.execute(
                "SELECT COALESCE(SUM(cost), 0) FROM sends WHERE lane='public' AND at>?", (since,)
            ).fetchone()
            if spent + route.cost > cfg.service_budget:
                return None, 0.0, "service budget exhausted"
            db.execute(
                "INSERT INTO sends (lane, dest, at, cost) VALUES ('public',?,?,?)",
                (route.destination, latest, route.cost),  # latest possible delivery
            )
            cur = db.execute(
                "INSERT INTO receipts (digest, send_at, expires_at) VALUES (?,?,?)", (egress.digest, send_at, latest)
            )
        return Authorization("lane", f"R{cur.lastrowid}"), send_at, "admitted"
