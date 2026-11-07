"""Elastic scope: permissions minted per task from owner-typed input, expiring on their own."""

from __future__ import annotations

import json
from dataclasses import dataclass

from .labels import Value
from .store import Store, parse_id


class ScopeError(TypeError):
    """Raised when something other than owner-typed text tries to mint scope."""


@dataclass(frozen=True)
class Grant:
    id: str
    kinds: frozenset[str]
    destinations: frozenset[str]
    expires_at: float


class GrantBook:
    def __init__(self, store: Store) -> None:
        self.store = store

    def mint(self, kinds: list[str], destinations: list[str], ttl: float, now: float) -> Grant:
        """Only plain strings the owner typed or selected mint clean scope. A resolved
        reference arrives as a Value and keeps its taint, so it is refused here."""
        for d in destinations:
            if isinstance(d, Value) or not isinstance(d, str):
                raise ScopeError("grant destinations must be owner-typed strings, not resolved values")
        if ttl <= 0:
            raise ValueError("ttl must be positive")
        cur = self.store.db.execute(
            "INSERT INTO grants (kinds, dests, expires_at) VALUES (?,?,?)",
            (json.dumps(sorted(kinds)), json.dumps(sorted(destinations)), now + ttl),
        )
        for d in destinations:
            self.store.set_destination(d, "owner", None)
        gid = f"G{cur.lastrowid}"
        self.store.audit(now, "grant.mint", grant=gid, kinds=sorted(kinds), dests=sorted(destinations), ttl=ttl)
        return Grant(gid, frozenset(kinds), frozenset(destinations), now + ttl)

    def end(self, gid: str, now: float) -> None:
        self.store.db.execute("UPDATE grants SET ended=1 WHERE id=?", (parse_id(gid, "G"),))
        self.store.audit(now, "grant.end", grant=gid)

    def get_active(self, gid: str, now: float) -> Grant | None:
        rid = parse_id(gid, "G")
        if rid is None:
            return None
        row = self.store.db.execute(
            "SELECT kinds, dests, expires_at FROM grants WHERE id=? AND ended=0 AND expires_at>?", (rid, now)
        ).fetchone()
        if row is None:
            return None
        return Grant(gid, frozenset(json.loads(row[0])), frozenset(json.loads(row[1])), row[2])

    def find(self, kind: str, destination: str, now: float) -> Grant | None:
        rows = self.store.db.execute(
            "SELECT id FROM grants WHERE ended=0 AND expires_at>? ORDER BY id", (now,)
        ).fetchall()
        for (rid,) in rows:
            g = self.get_active(f"G{rid}", now)
            if g and kind in g.kinds and destination in g.destinations:
                return g
        return None
