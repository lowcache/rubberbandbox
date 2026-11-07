"""Holds and the owner digest. Holds fail closed: nothing pending ever crosses on its own."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass

from .store import Store, parse_id
from .types import Authorization, Egress


@dataclass(frozen=True)
class DigestConfig:
    interval: float = 3_600.0  # fixed schedule
    per_cluster: int = 3  # interruption budget per source cluster per digest (A1)


@dataclass(frozen=True)
class DigestEntry:
    id: str
    kind: str
    destination: str
    provenance: str  # shown in the largest type: where the destination came from
    first_send: bool
    reason: str


@dataclass(frozen=True)
class Digest:
    entries: tuple[DigestEntry, ...]
    collapsed: dict[str, int]  # cluster -> pending items not shown this round
    notices: dict[str, int]  # "cluster/topic" -> count


class Approvals:
    def __init__(self, store: Store, config: DigestConfig) -> None:
        self.store = store
        self.config = config
        self._last_digest: float | None = None

    def hold(self, egress: Egress, cluster: str, reason: str, now: float) -> str:
        """Queue for the owner. Repeats of a pending egress collapse into one entry."""
        row = self.store.db.execute(
            "SELECT id FROM approvals WHERE digest=? AND status='pending'", (egress.digest,)
        ).fetchone()
        if row:
            return f"A{row[0]}"
        blob = json.dumps({"kind": egress.kind, "dest": egress.destination.id, "payload": [v.id for v in egress.payload]})
        cur = self.store.db.execute(
            "INSERT INTO approvals (egress, digest, cluster, reason, status, created_at) VALUES (?,?,?,?, 'pending', ?)",
            (blob, egress.digest, cluster, reason, now),
        )
        aid = f"A{cur.lastrowid}"
        self.store.audit(now, "hold", approval=aid, kind=egress.kind, dest=egress.destination.id, reason=reason)
        return aid

    def notice(self, topic: str, cluster: str, ref: str | None, now: float) -> None:
        self.store.db.execute(
            "INSERT INTO notices (cluster, topic, ref, created_at) VALUES (?,?,?,?)", (cluster, topic, ref, now)
        )

    def egress_of(self, aid: str) -> Egress | None:
        row = self.store.db.execute("SELECT egress FROM approvals WHERE id=?", (parse_id(aid, "A"),)).fetchone()
        if row is None:
            return None
        blob = json.loads(row[0])
        dest = self.store.get(blob["dest"])
        payload = tuple(self.store.get(v) for v in blob["payload"])
        if dest is None or any(v is None for v in payload):
            return None
        return Egress(blob["kind"], dest, payload)  # type: ignore[arg-type]

    def approve(self, aid: str, now: float) -> Authorization:
        egress = self.egress_of(aid)
        if egress is None:
            raise KeyError(aid)
        cur = self.store.db.execute(
            "UPDATE approvals SET status='approved' WHERE id=? AND status='pending'", (parse_id(aid, "A"),))
        if cur.rowcount:  # only a real state change is an approval; replays are left to the door
            self.store.set_destination(egress.destination.data, "approved", now)
            self.store.audit(now, "approve", approval=aid)
        return Authorization("approval", aid)

    def deny(self, aid: str, now: float) -> None:
        self.store.db.execute("UPDATE approvals SET status='denied' WHERE id=? AND status='pending'", (parse_id(aid, "A"),))
        self.store.audit(now, "deny", approval=aid)

    def digest(self, now: float) -> Digest | None:
        """Return the digest if one is due on the fixed schedule, else None."""
        if self._last_digest is not None and now - self._last_digest < self.config.interval:
            return None
        since = self._last_digest if self._last_digest is not None else float("-inf")
        self._last_digest = now
        rows = self.store.db.execute(
            "SELECT id, cluster, reason FROM approvals WHERE status='pending' ORDER BY id"
        ).fetchall()
        shown: Counter[str] = Counter()
        entries: list[DigestEntry] = []
        collapsed: Counter[str] = Counter()
        for rid, cluster, reason in rows:
            if shown[cluster] >= self.config.per_cluster:
                collapsed[cluster] += 1
                continue
            shown[cluster] += 1
            eg = self.egress_of(f"A{rid}")
            if eg is None:
                continue
            dest = eg.destination
            trust = "trusted" if dest.label.trusted else "untrusted"
            entries.append(
                DigestEntry(
                    id=f"A{rid}",
                    kind=eg.kind,
                    destination=dest.data,
                    provenance=f"This destination came from {dest.source} ({trust})",
                    first_send=self.store.destination(dest.data) is None,
                    reason=reason,
                )
            )
        notices: Counter[str] = Counter()
        for cluster, topic in self.store.db.execute(
            "SELECT cluster, topic FROM notices WHERE created_at>?", (since,)
        ).fetchall():
            notices[f"{cluster}/{topic}"] += 1
        return Digest(tuple(entries), dict(collapsed), dict(notices))
