"""The egress invariant. The door runs this on every crossing, independently of the bones.

No egress unless one of:
  approval     the owner tapped yes on exactly this egress (single use)
  grant        an active owner-minted grant covers (kind, destination); publishes need trusted payload
  lane         an unexpired public-lane receipt for exactly this egress; payload is owner-published
  public_read  a read-only kind whose destination and payload are all public
"""

from __future__ import annotations

from typing import Mapping

from .grants import GrantBook
from .labels import OWNER_PUBLIC
from .store import Store, parse_id
from .types import Authorization, Egress, KindSpec


def check(
    egress: Egress,
    auth: Authorization,
    kinds: Mapping[str, KindSpec],
    store: Store,
    grants: GrantBook,
    now: float,
) -> str | None:
    """Return None if the egress may cross, else the reason it may not."""
    spec = kinds.get(egress.kind)
    if spec is None:
        return f"unknown kind {egress.kind!r}"

    if auth.kind == "approval":
        row = _row(store, "SELECT digest, status, consumed FROM approvals WHERE id=?", auth.ref, "A")
        if row is None:
            return "no such approval"
        digest, status, consumed = row
        if status != "approved" or consumed:
            return "approval not granted or already used"
        if digest != egress.digest:
            return "approval is for a different egress"
        return None

    if auth.kind == "grant":
        grant = grants.get_active(auth.ref, now)
        if grant is None:
            return "grant missing, ended, or expired"
        if egress.kind not in grant.kinds or egress.destination.data not in grant.destinations:
            return "grant does not cover this kind and destination"
        if spec.publishes and not all(v.label.trusted for v in egress.payload):
            return "publish with untrusted payload needs owner approval"
        return None

    if auth.kind == "lane":
        if not spec.public_lane:
            return "kind is not eligible for the public lane"
        if not egress.payload or any(v.label != OWNER_PUBLIC for v in egress.payload):
            return "public lane carries owner-published data only"
        row = _row(store, "SELECT digest, consumed, send_at, expires_at FROM receipts WHERE id=?", auth.ref, "R")
        if row is None:
            return "no such lane receipt"
        if row[1]:
            return "lane receipt already used"
        if row[0] != egress.digest:
            return "lane receipt is for a different egress"
        if now < row[2]:
            return "before its slot"
        if now > row[3]:
            return "missed slot: reply cancelled, never caught up"
        return None

    if auth.kind == "public_read":
        if not spec.read_only:
            return "kind is not read-only"
        if not egress.destination.label.public or not all(v.label.public for v in egress.payload):
            return "read carries or targets private-derived data"
        return None

    return f"unknown authorization {auth.kind!r}"


def _row(store: Store, sql: str, ref: str, prefix: str) -> tuple | None:
    rid = parse_id(ref, prefix)
    return None if rid is None else store.db.execute(sql, (rid,)).fetchone()
