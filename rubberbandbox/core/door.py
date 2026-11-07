"""The steel door: sole holder of the tool adapters. Re-checks the invariant on every crossing,
at decision time and again at dispatch, so a bug in the bones cannot open it."""

from __future__ import annotations

import json
from typing import Callable, Mapping

from . import invariant
from .grants import GrantBook
from .labels import EXTERNAL_PRIVATE, EXTERNAL_PUBLIC
from .store import Store, egress_blob, egress_from_blob, parse_id
from .types import Authorization, Egress, KindSpec, ToolAdapter

_CONSUME = {"approval": ("approvals", "A"), "lane": ("receipts", "R")}  # single-use authorizations


class Door:
    def __init__(
        self,
        store: Store,
        grants: GrantBook,
        kinds: Mapping[str, KindSpec],
        adapters: Mapping[str, ToolAdapter],
        clock: Callable[[], float],
    ) -> None:
        missing = set(kinds) - set(adapters)
        if missing:
            raise ValueError(f"no adapter for kinds: {sorted(missing)}")
        self._store = store
        self._grants = grants
        self._kinds = dict(kinds)
        self._adapters = dict(adapters)
        self._clock = clock
        self.calls: Callable[[Egress], str | None] | None = None  # the registry's tool-call check

    def _check(self, egress: Egress, auth: Authorization, at: float) -> str | None:
        reason = invariant.check(egress, auth, self._kinds, self._store, self._grants, at)
        if reason is None and self.calls is not None:
            reason = self.calls(egress)
        elif reason is None and egress.names:
            reason = "named tool call with no registry to check it"
        return reason

    def set_kind(self, spec: KindSpec) -> None:
        if spec.name not in self._kinds:
            raise KeyError(f"no mounted kind {spec.name!r}")
        self._kinds[spec.name] = spec

    def cross(self, egress: Egress, auth: Authorization, send_at: float | None = None) -> tuple[str, str]:
        """Return ('sent'|'scheduled'|'refused'|'failed', reason). For the lane, the slot comes
        from the receipt itself; the caller's send_at is ignored."""
        now = self._clock()
        if auth.kind == "lane":
            rid = parse_id(auth.ref, "R")
            row = None if rid is None else self._store.db.execute(
                "SELECT send_at FROM receipts WHERE id=?", (rid,)).fetchone()
            send_at = row[0] if row else None
        at = max(now, send_at) if send_at is not None else now  # validity at the moment it would leave
        reason = self._check(egress, auth, at)
        if reason:
            self._store.audit(now, "door.refused", kind=egress.kind, dest=egress.destination.id, auth=auth.kind, reason=reason)
            return "refused", reason
        if send_at is not None and send_at > now:
            blob = egress_blob(egress)
            self._store.db.execute(
                "INSERT INTO scheduled (egress, auth, send_at) VALUES (?,?,?)",
                (blob, json.dumps([auth.kind, auth.ref]), send_at),
            )
            self._store.audit(now, "door.scheduled", kind=egress.kind, dest=egress.destination.id, send_at=send_at)
            return "scheduled", f"at {send_at:.0f}"
        return self._execute(egress, auth)

    def tick(self) -> list[tuple[str, str]]:
        """Dispatch scheduled crossings that are due, re-checking each (grants may have expired)."""
        now = self._clock()
        rows = self._store.db.execute(
            "SELECT id, egress, auth FROM scheduled WHERE status='pending' AND send_at<=? ORDER BY send_at, id", (now,)
        ).fetchall()
        results = []
        for sid, blob, auth_blob in rows:
            self._store.db.execute("UPDATE scheduled SET status='done' WHERE id=?", (sid,))
            egress = egress_from_blob(self._store, blob)
            if egress is None:
                results.append(("refused", "scheduled egress references missing values"))
                continue
            results.append(self._execute(egress, Authorization(*json.loads(auth_blob))))
        return results

    def _execute(self, egress: Egress, auth: Authorization) -> tuple[str, str]:
        with self._store.tx():
            now = self._clock()  # fresh per crossing: a slow adapter must not age earlier checks
            reason = self._check(egress, auth, now)
            spec = self._kinds.get(egress.kind)
            if reason is None and auth.kind in _CONSUME:
                table, prefix = _CONSUME[auth.kind]
                self._store.db.execute(f"UPDATE {table} SET consumed=1 WHERE id=?", (parse_id(auth.ref, prefix),))
        if reason:
            self._store.audit(now, "door.refused", kind=egress.kind, dest=egress.destination.id, auth=auth.kind, reason=reason)
            return "refused", reason
        try:
            extra: dict[str, object] = {"control": [v.data for v in egress.control]} if egress.control else {}
            if egress.names:
                extra["args"] = egress.args
            result = self._adapters[egress.kind].execute(
                egress.kind, egress.destination.data, [v.data for v in egress.payload], **extra)
        except Exception as exc:  # the outside world refused (e.g. provider hard cap)
            self._store.audit(now, "door.failed", kind=egress.kind, dest=egress.destination.id, error=repr(exc))
            return "failed", repr(exc)
        out = {} if result is None else {"output": self._output(egress, spec, result, now)}
        self._store.audit(now, "door.sent", kind=egress.kind, dest=egress.destination.id, auth=auth.kind, ref=auth.ref, **out)
        return "sent", auth.kind

    def _output(self, egress: Egress, spec: KindSpec, result: object, now: float) -> str:
        """Store what the tool returned: external, public only for a public read that sent nothing
        private (anything private that went out may come back as an echo)."""
        sent = (egress.destination, *egress.payload, *egress.control)
        label = EXTERNAL_PUBLIC if spec.read_only and all(v.label.public for v in sent) else EXTERNAL_PRIVATE
        data = result if isinstance(result, str) else json.dumps(result, sort_keys=True, default=str)
        return self._store.put(data, label, f"output:{egress.kind}", now).id
