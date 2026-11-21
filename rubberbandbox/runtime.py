"""Persistent polling, owner actions and withheld outbound effects."""

from __future__ import annotations

import fcntl
import json
import threading
import time
from dataclasses import dataclass
from typing import Protocol, Sequence

from .core.approvals import Digest
from .core.labels import EXTERNAL_PRIVATE
from .core.sandbox import Sandbox
from .core.store import Store
from .core.types import InboundEvent


@dataclass(frozen=True)
class Malformed:
    """An inbound record the source could not parse; quarantined, never retried."""

    line: int
    text: str
    error: str


class Source(Protocol):
    name: str

    def poll(self, cursor: str | None) -> tuple[Sequence[InboundEvent | Malformed], str | None]: ...


class JsonlSource:
    def __init__(self, name: str, path: str) -> None:
        self.name, self.path = name, path

    def poll(self, cursor: str | None) -> tuple[Sequence[InboundEvent | Malformed], str | None]:
        """Cursor counts complete lines. A last line without its newline is still being written."""
        consumed = int(cursor or "0")
        if consumed < 0:
            raise ValueError("negative JSONL cursor")
        items: list[InboundEvent | Malformed] = []
        complete = 0
        with open(self.path, encoding="utf-8", errors="replace") as stream:
            for index, line in enumerate(stream):
                if not line.endswith("\n"):
                    break
                complete = index + 1
                text = line.rstrip("\n")
                if index < consumed or not text.strip():
                    continue
                try:
                    data = json.loads(text)
                    if not isinstance(data, dict):
                        raise TypeError("not a JSON object")
                    items.append(InboundEvent(**data))
                except (ValueError, TypeError) as exc:
                    items.append(Malformed(index + 1, text, repr(exc)))
        return items, str(max(complete, consumed))


class ShadowAdapter:
    def __init__(self, store: Store | None, clock=time.time) -> None:
        self.store, self.clock = store, clock

    def execute(self, kind: str, destination: str, payload: Sequence[str], **extra: object) -> None:
        if self.store is None:
            raise RuntimeError("shadow adapter is not bound")
        self.store.audit(self.clock(), "shadow.withheld", kind=kind, destination=destination)


def render_digest(digest: Digest) -> str:
    def line(*fields: object) -> str:
        return "\t".join(str(v).replace("\\", "\\\\").replace("\t", "\\t").replace("\r", "\\r").replace("\n", "\\n") for v in fields)

    lines = [line(e.id, e.kind, e.destination, e.provenance, e.reason) for e in digest.entries]
    lines.extend(line("collapsed", cluster, count) for cluster, count in sorted(digest.collapsed.items()))
    lines.extend(line("notice", topic, count) for topic, count in sorted(digest.notices.items()))
    return "\n".join(lines)


def daemon_lock(db: str):
    lock = open(f"{db}.lock", "a")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        lock.close()
        raise RuntimeError(f"daemon already running for {db}") from exc
    return lock


class Runtime:
    def __init__(self, sandbox: Sandbox, sources: Sequence[Source], *, _lock=None) -> None:
        self.sandbox, self.store, self.sources = sandbox, sandbox.store, list(sources)
        if len({s.name for s in sources}) != len(sources):
            raise ValueError("duplicate source names")
        path = self.store.db.execute("PRAGMA database_list").fetchone()[2]
        self._lock = _lock if _lock is not None or not path else daemon_lock(path)  # in-memory: nothing to share
        try:
            with self.store.tx() as db:
                for source, delivery_id in db.execute(
                    "SELECT source, delivery_id FROM inbound_seen WHERE status='processing'"
                ).fetchall():
                    db.execute(
                        "UPDATE inbound_seen SET status='quarantined' WHERE source=? AND delivery_id=?",
                        (source, delivery_id),
                    )
                    self.store.audit(sandbox.clock(), "inbound.interrupted", source=source, delivery_id=delivery_id)
                    sandbox.approvals.notice("quarantined", f"runtime/{source}", None, sandbox.clock())
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        if self._lock is not None:
            self._lock.close()

    def run_once(self) -> None:
        sb, store = self.sandbox, self.store
        for row_id, action, ref in store.db.execute(
            "SELECT id, action, ref FROM owner_queue WHERE status='queued' ORDER BY id"
        ).fetchall():
            try:
                handler = {"approve": sb.owner_approve, "deny": sb.owner_deny, "stiffen": sb.stiffen}.get(action)
                if handler is None:
                    raise ValueError(f"unknown owner action: {action}")
                outcome = handler(ref)
                result = f"{outcome.status}: {outcome.reason}" if outcome is not None else "done"
                status = "done"
            except Exception as exc:
                status, result = "failed", repr(exc)
            store.db.execute("UPDATE owner_queue SET status=?, result=? WHERE id=?", (status, result[:500], row_id))
        for source in self.sources:
            row = store.db.execute("SELECT cursor FROM sources WHERE name=?", (source.name,)).fetchone()
            try:
                events, cursor = source.poll(row[0] if row else None)
            except Exception as exc:
                store.audit(sb.clock(), "source.error", source=source.name, error=repr(exc))
                continue
            for event in events:
                if isinstance(event, Malformed):
                    with store.tx():
                        raw = store.put(event.text, EXTERNAL_PRIVATE, f"{source.name}:malformed", sb.clock())
                        store.audit(sb.clock(), "source.malformed", source=source.name, line=event.line,
                                    error=event.error, raw=raw.id)
                        sb.approvals.notice("quarantined", f"runtime/{source.name}", raw.id, sb.clock())
                    continue
                existing = store.db.execute(
                    "SELECT status FROM inbound_seen WHERE source=? AND delivery_id=?",
                    (source.name, event.delivery_id),
                ).fetchone()
                if existing is not None:
                    continue
                store.db.execute(
                    "INSERT OR REPLACE INTO inbound_seen (source, delivery_id, status, at) VALUES (?,?,'processing',?)",
                    (source.name, event.delivery_id, sb.clock()),
                )
                status = "done"
                try:
                    sb.receive(event)
                except Exception as exc:
                    with store.tx():
                        store.audit(sb.clock(), "inbound.failed", source=source.name,
                                    delivery_id=event.delivery_id, error=repr(exc))
                        raw = store.put(event.text, EXTERNAL_PRIVATE, f"{event.channel}:failed", sb.clock())
                        sb.approvals.notice("quarantined", f"runtime/{source.name}", raw.id, sb.clock())
                        status = "quarantined"
                        store.db.execute(
                            "UPDATE inbound_seen SET status=? WHERE source=? AND delivery_id=?",
                            (status, source.name, event.delivery_id),
                        )
                store.db.execute(
                    "UPDATE inbound_seen SET status=? WHERE source=? AND delivery_id=?",
                    (status, source.name, event.delivery_id),
                )
            store.db.execute(
                "INSERT INTO sources (name, cursor) VALUES (?,?) ON CONFLICT(name) DO UPDATE SET cursor=excluded.cursor",
                (source.name, cursor),
            )
        sb.tick()
        digest = sb.digest()
        if digest is not None:
            store.db.execute("INSERT INTO digests (at, body) VALUES (?,?)", (sb.clock(), render_digest(digest)))

    def run_forever(self, stop: threading.Event, interval: float) -> None:
        while not stop.is_set():
            self.run_once()
            stop.wait(interval)
