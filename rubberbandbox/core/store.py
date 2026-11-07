"""SQLite-backed state: tagged values, destinations, lane accounting, approvals, schedule, audit."""

from __future__ import annotations

import json
import re
import sqlite3
from contextlib import contextmanager
from typing import Iterator

from .labels import Confidentiality, Integrity, Label, Value

_SCHEMA = """
CREATE TABLE IF NOT EXISTS vals (
  rowid INTEGER PRIMARY KEY, data TEXT NOT NULL, integrity TEXT NOT NULL,
  confidentiality TEXT NOT NULL, source TEXT NOT NULL, first_seen REAL NOT NULL);
CREATE TABLE IF NOT EXISTS destinations (
  key TEXT PRIMARY KEY, status TEXT NOT NULL, approved_at REAL);
CREATE TABLE IF NOT EXISTS delivery_ids (id TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS sends (
  id INTEGER PRIMARY KEY, lane TEXT NOT NULL, dest TEXT NOT NULL, at REAL NOT NULL, cost REAL NOT NULL);
CREATE TABLE IF NOT EXISTS receipts (
  id INTEGER PRIMARY KEY, digest TEXT NOT NULL, send_at REAL NOT NULL, expires_at REAL NOT NULL,
  consumed INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS approvals (
  id INTEGER PRIMARY KEY, egress TEXT NOT NULL, digest TEXT NOT NULL, cluster TEXT NOT NULL,
  reason TEXT NOT NULL, status TEXT NOT NULL, created_at REAL NOT NULL, consumed INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS notices (
  id INTEGER PRIMARY KEY, cluster TEXT NOT NULL, topic TEXT NOT NULL, ref TEXT, created_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS scheduled (
  id INTEGER PRIMARY KEY, egress TEXT NOT NULL, auth TEXT NOT NULL, send_at REAL NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending');
CREATE TABLE IF NOT EXISTS grants (
  id INTEGER PRIMARY KEY, kinds TEXT NOT NULL, dests TEXT NOT NULL, expires_at REAL NOT NULL,
  ended INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS audit (
  seq INTEGER PRIMARY KEY, at REAL NOT NULL, event TEXT NOT NULL, detail TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS audit_append_only_u BEFORE UPDATE ON audit
  BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_append_only_d BEFORE DELETE ON audit
  BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
"""


_ID = re.compile(r"([A-Z])([1-9][0-9]{0,17})")


def parse_id(ref: object, prefix: str) -> int | None:
    """Canonical ids only: expected prefix, ASCII digits, no leading zero, bounded. Never raises."""
    if not isinstance(ref, str) or not ref.isascii():
        return None
    m = _ID.fullmatch(ref)
    return int(m.group(2)) if m and m.group(1) == prefix else None


class Store:
    def __init__(self, path: str = ":memory:") -> None:
        self.db = sqlite3.connect(path, isolation_level=None)  # explicit transactions only
        self.db.executescript(_SCHEMA)

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        """Atomic section: BEGIN IMMEDIATE takes the write lock before any read."""
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield self.db
        except BaseException:
            self.db.execute("ROLLBACK")
            raise
        self.db.execute("COMMIT")

    # values
    def put(self, data: str, label: Label, source: str, now: float) -> Value:
        cur = self.db.execute(
            "INSERT INTO vals (data, integrity, confidentiality, source, first_seen) VALUES (?,?,?,?,?)",
            (data, label.integrity.value, label.confidentiality.value, source, now),
        )
        return Value(f"V{cur.lastrowid}", data, label, source, now)

    def get(self, vid: str) -> Value | None:
        rowid = parse_id(vid, "V")
        if rowid is None:
            return None
        row = self.db.execute(
            "SELECT data, integrity, confidentiality, source, first_seen FROM vals WHERE rowid=?", (rowid,)
        ).fetchone()
        if row is None:
            return None
        label = Label(Integrity(row[1]), Confidentiality(row[2]))
        return Value(vid, row[0], label, row[3], row[4])

    # destinations: 'owner' (owner-typed) or 'approved' (owner tapped yes on a first send)
    def destination(self, key: str) -> tuple[str, float | None] | None:
        row = self.db.execute("SELECT status, approved_at FROM destinations WHERE key=?", (key,)).fetchone()
        return (row[0], row[1]) if row else None

    def set_destination(self, key: str, status: str, approved_at: float | None) -> None:
        existing = self.destination(key)
        if existing and existing[0] == "owner":
            return  # never downgrade an owner-typed destination
        self.db.execute(
            "INSERT OR REPLACE INTO destinations (key, status, approved_at) VALUES (?,?,?)",
            (key, status, approved_at),
        )

    def audit(self, now: float, event: str, **detail: object) -> None:
        self.db.execute(
            "INSERT INTO audit (at, event, detail) VALUES (?,?,?)",
            (now, event, json.dumps(detail, sort_keys=True, default=str)),
        )

    def audit_log(self) -> list[tuple[float, str, dict]]:
        rows = self.db.execute("SELECT at, event, detail FROM audit ORDER BY seq").fetchall()
        return [(r[0], r[1], json.loads(r[2])) for r in rows]
