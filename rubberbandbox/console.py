"""Owner views and queued decisions; the daemon alone applies decisions."""

from __future__ import annotations

import argparse
import json
import os
import random
import re
from collections import Counter
import time
import unicodedata

from .config import load
from .core.store import Store, egress_from_blob, parse_id


def safe(s: object, *, multiline: bool = False) -> str:
    text = str(s)
    return "".join(
        (f"\\x{ord(c):02x}" if ord(c) <= 255 else f"\\u{ord(c):04x}")
        if unicodedata.category(c) in {"Cc", "Cf"} and not (multiline and c == "\n") else c
        for c in text
    )


def _line(*fields: object) -> None:
    print("\t".join(safe(field) for field in fields))


def _limit(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("limit must be positive")
    return number


def main(argv: list[str]) -> int:
    command = argv[0]
    parser = argparse.ArgumentParser(prog=f"rubberbandbox {command}")
    parser.add_argument("--config", required=True)
    if command in {"quarantine", "queue"}:
        parser.add_argument("--limit", type=_limit, default=20)
    if command in {"approve", "deny", "stiffen"}:
        parser.add_argument("ref")
    if command == "sample":
        parser.add_argument("--n", type=_limit, default=20)
        parser.add_argument("--hours", type=_limit, default=24)
    elif command == "label":
        parser.add_argument("raw")
        parser.add_argument("label")
    elif command == "metrics":
        parser.add_argument("--field", required=True)
    args = parser.parse_args(argv[1:])
    config = load(args.config)
    if not os.path.isfile(config.db):  # never create a stray database at a mistyped path
        parser.error(f"no database at {config.db}: start the daemon first")
    store = Store(config.db)
    try:
        if command == "sample":
            now = time.time()
            rows = store.db.execute(
                "SELECT c.raw, c.status, c.extracted FROM classifications c "
                "LEFT JOIN labels l ON l.raw=c.raw WHERE l.raw IS NULL AND c.at>=? AND c.at<=?",
                (now - args.hours * 3600, now),
            ).fetchall()
            for raw, status, extracted in random.SystemRandom().sample(rows, min(args.n, len(rows))):
                value = store.get(raw)
                _line(raw, status, extracted, value.data[:500] if value else "(no stored text)")
        elif command == "label":
            if parse_id(args.raw, "V") is None:
                parser.error("malformed raw id")
            if store.db.execute("SELECT raw FROM classifications WHERE raw=?", (args.raw,)).fetchone() is None:
                parser.error("unknown raw id")
            if re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", args.label) is None:
                parser.error("invalid label")
            store.db.execute("INSERT OR REPLACE INTO labels (raw, label, at) VALUES (?,?,?)",
                             (args.raw, args.label, time.time()))
            _line(args.raw, args.label)
        elif command == "metrics":
            _metrics(store, args.field)
        elif command == "digest":
            row = store.db.execute("SELECT at, body FROM digests ORDER BY at DESC, id DESC LIMIT 1").fetchone()
            if row is None:
                print("no digest released yet")
            else:
                print(safe(row[1], multiline=True) if row[1] else "(empty digest)")
        elif command == "pending":
            for rid, blob, reason, created in store.db.execute(
                "SELECT id, egress, reason, created_at FROM approvals WHERE status='pending' ORDER BY id"
            ).fetchall():
                eg = egress_from_blob(store, blob)
                if eg is None:
                    _line(f"A{rid}", "(missing stored egress)", reason, created)
                    continue
                dest = eg.destination
                trust = "trusted" if dest.label.trusted else "untrusted"
                _line(f"A{rid}", eg.kind, dest.data,
                      f"This destination came from {dest.source} ({trust})", reason, created)
        elif command == "quarantine":
            for rid, topic, cluster, created, ref in store.db.execute(
                "SELECT id, topic, cluster, created_at, ref FROM notices "
                "WHERE topic IN ('quarantined','unreadable') ORDER BY created_at DESC, id DESC LIMIT ?",
                (args.limit,),
            ).fetchall():
                value = store.get(ref) if ref is not None else None
                _line(rid, topic, cluster, created, value.data[:500] if value else "(no stored text)")
        elif command == "queue":
            for row in store.db.execute(
                "SELECT id, action, ref, status, result FROM owner_queue ORDER BY id DESC LIMIT ?", (args.limit,)
            ).fetchall():
                _line(*row)
        else:
            if command in {"approve", "deny"}:
                rid = parse_id(args.ref, "A")
                if rid is None:
                    parser.error("malformed approval id")
                if store.db.execute("SELECT id FROM approvals WHERE id=?", (rid,)).fetchone() is None:
                    parser.error("unknown approval id")
            elif not args.ref.strip() or any(unicodedata.category(c) in {"Cc", "Cf"} for c in args.ref):
                parser.error("cluster must be nonempty and contain no control or format characters")
            cur = store.db.execute("INSERT INTO owner_queue (at, action, ref) VALUES (?,?,?)",
                                   (time.time(), command, args.ref))
            _line(cur.lastrowid)
    finally:
        store.db._conn.close()
    return 0


def _metrics(store: Store, field: str) -> None:
    rows = store.db.execute(
        "SELECT l.label, c.status, c.extracted FROM labels l JOIN classifications c ON c.raw=l.raw"
    ).fetchall()
    if not rows:
        _line("no labeled classifications")
        return
    pairs: Counter = Counter()
    excluded: Counter = Counter()
    for label, status, extracted in rows:
        if status != "ok":
            excluded[status] += 1
            continue
        data = json.loads(extracted) if extracted is not None else {}
        value = data.get(field, "(none)")
        predicted = value if isinstance(value, str) else json.dumps(value, sort_keys=True)
        pairs[label, predicted] += 1
    support: Counter = Counter()
    predictions: Counter = Counter()
    for (label, predicted), count in pairs.items():
        support[label] += count
        predictions[predicted] += count
    _line("class", "precision", "recall", "support")
    for name in sorted(support.keys() | predictions.keys()):
        correct = pairs[name, name]
        precision = f"{correct / predictions[name]:.6f}" if predictions[name] else "-"
        recall = f"{correct / support[name]:.6f}" if support[name] else "-"
        _line(name, precision, recall, support[name])
    total = sum(pairs.values())
    correct = sum(count for (label, predicted), count in pairs.items() if label == predicted)
    _line("accuracy", f"{correct / total:.6f}" if total else "-", f"{correct}/{total}")
    for (label, predicted), count in sorted(pairs.items()):
        _line(f"{label} -> {predicted}: {count}")
    for status in ("budget", "error", "rejected"):
        _line("excluded", status, excluded[status])
