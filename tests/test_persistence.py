import random
import sqlite3

import pytest

from rubberbandbox.core import (
    EXTERNAL_PRIVATE, Egress, InboundEvent, ManualClock, Mount, Proposal, Sandbox,
)
from rubberbandbox.core.approvals import DigestConfig
from rubberbandbox.core.store import SCHEMA_VERSION, Store, StoreError
from rubberbandbox.packs.messaging import KINDS, KeywordClerk, MessagingPack, SimChannel


@pytest.fixture
def env(tmp_path):
    clock = ManualClock()
    channel = SimChannel()
    mounts = [Mount(MessagingPack(), KeywordClerk())]
    adapters = {kind: channel for kind in KINDS}

    def restart():
        return Sandbox(mounts, adapters, clock=clock, rng=random.Random(0),
                       digest=DigestConfig(interval=100), db=str(tmp_path / "state.db"))

    return restart, channel, clock


def private_egress(sb):
    dest = sb.store.put("sms:+12065550100", EXTERNAL_PRIVATE, "test", sb.clock())
    return Egress("msg.send", dest, (sb.owner_put("private work"),))


def test_stiffening_survives_restart_and_holds_granted_private_work(env):
    restart, channel, clock = env
    sb = restart()
    sb.owner_mint(["msg.send"], ["sms:+12065550100"], 1000)
    eg = private_egress(sb)
    assert sb._route(Proposal(eg), None, clock()).status == "sent"
    channel.sent.clear()
    sb.stiffen("messaging/sms:+1206")
    sb = restart()
    outcome = sb._route(Proposal(eg), None, clock())
    assert outcome.status == "held"
    assert "cluster stiffened" in outcome.reason
    assert "messaging/sms:+1206" in sb.stiffened
    assert channel.sent == []


def test_published_script_survives_restart_and_is_sent_on_public_lane(env):
    restart, channel, clock = env
    sb = restart()
    sb.owner_publish("script.price", "old price")
    published = sb.owner_publish("script.price", "Persisted owner price script.")
    sb.stiffen("messaging/sms:+1206")
    sb = restart()
    outcomes = sb.receive(InboundEvent("sms", True, "+12065550100", "d1", "price?", clock()))
    assert [o.status for o in outcomes] == ["scheduled"]
    clock.advance(300)
    sb.tick()
    assert [r["body"] for r in channel.sent] == [published.data]
    assert sb.published["script.price"] == published


def test_workspace_survives_restart_in_insertion_order(env):
    restart, _, _ = env
    sb = restart()
    values = [sb.owner_put("first"), sb.owner_put("second")]
    sb = restart()
    assert isinstance(sb.workspace, list)
    assert sb.workspace == values


@pytest.mark.parametrize("downtime", [100, 240])
def test_restart_skips_missed_digest_without_releasing_pending_approval(env, downtime):
    restart, channel, clock = env
    sb = restart()
    start = clock()
    aid = sb.approvals.hold(private_egress(sb), "messaging/sms:+1206", "test", clock())
    sb.approvals.notice("before", "cluster", None, clock())
    assert sb.digest().notices == {"cluster/before": 1}
    clock.advance(1)
    sb.approvals.notice("after", "cluster", None, clock())
    clock.t = start + downtime
    sb = restart()
    due = start + (downtime // 100 + 1) * 100
    assert sb.digest() is None
    assert [(event, detail) for _, event, detail in sb.store.audit_log() if event == "digest.missed"] == [
        ("digest.missed", {"missed_due": start + 100, "next_due": due})
    ]
    assert sb.store.db.execute("SELECT status FROM approvals WHERE id=?", (int(aid[1:]),)).fetchone() == ("pending",)
    clock.t = due - 0.1
    assert sb.digest() is None
    clock.t = due
    digest = sb.digest()
    assert [entry.id for entry in digest.entries] == [aid]
    assert digest.notices == {"cluster/after": 1}
    assert sb.digest() is None
    assert channel.sent == []


def test_late_digest_poll_keeps_original_grid(env):
    restart, _, clock = env
    sb = restart()
    start = clock()
    assert sb.digest() is not None
    clock.advance(140)
    assert sb.digest() is not None
    assert sb.digest() is None
    clock.t = start + 199.9
    assert sb.digest() is None
    clock.t = start + 200
    assert sb.digest() is not None
    assert sb.store.db.execute("SELECT next_due, last_released FROM digest_clock").fetchone() == (start + 300, start + 200)


def test_restart_before_due_preserves_digest_clock(env):
    restart, _, clock = env
    sb = restart()
    assert sb.digest() is not None
    clock.advance(40)
    sb = restart()
    assert sb.digest() is None
    clock.advance(60)
    assert sb.digest() is not None
    assert not any(event == "digest.missed" for _, event, _ in sb.store.audit_log())


@pytest.mark.parametrize("version,has_table", [(99, False), (99, True), (0, True)])
def test_incompatible_schema_is_rejected_without_modifying_file(tmp_path, version, has_table):
    path = tmp_path / "incompatible.db"
    with sqlite3.connect(path) as db:
        db.execute(f"PRAGMA user_version={version}")
        if has_table:
            db.execute("CREATE TABLE existing (value TEXT)")
            db.execute("INSERT INTO existing VALUES ('untouched')")
    before = path.read_bytes()
    with pytest.raises(StoreError):
        Store(str(path))
    assert path.read_bytes() == before


def test_fresh_schema_is_versioned_and_reopens(tmp_path):
    path = str(tmp_path / "fresh.db")
    store = Store(path)
    assert store.db.execute("PRAGMA user_version").fetchone() == (SCHEMA_VERSION,)
    assert Store(path).db.execute("PRAGMA user_version").fetchone() == (SCHEMA_VERSION,)


RUNTIME_TABLES = ("sources", "inbound_seen", "owner_queue", "digests", "classifications", "labels",
                  "clerk_calls", "stiffened", "published", "workspace", "digest_clock")


def pre_versioning_db(path):
    """A database as the code before schema versioning left it: no runtime tables, user_version 0."""
    store = Store(path)
    store.audit(1.0, "kept", note="before the upgrade")
    for table in RUNTIME_TABLES:
        store.db.execute(f"DROP TABLE {table}")
    store.db.execute("PRAGMA user_version=0")
    store.db._conn.close()


def test_a_pre_versioning_database_is_upgraded_in_place(tmp_path):
    path = str(tmp_path / "old.db")
    pre_versioning_db(path)
    store = Store(path)
    try:
        assert store.db.execute("PRAGMA user_version").fetchone() == (SCHEMA_VERSION,)
        assert [e for _, e, _ in store.audit_log()] == ["kept"]
        for table in RUNTIME_TABLES:
            assert store.db.execute(f"SELECT COUNT(*) FROM {table}").fetchone() == (0,)
    finally:
        store.db._conn.close()


def test_a_pre_versioning_database_missing_a_column_is_refused(tmp_path):
    path = str(tmp_path / "older.db")
    pre_versioning_db(path)
    with sqlite3.connect(path) as db:
        db.execute("DROP TABLE receipts")
        db.execute("CREATE TABLE receipts (id INTEGER PRIMARY KEY, digest TEXT NOT NULL)")  # no kind column
    before = open(path, "rb").read()
    with pytest.raises(StoreError):
        Store(path)
    assert open(path, "rb").read() == before
