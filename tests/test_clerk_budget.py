import random
import sqlite3
import threading

import pytest

from rubberbandbox.core import ClerkBudget, InboundEvent, ManualClock, Mount, Outcome, Sandbox
from rubberbandbox.core.store import Store
from rubberbandbox.packs.messaging import KINDS, KeywordClerk, MessagingPack, SimChannel


class CountingClerk:
    def __init__(self, raises=False):
        self.calls = 0
        self.raises = raises

    def extract(self, text):
        self.calls += 1
        if self.raises:
            raise RuntimeError("clerk unavailable")
        return KeywordClerk().extract(text)


@pytest.fixture
def env(tmp_path):
    clock, channel, clerk = ManualClock(), SimChannel(), CountingClerk()

    def restart(budget=None, disk=False):
        return Sandbox(
            [Mount(MessagingPack(), clerk)], {kind: channel for kind in KINDS},
            clock=clock, rng=random.Random(0), clerk_budget=budget,
            db=str(tmp_path / "state.db") if disk else ":memory:",
        )

    return restart, channel, clock, clerk


def receive(sb, origin="+12065550100", text="hello"):
    return sb.receive(InboundEvent("sms", True, origin, str(sb.clock()), text, sb.clock()))


def test_sender_limit_is_independent_and_expires_at_window_boundary(env):
    restart, _, clock, clerk = env
    sb = restart(ClerkBudget(2, 60, 100))
    receive(sb)
    receive(sb)
    assert clerk.calls == 2
    assert receive(sb) == [Outcome("airlock", "+12065550100", "quarantined", "clerk budget exhausted")]
    assert clerk.calls == 2
    assert sb.store.audit_log()[-1][1:] == (
        "clerk.budget", {"raw": "V3", "origin": "+12065550100", "limit": "sender"},
    )
    receive(sb, "+12065550101")
    assert clerk.calls == 3
    clock.advance(60)
    receive(sb)
    assert clerk.calls == 4


def test_daily_limit_across_origins_expires_at_day_boundary(env):
    restart, _, clock, clerk = env
    sb = restart(ClerkBudget(100, 60, 2))
    receive(sb)
    receive(sb, "+12065550101")
    assert receive(sb, "+12065550102")[0].status == "quarantined"
    assert clerk.calls == 2
    assert sb.store.audit_log()[-1][2]["limit"] == "day"
    clock.advance(86400)
    receive(sb, "+12065550102")
    assert clerk.calls == 3


def test_calls_stamped_after_a_backwards_clock_step_still_count(env):
    restart, _, clock, clerk = env
    sb = restart(ClerkBudget(1, 60, 100))
    receive(sb)
    clock.advance(-10)
    assert receive(sb)[0].status == "quarantined"
    assert clerk.calls == 1


def test_quarantine_retains_raw_without_approval_schedule_or_send(env):
    restart, channel, clock, clerk = env
    sb = restart(ClerkBudget(1, 60, 100))
    sb.owner_publish("script.price", "Owner price script.")
    receive(sb)
    assert receive(sb, text="price?")[0].status == "quarantined"
    assert clerk.calls == 1
    assert sb.tick() == []
    clock.advance(300)
    assert sb.tick() == []
    assert channel.sent == []
    assert sb.store.db.execute("SELECT COUNT(*) FROM approvals").fetchone() == (0,)
    assert sb.store.db.execute("SELECT COUNT(*) FROM scheduled").fetchone() == (0,)
    cluster, topic, ref = sb.store.db.execute("SELECT cluster, topic, ref FROM notices").fetchone()
    assert (cluster, topic) == ("messaging/sms:+1206", "quarantined")
    assert sb.store.get(ref).data == "price?"
    # A fresh destination proves the same price question can use the public lane.
    assert receive(sb, "+12065550101", "price?")[0].status == "scheduled"
    clock.advance(300)
    sb.tick()
    assert [row["body"] for row in channel.sent] == ["Owner price script."]


def test_sender_budget_survives_restart(env):
    restart, _, _, clerk = env
    budget = ClerkBudget(1, 60, 100)
    sb = restart(budget, disk=True)
    receive(sb)
    sb.store.db._conn.close()
    sb = restart(budget, disk=True)
    assert receive(sb)[0].status == "quarantined"
    assert clerk.calls == 1


def test_raising_clerk_spends_budget_before_the_call(env):
    restart, _, _, clerk = env
    sb = restart(ClerkBudget(1, 60, 100))
    clerk.raises = True
    extract = clerk.extract

    def checked_extract(text):
        assert sb.store.db.execute("SELECT COUNT(*) FROM clerk_calls").fetchone() == (1,)
        return extract(text)

    clerk.extract = checked_extract
    assert receive(sb)[0].status == "noticed"
    assert clerk.calls == 1
    assert sb.store.db.execute("SELECT origin, at FROM clerk_calls").fetchall() == [("+12065550100", sb.clock())]
    assert receive(sb)[0].status == "quarantined"
    assert clerk.calls == 1


def test_unlimited_budget_preserves_current_behavior(env):
    restart, _, _, clerk = env
    sb = restart()
    for _ in range(4):
        receive(sb)
    assert clerk.calls == 4
    assert sb.store.db.execute("SELECT COUNT(*) FROM clerk_calls").fetchone() == (0,)


def test_file_stores_wait_for_another_writer_and_use_wal(tmp_path, monkeypatch):
    connect = sqlite3.connect
    # Remove sqlite's default wait so only the Store pragma can provide it.
    monkeypatch.setattr(sqlite3, "connect", lambda *a, **kw: connect(*a, timeout=0, **kw))
    path = str(tmp_path / "shared.db")
    first, second = Store(path), Store(path)
    assert first.db.execute("PRAGMA journal_mode").fetchone() == ("wal",)
    assert second.db.execute("PRAGMA journal_mode").fetchone() == ("wal",)
    assert second.db.execute("PRAGMA busy_timeout").fetchone() == (5000,)
    started, done = threading.Event(), threading.Event()
    errors = []

    def write():
        started.set()
        try:
            with second.tx() as db:
                db.execute("INSERT INTO clerk_calls (origin, at) VALUES ('second', 2)")
        except BaseException as exc:
            errors.append(exc)
        finally:
            done.set()

    with first.tx() as db:
        db.execute("INSERT INTO clerk_calls (origin, at) VALUES ('first', 1)")
        worker = threading.Thread(target=write)
        worker.start()
        assert started.wait(2)
        waited = not done.wait(0.1)
    worker.join(6)
    assert waited
    assert done.is_set()
    assert errors == []
    assert second.db.execute("SELECT origin FROM clerk_calls ORDER BY id").fetchall() == [("first",), ("second",)]


def test_memory_store_keeps_default_journal_mode():
    assert Store().db.execute("PRAGMA journal_mode").fetchone() == ("memory",)
