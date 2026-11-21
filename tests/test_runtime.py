import json
import threading
from dataclasses import asdict

import pytest

from rubberbandbox.config import ConfigError, build, load, resolve_secret
from rubberbandbox.core import EXTERNAL_PRIVATE, Egress, InboundEvent, ManualClock
from rubberbandbox.core.approvals import Digest, DigestEntry
from rubberbandbox.core.store import Store
from rubberbandbox.runtime import JsonlSource, Runtime, ShadowAdapter, render_digest
from rubberbandbox.packs.messaging import KINDS, KeywordClerk


class FakeSource:
    def __init__(self, name, events=(), error=None):
        self.name, self.events, self.error = name, events, error
        self.cursors = []

    def poll(self, cursor):
        self.cursors.append(cursor)
        if self.error:
            raise self.error
        return self.events, str(int(cursor or 0) + len(self.events))


class CountingClerk:
    def __init__(self):
        self.calls = 0

    def extract(self, text):
        self.calls += 1
        return KeywordClerk().extract(text)


def config_file(tmp_path, extra="", clerk='kind = "stub"\nper_sender = 100\nsender_window = 60\nper_day = 1000', mode="shadow"):
    path = tmp_path / "runtime.toml"
    path.write_text(f'db = "{tmp_path / "state.db"}"\nmode = "{mode}"\n{extra}\n[clerk]\n{clerk}\n')
    return path


@pytest.fixture
def env(tmp_path, monkeypatch):
    clock = ManualClock()
    monkeypatch.setattr("rubberbandbox.config.time.time", clock)
    config = load(config_file(tmp_path, '[digest]\ninterval = 100\nper_cluster = 1'))
    sb, runtime = build(config)
    clerk = CountingClerk()
    object.__setattr__(sb.mounts[0], "clerk", clerk)
    yield sb, runtime, clock, clerk, config
    runtime.close()
    sb.store.db._conn.close()


def event(clock, delivery="one", text="hello", origin="+12065550100"):
    return InboundEvent("sms", True, origin, delivery, text, clock())


def events_of(sb, name):
    return [detail for _, key, detail in sb.store.audit_log() if key == name]


def test_jsonl_replay_build_only_uses_shadow_adapters(env, tmp_path):
    sb, runtime, clock, clerk, config = env
    sb.owner_publish("script.price", "Owner price script.")
    path = tmp_path / "inbound.jsonl"
    path.write_text(json.dumps(asdict(event(clock, text="price?"))) + "\n")
    runtime.sources = [JsonlSource("replay", str(path))]
    assert set(sb._door._adapters) == set(KINDS)
    assert all(type(a) is ShadowAdapter and a.store is sb.store for a in sb._door._adapters.values())
    runtime.run_once()
    assert events_of(sb, "shadow.withheld") == []
    assert sb.store.db.execute("SELECT status FROM scheduled").fetchall() == [("pending",)]
    clock.advance(300)
    runtime.run_once()
    assert events_of(sb, "shadow.withheld") == [{"kind": "msg.reply", "destination": "sms:+12065550100"}]
    assert sb.store.db.execute("SELECT name, cursor FROM sources").fetchall() == [("replay", "1")]
    assert clerk.calls == 1
    assert JsonlSource("replay", str(path)).poll("1") == ([], "1")


def test_jsonl_skips_blank_lines_quarantines_malformed_lines_and_waits_for_a_complete_last_line(env, tmp_path):
    sb, runtime, clock, clerk, config = env
    path = tmp_path / "inbound.jsonl"
    good = json.dumps(asdict(event(clock, "a", "hello")))
    later = json.dumps(asdict(event(clock, "b", "hello again")))
    path.write_text(good + "\n\n{not json\n" + json.dumps({"channel": "sms", "text": "no id"}) + "\n" + later + "\n"
                    + '{"channel": "sms", "authenticated": true, "origin": "+12065550100", "delivery_id": "c", "text": "partial')
    runtime.sources = [JsonlSource("inbox", str(path))]
    runtime.run_once()
    assert clerk.calls == 2
    assert sb.store.db.execute("SELECT delivery_id, status FROM inbound_seen ORDER BY delivery_id").fetchall() == [
        ("a", "done"), ("b", "done")]
    assert sb.store.db.execute("SELECT cursor FROM sources").fetchone() == ("5",)  # the partial last line waits
    notices = sb.store.db.execute("SELECT cluster, topic, ref FROM notices ORDER BY id").fetchall()
    assert [(c, t) for c, t, _ in notices] == [("runtime/inbox", "quarantined")] * 2
    texts = [sb.store.get(ref) for _, _, ref in notices]
    assert [(v.data, v.label, v.source) for v in texts] == [
        ("{not json", EXTERNAL_PRIVATE, "inbox:malformed"), ('{"channel": "sms", "text": "no id"}', EXTERNAL_PRIVATE, "inbox:malformed")]
    assert [d["line"] for d in events_of(sb, "source.malformed")] == [3, 4]
    assert events_of(sb, "source.error") == []
    runtime.run_once()
    assert clerk.calls == 2
    assert sb.store.db.execute("SELECT COUNT(*) FROM notices").fetchone() == (2,)
    with open(path, "a") as stream:
        stream.write('", "received_at": 1}\n')
    runtime.run_once()
    assert clerk.calls == 3
    assert sb.store.db.execute("SELECT cursor FROM sources").fetchone() == ("6",)


def test_dedupe_before_clerk_and_across_restart(env):
    sb, runtime, clock, clerk, config = env
    source = FakeSource("repeat", [event(clock)])
    runtime.sources = [source]
    runtime.run_once()
    runtime.run_once()
    assert clerk.calls == 1
    assert source.cursors == [None, "1"]
    runtime.close()
    restarted = Runtime(sb, [source])
    try:
        restarted.run_once()
        assert clerk.calls == 1
        assert sb.store.db.execute("SELECT status FROM inbound_seen").fetchall() == [("done",)]
    finally:
        restarted.close()


def test_crash_recovery_quarantines_and_never_replays(env):
    sb, runtime, clock, clerk, config = env
    sb.store.db.execute("INSERT INTO inbound_seen VALUES ('crash','one','processing',?)", (clock(),))
    runtime.close()
    restarted = Runtime(sb, [FakeSource("crash", [event(clock)])])
    try:
        assert sb.store.db.execute("SELECT status FROM inbound_seen").fetchone() == ("quarantined",)
        assert events_of(sb, "inbound.interrupted") == [{"source": "crash", "delivery_id": "one"}]
        assert sb.store.db.execute("SELECT cluster, topic, ref FROM notices").fetchall() == [
            ("runtime/crash", "quarantined", None)]
        restarted.run_once()
        assert clerk.calls == 0
    finally:
        restarted.close()


def test_receive_failure_retains_private_text_and_continues(env, monkeypatch):
    sb, runtime, clock, clerk, config = env
    receive = sb.receive

    def fail_first(e):
        if e.delivery_id == "bad":
            raise RuntimeError("receive failed")
        return receive(e)

    monkeypatch.setattr(sb, "receive", fail_first)
    runtime.sources = [FakeSource("batch", [event(clock, "bad", "private message"), event(clock, "good")])]
    runtime.run_once()
    assert sb.store.db.execute("SELECT delivery_id, status FROM inbound_seen ORDER BY delivery_id").fetchall() == [
        ("bad", "quarantined"), ("good", "done")]
    cluster, topic, ref = sb.store.db.execute("SELECT cluster, topic, ref FROM notices").fetchone()
    assert (cluster, topic) == ("runtime/batch", "quarantined")
    raw = sb.store.get(ref)
    assert (raw.data, raw.label, raw.source) == ("private message", EXTERNAL_PRIVATE, "sms:failed")
    assert events_of(sb, "inbound.failed") == [{"source": "batch", "delivery_id": "bad", "error": "RuntimeError('receive failed')"}]
    assert clerk.calls == 1
    assert sb.store.db.execute("SELECT cursor FROM sources").fetchone() == ("2",)


def test_source_error_preserves_cursor_and_other_sources_continue(env):
    sb, runtime, clock, clerk, config = env
    sb.store.db.execute("INSERT INTO sources VALUES ('bad','7')")
    bad = FakeSource("bad", error=RuntimeError("offline"))
    runtime.sources = [bad, FakeSource("good", [event(clock)])]
    runtime.run_once()
    assert events_of(sb, "source.error") == [{"source": "bad", "error": "RuntimeError('offline')"}]
    assert sb.store.db.execute("SELECT name, cursor FROM sources ORDER BY name").fetchall() == [("bad", "7"), ("good", "1")]
    assert clerk.calls == 1
    assert bad.cursors == ["7"]


def hold(sb, clock, destination="sms:+12065550100"):
    dest = sb.store.put(destination, EXTERNAL_PRIVATE, "test", clock())
    eg = Egress("msg.send", dest, (sb.owner_put("private response"),))
    return sb.approvals.hold(eg, "messaging/sms:+1206", "owner only", clock())


def enqueue(sb, clock, action, ref):
    sb.store.db.execute("INSERT INTO owner_queue (at, action, ref) VALUES (?,?,?)", (clock(), action, ref))


def test_owner_queue_order_unknown_action_and_held_approval(env):
    sb, runtime, clock, clerk, config = env
    approved, denied = hold(sb, clock), hold(sb, clock, "sms:+12065550101")
    runtime.run_once()
    clock.advance(300)
    runtime.run_once()
    assert events_of(sb, "shadow.withheld") == []
    for action, ref in [("approve", approved), ("unknown", "x"), ("deny", denied), ("stiffen", "messaging/sms:+1206")]:
        enqueue(sb, clock, action, ref)
    runtime.run_once()
    rows = sb.store.db.execute("SELECT action, status, result FROM owner_queue ORDER BY id").fetchall()
    assert [(a, s) for a, s, _ in rows] == [("approve", "done"), ("unknown", "failed"), ("deny", "done"), ("stiffen", "done")]
    assert rows[0][2].startswith("sent:")
    assert "unknown owner action" in rows[1][2]
    assert all(result for _, _, result in rows)
    assert events_of(sb, "shadow.withheld") == [{"kind": "msg.send", "destination": "sms:+12065550100"}]
    assert sb.store.db.execute("SELECT status FROM approvals ORDER BY id").fetchall() == [("approved",), ("denied",)]
    assert "messaging/sms:+1206" in sb.stiffened
    ordered = [name for _, name, _ in sb.store.audit_log() if name in {"approve", "deny", "stiffen"}]
    assert ordered == ["approve", "deny", "stiffen"]
    runtime.run_once()
    assert len(events_of(sb, "shadow.withheld")) == 1


def test_queue_exception_does_not_block_next_row(env, monkeypatch):
    sb, runtime, clock, clerk, config = env
    monkeypatch.setattr(sb, "owner_deny", lambda ref: (_ for _ in ()).throw(RuntimeError("bad owner row")))
    enqueue(sb, clock, "deny", "A1")
    enqueue(sb, clock, "stiffen", "cluster")
    runtime.run_once()
    assert sb.store.db.execute("SELECT status, result FROM owner_queue ORDER BY id").fetchall() == [
        ("failed", "RuntimeError('bad owner row')"), ("done", "done")]
    assert "cluster" in sb.stiffened


def test_digest_storage_restart_skips_missed_release_and_keeps_grid(env):
    sb, runtime, clock, clerk, config = env
    first = hold(sb, clock)
    hold(sb, clock, "sms:+12065550101")
    sb.approvals.notice("quarantined", "runtime/test", None, clock())
    runtime.run_once()
    body = sb.store.db.execute("SELECT at, body FROM digests").fetchone()
    assert body[0] == clock()
    assert first in body[1] and "msg.send" in body[1] and "owner only" in body[1]
    assert "This destination came from test (untrusted)" in body[1]
    assert "collapsed\tmessaging/sms:+1206\t1" in body[1]
    assert "notice\truntime/test/quarantined\t1" in body[1]
    clock.advance(100)
    runtime.run_once()
    assert sb.store.db.execute("SELECT COUNT(*) FROM digests").fetchone() == (2,)
    runtime.close()
    clock.advance(140)
    restarted_sb, restarted = build(config)
    try:
        restarted.run_once()
        assert restarted_sb.store.db.execute("SELECT COUNT(*) FROM digests").fetchone() == (2,)
        clock.advance(59.9)
        restarted.run_once()
        assert restarted_sb.store.db.execute("SELECT COUNT(*) FROM digests").fetchone() == (2,)
        clock.advance(0.1)
        restarted.run_once()
        assert restarted_sb.store.db.execute("SELECT COUNT(*) FROM digests").fetchone() == (3,)
        assert len(events_of(restarted_sb, "digest.missed")) == 1
    finally:
        restarted.close()
        restarted_sb.store.db._conn.close()


def test_render_digest_has_one_line_per_entry_and_counts():
    digest = Digest((DigestEntry("A1", "msg.send", "sms:+1", "owner", True, "held"),), {"cluster": 2}, {"cluster/topic": 3})
    assert render_digest(digest) == "A1\tmsg.send\tsms:+1\towner\theld\ncollapsed\tcluster\t2\nnotice\tcluster/topic\t3"


@pytest.mark.parametrize("extra", ['surprise = true', 'password = "inline"', '[nested]\napi_key = "inline"',
                                        '[[source]]\nkind = "jsonl"\nname = "x"\npath = "x"\ntoken = "inline"'])
def test_config_rejects_unknown_keys_and_nested_inline_secrets(tmp_path, extra):
    with pytest.raises(ConfigError):
        load(config_file(tmp_path, extra))


@pytest.mark.parametrize("key", ["password", "access_token", "my_secret", "api_key"])
def test_inline_secret_rejection_is_independent_of_unknown_top_level_guard(tmp_path, key):
    with pytest.raises(ConfigError, match="inline secret"):
        load(config_file(tmp_path, clerk=f'kind = "stub"\nper_sender = 1\nsender_window = 1\nper_day = 1\n{key} = "inline"'))


BUDGET = 'kind = "stub"\nper_sender = 1\nsender_window = 60\nper_day = 100'


@pytest.mark.parametrize("extra,clerk", [('[digest]\nintervall = 600', BUDGET),
                                         ("", BUDGET + "\nper_sendr = 1"),
                                         ('[[source]]\nkind = "jsonl"\nname = "x"\npath = "x"\nextra = 1', BUDGET)])
def test_config_rejects_unknown_keys_inside_tables(tmp_path, extra, clerk):
    with pytest.raises(ConfigError, match="unknown"):
        load(config_file(tmp_path, extra, clerk=clerk))


def test_config_rejects_live_mode(tmp_path):
    with pytest.raises(ConfigError, match="live mode is not available: no real outbound adapters"):
        load(config_file(tmp_path, mode="live"))


@pytest.mark.parametrize("missing", ["per_sender", "sender_window", "per_day"])
def test_config_requires_every_clerk_budget_field(tmp_path, missing):
    fields = {"kind": '"stub"', "per_sender": "1", "sender_window": "60", "per_day": "100"}
    del fields[missing]
    with pytest.raises(ConfigError, match="missing clerk budget"):
        load(config_file(tmp_path, clerk="\n".join(f"{k} = {v}" for k, v in fields.items())))


def test_config_defaults_jsonl_and_secret_references(tmp_path, monkeypatch):
    path = config_file(tmp_path, f'[[source]]\nkind = "jsonl"\nname = "replay"\npath = "{tmp_path / "events.jsonl"}"',
                       clerk='kind = "stub"\nper_sender = 1\nsender_window = 60\nper_day = 100\napi_key_env = "RBB_TEST_KEY"')
    config = load(path)
    assert config.poll_interval == 5.0
    assert (config.digest.interval, config.digest.per_cluster) == (3600, 3)
    assert (config.sources[0].name, config.sources[0].path) == ("replay", str(tmp_path / "events.jsonl"))
    monkeypatch.setenv("RBB_TEST_KEY", "external secret")
    assert resolve_secret({"api_key_env": "RBB_TEST_KEY"}, "api_key") == "external secret"
    file = tmp_path / "secret"
    file.write_text("file secret\n")  # the final newline every editor and echo adds is not part of it
    assert resolve_secret({"password_file": str(file)}, "password") == "file secret"
    with pytest.raises(ConfigError):
        resolve_secret({}, "missing")


def test_second_build_and_runtime_refused_without_digest_side_effects(env):
    sb, runtime, clock, clerk, config = env
    runtime.run_once()
    clock.advance(200)
    with pytest.raises(RuntimeError, match="daemon already running"):
        build(config)
    assert events_of(sb, "digest.missed") == []
    with pytest.raises(RuntimeError, match="daemon already running"):
        Runtime(sb, [])
    runtime.close()
    restarted = Runtime(sb, [])
    restarted.close()


def test_store_only_console_does_not_take_lock_or_advance_digest(env):
    sb, runtime, clock, clerk, config = env
    runtime.run_once()
    before = sb.store.db.execute("SELECT * FROM digest_clock").fetchall()
    clock.advance(200)
    console = Store(config.db)
    try:
        assert console.db.execute("SELECT * FROM digest_clock").fetchall() == before
    finally:
        console.db._conn.close()


def test_run_forever_waits_and_stops(env, monkeypatch):
    sb, runtime, clock, clerk, config = env
    calls = []

    class Stop:
        stopped = False

        def is_set(self):
            return self.stopped

        def wait(self, interval):
            calls.append(("wait", interval))
            self.stopped = True

    monkeypatch.setattr(runtime, "run_once", lambda: calls.append("run"))
    runtime.run_forever(Stop(), 0.25)
    assert calls == ["run", ("wait", 0.25)]
    stopped = threading.Event()
    stopped.set()
    runtime.run_forever(stopped, 0)
    assert calls == ["run", ("wait", 0.25)]


def test_cli_installs_stop_handlers_audits_and_closes(env, monkeypatch):
    from rubberbandbox import cli
    import signal

    sb, runtime, clock, clerk, config = env
    handlers, restored, previous = {}, {}, object()

    def install(sig, handler):
        if handler is previous:
            restored[sig] = handler
        else:
            handlers[sig] = handler
        return previous

    def run(stop, interval):
        assert interval == config.poll_interval
        assert events_of(sb, "runtime.start") == [{"mode": "shadow"}]
        for handler in handlers.values():
            stop.clear()
            handler(None, None)
            assert stop.is_set()

    monkeypatch.setattr("rubberbandbox.config.load", lambda path: config)
    monkeypatch.setattr("rubberbandbox.config.build", lambda value: (sb, runtime))
    monkeypatch.setattr(signal, "signal", install)
    monkeypatch.setattr(runtime, "run_forever", run)
    assert cli.main(["run", "--config", "owner.toml"]) == 0
    assert set(handlers) == set(restored) == {signal.SIGTERM, signal.SIGINT}
    assert runtime._lock.closed


def test_build_codex_clerk_uses_configured_budget_without_running_it(tmp_path, monkeypatch):
    from rubberbandbox.clerks import codex

    made = []

    class Clerk:
        def __init__(self, schema, guide):
            made.append((schema, guide))

    monkeypatch.setattr(codex, "CodexClerk", Clerk)
    config = load(config_file(tmp_path, clerk='kind = "codex"\nper_sender = 2\nsender_window = 60\nper_day = 10'))
    sb, runtime = build(config)
    try:
        assert len(made) == 1
        assert isinstance(sb.mounts[0].clerk, Clerk)
        assert sb.clerk_budget == config.clerk_budget
    finally:
        runtime.close()
        sb.store.db._conn.close()


def test_unavailable_clerk_retains_owner_notice_without_any_send(env, monkeypatch):
    sb, runtime, clock, clerk, config = env
    sb.owner_publish("script.price", "Published price.")

    def unavailable(text):
        raise RuntimeError("clerk unavailable")

    monkeypatch.setattr(sb.mounts[0].clerk, "extract", unavailable)
    runtime.sources = [FakeSource("offline", [event(clock, text="price?")])]
    runtime.run_once()
    clock.advance(300)
    runtime.run_once()
    assert events_of(sb, "shadow.withheld") == []
    assert sb.store.db.execute("SELECT COUNT(*) FROM scheduled").fetchone() == (0,)
    topic, ref = sb.store.db.execute("SELECT topic, ref FROM notices").fetchone()
    assert topic == "unreadable"
    assert sb.store.get(ref).data == "price?"


def test_existing_v1_database_gains_runtime_tables_without_version_bump(tmp_path):
    path = str(tmp_path / "old-v1.db")
    old = Store(path)
    for table in ("sources", "inbound_seen", "owner_queue", "digests"):
        old.db.execute(f"DROP TABLE {table}")
    old.db._conn.close()
    reopened = Store(path)
    try:
        for table in ("sources", "inbound_seen", "owner_queue", "digests"):
            assert reopened.db.execute(f"SELECT COUNT(*) FROM {table}").fetchone() == (0,)
        assert reopened.db.execute("PRAGMA user_version").fetchone() == (1,)
    finally:
        reopened.db._conn.close()


def test_digest_escapes_line_breaks_in_entry_fields():
    digest = Digest((DigestEntry("A1", "msg.send", "a\nb", "owner\r\ninput", True, "held\there"),), {}, {})
    assert render_digest(digest).splitlines() == ["A1\tmsg.send\ta\\nb\towner\\r\\ninput\theld\\there"]


def test_an_interrupted_message_is_quarantined_with_its_text(env):
    sb, runtime, clock, clerk, config = env
    sb.store.db.execute("INSERT INTO inbound_seen VALUES ('crash','one','processing',?)", (clock(),))
    raw = sb.store.put("cut off mid-receive", EXTERNAL_PRIVATE, "sms", clock())
    sb.store.audit(clock(), "inbound", channel="sms", delivery="one", authenticated=True, raw=raw.id)
    runtime.close()
    restarted = Runtime(sb, [])
    try:
        assert sb.store.db.execute("SELECT topic, ref FROM notices").fetchall() == [("quarantined", raw.id)]
    finally:
        restarted.close()


def test_a_failing_dispatch_is_audited_and_the_poll_completes(env, monkeypatch):
    sb, runtime, clock, clerk, config = env

    def broken():
        raise RuntimeError("adapter exploded")

    monkeypatch.setattr(sb, "tick", broken)
    runtime.run_once()
    assert events_of(sb, "runtime.error") == [{"stage": "tick", "error": "RuntimeError('adapter exploded')"}]
    assert sb.store.db.execute("SELECT COUNT(*) FROM digests").fetchone() == (1,)
