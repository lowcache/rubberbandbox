import unicodedata

import pytest

from rubberbandbox import cli
from rubberbandbox.config import build, load
from rubberbandbox.core import Egress, EXTERNAL_PRIVATE, ManualClock


@pytest.fixture
def env(tmp_path, monkeypatch):
    clock = ManualClock()
    monkeypatch.setattr("rubberbandbox.config.time.time", clock)
    path = tmp_path / "owner.toml"
    path.write_text(f'db = "{tmp_path / "state.db"}"\nmode = "shadow"\n'
                    '[digest]\ninterval = 100\n[clerk]\nkind = "stub"\n'
                    'per_sender = 100\nsender_window = 60\nper_day = 1000\n')
    config = load(path)
    sb, runtime = build(config)
    yield sb, runtime, clock, path, config
    runtime.close()
    sb.store.db._conn.close()


def run(env, command, *args):
    return cli.main([command, *args, "--config", str(env[3])])


def hold(env, destination="sms:+12065550100", source="inbound/sms", reason="owner only"):
    sb, _, clock, _, _ = env
    dest = sb.store.put(destination, EXTERNAL_PRIVATE, source, clock())
    eg = Egress("msg.send", dest, (sb.owner_put("private response"),))
    return sb.approvals.hold(eg, "messaging/sms:test", reason, clock())


def snapshot(sb):
    return (sb.store.db.execute("SELECT COUNT(*) FROM audit").fetchone(),
            sb.store.db.execute("SELECT * FROM digest_clock").fetchall())


def test_pending_is_current_read_only_and_has_provenance(env, capsys):
    aid = hold(env)
    other = hold(env, "sms:+12065550101")
    env[0].owner_deny(other)
    before = snapshot(env[0])
    assert run(env, "pending") == 0
    assert capsys.readouterr().out.splitlines() == [
        f"{aid}\tmsg.send\tsms:+12065550100\tThis destination came from inbound/sms (untrusted)\towner only\t{env[2]()}"
    ]
    assert snapshot(env[0]) == before


def test_every_console_command_leaves_missed_digest_for_daemon(env, capsys):
    sb, runtime, clock, _, config = env
    aid = hold(env)
    runtime.run_once()
    clock.advance(201)
    before = snapshot(sb)
    for command, args in [("digest", ()), ("pending", ()), ("quarantine", ()),
                          ("queue", ()), ("approve", (aid,)), ("deny", (aid,)),
                          ("stiffen", ("messaging/sms:test",))]:
        assert run(env, command, *args) == 0
        assert snapshot(sb) == before
        assert not any(key == "digest.missed" for _, key, _ in sb.store.audit_log())
    capsys.readouterr()
    runtime.close()
    restarted_sb, restarted = build(config)
    try:
        assert [key for _, key, _ in restarted_sb.store.audit_log()].count("digest.missed") == 1
        assert snapshot(restarted_sb)[1] != before[1]
    finally:
        restarted.close()
        restarted_sb.store.db._conn.close()


def test_approve_only_queues_then_daemon_consumes(env, capsys):
    sb, runtime, clock, _, _ = env
    aid = hold(env)
    before = snapshot(sb)
    assert run(env, "approve", aid) == 0
    assert capsys.readouterr().out == "1\n"
    assert sb.store.db.execute("SELECT at, action, ref, status FROM owner_queue").fetchall() == [
        (clock(), "approve", aid, "queued")]
    assert sb.store.db.execute("SELECT status, consumed FROM approvals").fetchall() == [("pending", 0)]
    assert snapshot(sb) == before
    runtime.run_once()
    assert sb.store.db.execute("SELECT status, consumed FROM approvals").fetchall() == [("approved", 1)]
    assert any(key == "shadow.withheld" for _, key, _ in sb.store.audit_log())


@pytest.mark.parametrize("command", ["approve", "deny"])
@pytest.mark.parametrize("aid", ["broken", "A01", "A999999"])
def test_invalid_approval_inserts_nothing(env, capsys, command, aid):
    with pytest.raises(SystemExit) as exc:
        run(env, command, aid)
    assert exc.value.code == 2
    assert "approval id" in capsys.readouterr().err
    assert env[0].store.db.execute("SELECT COUNT(*) FROM owner_queue").fetchone() == (0,)


def test_quarantine_escapes_inbound_controls_and_limits_newest(env, capsys):
    sb, _, clock, _, _ = env
    text = "\x1b]52;c;evil\x07\u202e" + "z" * 600
    value = sb.store.put(text, EXTERNAL_PRIVATE, "inbound", clock())
    sb.approvals.notice("unreadable", "old", None, clock())
    sb.approvals.notice("other", "omit", None, clock())
    sb.approvals.notice("quarantined", "new", value.id, clock())
    assert run(env, "quarantine", "--limit", "1") == 0
    output = capsys.readouterr().out
    assert output == f"3\tquarantined\tnew\t{clock()}\t\\x1b]52;c;evil\\x07\\u202e" + "z" * (500 - len("\x1b]52;c;evil\x07\u202e")) + "\n"
    assert all(c not in output for c in ("\x1b", "\x07", "\u202e"))
    run(env, "quarantine")
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 2 and "(no stored text)" in lines[1]


def test_digest_latest_and_queue_applied_result(env, capsys):
    sb, runtime, clock, _, _ = env
    run(env, "digest")
    assert capsys.readouterr().out == "no digest released yet\n"
    sb.store.db.execute("INSERT INTO digests (at, body) VALUES (?,?)", (clock() + 1, "latest\nbody\x1b\u202e"))
    sb.store.db.execute("INSERT INTO digests (at, body) VALUES (?,?)", (clock(), "older"))
    run(env, "digest")
    assert capsys.readouterr().out == "latest\nbody\\x1b\\u202e\n"
    sb.store.db.execute("INSERT INTO digests (at, body) VALUES (?,?)", (clock() + 2, ""))
    run(env, "digest")
    assert capsys.readouterr().out == "(empty digest)\n"
    aid = hold(env)
    run(env, "approve", aid)
    runtime.run_once()
    capsys.readouterr()
    status, result = sb.store.db.execute("SELECT status, result FROM owner_queue").fetchone()
    assert status == "done" and result.startswith("sent:")
    run(env, "queue")
    assert capsys.readouterr().out == f"1\tapprove\t{aid}\t{status}\t{result}\n"
    sb.store.db.execute("INSERT INTO owner_queue (at, action, ref, result) VALUES (?,?,?,?)",
                        (clock(), "deny\x1b", "A1\u202e", "bad\x07\nresult"))
    run(env, "queue", "--limit", "1")
    assert capsys.readouterr().out == "2\tdeny\\x1b\tA1\\u202e\tqueued\tbad\\x07\\x0aresult\n"


def test_console_refuses_a_missing_database_without_creating_it(tmp_path, capsys):
    path = tmp_path / "owner.toml"
    missing = tmp_path / "absent" / "state.db"
    path.write_text(f'db = "{missing}"\nmode = "shadow"\n[clerk]\nkind = "stub"\n'
                    'per_sender = 1\nsender_window = 60\nper_day = 1\n')
    with pytest.raises(SystemExit) as exc:
        cli.main(["pending", "--config", str(path)])
    assert exc.value.code == 2
    assert "no database" in capsys.readouterr().err
    assert not missing.parent.exists()


def test_pending_sanitises_every_stored_field(env, capsys):
    hold(env, "sms:x\x1b", "source\u202e", "reason\x07\n")
    run(env, "pending")
    output = capsys.readouterr().out
    assert "sms:x\\x1b" in output and "source\\u202e" in output and "reason\\x07\\x0a" in output


@pytest.mark.parametrize("cluster", ["", " ", "x\n", "x\u202e"])
def test_stiffen_rejects_empty_or_control_cluster(env, cluster):
    with pytest.raises(SystemExit) as exc:
        run(env, "stiffen", cluster)
    assert exc.value.code == 2
    assert env[0].store.db.execute("SELECT COUNT(*) FROM owner_queue").fetchone() == (0,)


def test_safe_covers_all_control_and_format_characters():
    from rubberbandbox.console import safe

    controls = "".join(chr(n) for n in range(0x110000) if unicodedata.category(chr(n)) in {"Cc", "Cf"})
    assert not any(unicodedata.category(c) in {"Cc", "Cf"} for c in safe(controls))
    assert safe("a\nb", multiline=True) == "a\nb"
    assert safe("a\tb", multiline=True) == "a\tb" and safe("a\tb") == "a\\x09b"  # digest columns stay columns


def test_deny_and_stiffen_only_queue_until_daemon_runs(env, capsys):
    sb, runtime, clock, _, _ = env
    aid = hold(env)
    before = snapshot(sb)
    run(env, "deny", aid)
    assert capsys.readouterr().out == "1\n"
    run(env, "stiffen", "messaging/sms:test")
    assert capsys.readouterr().out == "2\n"
    assert sb.store.db.execute("SELECT action, ref, status FROM owner_queue ORDER BY id").fetchall() == [
        ("deny", aid, "queued"), ("stiffen", "messaging/sms:test", "queued")]
    assert sb.store.db.execute("SELECT status FROM approvals").fetchone() == ("pending",)
    assert not sb.stiffened
    assert snapshot(sb) == before
    runtime.run_once()
    assert sb.store.db.execute("SELECT status FROM approvals").fetchone() == ("denied",)
    assert "messaging/sms:test" in sb.stiffened


def test_default_limits_are_twenty_newest_records(env, capsys):
    sb, _, clock, _, _ = env
    for n in range(21):
        sb.approvals.notice("unreadable", str(n), None, clock() + n)
        sb.store.db.execute("INSERT INTO owner_queue (at, action, ref) VALUES (?,?,?)", (clock(), "stiffen", str(n)))
    for command in ("quarantine", "queue"):
        run(env, command)
        lines = capsys.readouterr().out.splitlines()
        assert len(lines) == 20
        assert [int(line.split("\t")[0]) for line in lines] == list(range(21, 1, -1))


def test_reset_cursor_clears_one_known_source_and_audits_it(env, capsys):
    sb, _, _, path, config = env
    sb.store.db.execute("INSERT INTO sources (name, cursor) VALUES ('imap', '77:9'), ('other', '5')")
    path.write_text(path.read_text() + '[[source]]\nkind = "jsonl"\nname = "imap"\npath = "x"\n')
    assert run(env, "reset-cursor", "imap") == 0
    assert capsys.readouterr().out == "imap\treset\n"
    assert sb.store.db.execute("SELECT name, cursor FROM sources").fetchall() == [("other", "5")]
    assert [d for _, e, d in sb.store.audit_log() if e == "source.reset"] == [{"source": "imap"}]
    with pytest.raises(SystemExit) as exc:
        run(env, "reset-cursor", "nope")
    assert exc.value.code == 2
