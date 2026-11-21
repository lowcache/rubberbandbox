"""ThunderbirdSource: one folder of a Thunderbird mbox store, read-only, no credential."""

import os

import pytest

from rubberbandbox import mail
from rubberbandbox.config import build, load
from rubberbandbox.core import ManualClock
from rubberbandbox.mail import ThunderbirdSource
from rubberbandbox.runtime import Malformed


def msg(mid, status="0001", body="hello", subject="hi"):
    return (f"From - Sat Nov 21 10:00:00 2026\n"
            f"X-Mozilla-Status: {status}\nX-Mozilla-Status2: 00000000\n"
            f"Delivered-To: owner@gmail.com\n"
            f"Authentication-Results: mx.google.com; dkim=pass; spf=pass; dmarc=pass\n"
            f"From: sender@example.org\nTo: owner@gmail.com\nSubject: {subject}\nMessage-ID: <{mid}>\n\n"
            f"{body}\n\n").encode()


def folder(tmp_path, *messages):
    path = tmp_path / "INBOX"
    path.write_bytes(b"".join(messages))
    return path


def source(path, **kw):
    return ThunderbirdSource("tb", str(path), authserv_id="mx.google.com", clock=lambda: 1.0, **kw)


def ids(items):
    return [i.delivery_id for i in items]


def test_first_poll_starts_at_the_end_and_a_new_message_waits_until_whole(tmp_path):
    path = folder(tmp_path, msg("old"))
    tb = source(path)
    items, cursor = tb.poll(None)
    assert items == []
    with open(path, "ab") as f:
        f.write(msg("new"))
    items, cursor = tb.poll(cursor)
    assert items == []  # the tail grew since the last poll: it may still be being written
    items, cursor = tb.poll(cursor)
    assert ids(items) == ["new"] and items[0].authenticated
    assert tb.poll(cursor)[0] == []


def test_a_message_followed_by_another_is_taken_at_once(tmp_path):
    path = folder(tmp_path)
    tb = source(path)
    _, cursor = tb.poll(None)
    with open(path, "ab") as f:
        f.write(msg("a") + msg("b"))
    items, cursor = tb.poll(cursor)
    assert ids(items) == ["a"]
    assert ids(tb.poll(cursor)[0]) == ["b"]


def test_backfill_and_batch(tmp_path):
    path = folder(tmp_path, *(msg(f"m{i}") for i in range(5)))
    items, cursor = source(path, backfill=3).poll(None)
    assert ids(items) == ["m2", "m3"]  # m4 is the tail, taken once the file is seen not to grow
    assert ids(source(path, backfill=3).poll(cursor)[0]) == ["m4"]
    items, _ = source(path, backfill=5, batch=2).poll(None)
    assert ids(items) == ["m0", "m1"]


def test_deleted_messages_are_skipped_and_quoted_from_lines_restored(tmp_path):
    path = folder(tmp_path, msg("gone", status="0009"), msg("kept", body=">From the start\n>>From deeper"), msg("tail"))
    items, _ = source(path, backfill=3, include_body=True).poll(None)
    assert ids(items) == ["kept"]
    assert "\nFrom the start\n>From deeper" in items[0].text


def test_a_bad_status_header_is_malformed_and_the_folder_moves_on(tmp_path):
    path = folder(tmp_path, msg("bad", status="zz"), msg("good"), msg("tail"))
    items, cursor = source(path, backfill=3).poll(None)
    assert isinstance(items[0], Malformed) and ids(items[1:]) == ["good"]
    assert int(cursor.split(":")[1]) == len(msg("bad", status="zz") + msg("good"))


def test_a_compacted_folder_resumes_within_its_newest_messages(tmp_path, monkeypatch):
    monkeypatch.setattr(mail, "RESCAN", 2)
    path = folder(tmp_path, msg("a"), msg("b"))
    tb = source(path)
    _, cursor = tb.poll(None)
    fresh = tmp_path / "INBOX.new"
    fresh.write_bytes(msg("a") + msg("b") + msg("c"))  # Thunderbird compacts by writing a new file
    os.replace(fresh, path)
    items, cursor = tb.poll(cursor)
    assert ids(items) == ["b"]  # repeats like b are dropped downstream by Message-ID
    assert ids(tb.poll(cursor)[0]) == ["c"]


def test_a_folder_rewritten_in_place_is_not_read_from_a_stale_offset(tmp_path, monkeypatch):
    monkeypatch.setattr(mail, "RESCAN", 1)
    path = folder(tmp_path, msg("a-much-longer-id"), msg("bb"))
    tb = source(path)
    _, cursor = tb.poll(None)
    with open(path, "r+b") as f:  # same inode, shorter first message: the old offset now lands mid-message
        f.write(msg("x") + msg("bb") + msg("new"))
    items, cursor = tb.poll(cursor)
    assert all(not isinstance(i, Malformed) for i in items)
    assert ids(tb.poll(cursor)[0]) == ["new"]


def test_a_symlinked_folder_is_refused(tmp_path):
    real = folder(tmp_path, msg("a"))
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(OSError):
        source(link).poll(None)


def test_config_builds_a_thunderbird_source(tmp_path, monkeypatch):
    monkeypatch.setattr("rubberbandbox.config.time.time", ManualClock())
    path = folder(tmp_path, msg("a"))
    cfg = tmp_path / "owner.toml"
    cfg.write_text(f'db = "{tmp_path / "state.db"}"\nmode = "shadow"\npack = "triage"\n'
                   '[clerk]\nkind = "stub"\nper_sender = 5\nsender_window = 60\nper_day = 50\n'
                   f'[[source]]\nkind = "thunderbird"\nname = "gmail-1"\npath = "{path}"\n'
                   'authserv_id = "mx.google.com"\nbackfill = 1\n')
    sb, runtime = build(load(str(cfg)))
    try:
        assert isinstance(runtime.sources[0], ThunderbirdSource) and runtime.sources[0].backfill == 1
        runtime.run_once()
        runtime.run_once()
        assert sb.store.db.execute("SELECT COUNT(*) FROM classifications").fetchone() == (1,)
    finally:
        runtime.close()
        sb.store.db._conn.close()


def test_a_folder_truncated_below_the_cursor_is_resumed(tmp_path, monkeypatch):
    monkeypatch.setattr(mail, "RESCAN", 1)
    path = folder(tmp_path, msg("a"), msg("b"), msg("c"))
    tb = source(path)
    _, cursor = tb.poll(None)
    with open(path, "r+b") as f:  # same file, now shorter than the cursor
        f.truncate(0)
        f.write(msg("new"))
    items, cursor = tb.poll(cursor)
    assert items == [] and int(cursor.split(":")[1]) == 0  # the tail waits one poll, from the right place
    assert ids(tb.poll(cursor)[0]) == ["new"]


def test_a_file_that_is_not_an_mbox_folder_is_refused(tmp_path):
    index = tmp_path / "INBOX.msf"
    index.write_bytes(b"// <!-- <mdb:mork:z v=\"1.4\"/> -->\n")
    with pytest.raises(ValueError, match="not an mbox folder"):
        source(index).poll(None)
    empty = tmp_path / "Empty"
    empty.write_bytes(b"")
    assert source(empty).poll(None)[0] == []
