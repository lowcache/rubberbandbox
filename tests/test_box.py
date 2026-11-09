"""The box: one allowlist launcher (overlay + every namespace unshared + the door's socket), path
canonicalisation in the box's own view, the dispatch-time re-check, and staged writes."""

import json
import os
import shutil
import socket
import sys
import tempfile
import threading

import pytest

from rubberbandbox import mcp
from rubberbandbox.box import Box, BoxError, PathRejected, commit, launch_args, review, staged
from rubberbandbox.core import (EnumField, Grant, ManifestPack, ManualClock, Mount, Rules, Sandbox, Schema,
                                ToolDescriptor, ToolManifest, diff, security_view)
from rubberbandbox.core.grants import covers

from test_mcp import FAKE, box, output, run

pytestmark = pytest.mark.skipif(shutil.which("bwrap") is None, reason="bwrap is required")

WRITE = ToolManifest("fake/write", "write-staged", {"path": "destination", "text": "payload"})


@pytest.fixture
def door_socket():
    """A host unix socket standing in for the door's CONNECT proxy (slice d). AF_UNIX paths are
    capped at 108 bytes, so it lives in the short runtime dir."""
    d = tempfile.mkdtemp(prefix="rbb", dir=os.environ.get("XDG_RUNTIME_DIR"))
    path = os.path.join(d, "s")
    srv = socket.socket(socket.AF_UNIX)
    srv.bind(path)
    srv.listen(1)

    def serve():
        conn, _ = srv.accept()
        conn.sendall(b"pong:" + conn.recv(100))
        conn.close()

    threading.Thread(target=serve, daemon=True).start()
    yield path
    srv.close()
    shutil.rmtree(d)


@pytest.fixture
def folder(tmp_path):
    host = tmp_path / "host"
    (host / "docs").mkdir(parents=True)
    (host / "docs" / "keep.txt").write_text("keep")
    (host / "old.txt").write_text("old")
    return host, str(tmp_path / "stage")


def boxed(folder, **extra):
    host, stage = folder
    b = Box(folders={"/data": str(host)}, ro_paths=(FAKE,), stage=stage, **extra)
    return mcp.McpClient(mcp.ServerConfig("fake", (sys.executable, FAKE), box=b))


# ---- one launcher, all of it at once ----


def test_overlay_namespaces_and_door_socket_work_as_one_launcher(folder, door_socket, monkeypatch):
    monkeypatch.setenv("RBB_SECRET", "hunter2")
    host, _ = folder
    with boxed(folder, sockets={"/run/rbb/proxy.sock": door_socket}) as c:
        # nothing but the allowlist: no /etc; /home holds only the one listed file (the server's script)
        assert c.call("ls_root", {}) == '["data", "dev", "home", "nix", "proc", "run", "tmp"]'
        assert c.call("find", {"path": "/home"}) == f'["{FAKE}"]'
        store = json.loads(c.call("ls_root", {"path": "/nix/store"}))
        assert 0 < len(store) < 500  # the interpreter's closure, not the whole store
        assert c.call("sock_probe", {}) == "pong:ping"  # the only way out is the door's socket
        assert c.call("net_probe", {}) == "ENETUNREACH"
        assert "RBB_SECRET" not in c.call("env_probe", {})
        c.call("write", {"path": "/data/new.txt", "text": "staged"})
        assert not (host / "new.txt").exists()  # staged, not written
        assert ("/data/new.txt", "write") in [(s.path, s.action) for s in c.staged()]


def test_launcher_flags_isolate_even_if_the_caller_leaks_env(folder):
    host, stage = folder
    args = launch_args((sys.executable, FAKE), {"K": "v"}, "/", Box(folders={"/data": str(host)}, stage=stage), 9)
    for flag in ("--unshare-all", "--unshare-user", "--disable-userns", "--die-with-parent", "--new-session", "--clearenv"):
        assert flag in args
    binds = {args[i + 1] for i, a in enumerate(args) if a == "--ro-bind"}
    assert "/nix" not in binds and "/nix/store" not in binds and all(b.startswith("/nix/store/") for b in binds)
    assert args[args.index("--setenv") + 1:args.index("--setenv") + 3] == ["K", "v"]


def test_a_command_outside_the_store_does_not_start(tmp_path):
    script = tmp_path / "server.sh"
    script.write_text("#!/bin/sh\n")
    script.chmod(0o755)
    with pytest.raises(BoxError, match="not in the Nix store"):
        mcp.McpClient(mcp.ServerConfig("x", (str(script),)))


def test_box_paths_are_checked():
    with pytest.raises(BoxError):
        Box(folders={"/nix/evil": "/tmp"}, stage="/s")
    with pytest.raises(BoxError):
        Box(folders={"/data": "/a", "/data/sub": "/b"}, stage="/s")
    with pytest.raises(BoxError):
        Box(folders={"/data/../etc": "/a"}, stage="/s")


# ---- canonical paths in the live box ----


def test_links_resolve_in_the_box_never_on_the_host(folder):
    with boxed(folder) as c:
        c.call("link", {"path": "/data/evil", "target": "/etc/shadow"})
        c.call("link", {"path": "/data/docs/up", "target": "../old.txt"})
        assert c.resolve("/data/evil") == "/etc/shadow"  # the box's (absent) /etc, not the host's file
        assert c.resolve("/data/docs/up") == "/data/old.txt"
        with pytest.raises(PathRejected):
            c.resolve("/data/old.txt/x")  # under a file
    with pytest.raises(PathRejected, match="not running"):
        c.resolve("/data/old.txt")  # a stopped box fails closed


def test_a_path_that_moves_after_approval_becomes_a_new_call(folder):
    with boxed(folder) as c:
        sb, reg, hands, tools = box(c)
        reg.approve(WRITE, tools["write"])
        (held,) = run(sb, hands, {"kind": "fake/write", "args": {
            "path": {"literal": "/data/in/x.txt"}, "text": {"literal": "hi"}}})
        assert held.status == "held" and held.destination == "/data/in/x.txt"
        c.call("link", {"path": "/data/in", "target": "/data/docs"})  # the box changed while it waited
        moved = sb.owner_approve(held.reason.split(":")[0])
        assert moved.status == "held" and moved.destination == "/data/docs/x.txt"  # asked again, not sent
        assert sb.owner_approve(moved.reason.split(":")[0]).status == "sent"
        assert ("/data/docs/x.txt", "write") in [(s.path, s.action) for s in c.staged()]


def test_a_restarted_box_fails_closed(folder):
    with boxed(folder) as c:
        sb, reg, hands, tools = box(c)
        reg.approve(WRITE, tools["write"])
        (held,) = run(sb, hands, {"kind": "fake/write", "args": {
            "path": {"literal": "/data/x.txt"}, "text": {"literal": "hi"}}})
        c.discard()  # restarts the box: a new generation
        out = sb.owner_approve(held.reason.split(":")[0])
        assert out.status == "refused" and "not canonicalised in the running box" in out.reason


def test_grants_cover_whole_components_of_normal_paths():
    assert covers("/data/notes", "/data/notes") and covers("/data/notes", "/data/notes/a")
    assert not covers("/data/notes", "/data/notes-secret") and not covers("/data/notes", "/data/notes/../x")
    assert not covers("/data/notes", '["/data/notes/a"]') and covers("/", "/x")
    g = Grant("G1", frozenset({"k"}), frozenset({"sms:+1", "/data"}), 0.0)
    assert g.covers("sms:+1") and not g.covers("sms:+12") and g.covers("/data/a")
    pack = ManifestPack("p", Schema("s", {"intent": EnumField("none")}), [], [], Rules())
    sb = Sandbox([Mount(pack, None)], {}, clock=ManualClock())
    with pytest.raises(ValueError):
        sb.owner_mint(["k"], ["/data/../etc"], ttl=10)


# ---- the box's allowlist is part of the operator's identity ----


def test_a_wider_box_is_a_loosening_and_a_narrower_one_is_not():
    d = ToolDescriptor("fs", "read", {"type": "object", "properties": {"path": {"type": "string"}}})
    cfg = lambda **f: mcp.ServerConfig("fs", ("/nix/store/x-srv/bin/srv",), box=Box(folders=f, stage="/s")).endpoint
    two, one = cfg(**{"/a": "/h/a", "/b": "/h/b"}), cfg(**{"/a": "/h/a"})
    view = lambda e: security_view(d, e)
    assert diff(view(one), view(two), {"path": "destination"}).outcome == "loosened"
    assert diff(view(two), view(one), {"path": "destination"}).outcome == "accepted"
    assert diff(view(one), view(cfg(**{"/a": "/h/elsewhere"})), {"path": "destination"}).outcome == "loosened"


# ---- staged writes: review, commit, never through a link ----


def test_commit_applies_writes_deletes_and_replaced_dirs_but_never_symlinks(folder):
    host, _ = folder
    with boxed(folder) as c:
        c.call("write", {"path": "/data/new.txt", "text": "new"})
        c.call("rm", {"path": "/data/old.txt"})
        c.call("rm", {"path": "/data/docs"})
        c.call("write", {"path": "/data/docs/fresh.txt", "text": "fresh"})
        c.call("link", {"path": "/data/evil", "target": "/etc/passwd"})
        changes = {(s.path, s.action) for s in c.staged()}
        assert {("/data/old.txt", "delete"), ("/data/docs", "replace-dir"), ("/data/evil", "skip")} <= changes
        assert (host / "old.txt").exists() and (host / "docs" / "keep.txt").exists()  # nothing yet
        c.commit(c.review().digest)
        assert c.staged() == [] and c.call("ls_root", {})  # restarted and still serving
    assert (host / "new.txt").read_text() == "new" and not (host / "old.txt").exists()
    assert sorted(os.listdir(host / "docs")) == ["fresh.txt"]  # the whole dir was replaced
    assert not os.path.lexists(host / "evil")  # a link made in the box never lands on the host


def test_commit_replaces_a_host_link_instead_of_writing_through_it(tmp_path):
    host, outside = tmp_path / "host", tmp_path / "outside.txt"
    host.mkdir()
    outside.write_text("precious")
    (host / "victim").symlink_to(outside)
    b = Box(folders={"/data": str(host)}, stage=str(tmp_path / "stage"))
    upper, work = b.layer("/data")
    os.makedirs(upper)
    os.makedirs(work)
    with open(os.path.join(upper, "victim"), "w") as f:
        f.write("from the box")
    assert [(s.path, s.action) for s in staged(b)] == [("/data/victim", "write")]
    commit(b, review(b).digest)
    assert outside.read_text() == "precious"
    assert not (host / "victim").is_symlink() and (host / "victim").read_text() == "from the box"


def test_unknown_overlay_metadata_fails_closed(tmp_path):
    b = Box(folders={"/data": str(tmp_path / "host")}, stage=str(tmp_path / "stage"))
    upper, _ = b.layer("/data")
    os.makedirs(upper)
    p = os.path.join(upper, "moved")
    os.mkdir(p)
    try:
        os.setxattr(p, "user.overlay.redirect", b"/elsewhere")
    except OSError:
        pytest.skip("filesystem without user xattrs")
    with pytest.raises(BoxError, match="redirect"):
        staged(b)


# ---- review fixes (Codex sol-high, 2026-11-07) ----


def test_a_list_string_on_a_string_arg_is_one_path_not_a_list(folder):
    with boxed(folder) as c:
        sb, reg, hands, tools = box(c)
        reg.approve(WRITE, tools["write"])
        assert run(sb, hands, {"kind": "fake/write", "args": {
            "path": {"literal": '["/data/a"]'}, "text": {"literal": "x"}}}) == []
        assert any("not an absolute path" in d.get("reason", "")
                   for _, e, d in sb.store.audit_log() if e == "hands.malformed")


def test_mounts_may_not_overlap_and_ro_paths_name_specific_entries():
    for bad in (dict(folders={"/vault/private": "/h"}, ro_paths=("/vault",), stage="/s"),
                dict(ro_paths=("/etc",)), dict(ro_paths=("/nix/store",)), dict(ro_paths=("/dev/x",))):
        with pytest.raises(BoxError):
            Box(**bad)
    assert Box(ro_paths=("/etc/ssl",)).ro_paths == (os.path.realpath("/etc/ssl"),)


def test_a_directory_is_never_bound_as_a_socket(folder, tmp_path):
    host, stage = folder
    with pytest.raises(BoxError, match="not a socket"):
        launch_args((sys.executable,), {}, "/", Box(sockets={"/run/s": str(tmp_path)}), 9)


def test_host_folders_are_pinned_and_commit_never_follows_a_link_at_any_depth(tmp_path):
    real = tmp_path / "real" / "data"
    real.mkdir(parents=True)
    b = Box(folders={"/data": str(real)}, stage=str(tmp_path / "stage"))
    upper, work = b.layer("/data")
    os.makedirs(upper)
    os.makedirs(work)
    (tmp_path / "upper-file").write_text("x")
    shutil.copy(tmp_path / "upper-file", os.path.join(upper, "f"))
    (tmp_path / "real").rename(tmp_path / "moved")
    (tmp_path / "elsewhere" / "data").mkdir(parents=True)
    (tmp_path / "real").symlink_to(tmp_path / "elsewhere")  # an intermediate component is now a link
    with pytest.raises(BoxError):
        b.check_host()
    with pytest.raises(BoxError, match="link-free"):
        commit(b, review(b).digest)
    assert os.listdir(tmp_path / "elsewhere" / "data") == []


def test_commit_never_clobbers_an_unstaged_host_file(tmp_path):
    host = tmp_path / "host"
    host.mkdir()
    (host / ".rbb-commit-report").write_text("mine")
    b = Box(folders={"/data": str(host)}, stage=str(tmp_path / "stage"))
    upper, work = b.layer("/data")
    os.makedirs(upper)
    os.makedirs(work)
    with open(os.path.join(upper, "report"), "w") as f:
        f.write("new")
    commit(b, review(b).digest)
    assert (host / ".rbb-commit-report").read_text() == "mine" and (host / "report").read_text() == "new"
    assert sorted(os.listdir(host)) == [".rbb-commit-report", "report"]  # no temp left behind



# ---- no blind commit: the owner commits exactly what was reviewed ----


def test_a_review_shows_every_change_with_its_diff(folder):
    host, _ = folder
    with boxed(folder) as c:
        c.call("write", {"path": "/data/old.txt", "text": "new"})
        c.call("write", {"path": "/data/fresh.txt", "text": "hello"})
        c.call("rm", {"path": "/data/docs"})
        c.call("link", {"path": "/data/evil", "target": "/etc/passwd"})
        r = c.review()
        by = {x.path: x for x in r.changes}
        assert "-old" in by["/data/old.txt"].diff and "+new" in by["/data/old.txt"].diff
        assert by["/data/old.txt"].host.startswith("file:") and by["/data/fresh.txt"].host == "absent"
        assert by["/data/docs"].action == "delete" and by["/data/docs"].host.startswith("dir:")
        assert by["/data/evil"].action == "skip" and "never committed" in r.render()
        assert r.digest[:16] in r.render()


def test_commit_refuses_a_stage_that_changed_after_review(folder):
    host, _ = folder
    with boxed(folder) as c:
        c.call("write", {"path": "/data/a.txt", "text": "reviewed"})
        seen = c.review().digest
        c.call("write", {"path": "/data/a.txt", "text": "rewritten"})  # same paths and actions: only content differs
        with pytest.raises(BoxError, match="changed since it was reviewed"):
            c.commit(seen)
        seen = c.review().digest
        c.call("write", {"path": "/data/b.txt", "text": "slipped in after the review"})
        with pytest.raises(BoxError, match="changed since it was reviewed"):
            c.commit(seen)
        assert not (host / "a.txt").exists() and not (host / "b.txt").exists()  # nothing applied
        r = c.review()
        assert {x.path for x in r.changes} >= {"/data/a.txt", "/data/b.txt"}  # still staged, ready for review
        c.commit(r.digest)
    assert (host / "b.txt").read_text() == "slipped in after the review"


def test_commit_refuses_when_the_host_changed_under_the_review(folder):
    host, _ = folder
    with boxed(folder) as c:
        c.call("write", {"path": "/data/old.txt", "text": "box version"})
        seen = c.review().digest
        (host / "old.txt").write_text("the owner edited this meanwhile")
        with pytest.raises(BoxError, match="changed since it was reviewed"):
            c.commit(seen)
    assert (host / "old.txt").read_text() == "the owner edited this meanwhile"


def test_a_directory_replaced_by_a_file_is_pinned_by_its_whole_content(folder):
    host, _ = folder
    with boxed(folder) as c:
        c.call("rm", {"path": "/data/docs"})
        c.call("write", {"path": "/data/docs", "text": "now a file"})
        r = c.review()
        (ch,) = [x for x in r.changes if x.path == "/data/docs"]
        assert ch.action == "write" and ch.host.startswith("dir:") and "(host: dir)" in r.render()
        (host / "docs" / "added-later.txt").write_text("not what was reviewed")
        with pytest.raises(BoxError, match="changed since it was reviewed"):
            c.commit(r.digest)
    assert (host / "docs" / "keep.txt").exists()


def test_a_deleted_directory_is_pinned_by_its_whole_content(folder):
    host, _ = folder
    with boxed(folder) as c:
        c.call("rm", {"path": "/data/docs"})
        seen = c.review().digest
        (host / "docs" / "added-later.txt").write_text("not what was reviewed")
        with pytest.raises(BoxError, match="changed since it was reviewed"):
            c.commit(seen)
    assert (host / "docs" / "added-later.txt").exists()


def test_staged_work_lands_in_the_digest(folder):
    with boxed(folder) as c:
        sb, reg, hands, tools = box(c)
        c.wire(sb)
        c.call("write", {"path": "/data/n.txt", "text": "x"})
        c.call("write", {"path": "/data/n.txt", "text": "x"})  # same stage: no second notice
        rows = sb.store.db.execute("SELECT cluster, topic, ref FROM notices").fetchall()
        assert rows == [("fake/stage", "fs.staged", f"1 change(s), review {c.review().digest[:16]}")]
