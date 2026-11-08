"""MCP over stdio: every call is egress to the operator, bound by the registry, re-checked at the
door, run with no network, and its output stored with a label."""

import os
import random
import shutil
import sys

import pytest

from rubberbandbox import mcp
from rubberbandbox.box import Box
from rubberbandbox.core import (
    EXTERNAL_PRIVATE,
    EXTERNAL_PUBLIC,
    OWNER_PRIVATE,
    OWNER_PUBLIC,
    Authorization,
    BonesError,
    Egress,
    EnumField,
    InboundEvent,
    ManifestPack,
    ManifestRegistry,
    ManualClock,
    Mount,
    Rules,
    Sandbox,
    Schema,
    ToolDescriptor,
    ToolManifest,
    conservative,
)

FAKE = os.path.join(os.path.dirname(__file__), "fake_mcp_server.py")
FS_BIN = shutil.which("mcp-server-filesystem")


def fake(mode="normal", timeout=10.0, **box):
    """The fake server, boxed: its script is listed explicitly, like any non-Nix entry point."""
    return mcp.McpClient(mcp.ServerConfig("fake", (sys.executable, FAKE, mode), timeout=timeout,
                                          box=Box(ro_paths=(FAKE,), **box)))


class WebChannel:
    name = "web"

    def inbound_label(self, event):
        return EXTERNAL_PRIVATE

    def route(self, event):
        return None

    def fits(self, destination, text):
        return True


class Clerk:
    def extract(self, text):
        return {"intent": "none"}


class Scripted:
    """Hands that propose whatever the test hands them, and remember what they saw."""

    def __init__(self):
        self.next, self.seen = [], []

    def propose(self, view):
        self.seen.append(view)
        out, self.next = self.next, []
        return out


def box(client):
    """A sandbox with one inbound channel (for the hands) and the server's tools mounted."""
    clock, hands = ManualClock(), Scripted()
    web = ManifestPack("web", Schema("s", {"intent": EnumField("none", "other")}), [], [WebChannel()], Rules())
    server, adapters, tools = mcp.mount(client)
    sb = Sandbox([Mount(web, Clerk()), server], adapters, hands=hands, clock=clock, rng=random.Random(0))
    reg = ManifestRegistry(sb, {client.cfg.name: client.cfg.endpoint}, {client.cfg.name: client})
    for d in tools:
        reg.observe(d)
    return sb, reg, hands, {d.name: d for d in tools}


def run(sb, hands, *proposals):
    hands.next = list(proposals)
    return sb.receive(InboundEvent("web", True, "u1", f"d{sb.clock()}", "please do the thing", sb.clock()))


def output(sb):
    (detail,) = [d for _, e, d in sb.store.audit_log() if e == "door.sent"][-1:]
    return sb.store.get(detail["output"])


# ---- the stdio client against a pushy server ----


def test_identity_comes_from_owner_config_and_malformed_tools_are_dropped():
    with fake() as c:
        tools = c.list_tools()  # two pages, one malformed entry
        assert sorted(d.kind for d in tools) == [f"fake/{n}" for n in sorted(
            ["echo", "net_probe", "env_probe", "fail", "slow", "ask", "ls_root", "sock_probe", "write", "link", "rm", "find", "via_proxy", "hold_tunnel"])]
        assert all("trusted-bank-server" not in repr(d) for d in tools)
        assert c.call("echo", {"text": "hi", "count": 2}) == "hihi"


def test_server_runs_without_network_or_the_owner_environment(monkeypatch):
    monkeypatch.setenv("RBB_SECRET", "hunter2")
    with fake() as c:
        assert c.call("net_probe", {}) == "ENETUNREACH"
        assert "RBB_SECRET" not in c.call("env_probe", {})


def test_server_requests_are_refused():
    with fake() as c:
        assert c.call("ask", {}) == "-32601"  # no sampling: the server cannot borrow our model


def test_misbehaving_servers_fail_closed():
    with fake() as c:
        with pytest.raises(mcp.McpError, match="tool error"):
            c.call("fail", {})
    with fake(timeout=0.5) as c, pytest.raises(mcp.McpError, match="no response"):
        c.call("slow", {})
    with fake("garbage") as c, pytest.raises(mcp.McpError, match="non-JSON"):
        c.list_tools()
    with pytest.raises(mcp.McpError, match="protocol version"):
        fake("old")


def test_a_changed_launch_is_a_different_endpoint():
    a = mcp.ServerConfig("fs", ("srv", "/data"))
    assert a.endpoint != mcp.ServerConfig("fs", ("srv", "/")).endpoint
    assert a.endpoint != mcp.ServerConfig("fs", ("srv", "/data"), env={"X": "1"}).endpoint


# ---- calls through the sandbox ----


ECHO = ToolManifest("fake/echo", "read-private", {"text": "payload", "count": "control"})


def test_named_calls_bind_through_the_registry_and_outputs_are_labeled():
    with fake() as c:
        sb, reg, hands, tools = box(c)
        reg.approve(ECHO, tools["echo"])
        sb.owner_mint(["fake/echo"], ["mcp:fake"], ttl=3600)
        note = sb.owner_put("owner note")
        (out,) = run(sb, hands, {"kind": "fake/echo", "args": {"text": {"ref": note.id}}})
        assert out.status == "sent" and out.destination == "mcp:fake"
        got = output(sb)
        assert got.data == "owner note" and got.label == EXTERNAL_PRIVATE and got.source == "output:fake/echo"

        # an untrusted control arg (a literal shaped by inbound content) needs the owner
        (out,) = run(sb, hands, {"kind": "fake/echo", "args": {"text": {"ref": note.id}, "count": {"literal": "9"}}})
        assert out.status == "held"


def test_unapproved_args_and_unnamed_calls_never_reach_the_server():
    with fake() as c:
        sb, reg, hands, tools = box(c)
        reg.approve(ECHO, tools["echo"])
        sb.owner_mint(["fake/echo"], ["mcp:fake"], ttl=3600)
        note = sb.owner_put("x")
        assert run(sb, hands, {"kind": "fake/echo", "args": {"text": {"ref": note.id}, "to": {"literal": "a"}}}) == []
        assert any(d.get("reason", "").startswith("args not approved")
                   for _, e, d in sb.store.audit_log() if e == "hands.malformed")
        # positional form: the bones find the operator grant, the door still refuses
        (out,) = run(sb, hands, {"kind": "fake/echo", "destination": {"literal": "mcp:fake"},
                                 "payload": [{"ref": note.id}]})
        assert out.status == "refused" and "named" in out.reason


PROBE = ToolManifest("fake/net_probe", "read-private", {})


def test_unreviewed_tools_on_a_boxed_server_cannot_be_called_until_approved():
    with fake() as c:
        sb, reg, hands, tools = box(c)
        sb.owner_mint(["fake/net_probe"], ["mcp:fake"], ttl=3600)
        assert run(sb, hands, {"kind": "fake/net_probe", "args": {}}) == []
        assert any("unreviewed on a boxed server" in d.get("reason", "")
                   for _, e, d in sb.store.audit_log() if e == "hands.malformed")
        reg.approve(PROBE, tools["net_probe"])
        sb.owner_mint(["fake/net_probe"], ["mcp:fake"], ttl=3600)
        (out,) = run(sb, hands, {"kind": "fake/net_probe", "args": {}})
        assert out.status == "sent" and output(sb).data == "ENETUNREACH"


def test_the_door_blocks_a_boxed_tool_that_reverted_after_binding():
    with fake() as c:
        sb, reg, hands, tools = box(c)
        reg.approve(PROBE, tools["net_probe"])
        eg = reg.bind("fake/net_probe", {})
        assert reg.check_egress(eg) is None
        loose = ToolDescriptor("fake", "net_probe", tools["net_probe"].input_schema, {})  # hints dropped
        assert reg.observe(loose).outcome == "loosened"
        assert "unreviewed on a boxed server" in reg.check_egress(eg)  # inner layer, not just invalidation


def test_a_box_must_belong_to_an_owner_configured_server():
    clock = ManualClock()
    pack = ManifestPack("mcp", Schema("s", {"intent": EnumField("none")}), [], [], Rules())
    sb = Sandbox([Mount(pack, None)], {}, clock=clock)
    with pytest.raises(ValueError, match="not configured"):
        ManifestRegistry(sb, {}, {"s": object()})


def test_tool_errors_are_failures_not_outputs():
    with fake() as c:
        sb, reg, hands, tools = box(c)
        reg.approve(ToolManifest("fake/fail", "read-private", {}), tools["fail"])
        sb.owner_mint(["fake/fail"], ["mcp:fake"], ttl=3600)
        (out,) = run(sb, hands, {"kind": "fake/fail", "args": {}})
        assert out.status == "failed" and "tool error" in out.reason


def test_planner_sees_frozen_manifests_only():
    with fake() as c:
        sb, reg, hands, tools = box(c)
        reg.approve(ECHO, tools["echo"])
        run(sb, hands)
        (view,) = hands.seen
        assert view.tools == {"fake/echo": {"effect": "read-private", "args": {"text": "payload", "count": "control"}}}
        assert "IGNORE ALL PREVIOUS" not in repr(view) and "net_probe" not in repr(view)


# ---- binding and the door's re-check, without a live server ----


class Rec:
    def __init__(self, result=None):
        self.log, self.result = [], result

    def execute(self, kind, destination, payload, control=None, args=None):
        self.log.append((kind, destination, args))
        return self.result


POST = ToolDescriptor("chat", "post", {"type": "object", "properties": {
    "to": {"type": "string"}, "body": {"type": "string"}}}, {"readOnlyHint": False, "destructiveHint": False,
                                                              "openWorldHint": True})
GET = ToolDescriptor("web", "get", {"type": "object", "properties": {"q": {"type": "string"}}},
                     {"readOnlyHint": True, "openWorldHint": True})


@pytest.fixture
def unit():
    clock, rec = ManualClock(), Rec("result")
    tools = [conservative("chat/post", ["to", "body"]), conservative("web/get", ["q"])]
    pack = ManifestPack("mcp", Schema("s", {"intent": EnumField("none")}), tools, [], Rules())
    sb = Sandbox([Mount(pack, None)], {k: rec for k in pack.kinds}, clock=clock, rng=random.Random(0))
    reg = ManifestRegistry(sb, {"chat": "stdio:chat", "web": "stdio:web"})
    reg.approve(ToolManifest("chat/post", "send", {"to": "destination", "body": "payload"}), POST)
    reg.approve(ToolManifest("web/get", "read-public", {"q": "payload"}), GET)
    put = lambda d, label=OWNER_PRIVATE: sb.store.put(d, label, "t", clock())
    return sb, reg, rec, put


def test_destination_args_become_the_egress_destination(unit):
    sb, reg, rec, put = unit
    eg = reg.bind("chat/post", {"to": put("chat:u1"), "body": put("hi")})
    assert eg.destination.data == "chat:u1" and eg.names == ("to", "body")
    assert reg.bind("chat/post", {"body": put("hi")}).destination.data == "mcp:chat"
    assert "not a tool" in reg.bind("rogue/post", {})


def test_door_refuses_a_destination_filed_as_payload(unit):
    sb, reg, rec, put = unit
    g = sb.owner_mint(["chat/post"], ["mcp:chat"], ttl=3600)
    smuggled = Egress("chat/post", reg.operator("chat"), (put("chat:attacker"), put("hi")), (), ("", "to", "body"))
    assert sb._door.cross(smuggled, Authorization("grant", g.id)) == ("refused", "call args are not in their approved roles")
    honest = reg.bind("chat/post", {"body": put("hi")})
    assert sb._door.cross(honest, Authorization("grant", g.id))[0] == "sent"
    assert rec.log == [("chat/post", "mcp:chat", {"body": "hi"})]


def test_a_call_without_a_destination_arg_goes_to_its_operator(unit):
    sb, reg, rec, put = unit
    g = sb.owner_mint(["chat/post"], ["chat:u1"], ttl=3600)
    misdirected = Egress("chat/post", put("chat:u1"), (put("hi"),), (), ("", "body"))
    assert sb._door.cross(misdirected, Authorization("grant", g.id))[1] == "call with no destination arg must go to its operator"


def test_arg_names_are_part_of_what_the_owner_approved(unit):
    sb, reg, rec, put = unit
    v = put("x")
    assert Egress("k", v, (v,), (), ("", "a")).digest != Egress("k", v, (v,), (), ("", "b")).digest
    assert Egress("k", v, (v,)).digest != Egress("k", v, (v,), (), ("", "a")).digest
    with pytest.raises(ValueError):
        Egress("k", v, (v,), (), ("", ""))


def test_outputs_are_public_only_for_public_reads_that_sent_nothing_private(unit):
    sb, reg, rec, put = unit
    q = sb.owner_publish("q", "weather")
    assert sb._door.cross(reg.bind("web/get", {"q": q}), Authorization("public_read", ""))[0] == "sent"
    assert output(sb).label == EXTERNAL_PUBLIC
    g = sb.owner_mint(["web/get"], ["mcp:web"], ttl=3600)
    assert sb._door.cross(reg.bind("web/get", {"q": put("my diagnosis")}), Authorization("grant", g.id))[0] == "sent"
    assert output(sb).label == EXTERNAL_PRIVATE  # the server could echo the private query back


def test_named_calls_need_a_registry():
    clock = ManualClock()
    pack = ManifestPack("mcp", Schema("s", {"intent": EnumField("none")}), [conservative("x/t", ["a"])], [], Rules())
    sb = Sandbox([Mount(pack, None)], {"x/t": Rec()}, clock=clock)
    v = sb.store.put("mcp:x", OWNER_PUBLIC, "t", clock())
    sb.approvals.approve(sb.approvals.hold(Egress("x/t", v, (v,), (), ("", "a")), "c", "r", clock()), clock())
    assert sb._door.cross(Egress("x/t", v, (v,), (), ("", "a")), Authorization("approval", "A1"))[1] == \
        "named tool call with no registry to check it"


# ---- the official filesystem server, no network ----


READ = ToolManifest("fs/read_text_file", "read-private", {"path": "destination", "head": "control", "tail": "control"})
WRITE_FILE = ToolManifest("fs/write_file", "write-staged", {"path": "destination", "content": "payload"})


@pytest.mark.skipif(FS_BIN is None, reason="mcp-server-filesystem not on PATH (nix develop provides it)")
def test_official_filesystem_server(tmp_path):
    root = tmp_path / "root"
    (root / "notes").mkdir(parents=True)
    (root / "notes-secret").mkdir()
    (root / "notes" / "a.txt").write_text("meeting at noon\n")
    (root / "notes-secret" / "s.txt").write_text("pin 1234\n")
    cfg = mcp.ServerConfig("fs", (FS_BIN, "/data"), box=Box(folders={"/data": str(root)}, stage=str(tmp_path / "stage")))
    with mcp.McpClient(cfg) as c:
        sb, reg, hands, tools = box(c)
        assert len(tools) >= 10 and all(sb.kinds[f"fs/{n}"].grantable is False for n in tools)

        # in a box, a path filed as control would skip canonicalisation and the grant check
        with pytest.raises(BonesError, match="path_like"):
            reg.approve(ToolManifest("fs/read_text_file", "read-private",
                                     {"path": "control", "head": "control", "tail": "control"}), tools["read_text_file"])
        # the tool says it is destructive: filing write_file as write-staged needs an explicit override
        with pytest.raises(BonesError, match="annotations"):
            reg.approve(WRITE_FILE, tools["write_file"])

        reg.approve(READ, tools["read_text_file"])
        sb.owner_mint(["fs/read_text_file"], ["/data/notes"], ttl=3600)
        path = sb.owner_put("/data/notes/a.txt")
        (out,) = run(sb, hands, {"kind": "fs/read_text_file", "args": {"path": {"ref": path.id}}})
        assert out.status == "sent" and out.destination == "/data/notes/a.txt"
        assert output(sb).data == "meeting at noon\n" and output(sb).label == EXTERNAL_PRIVATE

        # lexical tricks are canonicalised before the grant check, and the canonical path is what is sent
        (out,) = run(sb, hands, {"kind": "fs/read_text_file", "args": {"path": {"literal": "/data/notes-secret/../notes/./a.txt"}}})
        assert out.status == "sent" and out.destination == "/data/notes/a.txt"
        # whole components: /data/notes never covers /data/notes-secret
        (out,) = run(sb, hands, {"kind": "fs/read_text_file", "args": {"path": {"literal": "/data/notes-secret/s.txt"}}})
        assert out.status == "held"
        # /etc does not exist in the box; if the owner waves it through anyway, nothing is there to read
        (out,) = run(sb, hands, {"kind": "fs/read_text_file", "args": {"path": {"literal": "/etc/passwd"}}})
        assert out.status == "held" and sb.owner_approve(out.reason.split(":")[0]).status == "failed"

        # several paths: each canonicalised, never grant-covered (approval per call), one bad path rejects all
        reg.approve(ToolManifest("fs/read_multiple_files", "read-private", {"paths": "destination"}),
                    tools["read_multiple_files"])
        assert sb.kinds["fs/read_multiple_files"].grantable is False  # a list of paths: approval only
        sb.owner_mint(["fs/read_multiple_files"], ["/data", '["/data/notes/a.txt"]'], ttl=3600)
        (out,) = run(sb, hands, {"kind": "fs/read_multiple_files", "args": {"paths": {"literal": '["/data/notes/a.txt"]'}}})
        assert out.status == "held" and out.destination == '["/data/notes/a.txt"]'
        assert run(sb, hands, {"kind": "fs/read_multiple_files", "args": {
            "paths": {"literal": '["/data/notes/a.txt", "/data/notes/a.txt/x"]'}}}) == []

        # writes are staged: the host folder is untouched until the owner commits
        reg.approve(WRITE_FILE, tools["write_file"], overrides=["annotations"])
        sb.owner_mint(["fs/write_file"], ["/data/notes"], ttl=3600)
        content = sb.owner_put("draft")
        (out,) = run(sb, hands, {"kind": "fs/write_file", "args": {
            "path": {"literal": "/data/notes/new.txt"}, "content": {"ref": content.id}}})
        assert out.status == "sent" and not (root / "notes" / "new.txt").exists()
        assert [(x.path, x.action) for x in c.staged()] == [("/data/notes", "mkdir"), ("/data/notes/new.txt", "write")]
        c.commit()
        assert (root / "notes" / "new.txt").read_text() == "draft" and c.staged() == []
