"""The door's CONNECT proxy: the only route out of a networked box, one grant-checked egress per
connection, names resolved door-side, private address space refused unless granted as a literal."""

import json
import shutil
import socket
import sys
import threading
import time

import pytest

from rubberbandbox import mcp, proxy
from rubberbandbox.box import Box
from rubberbandbox.core import ToolDescriptor, diff, security_view

from test_mcp import ECHO, FAKE, box, run

pytestmark = pytest.mark.skipif(shutil.which("bwrap") is None or shutil.which("nsenter") is None,
                                reason="bwrap and nsenter are required")


@pytest.fixture
def upstream():
    """A host-side echo server: what the box is trying to reach."""
    srv = socket.create_server(("127.0.0.1", 0))
    hits = []

    def serve():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            hits.append(1)
            data = conn.recv(4096)
            conn.sendall(b"echo:" + data)
            conn.close()

    threading.Thread(target=serve, daemon=True).start()
    yield srv.getsockname()[1], hits
    srv.close()


def networked(network=True, review=True):
    """A networked fake server; `review`: the owner has approved one of its tools as launched."""
    cfg = mcp.ServerConfig("fake", (sys.executable, FAKE), box=Box(ro_paths=(FAKE,), network=network))
    c = mcp.McpClient(cfg)
    sb, reg, hands, tools = box(c)
    if review:
        reg.approve(ECHO, tools["echo"])
    c.wire(sb)
    return c, sb, hands


def via(c, target, text="ping"):
    return json.loads(c.call("via_proxy", {"path": target, "text": text}))


def events(sb, name):
    return [d for _, e, d in sb.store.audit_log() if e == name]


def test_without_a_grant_the_door_refuses_and_tells_the_digest(upstream):
    port, hits = upstream
    c, sb, _ = networked()
    with c:
        assert via(c, f"127.0.0.1:{port}")["status"] == "HTTP/1.1 403 refused by the door"
    assert hits == [] and events(sb, "net.refused")[0]["target"] == f"127.0.0.1:{port}"
    assert [t for (t,) in sb.store.db.execute("SELECT topic FROM notices")] == ["net.refused"]


def test_a_granted_target_is_one_audited_egress(upstream):
    port, hits = upstream
    c, sb, _ = networked()
    with c:
        sb.owner_mint(["net:fake"], [f"127.0.0.1:{port}"], ttl=3600)
        out = via(c, f"127.0.0.1:{port}")
        assert out["status"] == "HTTP/1.1 200 Connection established" and out["echo"] == "echo:ping"
        assert out["env"] == "http://127.0.0.1:3128"  # clients are pointed at the door, not around it
        assert via(c, f"127.0.0.1:{port + 1 if port < 65535 else port - 1}")["status"].endswith("403 refused by the door")
    (sent,) = events(sb, "door.sent")
    assert sent["kind"] == "net:fake" and sent["auth"] == "grant" and hits == [1]
    assert events(sb, "net.closed")[0]["up"] == 4


def test_names_never_reach_private_address_space(upstream):
    port, hits = upstream
    c, sb, _ = networked()
    with c:
        sb.owner_mint(["net:fake"], [f"localhost:{port}"], ttl=3600)  # granted, but it resolves to loopback
        assert via(c, f"localhost:{port}")["status"].endswith("403 refused by the door")
    assert hits == [] and "non-public" in events(sb, "door.failed")[0]["error"]


def test_only_well_formed_connect_requests(upstream):
    port, _ = upstream
    c, sb, _ = networked()
    with c:
        assert via(c, f"GET http://127.0.0.1:{port}/ HTTP/1.1\r\nHost: x\r\n\r\n")["status"].endswith("405 CONNECT only")
        assert via(c, "CONNECT user@host:443 HTTP/1.1\r\n\r\n")["status"].endswith("400 bad target")
        assert c.call("net_probe", {}) == "ENETUNREACH"  # the proxy is the only route


def test_the_hands_cannot_open_connections(upstream):
    port, hits = upstream
    c, sb, hands = networked()
    with c:
        sb.owner_mint(["net:fake"], [f"127.0.0.1:{port}"], ttl=3600)
        (out,) = run(sb, hands, {"kind": "net:fake", "destination": {"literal": f"127.0.0.1:{port}"}, "payload": []})
        assert out.status == "failed" and "proxy request" in out.reason and hits == []


def test_an_unwired_or_stiffened_proxy_refuses(upstream):
    port, hits = upstream
    cfg = mcp.ServerConfig("fake", (sys.executable, FAKE), box=Box(ro_paths=(FAKE,), network=True))
    with mcp.McpClient(cfg) as c:
        assert via(c, f"127.0.0.1:{port}")["status"].endswith("403 proxy not wired to a door")
    c, sb, _ = networked()
    with c:
        sb.owner_mint(["net:fake"], [f"127.0.0.1:{port}"], ttl=3600)
        sb.stiffen("fake/unknown")
        assert via(c, f"127.0.0.1:{port}")["status"].endswith("403 refused by the door")
    assert hits == []


def test_a_box_without_network_has_no_proxy(upstream):
    port, _ = upstream
    c, sb, _ = networked(network=False)
    with c:
        assert via(c, f"127.0.0.1:{port}") == {"error": "ECONNREFUSED"}
        assert "net:fake" not in sb.kinds


def test_targets_are_normalised_before_any_grant_check():
    assert proxy.target("API.Example.COM.:443") == "api.example.com:443"
    assert proxy.target("[::FFFF:7f00:1]:80") == "[::ffff:127.0.0.1]:80"
    assert proxy.target("bücher.example:443") == "xn--bcher-kva.example:443"
    for bad in ("example.com", "example.com:0", "example.com:99999", "a@b:1", "-x.com:1", "ex ample.com:1", "[zz]:1", ":443"):
        assert proxy.target(bad) is None, bad
    assert not proxy._public("10.0.0.1") and not proxy._public("::ffff:127.0.0.1") and proxy._public("1.1.1.1")
    # translation prefixes carry an IPv4 destination: judge that, not the prefix
    assert not proxy._public("64:ff9b::7f00:1") and not proxy._public("64:ff9b::a00:1") and proxy._public("64:ff9b::808:808")
    assert not proxy._public("2002:7f00:1::1") and not proxy._public("2001:0:4136:e378:8000:63bf:80ff:fffe")


def test_store_results_are_consumed_like_cursors():
    from rubberbandbox.core.store import Store
    store = Store()
    for t in ("a", "b"):
        store.audit(0.0, t)
    r = store.db.execute("SELECT event FROM audit ORDER BY seq")
    assert r.fetchone() == ("a",) and r.fetchone() == ("b",) and r.fetchone() is None and r.fetchall() == []


def test_gaining_network_is_a_loosening_and_losing_it_is_not():
    d = ToolDescriptor("fs", "read", {"type": "object", "properties": {"q": {"type": "string"}}})
    ep = lambda net: mcp.ServerConfig("fs", ("/nix/store/x-srv/bin/srv",), box=Box(network=net)).endpoint
    view = lambda e: security_view(d, e)
    assert diff(view(ep(False)), view(ep(True)), {"q": "payload"}).outcome == "loosened"
    assert diff(view(ep(True)), view(ep(False)), {"q": "payload"}).outcome == "accepted"


def test_the_owner_env_cannot_point_traffic_around_the_door(upstream):
    port, _ = upstream
    cfg = mcp.ServerConfig("fake", (sys.executable, FAKE), env={"HTTPS_PROXY": "http://evil:1"},
                           box=Box(ro_paths=(FAKE,), network=True))
    with mcp.McpClient(cfg) as c:
        assert via(c, f"127.0.0.1:{port}")["env"] == "http://127.0.0.1:3128"


def test_a_transaction_holds_the_store_against_other_threads():
    from rubberbandbox.core.store import Store
    store, inside, done = Store(), threading.Event(), threading.Event()

    def owner():
        try:
            with store.tx() as db:
                db.execute("INSERT INTO notices (cluster, topic, ref, created_at) VALUES ('c','rolled-back',NULL,0)")
                inside.set()
                done.wait(0.3)  # the proxy thread tries to write meanwhile
                raise RuntimeError("abort")
        except RuntimeError:
            pass

    t = threading.Thread(target=owner)
    t.start()
    inside.wait()
    store.audit(1.0, "net.closed", target="x")  # must wait for the rollback, not join the transaction
    done.set()
    t.join()
    assert [e for _, e, _ in store.audit_log()] == ["net.closed"]
    assert store.db.execute("SELECT COUNT(*) FROM notices").fetchone() == (0,)


def test_a_connect_to_a_name_behind_nat64_loopback_is_refused(upstream, monkeypatch):
    """A granted name whose only address is 64:ff9b::7f00:1 (NAT64 for 127.0.0.1) never dials."""
    port, hits = upstream
    real = socket.getaddrinfo

    def resolver(host, *args, **kw):
        if host == "nat64.test":
            return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("64:ff9b::7f00:1", port, 0, 0))]
        return real(host, *args, **kw)

    monkeypatch.setattr(proxy.socket, "getaddrinfo", resolver)  # the door side runs in this process
    c, sb, _ = networked()
    with c:
        sb.owner_mint(["net:fake"], [f"nat64.test:{port}"], ttl=3600)
        assert via(c, f"nat64.test:{port}")["status"].endswith("403 refused by the door")
    (failed,) = events(sb, "door.failed")
    assert "non-public" in failed["error"] and hits == [] and events(sb, "door.sent") == []


def test_a_new_operator_loses_its_network_route(upstream):
    """Same server name, different launch: the door refuses at once, and observing it ends the grant."""
    port, hits = upstream
    c, sb, _ = networked()
    with c:
        reg, echo = sb.registry, {d.name: d for d in c.list_tools()}["echo"]
        g = sb.owner_mint(["net:fake"], [f"127.0.0.1:{port}"], ttl=3600)
        assert via(c, f"127.0.0.1:{port}")["status"].endswith("200 Connection established")
        reg.configure("fake", mcp.ServerConfig("fake", (sys.executable, FAKE, "other"),
                                               box=Box(ro_paths=(FAKE,), network=True)).endpoint)
        assert sb.grants.get_active(g.id, sb.clock()) is None  # ended on reconfigure, before any observe
        assert via(c, f"127.0.0.1:{port}")["status"].endswith("403 refused by the door")  # before any observe
        assert "endpoint changed" in reg.observe(echo).loosened
        assert sb.grants.get_active(g.id, sb.clock()) is None
    assert hits == [1]


def test_a_narrower_launch_keeps_the_route_and_a_tool_loosening_does_not_touch_it(upstream):
    port, hits = upstream
    c, sb, _ = networked()
    with c:
        reg, echo = sb.registry, {d.name: d for d in c.list_tools()}["echo"]
        g = sb.owner_mint(["net:fake"], [f"127.0.0.1:{port}"], ttl=3600)
        loose = ToolDescriptor("fake", "echo", {"type": "object", "properties": {"text": {}}}, echo.annotations)
        assert reg.observe(loose).outcome == "loosened"  # one tool loosened; same operator
        assert sb.grants.get_active(g.id, sb.clock()) is not None
        assert via(c, f"127.0.0.1:{port}")["status"].endswith("200 Connection established")


def test_no_reviewed_tool_means_no_network(upstream):
    port, hits = upstream
    c, sb, _ = networked(review=False)
    with c:
        sb.owner_mint(["net:fake"], [f"127.0.0.1:{port}"], ttl=3600)
        assert via(c, f"127.0.0.1:{port}")["status"].endswith("403 refused by the door")
    assert hits == [] and "no reviewed tool" in events(sb, "door.refused")[0]["reason"]


# ---- what counts as an endpoint change, and what happens to live tunnels ----

BASE = dict(command=("/nix/store/x-srv/bin/srv", "--root", "/data"), env={"K": "v"}, cwd="/",
            box=Box(folders={"/data": "/h/data"}, ro_paths=("/etc/ssl",), stage="/s", network=True))


def endpoint(**change):
    return mcp.ServerConfig("fs", **{**BASE, **change}).endpoint


@pytest.mark.parametrize("change", [
    dict(command=("/nix/store/x-srv/bin/srv", "--root", "/other")),  # launch args
    dict(command=("/nix/store/y-srv/bin/srv", "--root", "/data")),  # binary
    dict(env={"K": "w"}), dict(env={"K": "v", "J": "1"}), dict(cwd="/data"),
    dict(box=Box(folders={"/data": "/h/elsewhere"}, ro_paths=("/etc/ssl",), stage="/s", network=True)),
    dict(box=Box(folders={"/data": "/h/data", "/more": "/h/more"}, ro_paths=("/etc/ssl",), stage="/s", network=True)),
    dict(box=Box(folders={"/data": "/h/data"}, ro_paths=("/etc/ssl", "/etc/hosts"), stage="/s", network=True)),
])
def test_every_field_of_the_launch_is_part_of_the_operator(change):
    d = ToolDescriptor("fs", "read", {"type": "object", "properties": {"q": {"type": "string"}}})
    assert diff(security_view(d, endpoint()), security_view(d, endpoint(**change)), {"q": "payload"}).outcome == "loosened"


def test_a_remote_endpoint_that_changes_only_its_host_is_a_new_operator():
    d = ToolDescriptor("api", "get", {"type": "object", "properties": {"q": {"type": "string"}}})
    a, b = "https://mcp.example.com:443/v1", "https://mcp.example.net:443/v1"
    assert diff(security_view(d, a), security_view(d, b), {"q": "payload"}).outcome == "loosened"
    assert diff(security_view(d, a), security_view(d, a.replace(":443", ":8443")), {"q": "payload"}).outcome == "loosened"


def test_the_door_refuses_a_stored_grant_under_a_launch_nobody_reviewed(upstream):
    """Inner layer: a grant that survived (e.g. a persisted store, new process, new config) is still refused."""
    port, hits = upstream
    c, sb, _ = networked()
    with c:
        g = sb.owner_mint(["net:fake"], [f"127.0.0.1:{port}"], ttl=3600)
        # what a fresh process sees: grants persisted, config changed, configure() never ran
        sb.registry._endpoints["fake"] = mcp.ServerConfig("fake", (sys.executable, FAKE, "other"),
                                                          box=Box(ro_paths=(FAKE,), network=True)).endpoint
        assert via(c, f"127.0.0.1:{port}")["status"].endswith("403 refused by the door")
        assert "launch changed" in events(sb, "door.refused")[0]["reason"]
        assert sb.grants.get_active(g.id, sb.clock()) is not None
        sb.registry.observe({d.name: d for d in c.list_tools()}["echo"])  # observe alone must end it
        assert sb.grants.get_active(g.id, sb.clock()) is None
    assert hits == []


def test_losing_network_ends_the_route_and_its_tunnels_at_once(stream):
    port, got = stream
    c, sb, _ = networked()
    with c:
        g = sb.owner_mint(["net:fake"], [f"127.0.0.1:{port}"], ttl=3600)
        off = mcp.ServerConfig("fake", (sys.executable, FAKE), box=Box(ro_paths=(FAKE,), network=False)).endpoint
        sb.registry.configure("fake", off)  # a narrowing, yet the route must go
        assert sb.grants.get_active(g.id, sb.clock()) is None
        assert "not configured for network" in sb.registry.net_check("fake")


def test_reconfiguring_reverts_tool_semantics_at_once(upstream):
    c, sb, _ = networked()
    with c:
        assert sb.kinds["fake/echo"].grantable
        sb.registry.configure("fake", "stdio:a-new-launch")
        assert not sb.kinds["fake/echo"].grantable and not sb.kinds["fake/echo"].read_only


def test_narrowing_compares_values_exactly():
    from rubberbandbox.core.registry import _narrowed
    assert not _narrowed('stdio:{"cwd": 1, "network": false}', 'stdio:{"cwd": true, "network": false}')
    assert not _narrowed('stdio:{"network": "A"}', 'stdio:{"network": "B"}')
    assert _narrowed('stdio:{"folders": {"/a": "/h"}, "network": true}', 'stdio:{"folders": {}, "network": false}')


@pytest.fixture
def stream():
    """A long-lived upstream: echoes every chunk and records what reached it."""
    srv, got = socket.create_server(("127.0.0.1", 0)), []

    def serve():
        try:
            conn, _ = srv.accept()
        except OSError:
            return
        while data := conn.recv(4096):
            got.append(data)
            conn.sendall(b"echo:" + data)

    threading.Thread(target=serve, daemon=True).start()
    yield srv.getsockname()[1], got
    srv.close()


def revoke_by(how, c, sb, g, clock):
    if how == "reconfigure":
        sb.registry.configure("fake", mcp.ServerConfig("fake", (sys.executable, FAKE, "x"),
                                                       box=Box(ro_paths=(FAKE,), network=True)).endpoint)
    elif how == "end grant":
        sb.owner_end(g)
    elif how == "stiffen":
        sb.stiffen("fake/unknown")
    elif how == "expire":
        clock.advance(7200)


@pytest.mark.parametrize("how", ["reconfigure", "end grant", "stiffen", "expire"])
def test_a_live_tunnel_is_cut_when_its_authorization_lapses(stream, how):
    """The door-side splice, driven from the host so the test holds the tunnel itself."""
    port, got = stream
    c, sb, _ = networked()
    with c:
        g = sb.owner_mint(["net:fake"], [f"127.0.0.1:{port}"], ttl=3600)
        lst, closed = socket.create_server(("127.0.0.1", 0)), []
        proxy.serve(lst, lambda: proxy.gate(sb, "net:fake", c.net), lambda *a: closed.append(a),
                    threading.BoundedSemaphore(2))
        cl = socket.create_connection(lst.getsockname(), timeout=5)
        cl.sendall(f"CONNECT 127.0.0.1:{port} HTTP/1.1\r\n\r\n".encode())
        assert cl.recv(100).startswith(b"HTTP/1.1 200")
        cl.sendall(b"one")
        assert cl.recv(100) == b"echo:one"
        revoke_by(how, c, sb, g, sb.clock)
        if how == "expire":
            time.sleep(proxy.RECHECK + 0.2)  # no revocation event: the periodic re-check finds it
        try:
            cl.sendall(b"two")
            assert cl.recv(100) == b""  # cut, nothing echoed
        except OSError:
            pass
        for _ in range(50):
            if closed:
                break
            time.sleep(0.1)
        lst.close()
    assert got == [b"one"]  # no traffic after the lapse
    assert closed and closed[0][-1] is True


def test_reconfigured_tools_are_blocked_until_reviewed_again(upstream):
    c, sb, _ = networked()
    with c:
        reg = sb.registry
        assert reg.check_call("fake/echo", ["text"]) is None
        reg.configure("fake", "stdio:a-new-launch")
        assert "unreviewed on a boxed server" in reg.check_call("fake/echo", ["text"])  # before any observe


def test_a_tunnel_does_not_outlive_its_box(stream):
    port, got = stream
    c, sb, _ = networked()
    with c:
        sb.owner_mint(["net:fake"], [f"127.0.0.1:{port}"], ttl=3600)
        assert c.call("hold_tunnel", {"path": f"127.0.0.1:{port}"}) == "echo:one"
        c.discard()  # restart: the only peer of the tunnel inside the box dies
        for _ in range(50):
            if events(sb, "net.closed") or events(sb, "net.cut"):
                break
            time.sleep(0.1)
        assert events(sb, "net.closed") or events(sb, "net.cut")
    assert got == [b"one"]


def test_a_revocation_between_authorization_and_lease_is_not_missed(upstream):
    port, _ = upstream
    c, sb, _ = networked()
    with c:
        g = sb.owner_mint(["net:fake"], [f"127.0.0.1:{port}"], ttl=3600)
        seen = sb.revoked  # read before authorizing, as the gate does
        sb.owner_end(g)  # lands before the lease exists
        assert proxy.Lease(sb, "net:fake", f"127.0.0.1:{port}", seen).ok() is False
