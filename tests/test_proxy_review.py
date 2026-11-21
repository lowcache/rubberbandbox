"""Proxy defects found by the 2026-11-20 reviews (Fable 5.2 and Gemini 4 Carbon), host-side through
proxy_harness: the real serve/_handle/_splice/gate/NetAdapter/Lease with a fake sandbox, no bwrap."""

import errno
import pytest
import socket
import struct
import threading
import time

from proxy_harness import Proxy, Upstream
from rubberbandbox import proxy

def test_head_timeout_bounds_the_whole_head_not_each_recv(monkeypatch):
    """Invariant 3 (10 s head timeout): a request dripped slower than the deadline is never served."""
    monkeypatch.setattr(proxy, "HEAD_TIMEOUT", 0.5)
    up = Upstream()
    with Proxy() as p:
        dest = f"127.0.0.1:{up.port}"
        p.grant(dest)
        req = f"CONNECT {dest} HTTP/1.1\r\n\r\n".encode()
        s = socket.create_connection(("127.0.0.1", p.port), timeout=3)
        started = time.monotonic()
        try:
            for b in req[:8]:  # 8 bytes, 0.2 s apart: the head takes 1.6 s, over 3x the deadline
                s.sendall(bytes([b]))
                time.sleep(0.2)
            s.sendall(req[8:])
            resp = s.recv(200)
        except OSError:
            resp = b""
        took = time.monotonic() - started
        s.close()
        assert not resp.startswith(b"HTTP/1.1 200"), f"head took {took:.1f} s against a 0.5 s deadline: {resp!r}"
        assert up.hits == []
    up.close()

def test_target_refuses_an_ipv6_zone_id_with_box_chosen_bytes():
    """Invariant 1 (exact host:port): the door is never asked about a target carrying control bytes."""
    with Proxy() as p:
        s, resp = p.raw(b"CONNECT [fe80::1%\x1b[2J\nGRANTED:example.com]:443 HTTP/1.1\r\n\r\n")
        s.close()
        assert p.calls == [], f"the door was asked about {p.calls!r}"
        assert resp.startswith(b"HTTP/1.1 400"), resp

def test_names_resolving_to_non_global_ipv6_are_never_dialed(monkeypatch):
    """Invariant 2: a granted name whose only address is non-global is refused before any dial."""
    answers = {"site-local.test": "fec0::1",  # deprecated site-local (fec0::/10)
               "v4-translated.test": "::ffff:0:7f00:1",  # IPv4-translated ::ffff:0:0:0/96 carrying 127.0.0.1
               "v4-compatible.test": "::7f00:1",  # IPv4-compatible ::/96 carrying 127.0.0.1
               "multicast.test": "ff02::1"}  # link-local multicast
    real, dialed = socket.getaddrinfo, []

    def resolver(host, port, *args, **kw):
        if host in answers:
            return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", (answers[host], port, 0, 0))]
        return real(host, port, *args, **kw)

    def connect(self, addr):
        dialed.append(addr[0])
        raise OSError("test: not dialing")

    monkeypatch.setattr(proxy.socket, "getaddrinfo", resolver)
    monkeypatch.setattr(socket.socket, "connect", connect)
    adapter = proxy.NetAdapter()
    for name in answers:
        adapter.begin()
        try:
            adapter.execute("net:test", f"{name}:80", ())
        except proxy.NetError:
            pass
        finally:
            adapter.take()
    assert dialed == [], f"dialed non-global addresses: {dialed}"

def test_an_overlong_port_is_a_bad_target_not_a_crash():
    """Invariant 1: a malformed CONNECT target gets a 400, whatever its bytes."""
    with Proxy() as p:
        try:
            s, resp = p.raw(b"CONNECT example.com:" + b"0" * 5000 + b"80 HTTP/1.1\r\n\r\n")
            s.close()
        except OSError as exc:
            resp = repr(exc).encode()
        assert resp.startswith(b"HTTP/1.1 400"), f"no reply to a 5002-digit port: {resp!r}"

def test_a_tunnel_streaming_one_way_is_not_idle(monkeypatch):
    """Invariant 3 (300 s idle): only a tunnel silent in both directions idles out."""
    monkeypatch.setattr(proxy, "IDLE_TIMEOUT", 1.0)
    srv = socket.create_server(("127.0.0.1", 0))
    ticks = 12

    def feed():  # a download: the upstream talks every 0.2 s for 2.4 s, the box only listens
        conn, _ = srv.accept()
        with conn:
            try:
                for _ in range(ticks):
                    conn.sendall(b"x")
                    time.sleep(0.2)
            except OSError:
                pass

    threading.Thread(target=feed, daemon=True).start()
    with Proxy() as p:
        dest = f"127.0.0.1:{srv.getsockname()[1]}"
        p.grant(dest)
        s = p.connect_to(dest)
        s.settimeout(3)
        got = b""
        try:
            while chunk := s.recv(100):
                got += chunk
        except OSError:
            pass
        s.close()
        assert len(got) == ticks, f"stream cut after {len(got)} of {ticks} bytes, never 1 s without traffic"
    srv.close()

def test_back_pressure_does_not_break_the_tunnel():
    """Invariant 3/4: a tunnel ends on close, idle or a lapsed lease; not because a peer read slowly."""
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    total, got, done = 16 << 20, [], threading.Event()

    def slow():  # an upstream that stalls for 3x RECHECK before it reads the upload
        conn, _ = srv.accept()
        n = 0
        with conn:
            time.sleep(1.5)
            try:
                while data := conn.recv(1 << 20):
                    n += len(data)
            except OSError:
                pass
        got.append(n)
        done.set()

    threading.Thread(target=slow, daemon=True).start()
    with Proxy() as p:
        dest = f"127.0.0.1:{srv.getsockname()[1]}"
        p.grant(dest)
        s = p.connect_to(dest)
        s.settimeout(10)
        try:
            s.sendall(b"x" * total)
            s.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        assert done.wait(15)
        s.close()
        time.sleep(0.2)
        assert got == [total], f"upload truncated at {got[0]} of {total} bytes; on_close said {p.closed}"
    srv.close()

def test_a_closed_listener_serves_no_further_connection():
    """serve(): 'Accept until the listener closes.'"""
    up = Upstream()
    with Proxy() as p:
        dest = f"127.0.0.1:{up.port}"
        p.grant(dest)
        time.sleep(0.3)  # the accept loop is now blocked in accept()
    time.sleep(0.3)  # the listener is closed
    try:
        s = socket.create_connection(("127.0.0.1", p.port), timeout=2)
        s.sendall(f"CONNECT {dest} HTTP/1.1\r\n\r\n".encode())
        resp = s.recv(200)
        s.close()
    except OSError as exc:
        resp = repr(exc).encode()
    assert p.calls == [] and up.hits == [], f"served after close: {resp!r}"
    up.close()

def test_a_transient_accept_error_does_not_end_the_proxy():
    """Invariant 5 (keeps accepting): one aborted connection or one EMFILE must not stop the proxy."""

    class Flaky:
        """A listener whose first accept fails the way a transient kernel error does."""

        def __init__(self, real):
            self.real, self.failed = real, False

        def accept(self):
            if not self.failed:
                self.failed = True
                raise OSError(errno.EMFILE, "Too many open files")
            return self.real.accept()

        def __getattr__(self, name):  # settimeout, fileno, ...: whatever a fixed loop may ask for
            return getattr(self.real, name)

    lst = socket.create_server(("127.0.0.1", 0))
    proxy.serve(Flaky(lst), lambda: None, lambda *a: None, threading.BoundedSemaphore(2))
    s = socket.create_connection(lst.getsockname(), timeout=2)
    s.sendall(b"CONNECT 127.0.0.1:1 HTTP/1.1\r\n\r\n")
    try:
        resp = s.recv(200)
    except OSError as exc:
        resp = repr(exc).encode()
    s.close()
    lst.close()
    assert resp.startswith(b"HTTP/1.1 403"), f"no answer after one transient accept error: {resp!r}"

def test_non_global_multicast_and_reserved_dns_results_are_refused(monkeypatch):
    real_getaddrinfo = proxy.socket.getaddrinfo
    real_connect = socket.socket.connect
    dialed = []

    def fake_getaddrinfo(host, port, *args, **kwargs):
        if host == "non-global.example":
            return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::ffff:0:127.0.0.1", port, 0, 0))]
        return real_getaddrinfo(host, port, *args, **kwargs)

    def spy_connect(self, addr):
        if isinstance(addr, tuple) and addr[0] == "::ffff:0:127.0.0.1":
            dialed.append(addr)
            raise ConnectionRefusedError("would have dialed non-global address")
        return real_connect(self, addr)

    monkeypatch.setattr(proxy.socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(socket.socket, "connect", spy_connect)

    with Proxy() as p:
        p.grant("non-global.example:443")
        with pytest.raises(ConnectionError, match="403"):
            p.connect_to("non-global.example:443")

    assert dialed == []
    for non_global in ("::ffff:0:127.0.0.1", "::127.0.0.1", "224.0.0.1", "ff02::1"):
        assert not proxy._public(non_global), f"{non_global} was treated as public"

def test_lease_does_not_treat_grant_expired_during_connect_as_fresh(monkeypatch):
    monkeypatch.setattr(proxy, "RECHECK", 0.15)
    up = Upstream()
    try:
        with Proxy() as p:
            dest = f"127.0.0.1:{up.port}"
            p.grant(dest)
            real_execute = p.adapter.execute

            def slow_execute(kind, destination, payload, **kw):
                p.sb.grants.clear()  # TTL expires during DNS/TCP dial (no Sandbox.revoked bump)
                time.sleep(0.2)      # dial finishes > RECHECK after the grant was checked
                return real_execute(kind, destination, payload, **kw)

            monkeypatch.setattr(p.adapter, "execute", slow_execute)
            with p.connect_to(dest) as s:
                s.settimeout(1.0)
                s.sendall(b"one")
                first = s.recv(100)
                assert first == b""
    finally:
        up.close()

def test_revocation_during_backpressured_send_reports_cut_true(monkeypatch):
    monkeypatch.setattr(proxy, "RECHECK", 0.2)
    srv = socket.create_server(("127.0.0.1", 0))
    port = srv.getsockname()[1]

    def flood():
        try:
            conn, _ = srv.accept()
        except OSError:
            return
        with conn:
            try:
                conn.sendall(b"y" * (16 * 1024 * 1024))
            except OSError:
                pass

    threading.Thread(target=flood, daemon=True).start()
    try:
        with Proxy() as p:
            dest = f"127.0.0.1:{port}"
            p.grant(dest)
            with p.connect_to(dest) as s:
                time.sleep(0.05)   # pump(b->a) is now blocked inside a.sendall(chunk)
                s.sendall(b"a")    # refresh pump(a->b)'s recv timeout so a.sendall times out first
                time.sleep(0.03)
                p.revoke()         # grant revoked while tunnel is live
                for _ in range(40):
                    if p.closed:
                        break
                    time.sleep(0.05)
                assert p.closed and p.closed[-1][3] is True
    finally:
        srv.close()

def test_aborted_client_before_200_still_closes_upstream_and_reports_cut(monkeypatch):
    up = Upstream()
    dialed = threading.Event()
    proceed = threading.Event()
    try:
        with Proxy() as p:
            dest = f"127.0.0.1:{up.port}"
            p.grant(dest)
            real_execute = p.adapter.execute

            def synced_execute(kind, destination, payload, **kw):
                real_execute(kind, destination, payload, **kw)
                dialed.set()
                proceed.wait(2.0)

            monkeypatch.setattr(p.adapter, "execute", synced_execute)
            s = socket.create_connection(("127.0.0.1", p.port), timeout=2.0)
            s.sendall(f"CONNECT {dest} HTTP/1.1\r\n\r\n".encode())
            assert dialed.wait(2.0)
            p.revoke()  # revoked after upstream connected
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            s.close()   # TCP RST so conn.sendall(200) raises OSError
            proceed.set()
            time.sleep(0.15)
            assert p.closed == [(dest, 0, 0, True)]
    finally:
        up.close()


def test_a_tunnel_stops_at_its_grant_expiry_without_waiting_for_a_recheck(monkeypatch):
    """A grant running out is no revocation event: the lease cuts at the expiry itself, not up to RECHECK later."""
    monkeypatch.setattr(proxy, "RECHECK", 10.0)  # no periodic re-check during this test
    up = Upstream()
    with Proxy() as p:
        dest = f"127.0.0.1:{up.port}"
        p.grant(dest, ttl=0.6)
        s = p.connect_to(dest)
        s.settimeout(2)
        s.sendall(b"one")
        assert s.recv(100) == b"echo:one"
        time.sleep(0.8)  # the grant has expired; nothing was revoked
        try:
            s.sendall(b"two")
            reply = s.recv(100)
        except OSError:
            reply = b""
        s.close()
        assert reply == b"", f"a chunk crossed after the grant expired: {reply!r}"
    up.close()
