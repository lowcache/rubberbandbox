"""Host-side harness for rubberbandbox/proxy.py tests: the real serve/_handle/_splice/gate/NetAdapter/Lease,
with a fake sandbox instead of a box (no bwrap). For box-level tests use test_proxy.py's
`networked()` / `via()` / `upstream` instead.

    with Proxy() as p:                      # proxy listening on 127.0.0.1:p.port
        p.grant("127.0.0.1:%d" % up.port)   # owner grant for an exact target
        s = p.connect_to("127.0.0.1:%d" % up.port)   # socket after a 200, or raises with the status line
        p.revoke()                          # grant ended + revoked counter bumped (like Sandbox.owner_end)
    p.closed  -> [(dest, up_bytes, down_bytes, cut)], p.calls -> every target the door was asked about
"""
import socket
import threading
import time
from types import SimpleNamespace

from rubberbandbox import proxy


class FakeSandbox:
    """Mimics Sandbox.connect / still_allowed / revoked: a grant set checked per exact target."""

    def __init__(self, adapter):
        self.adapter, self.grants, self.revoked, self.calls, self.lock = adapter, set(), 0, [], threading.Lock()
        self.expires, self.clock = {}, time.time  # dest -> grant expiry, like GrantBook's expires_at

    def connect(self, kind, dest):
        self.calls.append(dest)
        if dest not in self.grants:
            return SimpleNamespace(status="refused", reason="no grant covers this target")
        try:
            self.adapter.execute(kind, dest, ())
        except Exception as exc:
            return SimpleNamespace(status="failed", reason=repr(exc))
        return SimpleNamespace(status="sent", reason="grant")

    def still_allowed(self, kind, dest):
        return dest in self.grants and self.clock() < self.expires.get(dest, float("inf"))

    def grant_expiry(self, kind, dest):
        return self.expires.get(dest) if dest in self.grants else None


class Proxy:
    def __init__(self, slots=proxy.MAX_CONNECTIONS):
        self.adapter = proxy.NetAdapter()
        self.sb = FakeSandbox(self.adapter)
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        self.slots = threading.BoundedSemaphore(slots)
        self.closed = []
        self.gate = proxy.gate(self.sb, "net:test", self.adapter)

    def __enter__(self):
        proxy.serve(self.listener, lambda: self.gate, lambda *a: self.closed.append(a), self.slots)
        return self

    def __exit__(self, *exc):
        self.listener.close()

    calls = property(lambda self: self.sb.calls)

    def grant(self, dest, ttl=None):
        self.sb.grants.add(dest)
        if ttl is not None:
            self.sb.expires[dest] = time.time() + ttl

    def revoke(self, dest=None):
        self.sb.grants.discard(dest) if dest else self.sb.grants.clear()
        self.sb.revoked += 1

    def raw(self, request: bytes, timeout=3.0) -> tuple[socket.socket, bytes]:
        """Send raw bytes; return (socket, first response bytes)."""
        s = socket.create_connection(("127.0.0.1", self.port), timeout=timeout)
        s.sendall(request)
        return s, s.recv(4096)

    def connect_to(self, dest, early=b""):
        s, resp = self.raw(f"CONNECT {dest} HTTP/1.1\r\nHost: {dest}\r\n\r\n".encode() + early)
        if not resp.startswith(b"HTTP/1.1 200"):
            s.close()
            raise ConnectionError(resp.split(b"\r\n")[0].decode())
        return s


class Upstream:
    """A host echo server: replies b'echo:' + each chunk until the client closes."""

    def __init__(self):
        self.srv = socket.create_server(("127.0.0.1", 0))
        self.port, self.hits = self.srv.getsockname()[1], []
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            self.hits.append(1)
            threading.Thread(target=self._echo, args=(conn,), daemon=True).start()

    @staticmethod
    def _echo(conn):
        with conn:
            while data := conn.recv(4096):
                conn.sendall(b"echo:" + data)

    def close(self):
        self.srv.close()
