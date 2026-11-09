"""The door's CONNECT proxy: the only route out of a networked box.

The box's network namespace has a down-to-loopback stack and no resolver. The door places a TCP
listener inside it (127.0.0.1:PORT); each CONNECT is an egress `net:<server>` to `host:port`, allowed
only by an owner grant for that exact target. Names resolve door-side, after the grant; a name that
resolves to a non-public address is refused (only an owner-granted IP literal may be private).
CEILING: TLS means the door sees the host, not the payload: a destination allowlist, not a label
check. Plain-HTTP (absolute-URI) proxying is refused: CONNECT only."""

from __future__ import annotations

import ipaddress
import os
import socket
import subprocess
import sys
import threading
import time
from typing import Callable

from .box import PROXY_PORT as PORT
MAX_HEAD = 8192
MAX_CONNECTIONS = 32
HEAD_TIMEOUT = 10.0
IDLE_TIMEOUT = 300.0
CONNECT_TIMEOUT = 10.0
DNS_TIMEOUT = 5.0
RESOLVERS = 4  # per server; a lookup past its deadline keeps its resolver until it returns
RECHECK = 0.5  # a live tunnel re-checks its authorization at least this often, and on every revocation

Gate = Callable[[str], "tuple[socket.socket, Lease] | str"]


class NetError(RuntimeError):
    pass


def target(authority: str) -> str | None:
    """Normal form 'host:port' (lowercase IDNA name, or IP literal; IPv6 in brackets), else None."""
    host, sep, port = authority.rpartition(":")
    if not sep or not port.isascii() or not port.isdigit() or not 0 < int(port) < 65536 or "@" in host:
        return None
    if host.startswith("[") and host.endswith("]"):
        try:
            return f"[{ipaddress.IPv6Address(host[1:-1]).compressed}]:{int(port)}"
        except ValueError:
            return None
    try:
        return f"{ipaddress.IPv4Address(host)}:{int(port)}"
    except ValueError:
        pass
    try:
        name = host.rstrip(".").encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError):
        return None
    labels = name.split(".")
    if not name or len(name) > 253 or not all(
            0 < len(x) < 64 and x.replace("-", "").isalnum() and x.isascii() and not x.startswith("-") for x in labels):
        return None
    return f"{name}:{int(port)}"


def _literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


_NAT64 = ipaddress.IPv6Network("64:ff9b::/96")  # global as a prefix, but it embeds any IPv4 address


def _public(addr: str) -> bool:
    ip = ipaddress.ip_address(addr.split("%")[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    elif isinstance(ip, ipaddress.IPv6Address) and ip in _NAT64:
        ip = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return ip.is_global  # 6to4 and Teredo are not global: refused outright


class NetAdapter:
    """The door's adapter for `net:<server>`: resolves and connects, only inside a proxy request."""

    def __init__(self) -> None:
        self._local = threading.local()
        self._resolvers = threading.BoundedSemaphore(RESOLVERS)

    def _lookup(self, host: str, port: int) -> list:
        """getaddrinfo under a deadline. Past it the CONNECT is refused (freeing its connection slot)
        while the lookup finishes in the background, so stalled lookups never exceed RESOLVERS."""
        if _literal(host):
            return socket.getaddrinfo(host, port, type=socket.SOCK_STREAM, flags=socket.AI_NUMERICHOST)
        out: list = []
        done = threading.Event()

        def run() -> None:
            try:
                out.append(socket.getaddrinfo(host, port, type=socket.SOCK_STREAM))
            except Exception as exc:
                out.append(exc)
            finally:
                self._resolvers.release()
                done.set()

        worker = threading.Thread(target=run, daemon=True)
        if not self._resolvers.acquire(blocking=False):
            raise NetError(f"cannot resolve {host}: every resolver is busy")
        try:
            worker.start()
        except BaseException:
            self._resolvers.release()
            raise
        if not done.wait(DNS_TIMEOUT):
            raise NetError(f"cannot resolve {host}: no answer within {DNS_TIMEOUT:g} s")
        if isinstance(out[0], Exception):
            raise out[0]
        return out[0]

    def begin(self) -> None:
        self._local.pending, self._local.sock = True, None

    def take(self) -> socket.socket | None:
        sock, self._local.pending, self._local.sock = getattr(self._local, "sock", None), False, None
        return sock

    def execute(self, kind: str, destination: str, payload: object, **_: object) -> None:
        if not getattr(self._local, "pending", False):  # a hands proposal or a stale approval: no socket
            raise NetError("network egress only happens inside a proxy request")
        host, _, port = destination.rpartition(":")
        try:
            infos = self._lookup(host.strip("[]"), int(port))
        except OSError as exc:
            raise NetError(f"cannot resolve {host}: {exc}") from None
        if not infos:
            raise NetError(f"{host} has no addresses")
        if not _literal(host) and not all(_public(i[4][0]) for i in infos):  # names never reach private space
            raise NetError(f"{host} resolves to a non-public address")
        family, stype, proto, _, addr = infos[0]  # connect to what was checked; never re-resolve
        sock = socket.socket(family, stype, proto)
        sock.settimeout(CONNECT_TIMEOUT)
        try:
            sock.connect(addr)
        except OSError as exc:
            sock.close()
            raise NetError(f"connect {destination}: {exc}") from None
        self._local.sock = sock


class Lease:
    """A tunnel's authorization. A tunnel lives only while a fresh check would still pass: checked
    before every forwarded chunk, at most RECHECK old, and immediately after any revocation. After a
    revocation at most one already-checked chunk per direction is written; an idle tunnel is cut
    within RECHECK."""

    def __init__(self, sandbox: object, kind: str, dest: str, seen: int) -> None:
        """`seen`: the revocation count read before the connection was authorized, so a revocation
        landing between authorization and this lease is caught by the first ok()."""
        self.sb, self.kind, self.dest = sandbox, kind, dest
        self._seen, self._at, self._ok = seen, time.monotonic(), True
        self._lock = threading.Lock()  # both pumps ask; a check in progress is never read as passed

    def ok(self) -> bool:
        with self._lock:
            now, revoked = time.monotonic(), self.sb.revoked  # type: ignore[attr-defined]
            if self._ok and (revoked != self._seen or now - self._at >= RECHECK):
                self._ok = self.sb.still_allowed(self.kind, self.dest)  # type: ignore[attr-defined]
                self._seen, self._at = revoked, now
            return self._ok


def gate(sandbox: object, kind: str, adapter: NetAdapter) -> Gate:
    """Authorize one CONNECT through the sandbox's door; the connected socket and its lease, or why not."""

    def check(dest: str) -> tuple[socket.socket, Lease] | str:
        seen = sandbox.revoked  # type: ignore[attr-defined]
        adapter.begin()
        try:
            out = sandbox.connect(kind, dest)  # type: ignore[attr-defined]
        finally:
            sock = adapter.take()
        if out.status != "sent":
            if sock is not None:
                sock.close()
            return out.reason
        return (sock, Lease(sandbox, kind, dest, seen)) if sock is not None else "no connection"

    return check


def listen_in(pid: int) -> socket.socket:
    """A listener on 127.0.0.1:PORT inside the box's network namespace, made by a short helper that
    joins the box's user and network namespaces (not its mounts) and hands the fd back."""
    ours, theirs = socket.socketpair()
    helper = ("import socket, sys\n"
              "s = socket.socket(); s.bind(('127.0.0.1', %d)); s.listen(%d)\n"
              "socket.send_fds(socket.socket(fileno=int(sys.argv[1])), [b'L'], [s.fileno()])\n") % (PORT, MAX_CONNECTIONS)
    try:
        run = subprocess.run(["nsenter", "-t", str(pid), "-U", "-n", "--preserve-credentials",
                              os.path.realpath(sys.executable), "-c", helper, str(theirs.fileno())],
                             pass_fds=(theirs.fileno(),), capture_output=True, timeout=10)
        theirs.close()
        if run.returncode != 0:
            raise NetError(f"cannot place the proxy listener: {run.stderr.decode(errors='replace')[-200:]}")
        ours.settimeout(5)
        _, fds, _, _ = socket.recv_fds(ours, 1, 1)
    except (OSError, subprocess.SubprocessError) as exc:
        raise NetError(f"cannot place the proxy listener: {exc!r}") from None
    finally:
        ours.close()
    if len(fds) != 1:
        raise NetError("proxy listener was not handed back")
    return socket.socket(fileno=fds[0])


def serve(listener: socket.socket, check: Callable[[], Gate | None], on_close: Callable[[str, int, int, bool], None],
          slots: threading.BoundedSemaphore) -> None:
    """Accept until the listener closes. `check()` returns the current gate (None: not wired yet).
    `slots` is the server's connection budget, shared across relaunches of its box."""

    def loop() -> None:
        while True:
            try:
                conn, _ = listener.accept()
            except OSError:
                return
            if not slots.acquire(blocking=False):
                _reply(conn, 503, "too many connections")
                continue
            try:
                threading.Thread(target=_handle, args=(conn, check(), on_close, slots), daemon=True).start()
            except Exception:  # no handler: give the slot back and keep accepting
                slots.release()
                _reply(conn, 503, "proxy busy")

    threading.Thread(target=loop, daemon=True).start()


def _reply(conn: socket.socket, code: int, reason: str) -> None:
    try:
        conn.sendall(f"HTTP/1.1 {code} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode())
    except OSError:
        pass
    conn.close()


def _head(conn: socket.socket) -> bytes | None:
    conn.settimeout(HEAD_TIMEOUT)
    buf = b""
    while b"\r\n\r\n" not in buf:
        try:
            chunk = conn.recv(MAX_HEAD + 1 - len(buf))
        except OSError:
            return None
        if not chunk:
            return None
        buf += chunk
        if len(buf) > MAX_HEAD:
            return None
    return buf


def _handle(conn: socket.socket, check: Gate | None, on_close: Callable[[str, int, int, bool], None],
            slots: threading.BoundedSemaphore) -> None:
    try:
        head = _head(conn)
        if head is None:
            return _reply(conn, 400, "bad request")
        head, _, early = head.partition(b"\r\n\r\n")
        parts = head.split(b"\r\n", 1)[0].decode("latin-1").split(" ")
        if len(parts) != 3 or parts[0] != "CONNECT" or not parts[2].startswith("HTTP/1."):
            return _reply(conn, 405, "CONNECT only")
        dest = target(parts[1])
        if dest is None:
            return _reply(conn, 400, "bad target")
        if check is None:
            return _reply(conn, 403, "proxy not wired to a door")
        granted = check(dest)
        if isinstance(granted, str):
            return _reply(conn, 403, "refused by the door")
        upstream, lease = granted
        conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        on_close(dest, *_splice(conn, upstream, early, lease))
    finally:
        slots.release()


def _splice(a: socket.socket, b: socket.socket, early: bytes, lease: Lease) -> tuple[int, int, bool]:
    """Copy both ways until either side closes, idles out, or the lease lapses (then both are cut).
    Returns (bytes box->out, bytes out->box, cut)."""
    counts, cut = [0, 0], threading.Event()
    for s in (a, b):
        s.settimeout(RECHECK)
    try:
        if early and lease.ok():  # a client that sent bytes before our 200
            b.sendall(early)
            counts[0] = len(early)
    except OSError:
        pass

    def pump(src: socket.socket, dst: socket.socket, i: int) -> None:
        idle = 0.0
        try:
            while not cut.is_set():
                if not lease.ok():
                    cut.set()
                    break
                try:
                    chunk = src.recv(65536)
                except socket.timeout:
                    idle += RECHECK
                    if idle >= IDLE_TIMEOUT:
                        break
                    continue
                if not chunk:
                    break
                if not lease.ok():  # the check right before anything crosses
                    cut.set()
                    break
                dst.sendall(chunk)
                counts[i] += len(chunk)
                idle = 0.0
        except OSError:
            pass
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    t = threading.Thread(target=pump, args=(b, a, 1), daemon=True)
    t.start()
    pump(a, b, 0)
    t.join()
    a.close()
    b.close()
    return counts[0], counts[1], cut.is_set()
