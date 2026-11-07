"""MCP over stdio: a stdlib JSON-RPC client, a server's tools as a channel-less pack, and the
door-side adapter. Every call is egress to the server's operator.

Server identity comes from owner config (name, launch command, box), never from serverInfo. A
local server runs in an allowlist box (see box.py): no network, no host env, staged writes."""

from __future__ import annotations

import itertools
import json
import os
import queue
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Iterable, Mapping, Sequence

from . import box as boxes
from .box import Box, PathRejected
from .core import ManifestPack, Mount, Rules, ToolAdapter, ToolDescriptor, conservative, generated_schema, prefix_cluster

PROTOCOL = "2025-06-18"
SUPPORTED = frozenset({"2025-06-18", "2025-03-26", "2024-11-05"})
MAX_MESSAGE = 16 << 20
MAX_PAGES = 64


class McpError(RuntimeError):
    pass


@dataclass(frozen=True)
class ServerConfig:
    """Owner config for one local server. The server gets only `env`, never the owner's environment.
    `cwd` is a path inside the box. CEILING: no network exception yet (the door CONNECT proxy)."""

    name: str
    command: tuple[str, ...]
    env: Mapping[str, str] = field(default_factory=dict)
    cwd: str = "/"
    timeout: float = 30.0
    box: Box = field(default_factory=Box)

    @property
    def endpoint(self) -> str:
        """Hashed into every tool's security view: a changed launch or a wider box is a loosening."""
        return "stdio:" + json.dumps({"command": list(self.command), "env": dict(sorted(self.env.items())),
                                      "cwd": self.cwd, "network": False, **self.box.identity()})


class McpClient:
    def __init__(self, cfg: ServerConfig) -> None:
        if "/" in cfg.name or not cfg.name:
            raise ValueError(f"bad server name {cfg.name!r}")
        self.cfg = cfg
        self.tools_changed = False  # set by notifications/tools/list_changed; the owner re-observes
        self.generation = 0  # bumps on every launch: paths canonicalised in an older box are stale
        self._ids = itertools.count(1)
        self._lock = threading.Lock()
        self._proc: subprocess.Popen | None = None
        self._launch()

    def _launch(self) -> None:
        self.generation += 1
        self._inbox: queue.Queue[dict | Exception] = queue.Queue()
        r, w = os.pipe()
        try:
            args = boxes.launch_args(self.cfg.command, self.cfg.env, self.cfg.cwd, self.cfg.box, w)
            self._proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                          stderr=subprocess.DEVNULL, pass_fds=(w,), env={})
            os.close(w)
            w = -1
            self.pid = boxes.info_pid(r)
        except BaseException:
            if w >= 0:
                os.close(w)
            os.close(r)
            self.close()
            raise
        os.close(r)
        threading.Thread(target=self._read, args=(self._proc, self._inbox), daemon=True).start()
        try:
            self._handshake()
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _read(proc: subprocess.Popen, inbox: queue.Queue) -> None:
        assert proc.stdout is not None
        while True:
            line = proc.stdout.readline(MAX_MESSAGE + 1)
            if not line:
                inbox.put(McpError("server closed its stdout"))
                return
            if len(line) > MAX_MESSAGE:
                inbox.put(McpError("message too large"))
                return
            try:
                msg = json.loads(line)
            except ValueError:
                msg = None
            if not isinstance(msg, dict):
                inbox.put(McpError("non-JSON-RPC output on stdout"))
                return
            inbox.put(msg)

    def _send(self, msg: dict) -> None:
        assert self._proc is not None and self._proc.stdin is not None
        self._proc.stdin.write(json.dumps(msg).encode() + b"\n")
        self._proc.stdin.flush()

    def request(self, method: str, params: Mapping[str, object] | None = None) -> dict:
        with self._lock:
            rid = next(self._ids)
            self._send({"jsonrpc": "2.0", "id": rid, "method": method, "params": dict(params or {})})
            deadline = time.monotonic() + self.cfg.timeout
            while True:
                try:
                    msg = self._inbox.get(timeout=max(0.0, deadline - time.monotonic()))
                except queue.Empty:
                    raise McpError(f"{method}: no response in {self.cfg.timeout}s") from None
                if isinstance(msg, Exception):
                    self._inbox.put(msg)  # sticky: the stream is dead for every later request
                    raise msg
                if "method" in msg:
                    self._server_message(msg)
                    continue
                if msg.get("id") != rid:
                    continue  # a late reply to a request that already timed out
                if "error" in msg:
                    raise McpError(f"{method}: {msg['error']!r}")
                result = msg.get("result")
                if not isinstance(result, dict):
                    raise McpError(f"{method}: malformed result")
                return result

    def _server_message(self, msg: dict) -> None:
        """We declare no client capabilities: sampling, elicitation and roots are all refused."""
        if msg.get("method") == "notifications/tools/list_changed":
            self.tools_changed = True
        if "id" in msg:
            self._send({"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32601, "message": "not supported"}})

    def _handshake(self) -> None:
        r = self.request("initialize", {"protocolVersion": PROTOCOL, "capabilities": {},
                                        "clientInfo": {"name": "rubberbandbox", "version": "0"}})
        if r.get("protocolVersion") not in SUPPORTED:
            raise McpError(f"unsupported protocol version {r.get('protocolVersion')!r}")
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def list_tools(self) -> list[ToolDescriptor]:
        """The server's tools, named under the owner's server name. Malformed entries are dropped."""
        out: dict[str, ToolDescriptor] = {}
        cursor = None
        for _ in range(MAX_PAGES):
            r = self.request("tools/list", {"cursor": cursor} if cursor else {})
            for t in r.get("tools", []) if isinstance(r.get("tools"), list) else []:
                if not (isinstance(t, dict) and isinstance(t.get("name"), str) and isinstance(t.get("inputSchema"), dict)):
                    continue
                if t["name"] in out:
                    raise McpError(f"tool {t['name']!r} listed twice")
                ann = t.get("annotations")
                desc = t.get("description")
                out[t["name"]] = ToolDescriptor(self.cfg.name, t["name"], t["inputSchema"],
                                                ann if isinstance(ann, dict) else {},
                                                desc if isinstance(desc, str) else "")
            cursor = r.get("nextCursor")
            if not isinstance(cursor, str):
                self.tools_changed = False
                return list(out.values())
        raise McpError("tools/list did not terminate")

    def call(self, name: str, arguments: Mapping[str, object]) -> str:
        r = self.request("tools/call", {"name": name, "arguments": dict(arguments)})
        text = _render(r)
        if r.get("isError") is True:
            raise McpError(f"tool error: {text[:500]}")
        return text

    def close(self) -> None:
        proc, self._proc = self._proc, None
        if proc is None:
            return
        try:
            if proc.stdin:
                proc.stdin.close()
            proc.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            proc.kill()
            proc.wait()

    # ---- the box ----

    def resolve(self, path: str) -> str:
        """Canonical path in this box's view. A stopped box fails closed (no host fallback)."""
        if self._proc is None or self._proc.poll() is not None:
            raise PathRejected("box is not running")
        return boxes.resolve(f"/proc/{self.pid}/root", path)

    def staged(self) -> list[boxes.Staged]:
        return boxes.staged(self.cfg.box)

    def commit(self) -> list[boxes.Staged]:
        """Stop the server, apply its staged writes to the host folders, start it again."""
        self.close()
        try:
            return boxes.commit(self.cfg.box)
        finally:
            self._launch()

    def discard(self) -> None:
        self.close()
        try:
            boxes.discard(self.cfg.box)
        finally:
            self._launch()

    def __enter__(self) -> McpClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _render(result: Mapping[str, object]) -> str:
    """A call result as stored output text: the content blocks, else structured content."""
    blocks = result.get("content") if isinstance(result.get("content"), list) else []
    if not blocks and "structuredContent" in result:
        return json.dumps(result["structuredContent"], sort_keys=True)
    return "\n".join(b["text"] if isinstance(b, dict) and b.get("type") == "text" and isinstance(b.get("text"), str)
                     else json.dumps(b, sort_keys=True) for b in blocks)  # type: ignore[union-attr]


def _coerce(schema: object, data: str) -> object:
    """Values cross the door as strings; non-string args are carried as JSON text."""
    t = schema.get("type") if isinstance(schema, Mapping) else None
    if t == "string" or (isinstance(t, list) and "string" in t):
        return data
    try:
        return json.loads(data)
    except ValueError:
        return data


class McpAdapter:
    """The door's handle on one server. Only named calls (bound by the registry) go through."""

    def __init__(self, client: McpClient, tools: Iterable[ToolDescriptor]) -> None:
        self.client = client
        self._props = {d.kind: d.input_schema.get("properties", {}) for d in tools}

    def execute(self, kind: str, destination: str, payload: Sequence[str], control: Sequence[str] | None = None,
                args: Mapping[str, str] | None = None) -> str:
        if args is None or kind not in self._props:
            raise McpError(f"{kind}: not a named call to this server")
        props = self._props[kind] if isinstance(self._props[kind], Mapping) else {}
        return self.client.call(kind.partition("/")[2], {a: _coerce(props.get(a), v) for a, v in args.items()})


def mount(client: McpClient) -> tuple[Mount, dict[str, ToolAdapter], list[ToolDescriptor]]:
    """A server's current tools as a channel-less pack, every tool at the conservative default
    until the owner approves a manifest. CEILING: tools added later are not mounted until restart."""
    tools = client.list_tools()
    name = client.cfg.name
    pack = ManifestPack(name, generated_schema(name, ()), [conservative(d.kind, _args(d)) for d in tools],
                        (), Rules(), prefix_cluster("mcp"))
    adapter = McpAdapter(client, tools)
    return Mount(pack, None), {d.kind: adapter for d in tools}, tools


def _args(d: ToolDescriptor) -> list[str]:
    props = d.input_schema.get("properties")
    return [str(a) for a in props] if isinstance(props, Mapping) else []
