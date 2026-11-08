"""Frozen, versioned manifests for live tools: security hashing, bones validation, and the
loosening diff. The diff baseline is always the last owner-approved manifest; auto-accepted
versions never move it."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field, replace
from typing import TYPE_CHECKING, Iterable, Mapping, Protocol

from .labels import OWNER_PUBLIC, Value
from .manifest import ToolManifest, compile_kind, conservative
from .types import Egress, KindSpec

if TYPE_CHECKING:
    from .sandbox import Sandbox

# Unannotated means the unsafe value; a flip toward it is a loosening.
HINT_DEFAULTS = {"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True}
OVERRIDABLE = frozenset({"annotations", "destination_like", "path_like"})  # owner may override; the rest are structural
PATH_MOVED = "path moved since approval"
_BOX_LISTS = ("folders", "ro_paths", "sockets")  # box allowlists: removing entries is a tightening

_RANK = {"read-public": 0, "read-private": 1, "write-staged": 2, "send": 3, "publish": 4, "spend": 5, "delete": 5}
_PROSE = frozenset({"description", "title", "examples", "$comment", "$schema", "$id"})
_DATA = frozenset({"enum", "const", "default"})
_MAPS = frozenset({"properties", "patternProperties", "$defs", "definitions", "dependentSchemas"})
_UPPER = ("maxLength", "maxItems", "maxProperties", "maximum", "exclusiveMaximum")
_LOWER = ("minLength", "minItems", "minProperties", "minimum", "exclusiveMinimum")
_EXACT = ("pattern", "format", "const", "multipleOf")
_KNOWN = frozenset({"type", "enum", *_UPPER, *_LOWER, *_EXACT})
_DEST_FORMATS = frozenset({"uri", "uri-reference", "iri", "url", "email", "idn-email", "hostname",
                           "idn-hostname", "ipv4", "ipv6"})
_PATH_NAMES = re.compile(r"(^|_)(path|paths|file|files|filename|dir|dirs|directory|folder|source|src|"
                         r"destination|dest|dst|target)($|_)")
_DEST_NAMES = re.compile(r"(^|_)(url|uri|to|cc|bcc|recipients?|email|phone|webhook|endpoint|host|hostname|"
                         r"address|callback|destination|dest)($|_)")


@dataclass(frozen=True)
class ToolDescriptor:
    """A tool as its server reports it right now. Untrusted, annotations included."""

    server: str
    name: str
    input_schema: Mapping[str, object]
    annotations: Mapping[str, object] = field(default_factory=dict)
    description: str = ""  # prose: never hashed

    @property
    def kind(self) -> str:
        return f"{self.server}/{self.name}"


class Resolver(Protocol):
    """A box's view of its own filesystem (the MCP client of a boxed local server)."""

    generation: int  # changes whenever the box restarts

    def resolve(self, path: str) -> str:
        """The canonical path; raises ValueError on a reject or a stopped box."""
        ...


@dataclass(frozen=True)
class Problem:
    rule: str  # name | args | annotations | read_with_payload | destination_like
    detail: str


class BonesError(ValueError):
    def __init__(self, problems: list[Problem]) -> None:
        super().__init__("; ".join(f"{p.rule}: {p.detail}" for p in problems))
        self.problems = problems


@dataclass(frozen=True)
class Change:
    added: tuple[str, ...] = ()  # new args: refused until approved
    loosened: tuple[str, ...] = ()  # an existing field got looser: the whole tool reverts
    other: tuple[str, ...] = ()  # neutral or tightening: auto-accepted

    @property
    def outcome(self) -> str:
        if self.loosened:
            return "loosened"
        if self.added:
            return "additive"
        return "accepted" if self.other else "unchanged"


# ---- the security view: what is hashed ----


def _schema(x: object) -> object:
    """Drop prose keywords at schema level only; arg names and data values are kept verbatim."""
    if isinstance(x, list):
        return [_schema(v) for v in x]
    if not isinstance(x, Mapping):
        return x
    out: dict[str, object] = {}
    for k, v in x.items():
        if k in _PROSE:
            continue
        if k in _DATA:
            out[k] = v
        elif k in _MAPS and isinstance(v, Mapping):
            out[k] = {str(n): _schema(s) for n, s in v.items()}
        else:
            out[k] = _schema(v)
    return out


def security_view(desc: ToolDescriptor, endpoint: str) -> dict:
    """The security-relevant fields: owner-configured endpoint, arg schemas, required set, hints.
    Description prose is excluded: the planner only ever reads frozen manifest text."""
    schema = desc.input_schema if isinstance(desc.input_schema, Mapping) else {}
    props = schema.get("properties")
    props = props if isinstance(props, Mapping) else {}
    required = schema.get("required")
    hints = desc.annotations if isinstance(desc.annotations, Mapping) else {}
    return {
        "endpoint": endpoint,
        "args": {str(n): _schema(s) for n, s in props.items()},
        "required": sorted({r for r in required if isinstance(r, str)}) if isinstance(required, list) else [],
        "hints": {k: hints[k] if isinstance(hints.get(k), bool) else d for k, d in HINT_DEFAULTS.items()},
        "extra": _schema({k: v for k, v in schema.items() if k not in ("properties", "required", "type")}),
    }


def view_hash(view: dict) -> str:
    return hashlib.sha256(json.dumps(view, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


# ---- the diff ----


def _types(s: Mapping) -> set[str]:
    t = s.get("type")
    if isinstance(t, str):
        return {t}
    if isinstance(t, list) and all(isinstance(x, str) for x in t):
        return set(t)
    return {"*"}


def _num(x: object) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def _canon(x: object) -> str:
    return json.dumps(x, sort_keys=True)


def _widened(a: Mapping, b: Mapping) -> str | None:
    """Why schema `b` accepts something `a` did not, or None. Unknown keywords compare by equality."""
    ta, tb = _types(a), _types(b)
    if "number" in ta:
        tb = tb - {"integer"}
    if "*" not in ta and not tb <= ta:
        return f"type widened {sorted(ta)} -> {sorted(_types(b))}"
    if "enum" in a:
        old = {_canon(v) for v in a["enum"]} if isinstance(a["enum"], list) else set()
        new = b.get("enum")
        if not isinstance(new, list) or not {_canon(v) for v in new} <= old:
            return "enum widened or dropped"
    for k in _UPPER:
        if k in a and not (_num(a[k]) and _num(b.get(k)) and b[k] <= a[k]):
            return f"{k} raised or dropped"
    for k in _LOWER:
        if k in a and not (_num(a[k]) and _num(b.get(k)) and b[k] >= a[k]):
            return f"{k} lowered or dropped"
    for k in _EXACT:
        if k in a and _canon(b.get(k)) != _canon(a[k]):
            return f"{k} changed or dropped"
    # CEILING: nested and unrecognised keywords compare by equality, so some narrowings read as loosenings
    if _canon({k: v for k, v in a.items() if k not in _KNOWN}) != _canon({k: v for k, v in b.items() if k not in _KNOWN}):
        return "nested schema changed"
    return None


def _narrowed(old: str, new: str) -> bool:
    """A box that only lost allowlist entries (folders, read-only paths, sockets) is tighter."""
    try:
        a, b = json.loads(old.removeprefix("stdio:")), json.loads(new.removeprefix("stdio:"))
    except ValueError:
        return False
    if not (isinstance(a, dict) and isinstance(b, dict)) or {k: v for k, v in a.items() if k not in _BOX_LISTS} != \
            {k: v for k, v in b.items() if k not in _BOX_LISTS}:
        return False
    for k in _BOX_LISTS:
        x, y = a.get(k, []), b.get(k, [])
        pairs = (lambda v: {_canon(i) for i in (v.items() if isinstance(v, dict) else v)})
        if type(x) is not type(y) or not pairs(y) <= pairs(x):
            return False
    return True


def diff(old: dict, new: dict, roles: Mapping[str, str]) -> Change:
    added: list[str] = []
    loose: list[str] = []
    other: list[str] = []
    if old["endpoint"] != new["endpoint"]:
        (other if _narrowed(old["endpoint"], new["endpoint"]) else loose).append("endpoint changed")
    for hint, unsafe in HINT_DEFAULTS.items():
        a, b = old["hints"][hint], new["hints"][hint]
        if a != b:
            (loose if b == unsafe else other).append(f"{hint}: {a} -> {b}")
    if _canon(old["extra"]) != _canon(new["extra"]):
        loose.append("schema-level keywords changed")
    for arg in sorted(old["args"].keys() | new["args"].keys()):
        steers = roles.get(arg, "payload") != "payload"  # control and destination args steer the call
        if arg not in new["args"]:
            (loose if steers else other).append(f"{arg}: removed")
            continue
        if arg not in old["args"]:
            added.append(arg)
            continue
        why = _widened(old["args"][arg], new["args"][arg])
        if why:
            loose.append(f"{arg}: {why}")
        elif _canon(old["args"][arg]) != _canon(new["args"][arg]):
            other.append(f"{arg}: narrowed")
        was, now = arg in old["required"], arg in new["required"]
        if was and not now:
            (loose if steers else other).append(f"{arg}: no longer required")
        elif now and not was:
            other.append(f"{arg}: now required")
    return Change(tuple(added), tuple(loose), tuple(other))


# ---- bones validation of a drafted manifest ----


def _destination_like(arg: str, schema: object) -> bool:
    snake = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", arg).lower()
    fmt = schema.get("format") if isinstance(schema, Mapping) else None
    return bool(_DEST_NAMES.search(snake)) or fmt in _DEST_FORMATS


def bones(m: ToolManifest, desc: ToolDescriptor, boxed: bool = False) -> list[Problem]:
    """Structural checks before the owner ever sees a draft. They catch structural loosening,
    not a wrong-but-legal classification (that is the honest limit)."""
    view = security_view(desc, "")
    hints = view["hints"]
    out: list[Problem] = []
    if m.name != desc.kind:
        out.append(Problem("name", f"manifest {m.name!r} is not for tool {desc.kind!r}"))
    live, declared = set(view["args"]), set(m.args)
    if live != declared:
        out.append(Problem("args", f"no role for {sorted(live - declared)}; unknown {sorted(declared - live)}"))
    floor = 0 if hints["readOnlyHint"] else 5 if hints["destructiveHint"] else 2
    if _RANK[m.effect] < floor:
        out.append(Problem("annotations", f"{m.effect} is looser than the tool's own annotations"))
    roles = set(m.args.values())
    if m.effect.startswith("read") and {"destination", "payload"} <= roles:
        out.append(Problem("read_with_payload", "a tool that carries payload to a destination is not a read"))
    if hints["openWorldHint"]:
        for arg, schema in view["args"].items():
            if arg in m.args and m.args[arg] != "destination" and _destination_like(arg, schema):
                out.append(Problem("destination_like", f"{arg} looks like a destination, filed as {m.args[arg]}"))
    if boxed:  # in a box, destination args are the paths that get canonicalised and grant-checked
        for arg in view["args"]:
            snake = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", arg).lower()
            if arg in m.args and m.args[arg] != "destination" and _PATH_NAMES.search(snake):
                out.append(Problem("path_like", f"{arg} looks like a path, filed as {m.args[arg]}"))
    return out


def explain(m: ToolManifest) -> list[tuple[str, str, str, bool]]:
    """The approval screen: (field, conservative default, proposed, looser?) rows."""
    d = conservative(m.name, m.args)
    rows = []
    if m.effect != d.effect:
        rows.append(("effect", d.effect, m.effect, _RANK[m.effect] < _RANK[d.effect]))
    rows += [(f"arg {a}", "payload", r, False) for a, r in sorted(m.args.items()) if r != "payload"]
    if compile_kind(m).grantable:
        rows.append(("grants", "approval per call", "grantable", True))
    if m.lane:
        rows.append(("public lane", "no", "yes", True))
    return rows


# ---- the registry ----


@dataclass(frozen=True)
class Approved:
    version: int
    manifest: ToolManifest
    view: dict
    hash: str


class ManifestRegistry:
    """Holds the owner-approved manifest per tool and reconciles it with what servers report.
    Server identity comes from owner config (`endpoints`), never from the server itself."""

    def __init__(self, sandbox: Sandbox, endpoints: Mapping[str, str], boxes: Mapping[str, Resolver] = {}) -> None:
        self.sb = sandbox
        self.endpoints = dict(endpoints)
        self.boxes = dict(boxes)  # server -> its box; destination args there are box paths
        if set(self.boxes) - set(self.endpoints):  # an unconfigured box would escape every box rule
            raise ValueError(f"boxed servers not configured by the owner: {sorted(set(self.boxes) - set(self.endpoints))}")
        self._minted: dict[str, tuple[str, int]] = {}  # canonical value id -> (server, box generation)
        self._live: dict[str, tuple[str, dict]] = {}  # kind -> (hash, view) last observed
        self._operators: dict[str, Value] = {}
        sandbox.attach(self)

    def _view(self, desc: ToolDescriptor) -> dict:
        if desc.server not in self.endpoints:
            raise ValueError(f"server {desc.server!r} is not configured by the owner")
        return security_view(desc, self.endpoints[desc.server])

    def approved(self, kind: str) -> Approved | None:
        row = self.sb.store.db.execute(
            "SELECT version, manifest, view, hash FROM manifests WHERE tool=? ORDER BY version DESC LIMIT 1", (kind,)
        ).fetchone()
        if row is None:
            return None
        return Approved(row[0], ToolManifest(**json.loads(row[1])), json.loads(row[2]), row[3])

    def approve(self, manifest: ToolManifest, desc: ToolDescriptor, overrides: Iterable[str] = ()) -> int:
        """Owner approval of a manifest against the tool as it is now. Returns the new version."""
        overrides = frozenset(overrides) & OVERRIDABLE
        problems = [p for p in bones(manifest, desc, desc.server in self.boxes) if p.rule not in overrides]
        if problems:
            raise BonesError(problems)
        if desc.kind not in self.sb.kinds:
            raise KeyError(f"tool {desc.kind!r} is not mounted")
        view = self._view(desc)
        h, now = view_hash(view), self.sb.clock()
        prev = self.approved(desc.kind)
        version = (prev.version if prev else 0) + 1
        self.sb.store.db.execute(
            "INSERT INTO manifests (tool, version, manifest, view, hash, overrides, approved_at) VALUES (?,?,?,?,?,?,?)",
            (desc.kind, version, json.dumps(asdict(manifest)), json.dumps(view), h, json.dumps(sorted(overrides)), now),
        )
        self.sb.invalidate_kind(desc.kind)  # anything issued under the previous version
        self.sb.set_kind(self._compile(manifest, view))
        self._live[desc.kind] = (h, view)
        self.sb.store.audit(now, "manifest.approve", tool=desc.kind, version=version, overrides=sorted(overrides))
        return version

    def observe(self, desc: ToolDescriptor) -> Change:
        """Reconcile a live descriptor (e.g. from tools/list) with the approved baseline."""
        kind, view = desc.kind, self._view(desc)
        h = view_hash(view)
        prev = self._live.get(kind)
        self._live[kind] = (h, view)
        changed = prev is None or prev[0] != h
        base = self.approved(kind)
        if base is None:
            change = Change(loosened=("no approved manifest",))  # unreviewed: conservative default
            if kind in self.sb.kinds:
                self.sb.set_kind(compile_kind(conservative(kind, view["args"])))
            return change
        change = diff(base.view, view, base.manifest.args)
        if change.outcome == "loosened":
            if changed:  # each new loosened version kills what was authorized before it
                self.sb.invalidate_kind(kind)
            self.sb.set_kind(compile_kind(conservative(kind, view["args"])))
        else:  # unchanged, additive or tightening vs what the owner approved
            self.sb.set_kind(self._compile(base.manifest, view))
        if changed:
            now = self.sb.clock()
            if change.outcome != "unchanged":  # lands in the batched digest, never an interrupt
                self.sb.approvals.notice(f"manifest.{change.outcome}", desc.server, kind, now)
            self.sb.store.audit(now, f"manifest.{change.outcome}", tool=kind, added=change.added,
                                loosened=change.loosened, other=change.other)
        return change

    @staticmethod
    def _compile(m: ToolManifest, view: dict) -> KindSpec:
        """A destination that is a list of paths or addresses is never grant-covered: approval only."""
        spec = compile_kind(m)
        if any(r == "destination" and "array" in _types(view["args"].get(a, {})) for a, r in m.args.items()):
            spec = replace(spec, grantable=False)
        return spec

    def _many(self, kind: str, arg: str) -> bool:
        """Whether the server takes this arg as a list, per the schema calls are bound against."""
        live, base = self._live.get(kind), self.approved(kind)
        view = live[1] if live else base.view if base else {"args": {}}
        schema = view["args"].get(arg)
        return isinstance(schema, Mapping) and "array" in _types(schema)

    def roles(self, kind: str) -> dict[str, str] | None:
        """Arg roles calls are bound by now. Partial validity: only args the owner approved, or,
        while the tool is reverted to approval-per-call, the server's current args as payload."""
        base, live = self.approved(kind), self._live.get(kind)
        if base is None and live is None:
            return None
        if self._reverted(kind) and live:
            return dict(conservative(kind, live[1]["args"]).args)
        return {a: base.manifest.args[a] for a in base.view["args"]}  # type: ignore[union-attr]

    def _reverted(self, kind: str) -> bool:
        """No owner-approved manifest, or the live tool loosened past it."""
        base, live = self.approved(kind), self._live.get(kind)
        return base is None or (live is not None and bool(diff(base.view, live[1], base.manifest.args).loosened))

    def _unreviewed_in_box(self, kind: str) -> str | None:
        """In a box, roles decide which args are canonicalised paths; without reviewed roles a raw
        path would reach the server. Such tools are not callable until the owner approves a manifest."""
        if kind.partition("/")[0] in self.boxes and self._reverted(kind):
            return f"{kind} is unreviewed on a boxed server: approve a manifest first"
        return None

    def check_call(self, kind: str, args: Iterable[str]) -> str | None:
        blocked = self._unreviewed_in_box(kind)
        if blocked:
            return blocked
        roles = self.roles(kind)
        if roles is None:
            return f"unknown tool {kind!r}"
        unknown = sorted(set(args) - set(roles))
        return f"args not approved: {unknown}" if unknown else None

    def manages(self, kind: str) -> bool:
        server, sep, _ = kind.partition("/")
        return bool(sep) and server in self.endpoints

    def operator(self, server: str) -> Value:
        """The destination of a call with no destination arg: the server's owner-configured operator."""
        if server not in self._operators:
            self._operators[server] = self.sb.store.put(f"mcp:{server}", OWNER_PUBLIC, "owner:config", self.sb.clock())
        return self._operators[server]

    def bind(self, kind: str, args: Mapping[str, Value]) -> Egress | str:
        """Named call args -> an egress with each value in its role's position, or why not."""
        if not self.manages(kind):
            return f"{kind!r} is not a tool of an owner-configured server"
        why = self.check_call(kind, args)
        if why:
            return why
        roles = self.roles(kind) or {}
        server = kind.partition("/")[0]
        if server in self.boxes:
            try:
                args = {a: self._canonical(kind, a, v) if roles[a] == "destination" else v for a, v in args.items()}
            except ValueError as exc:
                return f"path rejected: {exc}"
        by_role = {r: sorted(a for a in args if roles[a] == r) for r in ("destination", "payload", "control")}
        dests = by_role["destination"]
        # CEILING: one destination per egress; extra destination args ride as payload (approval-only kind)
        dest_name, payload = (dests[0], dests[1:] + by_role["payload"]) if dests else ("", by_role["payload"])
        dest = args[dest_name] if dest_name else self.operator(server)
        return Egress(kind, dest, tuple(args[a] for a in payload), tuple(args[a] for a in by_role["control"]),
                      (dest_name, *payload, *by_role["control"]))

    def check_egress(self, eg: Egress) -> str | None:
        """The door's re-check: every position holds an approved arg of the matching role, so a
        binding bug cannot pass a destination off as payload under an operator grant."""
        if not self.manages(eg.kind):
            return "named args on a tool no server owns" if eg.names else None
        blocked = self._unreviewed_in_box(eg.kind)
        if blocked:
            return blocked
        roles = self.roles(eg.kind)
        if roles is None or not eg.names:
            return "tool call without approved, named args"
        dest = eg.names[0]
        expected = [{"payload", "destination"} if dest else {"payload"}] * len(eg.payload) + [{"control"}] * len(eg.control)
        if (dest and roles.get(dest) != "destination") or any(
                roles.get(n) not in ok for n, ok in zip(eg.names[1:], expected)):
            return "call args are not in their approved roles"
        if not dest and eg.destination.data != f"mcp:{eg.kind.partition('/')[0]}":
            return "call with no destination arg must go to its operator"
        return self._check_paths(eg, roles)

    # ---- box paths: canonical at bind, canonical again at dispatch ----

    def _resolve(self, server: str, data: str, many: bool) -> str:
        """A path, or for a list-typed arg a JSON list of paths (each checked; any reject rejects
        the whole call). The schema decides which, so what is checked is what the server gets."""
        box = self.boxes[server]
        if not many:
            return box.resolve(data)
        paths = json.loads(data)
        if not isinstance(paths, list) or not paths or not all(isinstance(p, str) for p in paths):
            raise ValueError("a path list must be a non-empty JSON list of strings")
        return json.dumps([box.resolve(p) for p in paths])

    def _canonical(self, kind: str, arg: str, v: Value) -> Value:
        """The checked path is the sent path: a new value holding the canonical form, same label."""
        server = kind.partition("/")[0]
        canon = self._resolve(server, v.data, self._many(kind, arg))
        out = self.sb.store.put(canon, v.label, f"canonical:{server}", self.sb.clock())
        self._minted[out.id] = (server, self.boxes[server].generation)
        return out

    def _check_paths(self, eg: Egress, roles: Mapping[str, str]) -> str | None:
        server = eg.kind.partition("/")[0]
        box = self.boxes.get(server)
        if box is None:
            return None
        for name, v in zip(eg.names, (eg.destination, *eg.payload, *eg.control)):
            if not name or roles.get(name) != "destination":
                continue
            if self._minted.get(v.id) != (server, box.generation):  # a restarted box fails closed
                return "path was not canonicalised in the running box"
            try:
                again = self._resolve(server, v.data, self._many(eg.kind, name))
            except ValueError as exc:
                return f"path rejected at dispatch: {exc}"
            if again != v.data:
                return f"{PATH_MOVED}: {v.data} now resolves to {again}"
        return None

    def rebind(self, eg: Egress) -> Egress | str:
        """The same call bound afresh: a moved path becomes a new call for the owner, never the old approval."""
        values = (eg.destination, *eg.payload, *eg.control)
        return self.bind(eg.kind, {n: v for n, v in zip(eg.names, values) if n})

    def catalog(self) -> dict[str, dict]:
        """What the planner may read: frozen owner-approved manifests only, never live descriptions."""
        rows = self.sb.store.db.execute(
            "SELECT tool, manifest FROM manifests m WHERE version=(SELECT MAX(version) FROM manifests WHERE tool=m.tool)")
        out = {}
        for tool, blob in rows:
            m = json.loads(blob)
            out[tool] = {"effect": m["effect"], "args": m["args"]}
        return out

    def change_counts(self) -> dict[str, int]:
        """Manifest changes per server so far: a churny server shows up here, not as interrupts."""
        rows = self.sb.store.db.execute(
            "SELECT cluster, COUNT(*) FROM notices WHERE topic LIKE 'manifest.%' GROUP BY cluster").fetchall()
        return dict(rows)
