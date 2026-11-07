"""Frozen, versioned manifests for live tools: security hashing, bones validation, and the
loosening diff. The diff baseline is always the last owner-approved manifest; auto-accepted
versions never move it."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Iterable, Mapping

from .manifest import ToolManifest, compile_kind, conservative

if TYPE_CHECKING:
    from .sandbox import Sandbox

# Unannotated means the unsafe value; a flip toward it is a loosening.
HINT_DEFAULTS = {"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True}
OVERRIDABLE = frozenset({"annotations", "destination_like"})  # owner may override; the rest are structural

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


def diff(old: dict, new: dict, roles: Mapping[str, str]) -> Change:
    added: list[str] = []
    loose: list[str] = []
    other: list[str] = []
    if old["endpoint"] != new["endpoint"]:
        loose.append("endpoint changed")
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


def bones(m: ToolManifest, desc: ToolDescriptor) -> list[Problem]:
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

    def __init__(self, sandbox: Sandbox, endpoints: Mapping[str, str]) -> None:
        self.sb = sandbox
        self.endpoints = dict(endpoints)
        self._live: dict[str, tuple[str, dict]] = {}  # kind -> (hash, view) last observed

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
        problems = [p for p in bones(manifest, desc) if p.rule not in overrides]
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
        self.sb.set_kind(compile_kind(manifest))
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
            self.sb.set_kind(compile_kind(base.manifest))
        if changed:
            now = self.sb.clock()
            if change.outcome != "unchanged":  # lands in the batched digest, never an interrupt
                self.sb.approvals.notice(f"manifest.{change.outcome}", desc.server, kind, now)
            self.sb.store.audit(now, f"manifest.{change.outcome}", tool=kind, added=change.added,
                                loosened=change.loosened, other=change.other)
        return change

    def check_call(self, kind: str, args: Iterable[str]) -> str | None:
        """Partial validity: a call may only use args the owner approved (or, while the tool is
        reverted to approval-per-call, args the server currently declares)."""
        base, live = self.approved(kind), self._live.get(kind)
        if base is None and live is None:
            return f"unknown tool {kind!r}"
        reverted = base is None or (live is not None and diff(base.view, live[1], base.manifest.args).loosened)
        allowed = set(live[1]["args"]) if reverted and live else set(base.view["args"])  # type: ignore[union-attr]
        unknown = sorted(set(args) - allowed)
        return f"args not approved: {unknown}" if unknown else None

    def change_counts(self) -> dict[str, int]:
        """Manifest changes per server so far: a churny server shows up here, not as interrupts."""
        rows = self.sb.store.db.execute(
            "SELECT cluster, COUNT(*) FROM notices WHERE topic LIKE 'manifest.%' GROUP BY cluster").fetchall()
        return dict(rows)
