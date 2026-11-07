"""Per-tool effect manifests: what a tool does, declared once and compiled into door semantics.

The irreducible input is per-tool classification; everything the door enforces derives from it."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Mapping

from .casefile import REF_SHAPES, EnumField, Field, Schema, TypedRefs
from .types import KindSpec

EFFECTS = ("read-public", "read-private", "write-staged", "send", "publish", "spend", "delete")
ROLES = ("destination", "payload", "control")
_APPROVAL_ONLY = frozenset({"spend", "delete"})
_PUBLISHES = frozenset({"publish", "spend", "delete"})  # irreversible: grants need trusted payload


@dataclass(frozen=True)
class ToolManifest:
    name: str
    effect: str = "send"
    args: Mapping[str, str] = field(default_factory=dict)  # arg name -> role
    lane: bool = False  # a send that may leave through the public lane (the mail slot)
    reviewed: bool = True  # False: conservative default for an unclassified tool

    def __post_init__(self) -> None:
        if self.effect not in EFFECTS:
            raise ValueError(f"{self.name}: unknown effect {self.effect!r}")
        bad = {a: r for a, r in self.args.items() if r not in ROLES}
        if bad:
            raise ValueError(f"{self.name}: unknown arg roles {bad}")
        if self.lane and self.effect != "send":
            raise ValueError(f"{self.name}: only a send may use the public lane")


def conservative(name: str, args: Iterable[str] = ()) -> ToolManifest:
    """An unknown tool is an irreversible send of every arg, approved per call."""
    return ToolManifest(name, "send", {a: "payload" for a in args}, reviewed=False)


def compile_kind(m: ToolManifest) -> KindSpec:
    destinations = sum(role == "destination" for role in m.args.values())
    return KindSpec(
        m.name,
        read_only=m.effect == "read-public",
        publishes=m.effect in _PUBLISHES,
        public_lane=m.lane,
        # CEILING: one destination per egress; multi-destination tools (to/cc/bcc) are approval-only
        grantable=m.reviewed and m.effect not in _APPROVAL_ONLY and destinations <= 1,
    )


def compile_kinds(manifests: Iterable[ToolManifest]) -> dict[str, KindSpec]:
    kinds: dict[str, KindSpec] = {}
    for m in manifests:
        if m.name in kinds:
            raise ValueError(f"tool {m.name!r} declared twice")
        kinds[m.name] = compile_kind(m)
    return kinds


def generated_schema(name: str, tools: Iterable[ToolManifest], vocabulary: Iterable[str] = ()) -> Schema:
    """Case file for a deployment: intent = owner vocabulary + mounted tools + none/other, plus one
    typed ref list per entity type. Built from the frozen manifests, never a live tool list."""
    intents = {*vocabulary, *(t.name for t in tools), "none", "other"}
    fields: dict[str, Field] = {"intent": EnumField(*sorted(intents))}
    for kind in REF_SHAPES:
        fields[f"{kind}s"] = TypedRefs(kind)
    return Schema(name, fields)
