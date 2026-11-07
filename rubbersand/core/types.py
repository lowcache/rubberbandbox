"""Domain-agnostic shapes: egress, proposals, authorizations, and the three plug points."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Literal, Mapping, Protocol, Sequence

from .casefile import CaseFile, Schema
from .labels import Label, Value


@dataclass(frozen=True)
class KindSpec:
    """What a pack declares about one egress kind."""

    name: str
    read_only: bool = False  # a fetch: may stay inside if destination and payload are public
    publishes: bool = False  # irreversible publish: payload must be trusted unless the owner approves
    public_lane: bool = False  # may leave through the public lane (mail slot)


@dataclass(frozen=True)
class Egress:
    """Anything leaving the sandbox: a send, fetch, push, payment..."""

    kind: str
    destination: Value
    payload: tuple[Value, ...]

    @property
    def digest(self) -> str:
        h = hashlib.sha256(self.kind.encode())
        for v in (self.destination, *self.payload):
            h.update(b"\0" + v.id.encode())
        return h.hexdigest()


@dataclass(frozen=True)
class Proposal:
    """A requested egress; the bones decide which path (if any) authorizes it."""

    egress: Egress
    lane: bool = False  # ask for the public lane (requires a route receipt)


@dataclass(frozen=True)
class Notice:
    """Owner-facing, non-egress: 'a customer asked to book'. Lands in the digest."""

    topic: str
    ref: str | None = None


AuthKind = Literal["approval", "grant", "lane", "public_read"]


@dataclass(frozen=True)
class Authorization:
    kind: AuthKind
    ref: str  # approval id (A..) / grant id (G..) / lane receipt id (R..) / "" for public_read


@dataclass(frozen=True)
class InboundEvent:
    channel: str
    authenticated: bool  # provider/MTA signature verified by the adapter, not by content
    origin: str  # provider-reported return route; NOT a verified identity
    delivery_id: str
    text: str
    received_at: float
    meta: Mapping[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class RouteReceipt:
    """A pack's verdict that an inbound event has a constrained, reply-capable return route."""

    destination: str
    delivery_id: str
    cost: float | None  # None = unknown cost -> lane refuses
    arrived_at: float


@dataclass(frozen=True)
class DecideContext:
    casefile: CaseFile
    event: InboundEvent
    route: RouteReceipt | None
    published: Mapping[str, Value]  # owner-published values by name
    render: "RenderFn"
    destination: "DestFn"


class RenderFn(Protocol):
    def __call__(self, template: Value, slots: Mapping[str, Value]) -> Value: ...


class DestFn(Protocol):
    def __call__(self, key: str, label: Label) -> Value: ...


class Pack(Protocol):
    name: str
    channels: frozenset[str]  # inbound event channels this pack owns; disjoint across mounted packs
    schema: Schema
    kinds: Mapping[str, KindSpec]  # kind names are unique across mounted packs

    def inbound_label(self, event: InboundEvent) -> Label: ...

    def route(self, event: InboundEvent) -> RouteReceipt | None: ...

    def decide(self, ctx: DecideContext) -> Sequence[Proposal | Notice]: ...

    def cluster(self, destination: str) -> str: ...


class Clerk(Protocol):
    """Quarantined extractor: no tools, no memory. Its output is untrusted until validated."""

    def extract(self, text: str) -> object: ...


class ToolAdapter(Protocol):
    """The outside world. Only the door holds adapters."""

    def execute(self, kind: str, destination: str, payload: Sequence[str]) -> object: ...


@dataclass(frozen=True)
class HandsView:
    """Everything the hands may see: enum/int fields verbatim, values only as inert tokens.

    The hands never read value data: `visible` maps id -> descriptor, e.g.
    'source=sms trusted=no public=no'. They act on values by reference."""

    casefile: Mapping[str, object]
    visible: Mapping[str, str]
    schema: str = ""  # which pack's case file this is, for agents spanning several packs


class Hands(Protocol):
    """The smart model. Returns raw proposals: {'kind', 'destination', 'payload'} where each
    destination/payload item is {'ref': id} or {'literal': str}."""

    def propose(self, view: HandsView) -> object: ...
