"""A pack assembled from declarations: tool manifests, per-channel adapters, and a rule table.

Route validation lives with the channel, tool semantics with the manifest, and scripts are owner
content. Nothing here is per-workflow code."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Iterable, Mapping, Protocol, Sequence
from urllib.parse import urlsplit

from .casefile import EnumField, Schema
from .labels import EXTERNAL_PRIVATE, Label
from .manifest import ToolManifest, compile_kinds
from .types import DecideContext, Egress, InboundEvent, KindSpec, Notice, Proposal, RouteReceipt

_SLOT = re.compile(r"\{([a-z_]+)\}")


class ChannelAdapter(Protocol):
    name: str  # the inbound event channel it owns

    def inbound_label(self, event: InboundEvent) -> Label: ...

    def route(self, event: InboundEvent) -> RouteReceipt | None:
        """A constrained return route for an authenticated event, or None."""
        ...

    def fits(self, destination: str, text: str) -> bool:
        """Whether a rendered reply fits this channel's message limits."""
        ...


@dataclass(frozen=True)
class Reply:
    """A scripted public-lane reply: a case-file enum value picks an owner-published script."""

    field: str
    scripts: Mapping[str, str]  # enum value -> published script name
    fallback: str
    kind: str


@dataclass(frozen=True)
class Rules:
    notices: Mapping[str, Mapping[str, str]] = field(default_factory=dict)  # field -> {value: topic}
    reply: Reply | None = None
    authenticated_only: bool = True  # unauthenticated events produce nothing at all


def prefix_cluster(*schemes: str) -> Callable[[str], str]:
    """Cluster by owner-listed scheme prefix, else URL host, else 'unknown'. Unlisted schemes do
    not get their own cluster, so a hostile destination cannot fan out the interruption budget."""

    def cluster(destination: str) -> str:
        for s in schemes:
            if destination.startswith(f"{s}:"):
                return s
        try:
            url = urlsplit(destination)
            if url.scheme in ("http", "https") and url.hostname:
                return url.hostname
        except ValueError:
            pass
        return "unknown"

    return cluster


class ManifestPack:
    """Satisfies the Pack protocol. name/channels/kinds/schema are properties so a subclass may
    still override them as plain class attributes."""

    def __init__(
        self,
        name: str,
        schema: Schema,
        tools: Iterable[ToolManifest],
        channels: Iterable[ChannelAdapter],
        rules: Rules,
        cluster: Callable[[str], str] = prefix_cluster(),
    ) -> None:
        self.tools = tuple(tools)
        self._name, self._schema, self._kinds = name, schema, compile_kinds(self.tools)
        self._adapters: dict[str, ChannelAdapter] = {}
        for c in channels:
            if c.name in self._adapters:
                raise ValueError(f"channel {c.name!r} declared twice")
            self._adapters[c.name] = c
        self.rules, self._cluster = rules, cluster
        _check_rules(schema, rules, self._kinds)

    name = property(lambda self: self._name)
    schema = property(lambda self: self._schema)
    kinds = property(lambda self: self._kinds)
    channels = property(lambda self: frozenset(self._adapters))

    def inbound_label(self, event: InboundEvent) -> Label:
        adapter = self._adapters.get(event.channel)
        return adapter.inbound_label(event) if adapter else EXTERNAL_PRIVATE

    def route(self, event: InboundEvent) -> RouteReceipt | None:
        adapter = self._adapters.get(event.channel)
        if not event.authenticated or adapter is None:
            return None
        return adapter.route(event)

    def decide(self, ctx: DecideContext) -> Sequence[Proposal | Notice]:
        cf, rules = ctx.casefile, self.rules
        if rules.authenticated_only and not ctx.event.authenticated:
            return []
        out: list[Proposal | Notice] = [
            Notice(topics[str(cf[f])], cf.origin) for f, topics in rules.notices.items() if str(cf[f]) in topics
        ]
        reply = rules.reply
        if reply is None or ctx.route is None:
            return out
        script = reply.scripts.get(str(cf[reply.field]), reply.fallback)
        template = ctx.published.get(script) or ctx.published.get(reply.fallback)
        if template is None:
            return out
        slots = {s: ctx.published[s] for s in _SLOT.findall(template.data) if s in ctx.published}
        text = ctx.render(template, slots)
        if not self._adapters[ctx.event.channel].fits(ctx.route.destination, text.data):
            out.append(Notice("script_too_long", text.id))
            return out
        dest = ctx.destination(ctx.route.destination, EXTERNAL_PRIVATE)
        out.append(Proposal(Egress(reply.kind, dest, (text,)), lane=True))
        return out

    def cluster(self, destination: str) -> str:
        return self._cluster(destination)


def _check_rules(schema: Schema, rules: Rules, kinds: Mapping[str, KindSpec]) -> None:
    """Rules may only name enum fields and values the schema actually has."""
    keyed = [(f, set(m)) for f, m in rules.notices.items()]
    if rules.reply is not None:
        keyed.append((rules.reply.field, set(rules.reply.scripts)))
        spec = kinds.get(rules.reply.kind)
        if spec is None or not spec.public_lane:
            raise ValueError(f"reply kind {rules.reply.kind!r} is not a mounted public-lane tool")
    for f, values in keyed:
        spec = schema.fields.get(f)
        if not isinstance(spec, EnumField):
            raise ValueError(f"rule field {f!r} is not an enum field of {schema.name}")
        if values - spec.choices:
            raise ValueError(f"rule values {sorted(values - spec.choices)} not in {f!r}")
