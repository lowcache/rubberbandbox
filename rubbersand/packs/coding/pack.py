"""Coding workflow: issue-driven work without a public lane."""

from __future__ import annotations

from typing import Sequence
from urllib.parse import urlsplit

from rubbersand.core import (
    EXTERNAL_PRIVATE,
    EXTERNAL_PUBLIC,
    DecideContext,
    EnumField,
    InboundEvent,
    KindSpec,
    Label,
    Notice,
    RefList,
    RouteReceipt,
    Schema,
)

SCHEMA = Schema(
    "coding.issue",
    {
        "task": EnumField("fix", "docs", "release", "other"),
        "links": RefList(max_items=8),
        "mentions": RefList(max_items=8),
    },
)

KINDS = {
    "http.fetch": KindSpec("http.fetch", read_only=True),
    "http.post": KindSpec("http.post"),
    "git.push": KindSpec("git.push", publishes=True),
    "pkg.publish": KindSpec("pkg.publish", publishes=True),
}


class CodingPack:
    name = "coding"
    channels = frozenset({"tracker"})
    schema = SCHEMA
    kinds = KINDS

    def inbound_label(self, event: InboundEvent) -> Label:
        public = event.authenticated and event.meta.get("visibility") == "public"
        return EXTERNAL_PUBLIC if public else EXTERNAL_PRIVATE

    def route(self, event: InboundEvent) -> RouteReceipt | None:
        return None

    def decide(self, ctx: DecideContext) -> Sequence[Notice]:
        if ctx.casefile["task"] == "release":
            return [Notice("release_requested", ctx.casefile.origin)]
        return []

    def cluster(self, destination: str) -> str:
        if destination.startswith("git:"):
            return "git"
        if destination.startswith("pkg:"):
            return "pkg"
        try:
            url = urlsplit(destination)
            if url.scheme in ("http", "https") and url.hostname:
                return url.hostname
        except ValueError:
            pass
        return "unknown"
