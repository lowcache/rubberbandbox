"""Coding workflow: issue-driven work without a public lane. Declarations only."""

from __future__ import annotations

from rubberbandbox.core import (
    EXTERNAL_PRIVATE,
    EXTERNAL_PUBLIC,
    EnumField,
    InboundEvent,
    Label,
    ManifestPack,
    RefList,
    RouteReceipt,
    Rules,
    Schema,
    ToolManifest,
    compile_kinds,
    prefix_cluster,
)

SCHEMA = Schema(
    "coding.issue",
    {
        "task": EnumField("fix", "docs", "release", "other"),
        "links": RefList(max_items=8),
        "mentions": RefList(max_items=8),
    },
)

TOOLS = (
    ToolManifest("http.fetch", "read-public", {"url": "destination"}),
    ToolManifest("http.post", "send", {"url": "destination", "body": "payload"}),
    ToolManifest("git.push", "publish", {"remote": "destination", "patch": "payload"}),
    ToolManifest("pkg.publish", "publish", {"package": "destination", "artifact": "payload"}),
)
KINDS = compile_kinds(TOOLS)

RULES = Rules(notices={"task": {"release": "release_requested"}}, authenticated_only=False)


class TrackerChannel:
    name = "tracker"

    def inbound_label(self, event: InboundEvent) -> Label:
        public = event.authenticated and event.meta.get("visibility") == "public"
        return EXTERNAL_PUBLIC if public else EXTERNAL_PRIVATE

    def route(self, event: InboundEvent) -> RouteReceipt | None:
        return None

    def fits(self, destination: str, text: str) -> bool:
        return False


class CodingPack(ManifestPack):
    def __init__(self) -> None:
        super().__init__("coding", SCHEMA, TOOLS, (TrackerChannel(),), RULES, prefix_cluster("git", "pkg"))
