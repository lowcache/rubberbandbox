"""Messaging pack: inbound SMS/email for a small service business, replies through the public lane.
Declarations only: tool manifests, one adapter per channel, a rule table, and owner scripts."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Mapping

from rubberbandbox.core import (
    EXTERNAL_PRIVATE,
    EnumField,
    InboundEvent,
    Label,
    ManifestPack,
    RefList,
    Reply,
    RouteReceipt,
    Rules,
    Schema,
    ToolManifest,
    compile_kinds,
)

SCHEMA = Schema(
    "messaging.inbound",
    {
        "need": EnumField("price", "availability", "booking", "complaint", "other"),
        "requested_action": EnumField("reply", "call", "visit", "none"),
        "mentions": RefList(max_items=8),
    },
)

TOOLS = (
    ToolManifest("msg.reply", "send", {"to": "destination", "body": "payload"}, lane=True),
    ToolManifest("msg.send", "send", {"to": "destination", "body": "payload"}),
)
KINDS = compile_kinds(TOOLS)

SCRIPT_FOR_NEED = {
    "price": "script.price",
    "availability": "script.availability",
    "booking": "script.booking",
    "complaint": "script.complaint",
    "other": "script.generic",
}

# Owner-published defaults for the demo; a real owner edits and approves these.
DEFAULT_PUBLISHED = {
    "price_list": "Standard clean $120, deep clean $220.",
    "availability_snapshot": "Tue & Thu afternoons this week.",
    "script.price": "Thanks for asking! Our prices: {price_list} Reply to book a time.",
    "script.availability": "Thanks! Current openings: {availability_snapshot} The owner will confirm.",
    "script.booking": "Thanks! We got your booking request and the owner will confirm shortly.",
    "script.complaint": "We're sorry to hear that. The owner will personally follow up soon.",
    "script.generic": "Thanks for your message! We'll get back to you soon.",
}

CLERK_GUIDE = """This is a customer message to a small home-cleaning business.
need: price = asks what something costs or for a quote; availability = asks when the business is
free or open; booking = wants to book, reschedule, cancel, skip or confirm an appointment;
complaint = unhappy about service, damage, a no-show, or wants a refund; other = anything else.
Choose the customer's main need.
requested_action: call or visit only if they explicitly ask for a phone call or an in-person
visit; reply if they ask a question or expect an answer; otherwise none."""

_E164 = re.compile(r"\+\d{8,15}")
_MAILBOX = re.compile(r"[^@\s<>]+@[^@\s<>]+\.[^@\s<>]+")  # plausible addr-spec; not a full RFC 5322 parser


@dataclass(frozen=True)
class MessagingConfig:
    allowed_prefixes: tuple[str, ...] = ("+1206", "+1425", "+1253")  # service area
    denied_prefixes: tuple[str, ...] = ("+1900", "+1976")  # premium-rate
    sms_cost: Mapping[str, float] = field(default_factory=lambda: {"+1": 0.0079})  # per segment
    sms_max_chars: int = 160  # one GSM-7 segment
    email_max_bytes: int = 1000


RULES = Rules(
    notices={
        "need": {"booking": "booking", "complaint": "complaint"},
        "requested_action": {"call": "call", "visit": "visit"},  # never auto-call, never auto-book
    },
    reply=Reply("need", SCRIPT_FOR_NEED, "script.generic", "msg.reply"),
)


class SmsChannel:
    name = "sms"

    def __init__(self, config: MessagingConfig) -> None:
        self.config = config

    def inbound_label(self, event: InboundEvent) -> Label:
        return EXTERNAL_PRIVATE  # customer messages are untrusted and private to the owner

    def route(self, event: InboundEvent) -> RouteReceipt | None:
        """A constrained return route, or None. 'Reported route', never a verified identity."""
        o, cfg = event.origin, self.config
        if not isinstance(o, str) or not _E164.fullmatch(o):
            return None
        if o.startswith(cfg.denied_prefixes) or not o.startswith(cfg.allowed_prefixes):
            return None
        prefixes = [p for p in cfg.sms_cost if o.startswith(p)]
        cost = cfg.sms_cost[max(prefixes, key=len)] if prefixes else None
        return RouteReceipt(f"sms:{o}", event.delivery_id, cost, event.received_at)

    def fits(self, destination: str, text: str) -> bool:
        return len(text) <= self.config.sms_max_chars and text.isascii()


class EmailChannel:
    name = "email"

    def __init__(self, config: MessagingConfig) -> None:
        self.config = config

    def inbound_label(self, event: InboundEvent) -> Label:
        return EXTERNAL_PRIVATE

    def route(self, event: InboundEvent) -> RouteReceipt | None:
        m = event.meta
        froms, env = m.get("from"), m.get("envelope_from")
        if m.get("dmarc") != "pass":
            return None
        if not isinstance(froms, list) or len(froms) != 1 or not isinstance(froms[0], str):
            return None
        if not isinstance(env, str) or not _MAILBOX.fullmatch(env) or env.lower() != froms[0].lower():
            return None
        if not isinstance(event.origin, str) or event.origin.lower() != env.lower():
            return None
        if m.get("auto_submitted", "no") != "no" or m.get("list_id") is not None:
            return None
        # Reply-To and addresses in content are ignored by construction: only env is used.
        return RouteReceipt(f"email:{env.lower()}", event.delivery_id, 0.0, event.received_at)

    def fits(self, destination: str, text: str) -> bool:
        return len(text.encode()) <= self.config.email_max_bytes


def cluster(destination: str) -> str:
    channel, _, addr = destination.partition(":")
    if not addr:  # bare origin (e.g. for notices)
        addr, channel = destination, ("sms" if destination.startswith("+") else "email")
    if channel == "sms":
        return f"sms:{addr[:5]}"
    return f"email:{addr.rpartition('@')[2].lower()}"


class MessagingPack(ManifestPack):
    def __init__(self, config: MessagingConfig | None = None) -> None:
        self.config = config or MessagingConfig()
        channels = (SmsChannel(self.config), EmailChannel(self.config))
        super().__init__("messaging", SCHEMA, TOOLS, channels, RULES, cluster)
