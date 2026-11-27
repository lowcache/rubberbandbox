"""Read-only mail triage declarations."""
from __future__ import annotations

from rubberbandbox.core import EXTERNAL_PRIVATE, EnumField, InboundEvent, ManifestPack, Rules, Schema, TypedRefs

SCHEMA = Schema("mail.triage", {"label": EnumField("legit", "bulk", "phishing"),
                                 "urls": TypedRefs("url", max_items=8)})
TOOLS = ()
KINDS = {}
RULES = Rules(notices={"label": {"phishing": "phishing"}}, authenticated_only=False)
_URLS = SCHEMA.fields["urls"]
# The JSON schema cannot carry span bounds, and one out-of-shape URL rejects the whole form; so say them.
CLERK_GUIDE = f"""Classify mail. legit is ordinary wanted correspondence. bulk is mail sent to many recipients rather than written to the owner: newsletters, promotions, marketing and unsolicited advertising, whether or not the owner signed up. phishing is impersonation, credential or payment lures, including scams; it outranks bulk. Extract up to {_URLS.max_items} URLs. Copy only http:// or https:// URLs, never mailto: or other schemes, and skip any URL longer than {_URLS.max_len} characters."""


class MailChannel:
    name = "mail"
    def inbound_label(self, event: InboundEvent): return EXTERNAL_PRIVATE
    def route(self, event: InboundEvent): return None
    def fits(self, destination: str, text: str): return False


def _cluster(destination: str) -> str:
    value = destination.rsplit("@", 1)[-1].lower() if "@" in destination else ""
    return value or "unknown"


class TriagePack(ManifestPack):
    def __init__(self):
        super().__init__("triage", SCHEMA, TOOLS, (MailChannel(),), RULES, _cluster)
