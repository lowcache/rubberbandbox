"""Read-only mail triage declarations."""
from __future__ import annotations

from rubberbandbox.core import EXTERNAL_PRIVATE, EnumField, InboundEvent, ManifestPack, Rules, Schema, TypedRefs

SCHEMA = Schema("mail.triage", {"label": EnumField("legit", "graymail", "spam", "phishing"),
                                 "urls": TypedRefs("url", max_items=8)})
TOOLS = ()
KINDS = {}
RULES = Rules(notices={"label": {"phishing": "phishing", "spam": "spam"}}, authenticated_only=False)
_URLS = SCHEMA.fields["urls"]
# The JSON schema cannot carry span bounds, and one out-of-shape URL rejects the whole form; so say them.
CLERK_GUIDE = f"""Classify mail. legit is ordinary wanted correspondence. graymail is wanted-once bulk mail such as newsletters and promotions the owner may have signed up for. phishing is impersonation, credential or payment lures. spam is unsolicited bulk with no relationship. Extract up to {_URLS.max_items} URLs. Copy only http:// or https:// URLs, never mailto: or other schemes, and skip any URL longer than {_URLS.max_len} characters."""


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
