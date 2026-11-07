"""Deterministic stand-in for the clerk. A real clerk is an LLM with constrained decoding into
the same schema; the property tests treat the clerk as fully hostile, so this stub proves nothing
less by being simple."""

from __future__ import annotations

import re

_NEED_RULES = [
    ("complaint", r"\b(complain|complaint|refund|terrible|awful|disappoint|damage|damaged|broke|broken|missed|upset|unhappy|not happy|worst)\b"),
    ("booking", r"\b(book|booking|schedule|reschedule|cancel|appointment|sign me up|set up a)\b"),
    ("price", r"\b(price|prices|pricing|cost|costs|how much|quote|rate|rates|charge|\$)"),
    ("availability", r"\b(available|availability|openings?|free on|any time|when can|slots?|this week|next week|weekend|saturday|sunday|monday|tuesday|wednesday|thursday|friday)\b"),
]
_SPANS = re.compile(r"\+?\d[\d\-\s().]{6,}\d|[\w.+-]+@[\w-]+\.[\w.-]+|https?://\S+")


class KeywordClerk:
    def extract(self, text: str) -> dict:
        low = text.lower()
        need = next((n for n, pat in _NEED_RULES if re.search(pat, low)), "other")
        if re.search(r"\bcall (me|us)\b|\bgive me a call\b", low):
            action = "call"
        elif re.search(r"\b(come by|visit|stop by)\b", low):
            action = "visit"
        elif "?" in text or need != "other":
            action = "reply"
        else:
            action = "none"
        mentions = [m.strip()[:512] for m in _SPANS.findall(text)][:8]
        return {"need": need, "requested_action": action, "mentions": mentions}
