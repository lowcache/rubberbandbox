"""Deterministic keyword and span extraction for coding issues."""

from __future__ import annotations

import re

_TASK_RULES = [
    ("release", r"\b(release|publish|deploy)\b"),
    ("fix", r"\b(fix|bug|repair|broken|patch)\b"),
    ("docs", r"\b(docs?|documentation|readme)\b"),
]
_SPANS = re.compile(
    r"https?://[^\s<>\"']+|[\w.+-]+@[\w-]+(?:\.[\w-]+)+|(?<![\w@])@[\w-]+",
    re.IGNORECASE,
)


class KeywordClerk:
    def extract(self, text: str) -> dict:
        task = next((name for name, pattern in _TASK_RULES if re.search(pattern, text.lower())), "other")
        links, mentions = [], []
        for match in _SPANS.finditer(text):
            span = match.group()
            if span.lower().startswith(("http://", "https://")):
                links.append(span.rstrip(".,;:!?)]}")[:512])
            else:
                mentions.append(span[:512])
        return {"task": task, "links": links[:8], "mentions": mentions[:8]}
