from __future__ import annotations
import re

_URL = re.compile(r"https?://[^\s<>\"]+", re.I)
_PHISH = re.compile(r"\b(verify|password|suspended|urgent)\b", re.I)
_BULK = re.compile(r"\b(viagra|casino|crypto|bitcoin|loan|winner|prize)\b", re.I)

class KeywordTriageClerk:
    def extract(self, text: str) -> dict:
        urls = _URL.findall(text)[:8]
        if urls and _PHISH.search(text): label = "phishing"
        elif "List-Unsubscribe:" in text or "List-Id:" in text or _BULK.search(text): label = "bulk"
        else: label = "legit"
        return {"label": label, "urls": urls}
