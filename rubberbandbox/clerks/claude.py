"""A clerk backed by Claude: stateless, tool-less extraction into a pack's schema.

Each call is a fresh request with no history and no tools. The inbound text is passed as data,
and output is constrained to a JSON schema generated from the pack's Schema. The airlock still
validates everything afterwards (bounds, lengths), so the model is never the last check.
Any failure raises; the sandbox treats that as "uncertain: ask, never act"."""

from __future__ import annotations

import json
from typing import Any

from rubberbandbox.core import Schema

from .jsonschema import SYSTEM, ClerkUncertain, json_schema

DEFAULT_MODEL = "claude-opus-5-5"


class ClaudeClerk:
    def __init__(
        self,
        schema: Schema,
        guide: str = "",
        *,
        client: Any = None,
        model: str = DEFAULT_MODEL,
        effort: str = "low",
        max_tokens: int = 4096,  # thinking is always on for this model; leave room beyond the JSON
    ) -> None:
        if client is None:
            import anthropic  # optional dependency, only needed for the live clerk

            client = anthropic.Anthropic()
        self.client = client
        self.model = model
        self.effort = effort
        self.max_tokens = max_tokens
        self.system = SYSTEM + ("\n\n" + guide if guide else "")
        self.format = {"type": "json_schema", "schema": json_schema(schema)}

    def extract(self, text: str) -> object:
        response = self.client.beta.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            system=self.system,
            messages=[{"role": "user", "content": f"<message>\n{text}\n</message>"}],
            output_config={"effort": self.effort, "format": self.format},
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",  # a safety decline is retried on a fallback model in the same call
        )
        if response.stop_reason != "end_turn":
            raise ClerkUncertain(f"stop_reason={response.stop_reason}")
        body = next((b.text for b in response.content if b.type == "text"), None)
        if body is None:
            raise ClerkUncertain("no text block")
        return json.loads(body)
