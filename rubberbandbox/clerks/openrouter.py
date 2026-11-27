"""A clerk backed by any OpenRouter model: one stateless, tool-less chat completion per message.

No agent and no tools: the request carries no tool definitions, so the model can only answer.
Output is constrained to the pack's JSON schema, and providers that cannot honour that (or that
keep prompts for training) are excluded. The airlock still validates everything afterwards.
Any failure raises; the sandbox treats that as "uncertain: ask, never act"."""

from __future__ import annotations

import json
import os
import urllib.request
from typing import Callable

from rubberbandbox.core import Schema

from .jsonschema import SYSTEM, ClerkUncertain, json_schema

DEFAULT_MODEL = "anthropic/claude-sonnet-5.5"
URL = "https://openrouter.ai/api/v1/chat/completions"


def _post(body: dict, *, key: str, timeout: float) -> dict:
    request = urllib.request.Request(URL, json.dumps(body).encode(), method="POST", headers={
        "Authorization": f"Bearer {key}", "Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.load(response)


class OpenRouterClerk:
    def __init__(
        self,
        schema: Schema,
        guide: str = "",
        *,
        model: str = DEFAULT_MODEL,
        max_tokens: int = 4096,
        timeout: float = 120.0,
        post: Callable[[dict], dict] | None = None,
    ) -> None:
        if post is None:
            key = os.environ.get("OPENROUTER_API_KEY")
            if not key:
                raise ClerkUncertain("OPENROUTER_API_KEY is not set")
            post = lambda body: _post(body, key=key, timeout=timeout)  # noqa: E731
        self.post, self.model, self.max_tokens = post, model, max_tokens
        self.system = SYSTEM + ("\n\n" + guide if guide else "")
        self.format = {"type": "json_schema",
                       "json_schema": {"name": "form", "strict": True, "schema": json_schema(schema)}}

    def extract(self, text: str) -> object:
        reply = self.post({
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": [{"role": "system", "content": self.system},
                         {"role": "user", "content": f"<message>\n{text}\n</message>"}],
            "response_format": self.format,
            "provider": {"require_parameters": True, "data_collection": "deny"},
        })
        if "error" in reply:
            raise ClerkUncertain(f"openrouter error: {str(reply['error'])[:300]}")
        choice = (reply.get("choices") or [{}])[0]
        message = choice.get("message") or {}
        if choice.get("finish_reason") != "stop" or message.get("tool_calls"):
            raise ClerkUncertain(f"finish_reason={choice.get('finish_reason')}")
        if not isinstance(message.get("content"), str):
            raise ClerkUncertain("no content")
        return json.loads(message["content"])
