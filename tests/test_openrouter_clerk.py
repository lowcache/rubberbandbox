"""The OpenRouter clerk, offline: a fake post function stands in for the API."""

import json

import pytest

from rubberbandbox.clerks.openrouter import ClerkUncertain, OpenRouterClerk, json_schema
from rubberbandbox.core import InboundEvent
from rubberbandbox.packs.messaging import CLERK_GUIDE, SCHEMA, build

GOOD = {"need": "price", "requested_action": "reply", "mentions": []}


class FakePost:
    def __init__(self, reply=None, raises=None):
        self.reply, self.raises, self.calls = reply, raises, []

    def __call__(self, body):
        self.calls.append(body)
        if self.raises:
            raise self.raises
        return self.reply


def completion(content, finish="stop", **message):
    text = content if isinstance(content, str) or content is None else json.dumps(content)
    return {"choices": [{"finish_reason": finish, "message": {"role": "assistant", "content": text, **message}}]}


def test_request_is_tool_less_schema_bound_and_excludes_training_providers():
    post = FakePost(completion(GOOD))
    assert OpenRouterClerk(SCHEMA, CLERK_GUIDE, model="x/y", post=post).extract("how much?") == GOOD
    (body,) = post.calls
    assert body["model"] == "x/y" and "tools" not in body and "tool_choice" not in body
    assert body["response_format"]["json_schema"] == {"name": "form", "strict": True, "schema": json_schema(SCHEMA)}
    assert body["provider"] == {"require_parameters": True, "data_collection": "deny"}
    system, user = body["messages"]
    assert system["role"] == "system" and CLERK_GUIDE in system["content"]
    assert user == {"role": "user", "content": "<message>\nhow much?\n</message>"}


def test_missing_key_refuses_to_build(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    with pytest.raises(ClerkUncertain, match="OPENROUTER_API_KEY"):
        OpenRouterClerk(SCHEMA)


@pytest.mark.parametrize(
    "post",
    [
        FakePost({"error": {"code": 402, "message": "insufficient credits"}}),
        FakePost(completion(GOOD, finish="length")),
        FakePost(completion(None, finish="tool_calls", tool_calls=[{"function": {"name": "x"}}])),
        FakePost(completion(GOOD, tool_calls=[{"function": {"name": "x"}}])),
        FakePost(completion(None)),
        FakePost(completion("not json")),
        FakePost({}),
        FakePost(raises=TimeoutError("read timed out")),
    ],
    ids=["api-error", "truncated", "tool-call", "tool-call-with-stop", "no-content", "malformed", "empty", "timeout"],
)
def test_any_failure_fails_closed(post):
    sb, channel, clock = build(clerk=OpenRouterClerk(SCHEMA, CLERK_GUIDE, post=post))
    (out,) = sb.receive(InboundEvent("sms", True, "+12065550100", "d1", "how much?", clock()))
    clock.advance(400)
    sb.tick()
    assert out.status == "noticed" and channel.sent == []
