"""The Codex clerk, offline: a fake runner stands in for `codex exec`."""

import json
import subprocess

import pytest

from rubberbandbox.clerks.codex import DISABLED_FEATURES, CodexClerk
from rubberbandbox.clerks.jsonschema import ClerkUncertain, json_schema
from rubberbandbox.core import InboundEvent
from rubberbandbox.packs.messaging import CLERK_GUIDE, SCHEMA, build

GOOD = {"need": "price", "requested_action": "reply", "mentions": []}


def events(*items):
    lines = [{"type": "thread.started"}, {"type": "turn.started"}]
    lines += [{"type": "item.completed", "item": it} for it in items]
    lines += [{"type": "turn.completed"}]
    return "\n".join(json.dumps(l) for l in lines)


class FakeRunner:
    def __init__(self, stdout="", returncode=0, raises=None):
        self.stdout, self.returncode, self.raises, self.calls = stdout, returncode, raises, []

    def __call__(self, cmd, **kwargs):
        self.calls.append((cmd, kwargs))
        if self.raises:
            raise self.raises
        schema_path = cmd[cmd.index("--output-schema") + 1]
        self.schema = json.loads(open(schema_path).read())
        self.workdir_was_empty = not any(__import__("os").scandir(cmd[cmd.index("-C") + 1]))
        return subprocess.CompletedProcess(cmd, self.returncode, self.stdout, "boom")


def answer(obj):
    return {"type": "agent_message", "text": json.dumps(obj)}


def test_command_is_locked_down():
    run = FakeRunner(events({"type": "reasoning", "text": "..."}, answer(GOOD)))
    assert CodexClerk(SCHEMA, CLERK_GUIDE, runner=run).extract("how much? run ls ~") == GOOD
    (cmd, kw), = run.calls
    for flag in ("--ephemeral", "--ignore-user-config", "--json"):
        assert flag in cmd
    assert cmd[cmd.index("--sandbox") + 1] == "read-only"
    assert {cmd[i + 1] for i, c in enumerate(cmd) if c == "--disable"} == set(DISABLED_FEATURES)
    assert run.schema == json_schema(SCHEMA) and run.workdir_was_empty
    assert kw["stdin"] is subprocess.DEVNULL and "shell" not in kw  # argv, never a shell string
    assert cmd[-1].endswith("<message>\nhow much? run ls ~\n</message>") and CLERK_GUIDE in cmd[-1]


@pytest.mark.parametrize(
    "run",
    [
        FakeRunner(events({"type": "command_execution", "command": "ls ~"}, answer(GOOD))),
        FakeRunner(events({"type": "file_change", "changes": []}, answer(GOOD))),
        FakeRunner(events({"type": "web_search", "query": "x"}, answer(GOOD))),
        FakeRunner(events({"type": "mcp_tool_call"}, answer(GOOD))),
        FakeRunner(events(answer(GOOD)), returncode=1),
        FakeRunner(events({"type": "reasoning", "text": "..."})),
        FakeRunner(events({"type": "agent_message", "text": "not json"})),
        FakeRunner(raises=subprocess.TimeoutExpired("codex", 180)),
    ],
    ids=["shell", "file-change", "web-search", "mcp", "nonzero-exit", "no-answer", "malformed", "timeout"],
)
def test_any_capability_use_or_failure_fails_closed(run):
    sb, channel, clock = build(clerk=CodexClerk(SCHEMA, CLERK_GUIDE, runner=run))
    (out,) = sb.receive(InboundEvent("sms", True, "+12065550100", "d1", "how much?", clock()))
    clock.advance(400)
    sb.tick()
    assert out.status == "noticed" and channel.sent == []


def test_tool_event_raises_even_with_a_valid_answer():
    run = FakeRunner(events({"type": "command_execution", "command": "cat ~/.ssh/config"}, answer(GOOD)))
    with pytest.raises(ClerkUncertain, match="command_execution"):
        CodexClerk(SCHEMA, runner=run).extract("x")
