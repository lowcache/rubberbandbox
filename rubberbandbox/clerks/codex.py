"""A clerk backed by the Codex CLI (`codex exec`), for running on a ChatGPT plan without an API key.

Codex is an agent, so it is locked down to behave as a clerk: ephemeral, user config (and its MCP
servers) ignored, read-only sandbox, shell/exec/image tools disabled, an empty working directory,
and output constrained to the pack's JSON schema. The flags are not trusted alone: the event
stream is checked on every call, and any item other than reasoning or the final message (a tool
call, a file change, a search) fails closed."""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Callable

from rubberbandbox.core import Schema

from .jsonschema import SYSTEM, ClerkUncertain, json_schema

DISABLED_FEATURES = ("shell_tool", "unified_exec", "view_image", "tool_suggest", "sleep_tool")
ALLOWED_ITEMS = {"agent_message", "reasoning"}


class CodexClerk:
    def __init__(
        self,
        schema: Schema,
        guide: str = "",
        *,
        model: str | None = None,
        timeout: float = 180.0,
        codex: str = "codex",
        runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
    ) -> None:
        self.instructions = SYSTEM + ("\n\n" + guide if guide else "")
        self.schema = json_schema(schema)
        self.model, self.timeout, self.codex, self.runner = model, timeout, codex, runner

    def command(self, workdir: str, schema_path: str, prompt: str) -> list[str]:
        cmd = [self.codex, "exec", "--ephemeral", "--ignore-user-config", "--skip-git-repo-check",
               "--sandbox", "read-only", "-C", workdir, "--output-schema", schema_path, "--json"]
        for feature in DISABLED_FEATURES:
            cmd += ["--disable", feature]
        if self.model:
            cmd += ["-m", self.model]
        return cmd + [prompt]

    def extract(self, text: str) -> object:
        prompt = f"{self.instructions}\n\n<message>\n{text}\n</message>"
        with tempfile.TemporaryDirectory(prefix="rubberbandbox-clerk-") as tmp:
            schema_path = Path(tmp, "schema.json")
            schema_path.write_text(json.dumps(self.schema))
            workdir = Path(tmp, "empty")
            workdir.mkdir()
            proc = self.runner(
                self.command(str(workdir), str(schema_path), prompt),
                stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=self.timeout,
            )
        if proc.returncode != 0:
            raise ClerkUncertain(f"codex exited {proc.returncode}: {proc.stderr.strip()[-300:]}")
        final = None
        for line in proc.stdout.splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            item = event.get("item") if isinstance(event, dict) else None
            if not isinstance(item, dict):
                continue
            kind = item.get("type")
            if kind not in ALLOWED_ITEMS:
                raise ClerkUncertain(f"clerk used a capability it must not have: {kind!r}")
            if kind == "agent_message" and event.get("type") == "item.completed":
                final = item.get("text")
        if not isinstance(final, str):
            raise ClerkUncertain("no final message")
        return json.loads(final)
