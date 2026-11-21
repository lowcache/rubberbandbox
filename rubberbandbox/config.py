"""Owner configuration for the shadow daemon."""

from __future__ import annotations

import math
import os
import time
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from .core.approvals import DigestConfig
from .core.sandbox import ClerkBudget, Mount, Sandbox
from .packs.messaging import CLERK_GUIDE, KINDS, SCHEMA, KeywordClerk, MessagingPack
from .runtime import JsonlSource, Runtime, ShadowAdapter, daemon_lock


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class SourceConfig:
    name: str
    path: str


@dataclass(frozen=True)
class Config:
    db: str
    mode: str
    poll_interval: float
    digest: DigestConfig
    clerk_kind: str
    clerk_budget: ClerkBudget
    sources: tuple[SourceConfig, ...]


def _secrets(value: object) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            sensitive = any(word in key.lower() for word in ("password", "token", "secret", "api_key"))
            reference = key.lower().endswith(("_env", "_file"))
            if sensitive and isinstance(item, str) and not reference:
                raise ConfigError(f"inline secret forbidden: {key}")
            _secrets(item)
    elif isinstance(value, list):
        for item in value:
            _secrets(item)


def resolve_secret(table: Mapping[str, object], name: str) -> str:
    env, file = table.get(f"{name}_env"), table.get(f"{name}_file")
    if (env is None) == (file is None):
        raise ConfigError(f"provide exactly one of {name}_env or {name}_file")
    try:
        if env is not None:
            return os.environ[env]
        return Path(file).read_text(encoding="utf-8")
    except (KeyError, OSError, TypeError) as exc:
        raise ConfigError(f"cannot resolve secret {name}") from exc


def _number(table: dict, name: str, default=None, *, integer=False):
    value = table.get(name, default)
    types = (int,) if integer else (int, float)
    if type(value) not in types or not math.isfinite(value) or value <= 0:
        raise ConfigError(f"{name} must be a positive {'integer' if integer else 'number'}")
    return value if integer else float(value)


def _known(table: dict, where: str, allowed: set[str]) -> None:
    unknown = {k for k in table if k not in allowed and not k.endswith(("_env", "_file"))}
    if unknown:
        raise ConfigError(f"unknown keys in {where}: {', '.join(sorted(unknown))}")


def _text(table: dict, name: str) -> str:
    value = table.get(name)
    if not isinstance(value, str) or not value:
        raise ConfigError(f"{name} must be a nonempty string")
    return value


def load(path: str) -> Config:
    try:
        with open(path, "rb") as stream:
            data = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(str(exc)) from exc
    _secrets(data)
    unknown = set(data) - {"db", "mode", "poll_interval", "digest", "clerk", "source"}
    if unknown:
        raise ConfigError(f"unknown top-level keys: {', '.join(sorted(unknown))}")
    db, mode = _text(data, "db"), _text(data, "mode")
    if mode != "shadow":
        raise ConfigError("live mode is not available: no real outbound adapters")
    digest, clerk, sources = data.get("digest", {}), data.get("clerk", {}), data.get("source", [])
    if not isinstance(digest, dict) or not isinstance(clerk, dict) or not isinstance(sources, list):
        raise ConfigError("digest and clerk must be tables; source must be an array of tables")
    _known(digest, "[digest]", {"interval", "per_cluster"})
    _known(clerk, "[clerk]", {"kind", "per_sender", "sender_window", "per_day"})
    kind = _text(clerk, "kind")
    if kind not in {"stub", "codex"}:
        raise ConfigError(f"unknown clerk kind: {kind}")
    required = {"per_sender", "sender_window", "per_day"}
    budget = None
    if required <= clerk.keys():
        budget = ClerkBudget(_number(clerk, "per_sender", integer=True),
                             _number(clerk, "sender_window"), _number(clerk, "per_day", integer=True))
    if budget is None:
        raise ConfigError("missing clerk budget: the daemon never runs an unbudgeted clerk")
    configs = []
    for source in sources:
        if not isinstance(source, dict) or source.get("kind") != "jsonl":
            raise ConfigError("source kind must be jsonl")
        _known(source, "[[source]]", {"kind", "name", "path"})
        configs.append(SourceConfig(_text(source, "name"), _text(source, "path")))
    if len({s.name for s in configs}) != len(configs):
        raise ConfigError("duplicate source names")
    return Config(db, mode, _number(data, "poll_interval", 5.0),
                  DigestConfig(_number(digest, "interval", DigestConfig().interval),
                               _number(digest, "per_cluster", DigestConfig().per_cluster, integer=True)),
                  kind, budget, tuple(configs))


def build(config: Config) -> tuple[Sandbox, Runtime]:
    if config.mode != "shadow":
        raise ConfigError("live mode is not available: no real outbound adapters")
    if config.clerk_budget is None:
        raise ConfigError("missing clerk budget: the daemon never runs an unbudgeted clerk")
    lock = daemon_lock(config.db)
    sandbox = None
    try:
        if config.clerk_kind == "stub":
            clerk = KeywordClerk()
        elif config.clerk_kind == "codex":
            from .clerks.codex import CodexClerk
            clerk = CodexClerk(SCHEMA, CLERK_GUIDE)
        else:
            raise ConfigError(f"unknown clerk kind: {config.clerk_kind}")
        # Door copies the mapping; bind the shared adapter before the runtime can poll.
        adapter = ShadowAdapter(None)
        sandbox = Sandbox([Mount(MessagingPack(), clerk)], {kind: adapter for kind in KINDS},
                          clock=time.time, db=config.db, digest=config.digest, clerk_budget=config.clerk_budget)
        adapter.store, adapter.clock = sandbox.store, sandbox.clock
        return sandbox, Runtime(sandbox, [JsonlSource(s.name, s.path) for s in config.sources], _lock=lock)
    except BaseException:
        lock.close()
        if sandbox is not None:
            sandbox.store.db._conn.close()
        raise
