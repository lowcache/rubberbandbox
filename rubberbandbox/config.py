"""Owner configuration for the shadow daemon."""

from __future__ import annotations

import math
import os
import time
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

from .core.approvals import DigestConfig
from .core.sandbox import ClerkBudget, Mount, Sandbox
from .packs.messaging import CLERK_GUIDE, KINDS, SCHEMA, KeywordClerk, MessagingPack
from .packs.triage import CLERK_GUIDE as TRIAGE_GUIDE, KINDS as TRIAGE_KINDS, SCHEMA as TRIAGE_SCHEMA, KeywordTriageClerk, TriagePack
from .mail import EmlSource, ImapSource, ThunderbirdSource
from .runtime import JsonlSource, Runtime, ShadowAdapter, daemon_lock


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class SourceConfig:
    name: str
    kind: str = "jsonl"
    path: str | None = None
    authserv_id: str | None = None
    include_body: bool = False
    host: str | None = None
    port: int = 993
    user: str | None = None
    password_ref: Mapping[str, str] = field(default_factory=dict)  # password_env or password_file
    mailbox: str = "INBOX"
    backfill: int = 0


@dataclass(frozen=True)
class Config:
    db: str
    mode: str
    poll_interval: float
    digest: DigestConfig
    clerk_kind: str
    clerk_budget: ClerkBudget
    sources: tuple[SourceConfig, ...]
    pack: str = "messaging"
    clerk_model: str | None = None


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
        return Path(file).read_text(encoding="utf-8").rstrip("\r\n")  # editors and echo add a final newline
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
    unknown = set(data) - {"db", "mode", "poll_interval", "digest", "clerk", "source", "pack"}
    if unknown:
        raise ConfigError(f"unknown top-level keys: {', '.join(sorted(unknown))}")
    db, mode = _text(data, "db"), _text(data, "mode")
    pack = data.get("pack", "messaging")
    if pack not in {"messaging", "triage"}: raise ConfigError("pack must be messaging or triage")
    if mode != "shadow":
        raise ConfigError("live mode is not available: no real outbound adapters")
    digest, clerk, sources = data.get("digest", {}), data.get("clerk", {}), data.get("source", [])
    if not isinstance(digest, dict) or not isinstance(clerk, dict) or not isinstance(sources, list):
        raise ConfigError("digest and clerk must be tables; source must be an array of tables")
    _known(digest, "[digest]", {"interval", "per_cluster"})
    _known(clerk, "[clerk]", {"kind", "model", "per_sender", "sender_window", "per_day"})
    kind = _text(clerk, "kind")
    if kind not in {"stub", "codex", "openrouter"}:
        raise ConfigError(f"unknown clerk kind: {kind}")
    model = _text(clerk, "model") if "model" in clerk else None
    if model is not None and kind != "openrouter":
        raise ConfigError("[clerk] model applies only to kind openrouter")
    required = {"per_sender", "sender_window", "per_day"}
    budget = None
    if required <= clerk.keys():
        budget = ClerkBudget(_number(clerk, "per_sender", integer=True),
                             _number(clerk, "sender_window"), _number(clerk, "per_day", integer=True))
    if budget is None:
        raise ConfigError("missing clerk budget: the daemon never runs an unbudgeted clerk")
    configs = []
    for source in sources:
        if not isinstance(source, dict): raise ConfigError("source must be a table")
        source_kind = source.get("kind")
        if source_kind == "jsonl":
            _known(source, "[[source]]", {"kind", "name", "path"})
            configs.append(SourceConfig(_text(source, "name"), "jsonl", path=_text(source, "path")))
        elif source_kind == "eml":
            _known(source, "[[source]]", {"kind", "name", "path", "authserv_id", "include_body"})
            body = source.get("include_body", False)
            if type(body) is not bool: raise ConfigError("include_body must be boolean")
            configs.append(SourceConfig(_text(source, "name"), "eml", path=_text(source, "path"), authserv_id=_text(source, "authserv_id"), include_body=body))
        elif source_kind == "thunderbird":
            _known(source, "[[source]]", {"kind", "name", "path", "authserv_id", "include_body", "backfill"})
            body, backfill = source.get("include_body", False), source.get("backfill", 0)
            if type(body) is not bool or type(backfill) is not int or backfill < 0:
                raise ConfigError("invalid thunderbird source option")
            configs.append(SourceConfig(_text(source, "name"), "thunderbird", path=_text(source, "path"),
                                        authserv_id=_text(source, "authserv_id"), include_body=body,
                                        backfill=backfill))
        elif source_kind == "imap":
            _known(source, "[[source]]", {"kind", "name", "host", "port", "user", "password_env", "password_file", "mailbox", "authserv_id", "include_body", "backfill"})
            body, backfill = source.get("include_body", False), source.get("backfill", 0)
            if type(body) is not bool or type(backfill) is not int or backfill < 0: raise ConfigError("invalid imap source option")
            port = source.get("port", 993)
            if type(port) is not int or not 0 < port < 65536: raise ConfigError("port must be valid")
            mailbox = source.get("mailbox", "INBOX")
            if not isinstance(mailbox, str) or not mailbox:
                raise ConfigError("mailbox must be a nonempty string")
            ref = {k: source[k] for k in ("password_env", "password_file") if k in source}
            if len(ref) != 1:
                raise ConfigError("provide exactly one of password_env or password_file")
            configs.append(SourceConfig(_text(source, "name"), "imap", host=_text(source, "host"), port=port,
                                        user=_text(source, "user"), password_ref=ref, mailbox=mailbox,
                                        authserv_id=_text(source, "authserv_id"), include_body=body,
                                        backfill=backfill))
        else: raise ConfigError("unknown source kind")
    if len({s.name for s in configs}) != len(configs):
        raise ConfigError("duplicate source names")
    return Config(db, mode, _number(data, "poll_interval", 5.0),
                  DigestConfig(_number(digest, "interval", DigestConfig().interval),
                               _number(digest, "per_cluster", DigestConfig().per_cluster, integer=True)),
                  kind, budget, tuple(configs), pack, model)


def build(config: Config) -> tuple[Sandbox, Runtime]:
    if config.mode != "shadow":
        raise ConfigError("live mode is not available: no real outbound adapters")
    if config.clerk_budget is None:
        raise ConfigError("missing clerk budget: the daemon never runs an unbudgeted clerk")
    lock = daemon_lock(config.db)
    sandbox = None
    try:
        if config.clerk_kind == "stub":
            clerk = KeywordTriageClerk() if config.pack == "triage" else KeywordClerk()
        elif config.clerk_kind == "codex":
            from .clerks.codex import CodexClerk
            clerk = CodexClerk(TRIAGE_SCHEMA, TRIAGE_GUIDE) if config.pack == "triage" else CodexClerk(SCHEMA, CLERK_GUIDE)
        elif config.clerk_kind == "openrouter":
            from .clerks.openrouter import DEFAULT_MODEL, OpenRouterClerk
            schema, guide = (TRIAGE_SCHEMA, TRIAGE_GUIDE) if config.pack == "triage" else (SCHEMA, CLERK_GUIDE)
            clerk = OpenRouterClerk(schema, guide, model=config.clerk_model or DEFAULT_MODEL)
        else:
            raise ConfigError(f"unknown clerk kind: {config.clerk_kind}")
        # Door copies the mapping; bind the shared adapter before the runtime can poll.
        adapter = ShadowAdapter(None)
        pack = TriagePack() if config.pack == "triage" else MessagingPack()
        kinds = TRIAGE_KINDS if config.pack == "triage" else KINDS
        sandbox = Sandbox([Mount(pack, clerk)], {kind: adapter for kind in kinds},
                          clock=time.time, db=config.db, digest=config.digest, clerk_budget=config.clerk_budget)
        adapter.store, adapter.clock = sandbox.store, sandbox.clock
        source_objects = []
        for s in config.sources:
            if s.kind == "jsonl": source_objects.append(JsonlSource(s.name, s.path))
            elif s.kind == "eml": source_objects.append(EmlSource(s.name, s.path, authserv_id=s.authserv_id, include_body=s.include_body))
            elif s.kind == "thunderbird":
                source_objects.append(ThunderbirdSource(s.name, s.path, authserv_id=s.authserv_id,
                                                        include_body=s.include_body, backfill=s.backfill))
            else: source_objects.append(ImapSource(s.name, host=s.host, port=s.port, user=s.user,
                                                   password=resolve_secret(s.password_ref, "password"),
                                                   mailbox=s.mailbox, authserv_id=s.authserv_id,
                                                   include_body=s.include_body, backfill=s.backfill))
        return sandbox, Runtime(sandbox, source_objects, _lock=lock)
    except BaseException:
        lock.close()
        if sandbox is not None:
            sandbox.store.db._conn.close()
        raise
