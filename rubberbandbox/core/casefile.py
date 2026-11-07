"""The airlock: clerk output is forced into typed fields; no free-text string crosses."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Mapping

from .labels import Label, Value


class AirlockViolation(ValueError):
    """Clerk output did not fit the schema. Treated as 'uncertain': ask, never act."""


@dataclass(frozen=True)
class EnumField:
    choices: frozenset[str]

    def __init__(self, *choices: str) -> None:
        object.__setattr__(self, "choices", frozenset(choices))


@dataclass(frozen=True)
class IntField:
    lo: int
    hi: int


@dataclass(frozen=True)
class RefList:
    """Clerk-extracted spans (numbers, URLs, names). Stored as tagged values; only ids cross."""

    max_items: int = 8
    max_len: int = 512


# Span shapes for typed refs: a span that does not fit its type never crosses.
REF_SHAPES = {
    "url": re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE),
    "email": re.compile(r"[^@\s<>]+@[^@\s<>]+\.[^@\s<>]+"),
    "phone": re.compile(r"\+?[0-9][0-9 ().-]{5,22}[0-9]"),
    "amount": re.compile(r"[$€£]?[0-9][0-9,]{0,15}(\.[0-9]{1,2})?"),
    "date": re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}|[0-9]{1,2}/[0-9]{1,2}(/[0-9]{2,4})?"),
    "name": re.compile(r"[^\W\d_]+(?:[ '.-][^\W\d_]+){0,5}"),
}


@dataclass(frozen=True)
class TypedRefs:
    """Like RefList, but every span must fully match the shape of `kind` (see REF_SHAPES)."""

    kind: str
    max_items: int = 8
    max_len: int = 512

    def __post_init__(self) -> None:
        if self.kind not in REF_SHAPES:
            raise ValueError(f"unknown ref type {self.kind!r}")


Field = EnumField | IntField | RefList | TypedRefs


@dataclass(frozen=True)
class Schema:
    name: str
    fields: Mapping[str, Field]


@dataclass(frozen=True)
class CaseFile:
    schema: str
    fields: Mapping[str, object]  # enum str | int | tuple of value ids
    origin: str  # id of the raw content value; the hands never get its data
    refs: tuple[str, ...] = field(default=())

    def __getitem__(self, key: str) -> object:
        return self.fields[key]


def validate(
    schema: Schema,
    raw: object,
    origin: Value,
    store_span: Callable[[str, Label], Value],
) -> CaseFile:
    """Return a CaseFile or raise AirlockViolation. Spans inherit the origin's label."""
    if not isinstance(raw, dict):
        raise AirlockViolation("clerk output is not an object")
    extra = set(raw) - set(schema.fields)
    if extra:
        raise AirlockViolation(f"unknown fields: {sorted(map(str, extra))}")
    out: dict[str, object] = {}
    refs: list[str] = []
    for name, spec in schema.fields.items():
        if name not in raw:
            raise AirlockViolation(f"missing field: {name}")
        val = raw[name]
        if isinstance(spec, EnumField):
            if not isinstance(val, str) or val not in spec.choices:
                raise AirlockViolation(f"{name}: not one of the enum choices")
            out[name] = val
        elif isinstance(spec, IntField):
            if type(val) is not int or not spec.lo <= val <= spec.hi:
                raise AirlockViolation(f"{name}: not an int in [{spec.lo}, {spec.hi}]")
            out[name] = val
        elif isinstance(spec, (RefList, TypedRefs)):
            if not isinstance(val, list) or len(val) > spec.max_items:
                raise AirlockViolation(f"{name}: not a list of at most {spec.max_items}")
            shape = REF_SHAPES[spec.kind] if isinstance(spec, TypedRefs) else None
            ids = []
            for span in val:
                if not isinstance(span, str) or not 0 < len(span) <= spec.max_len:
                    raise AirlockViolation(f"{name}: bad span")
                if shape is not None and not shape.fullmatch(span):
                    raise AirlockViolation(f"{name}: span is not a {spec.kind}")
                ids.append(store_span(span, origin.label).id)
            out[name] = tuple(ids)
            refs.extend(ids)
        else:  # pragma: no cover - schema construction error
            raise TypeError(f"unknown field type for {name}")
    return CaseFile(schema.name, out, origin.id, tuple(refs))
