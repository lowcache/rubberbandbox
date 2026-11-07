"""Provenance labels: integrity (who authored it) x confidentiality (who may see it)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable


class Integrity(Enum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


class Confidentiality(Enum):
    PUBLIC = "public"
    PRIVATE = "private"


@dataclass(frozen=True)
class Label:
    integrity: Integrity
    confidentiality: Confidentiality

    @property
    def trusted(self) -> bool:
        return self.integrity is Integrity.TRUSTED

    @property
    def public(self) -> bool:
        return self.confidentiality is Confidentiality.PUBLIC

    def join(self, other: Label) -> Label:
        """Taint only rises: untrusted and private both dominate."""
        return Label(
            Integrity.UNTRUSTED if not (self.trusted and other.trusted) else Integrity.TRUSTED,
            Confidentiality.PUBLIC if (self.public and other.public) else Confidentiality.PRIVATE,
        )


OWNER_PUBLIC = Label(Integrity.TRUSTED, Confidentiality.PUBLIC)
OWNER_PRIVATE = Label(Integrity.TRUSTED, Confidentiality.PRIVATE)
EXTERNAL_PUBLIC = Label(Integrity.UNTRUSTED, Confidentiality.PUBLIC)
EXTERNAL_PRIVATE = Label(Integrity.UNTRUSTED, Confidentiality.PRIVATE)


def join_all(labels: Iterable[Label]) -> Label:
    """Join with a private baseline: nothing is public unless provenance proves it (A3)."""
    out = OWNER_PRIVATE
    for label in labels:
        out = out.join(label)
    return out


def join_proven(labels: Iterable[Label]) -> Label:
    """Join with no baseline; for values built only from labeled parts (e.g. rendered scripts)."""
    labels = list(labels)
    if not labels:
        return OWNER_PRIVATE
    out = labels[0]
    for label in labels[1:]:
        out = out.join(label)
    return out


@dataclass(frozen=True)
class Value:
    """A datum plus where it came from. Only `id`s cross the airlock; `data` stays in the store."""

    id: str
    data: str
    label: Label
    source: str
    first_seen: float
