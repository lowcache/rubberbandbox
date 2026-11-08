"""Wiring plus the bones' routing: which authorization path, if any, a proposal takes."""

from __future__ import annotations

import json
import random
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable, Mapping, Sequence

from .approvals import Approvals, Digest, DigestConfig
from .casefile import AirlockViolation, CaseFile, validate
from .door import Door
from .grants import Grant, GrantBook
from .labels import EXTERNAL_PRIVATE, OWNER_PRIVATE, OWNER_PUBLIC, Label, Value, join_all, join_proven
from .public_lane import LaneConfig, PublicLane
from .registry import PATH_MOVED
from .store import Store
from .types import (
    Authorization,
    Clerk,
    DecideContext,
    Egress,
    Hands,
    HandsView,
    InboundEvent,
    KindSpec,
    Notice,
    Pack,
    Proposal,
    RouteReceipt,
    ToolAdapter,
)

if TYPE_CHECKING:
    from .registry import ManifestRegistry

MAX_PROPOSALS = 16
MAX_LITERAL = 2048


@dataclass(frozen=True)
class Mount:
    """A pack and the clerk that reads its inbound content."""

    pack: Pack
    clerk: Clerk | None  # None: inbound on its channels fails closed at the airlock


@dataclass(frozen=True)
class Outcome:
    kind: str
    destination: str
    status: str  # sent | scheduled | held | dropped | refused | failed | noticed
    reason: str


class ManualClock:
    def __init__(self, start: float = 1_000_000.0) -> None:
        self.t = start

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


def _grant_blocker(spec: KindSpec, eg: Egress) -> str | None:
    """Why a covering grant still may not carry this egress (mirrors the invariant's grant path)."""
    if spec.publishes and not all(v.label.trusted for v in eg.payload):
        return "publish with untrusted payload"
    if not spec.read_only and not all(v.label.trusted for v in eg.control):
        return "untrusted control args"
    return None


class Sandbox:
    def __init__(
        self,
        mounts: Sequence[Mount],
        adapters: Mapping[str, ToolAdapter],
        *,
        hands: Hands | None = None,
        clock: Callable[[], float],
        rng: random.Random | None = None,
        lane: LaneConfig = LaneConfig(),
        digest: DigestConfig = DigestConfig(),
        db: str = ":memory:",
    ) -> None:
        if not mounts:
            raise ValueError("at least one pack must be mounted")
        self.mounts = list(mounts)
        self._by_channel: dict[str, Mount] = {}
        self.kinds: dict[str, KindSpec] = {}
        self._kind_owner: dict[str, Pack] = {}
        for m in self.mounts:
            for ch in m.pack.channels:
                if ch in self._by_channel:
                    raise ValueError(f"channel {ch!r} claimed by {self._by_channel[ch].pack.name} and {m.pack.name}")
                self._by_channel[ch] = m
            for name, spec in m.pack.kinds.items():
                if name in self.kinds:
                    raise ValueError(f"kind {name!r} declared by {self._kind_owner[name].name} and {m.pack.name}")
                self.kinds[name] = spec
                self._kind_owner[name] = m.pack
        self.hands = hands
        self.clock = clock
        self.store = Store(db)
        self.grants = GrantBook(self.store)
        self.lane = PublicLane(self.store, lane, rng or random.Random())
        self.approvals = Approvals(self.store, digest)
        self._door = Door(self.store, self.grants, self.kinds, adapters, clock)
        self.published: dict[str, Value] = {}
        self.workspace: list[Value] = []
        self.stiffened: set[str] = set()
        self.registry: ManifestRegistry | None = None
        self.revoked = 0  # bumped by every revocation; live tunnels re-check when it moves

    def attach(self, registry: ManifestRegistry) -> None:
        """The registry binds named tool calls; the door re-checks every one against it."""
        self.registry = registry
        self._door.calls = registry.check_egress

    # ---- owner side: the only places trust is minted or lowered ----

    def owner_publish(self, name: str, data: str) -> Value:
        v = self.store.put(data, OWNER_PUBLIC, "owner:published", self.clock())
        self.published[name] = v
        return v

    def owner_put(self, data: str) -> Value:
        """Owner-private data visible to the hands as a token (e.g. a credential, a file)."""
        v = self.store.put(data, OWNER_PRIVATE, "owner:workspace", self.clock())
        self.workspace.append(v)
        return v

    def owner_mint(self, kinds: list[str], destinations: list[str], ttl: float) -> Grant:
        return self.grants.mint(kinds, destinations, ttl, self.clock())

    def owner_end(self, grant: Grant) -> None:
        self.grants.end(grant.id, self.clock())
        self.revoked += 1

    def owner_approve(self, aid: str) -> Outcome:
        now = self.clock()
        egress = self.approvals.egress_of(aid)
        if egress is None:
            return Outcome("?", "?", "refused", "no such approval")
        auth = self.approvals.approve(aid, now)
        status, reason = self._door.cross(egress, auth)
        if status == "refused" and self.registry is not None and reason.startswith(PATH_MOVED):
            fresh = self.registry.rebind(egress)  # a different file than the owner approved: ask again
            if isinstance(fresh, Egress):
                return self._hold(fresh, self._cluster(fresh.destination.data, self._kind_owner[fresh.kind]), reason, now)
        return Outcome(egress.kind, egress.destination.data, status, reason)

    def owner_deny(self, aid: str) -> None:
        self.approvals.deny(aid, self.clock())

    def digest(self) -> Digest | None:
        return self.approvals.digest(self.clock())

    def stiffen(self, cluster: str) -> None:
        """Tighten private work for a cluster. Never touches the public lane."""
        self.stiffened.add(cluster)
        self.revoked += 1
        self.store.audit(self.clock(), "stiffen", cluster=cluster)

    def tick(self) -> list[tuple[str, str]]:
        return self._door.tick()

    def connect(self, kind: str, target: str) -> Outcome:
        """One outbound connection a box asked for (its proxy): egress to `target`, by grant only.
        A refusal lands in the digest as a notice, never an interrupt: the owner may mint a grant."""
        now = self.clock()
        spec, owner = self.kinds.get(kind), self._kind_owner.get(kind)
        if spec is None or owner is None:
            return Outcome(kind, target, "refused", "unknown kind")
        dest = self.store.put(target, EXTERNAL_PRIVATE, f"{kind}:request", now)  # chosen inside the box
        cluster = self._cluster(target, owner)
        grant = self.grants.find(kind, target, now) if spec.grantable and cluster not in self.stiffened else None
        if grant is None:
            self.approvals.notice("net.refused", cluster, dest.id, now)
            self.store.audit(now, "net.refused", kind=kind, dest=dest.id, target=target)
            return Outcome(kind, target, "refused", "no grant covers this target")
        return Outcome(kind, target, *self._door.cross(Egress(kind, dest, ()), Authorization("grant", grant.id)))

    def still_allowed(self, kind: str, target: str) -> bool:
        """Would a connection to `target` be authorized right now? Live tunnels ask this; it dials nothing."""
        now = self.clock()
        spec, owner = self.kinds.get(kind), self._kind_owner.get(kind)
        if spec is None or owner is None or not spec.grantable or self._cluster(target, owner) in self.stiffened:
            return False
        if self.grants.find(kind, target, now) is None:
            return False
        probe = Egress(kind, Value("V0", target, EXTERNAL_PRIVATE, f"{kind}:recheck", now), ())  # never stored
        return self._door.calls is None or self._door.calls(probe) is None

    # ---- manifest changes (driven by the registry) ----

    def set_kind(self, spec: KindSpec) -> None:
        """Swap the semantics of a mounted kind, in the bones and the door together."""
        self._door.set_kind(spec)
        self.kinds[spec.name] = spec

    def invalidate_kind(self, kind: str) -> None:
        """Fail closed: every grant, approval, lane receipt and scheduled send issued for `kind`
        under earlier semantics stops authorizing anything."""
        now = self.clock()
        with self.store.tx() as db:
            grants = [gid for gid, ks in db.execute("SELECT id, kinds FROM grants WHERE ended=0")
                      if kind in json.loads(ks)]
            approvals = [aid for aid, blob in db.execute(
                "SELECT id, egress FROM approvals WHERE status IN ('pending','approved') AND consumed=0")
                if json.loads(blob)["kind"] == kind]
            scheduled = [sid for sid, blob in db.execute("SELECT id, egress FROM scheduled WHERE status='pending'")
                         if json.loads(blob)["kind"] == kind]
            db.executemany("UPDATE grants SET ended=1 WHERE id=?", [(i,) for i in grants])
            db.executemany("UPDATE approvals SET status='invalidated' WHERE id=?", [(i,) for i in approvals])
            db.executemany("UPDATE scheduled SET status='invalidated' WHERE id=?", [(i,) for i in scheduled])
            receipts = db.execute("UPDATE receipts SET consumed=1 WHERE kind=? AND consumed=0", (kind,)).rowcount
        self.revoked += 1
        self.store.audit(now, "kind.invalidated", kind=kind, grants=len(grants), approvals=len(approvals),
                         scheduled=len(scheduled), receipts=receipts)

    # ---- inbound ----

    def receive(self, event: InboundEvent) -> list[Outcome]:
        now = self.clock()
        mount = self._by_channel.get(event.channel)
        if mount is None:  # fail closed: no pack owns this channel
            self.store.audit(now, "inbound.unrouted", channel=event.channel, delivery=event.delivery_id)
            return [Outcome("inbound", event.origin, "dropped", f"no pack for channel {event.channel!r}")]
        pack = mount.pack
        label = pack.inbound_label(event)
        if not event.authenticated:  # unauthenticated provenance can never claim trust or publicity
            label = label.join(EXTERNAL_PRIVATE)
        raw = self.store.put(event.text, label, event.channel, now)
        self.store.audit(now, "inbound", channel=event.channel, delivery=event.delivery_id,
                         authenticated=event.authenticated, raw=raw.id)
        try:
            extracted = mount.clerk.extract(event.text)
        except Exception as exc:  # a clerk that fails (API error, refusal) is just uncertain
            extracted = None
            self.store.audit(now, "clerk.error", raw=raw.id, error=repr(exc))
        try:
            cf = validate(
                pack.schema,
                extracted,
                raw,
                lambda span, label: self.store.put(span, label, f"{event.channel}:span", now),
            )
        except AirlockViolation as exc:
            # uncertain means ask, never act
            self.store.audit(now, "airlock.reject", raw=raw.id, reason=str(exc))
            self.approvals.notice("unreadable", self._cluster(event.origin, pack), raw.id, now)
            return [Outcome("airlock", event.origin, "noticed", str(exc))]

        route = pack.route(event)
        ctx = DecideContext(
            casefile=cf,
            event=event,
            route=route,
            published=dict(self.published),
            render=self._render,
            destination=lambda key, label: self.store.put(key, label, f"{event.channel}:route", now),
        )
        items: list[Proposal | Notice] = []
        for item in pack.decide(ctx):
            if isinstance(item, Proposal) and self._kind_owner.get(item.egress.kind) is not pack:
                # packs stay in their lane: only the hands span domains
                self.store.audit(now, "pack.foreign_kind", pack=pack.name, kind=item.egress.kind)
                continue
            items.append(item)
        if self.hands is not None:
            items.extend(self._from_hands(cf, raw, now))

        outcomes = []
        for item in items:
            if isinstance(item, Notice):
                self.approvals.notice(item.topic, self._cluster(event.origin, pack), item.ref, now)
                outcomes.append(Outcome("notice", item.topic, "noticed", ""))
            else:
                outcomes.append(self._route(item, route, now))
        return outcomes

    def _route(self, prop: Proposal, route: RouteReceipt | None, now: float) -> Outcome:
        eg = prop.egress
        dest = eg.destination.data
        spec = self.kinds.get(eg.kind)
        if spec is None:
            self.store.audit(now, "bones.drop", kind=eg.kind, reason="unknown kind")
            return Outcome(eg.kind, dest, "dropped", "unknown kind")
        cluster = self._cluster(dest, self._kind_owner[eg.kind])

        if prop.lane:
            # public lane: blind to suspicion, refusals are silent (no owner interruption)
            if route is None:
                self.store.audit(now, "lane.refused", dest=eg.destination.id, reason="no constrained route")
                return Outcome(eg.kind, dest, "dropped", "no constrained route")
            auth, send_at, why = self.lane.admit(eg, route, self.kinds, now)
            if auth is None:
                self.store.audit(now, "lane.refused", dest=eg.destination.id, reason=why)
                return Outcome(eg.kind, dest, "dropped", why)
            return Outcome(eg.kind, dest, *self._door.cross(eg, auth, send_at))

        # private work: stiffening applies here only
        if cluster in self.stiffened:
            return self._hold(eg, cluster, "cluster stiffened", now)
        grant = self.grants.find(eg.kind, dest, now) if spec.grantable else None
        blocked = _grant_blocker(spec, eg)
        if grant is not None and blocked is None:
            return Outcome(eg.kind, dest, *self._door.cross(eg, Authorization("grant", grant.id)))
        if spec.read_only and all(v.label.public for v in (eg.destination, *eg.payload, *eg.control)):
            return Outcome(eg.kind, dest, *self._door.cross(eg, Authorization("public_read", "")))
        if not spec.grantable:
            reason = "kind needs owner approval per egress"
        elif grant is None:
            reason = "no grant covers this egress"
        else:
            reason = blocked or ""
        return self._hold(eg, cluster, reason, now)

    def _hold(self, eg: Egress, cluster: str, reason: str, now: float) -> Outcome:
        aid = self.approvals.hold(eg, cluster, reason, now)
        return Outcome(eg.kind, eg.destination.data, "held", f"{aid}: {reason}")

    def _render(self, template: Value, slots: Mapping[str, Value]) -> Value:
        text = template.data
        for name, v in slots.items():
            text = text.replace("{" + name + "}", v.data)
        label = join_proven([template.label, *(v.label for v in slots.values())])
        return self.store.put(text, label, "render", self.clock())

    def _cluster(self, destination: str, pack: Pack) -> str:
        try:
            return f"{pack.name}/{pack.cluster(destination)}"
        except Exception:
            return f"{pack.name}/unknown"

    # ---- the hands: see tokens, act by reference ----

    def _hands_view(self, cf: CaseFile) -> tuple[HandsView, dict[str, Value]]:
        visible: dict[str, Value] = {}
        for vid in (*cf.refs, *(v.id for v in self.workspace), *(v.id for v in self.published.values())):
            v = self.store.get(vid)
            if v is not None:
                visible[vid] = v
        tokens = {
            vid: f"source={v.source} trusted={'yes' if v.label.trusted else 'no'} public={'yes' if v.label.public else 'no'}"
            for vid, v in visible.items()
        }
        tools = self.registry.catalog() if self.registry else {}
        return HandsView(dict(cf.fields), tokens, cf.schema, tools), visible

    def _from_hands(self, cf: CaseFile, raw: Value, now: float) -> list[Proposal]:
        assert self.hands is not None
        view, visible = self._hands_view(cf)
        # literals carry everything the hands were shown, including the inbound content's taint
        context: Label = join_all([raw.label, *(v.label for v in visible.values())])
        try:
            proposed = self.hands.propose(view)
        except Exception as exc:
            self.store.audit(now, "hands.error", error=repr(exc))
            return []
        if not isinstance(proposed, list):
            self.store.audit(now, "hands.malformed", reason="not a list")
            return []
        if len(proposed) > MAX_PROPOSALS:
            self.store.audit(now, "hands.truncated", proposed=len(proposed), kept=MAX_PROPOSALS)
        out: list[Proposal] = []
        for item in proposed[:MAX_PROPOSALS]:
            eg = self._hands_egress(item, visible, context, now)
            if not isinstance(eg, Egress):
                self.store.audit(now, "hands.malformed", reason=eg or "bad proposal")
                continue
            out.append(Proposal(eg))
        return out

    def _hands_egress(self, item: object, visible: dict[str, Value], context: Label, now: float) -> Egress | str | None:
        if not isinstance(item, dict) or not isinstance(item.get("kind"), str):
            return None
        if "args" in item:
            return self._hands_call(item["kind"], item["args"], visible, context, now)
        payload_items = item.get("payload", [])
        if not isinstance(payload_items, list) or len(payload_items) > MAX_PROPOSALS:
            return None
        control_items = item.get("control", [])
        if not isinstance(control_items, list) or len(control_items) > MAX_PROPOSALS:
            return None
        dest = self._hands_value(item.get("destination"), visible, context, now)
        payload = [self._hands_value(p, visible, context, now) for p in payload_items]
        control = [self._hands_value(c, visible, context, now) for c in control_items]
        if dest is None or any(p is None for p in (*payload, *control)):
            return None
        return Egress(item["kind"], dest, tuple(payload), tuple(control))  # type: ignore[arg-type]

    def _hands_call(self, kind: str, items: object, visible: dict[str, Value], context: Label, now: float) -> Egress | str | None:
        if self.registry is None or not isinstance(items, dict) or len(items) > MAX_PROPOSALS:
            return None
        args = {a: self._hands_value(x, visible, context, now) for a, x in items.items() if isinstance(a, str)}
        if len(args) != len(items) or any(v is None for v in args.values()):
            return None
        return self.registry.bind(kind, args)  # type: ignore[arg-type]

    def _hands_value(self, x: object, visible: dict[str, Value], context: Label, now: float) -> Value | None:
        if not isinstance(x, dict) or len(x) != 1:
            return None
        if "ref" in x:
            return visible.get(x["ref"]) if isinstance(x["ref"], str) else None
        if "literal" in x and isinstance(x["literal"], str) and len(x["literal"]) <= MAX_LITERAL:
            return self.store.put(x["literal"], context, "hands", now)
        return None
