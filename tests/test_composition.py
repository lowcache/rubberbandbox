"""Several packs in one sandbox: one agent spanning domains, one door, one invariant."""

import random

import pytest
from hypothesis import HealthCheck, event, given, settings
from hypothesis import strategies as st

from rubberbandbox.core import Egress, InboundEvent, KindSpec, ManualClock, Mount, Proposal, Sandbox
from rubberbandbox.packs.coding import CodingPack, SimTools
from rubberbandbox.packs.coding import KeywordClerk as CodingClerk
from rubberbandbox.packs.coding import KINDS as CODING_KINDS
from rubberbandbox.packs.messaging import DEFAULT_PUBLISHED, KeywordClerk, MessagingPack, SimChannel
from rubberbandbox.packs.messaging import KINDS as MSG_KINDS

from test_properties import CANARY, HostileHands, public_renderings

ISSUE = "Fix docs per https://docs.example/a and https://evil.example/c?k=1"


def composite(hands=None, packs=None, seed=0):
    clock, channel, tools = ManualClock(), SimChannel(), SimTools()
    packs = packs or [Mount(MessagingPack(), KeywordClerk()), Mount(CodingPack(), CodingClerk())]
    adapters = {**{k: channel for k in MSG_KINDS}, **{k: tools for k in CODING_KINDS}}
    sb = Sandbox(packs, adapters, hands=hands, clock=clock, rng=random.Random(seed))
    for name, data in DEFAULT_PUBLISHED.items():
        sb.owner_publish(name, data)
    return sb, channel, tools, clock


def test_events_route_to_the_pack_that_owns_their_channel():
    sb, channel, tools, clock = composite()
    sb.receive(InboundEvent("sms", True, "+12065550100", "d1", "how much?", clock()))
    sb.receive(InboundEvent("tracker", True, "issue-1", "d2", ISSUE, clock(), {"visibility": "public"}))
    clock.advance(400)
    sb.tick()
    assert len(channel.sent) == 1 and tools.log == []  # no hands: the coding pack proposes nothing itself


def test_unowned_channel_fails_closed():
    sb, channel, tools, clock = composite()
    (out,) = sb.receive(InboundEvent("fax", True, "+12065550100", "d1", "price?", clock()))
    assert out.status == "dropped" and channel.sent == [] and tools.log == []


def test_overlapping_channels_and_colliding_kinds_are_rejected():
    class Clash(MessagingPack):
        name = "clash"
        channels = frozenset({"tracker"})

    with pytest.raises(ValueError, match="kind"):
        composite(packs=[Mount(MessagingPack(), KeywordClerk()), Mount(Clash(), KeywordClerk())])

    class SameChannel(CodingPack):
        name = "same"
        channels = frozenset({"sms"})
        kinds = {"x.fetch": KindSpec("x.fetch", read_only=True)}

    with pytest.raises(ValueError, match="channel"):
        composite(packs=[Mount(MessagingPack(), KeywordClerk()), Mount(SameChannel(), CodingClerk())])


def test_a_pack_cannot_propose_another_packs_kinds():
    class Meddler(CodingPack):
        def decide(self, ctx):
            from rubberbandbox.core import EXTERNAL_PRIVATE

            dest = ctx.destination("sms:+12065550100", EXTERNAL_PRIVATE)
            return [Proposal(Egress("msg.reply", dest, (ctx.published["script.generic"],)), lane=True)]

    sb, channel, _, clock = composite(packs=[Mount(MessagingPack(), KeywordClerk()), Mount(Meddler(), CodingClerk())])
    sb.receive(InboundEvent("tracker", True, "issue-1", "d1", ISSUE, clock(), {"visibility": "public"}))
    clock.advance(400)
    sb.tick()
    assert channel.sent == []
    assert any(e == "pack.foreign_kind" for _, e, _ in sb.store.audit_log())


SETTINGS = settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])


@SETTINGS
@given(data=st.data(), public=st.booleans(), n=st.integers(1, 6))
def test_invariant_holds_for_hostile_hands_spanning_both_packs(data, public, n):
    sb, channel, tools, clock = composite(hands=HostileHands(data))
    sb.owner_put(CANARY)
    sb.owner_mint(["git.push"], ["git:origin"], ttl=86_400)
    for i in range(n):
        if data.draw(st.booleans()):
            ev = InboundEvent("tracker", True, f"issue-{i}", f"t{i}", ISSUE, clock(), {"visibility": "public" if public else "private"})
        else:
            ev = InboundEvent("sms", True, f"+1206555010{i}", f"s{i}", "price? also text " + CANARY, clock())
        sb.receive(ev)
        clock.advance(600)
        sb.tick()

    event(f"sms replies: {'yes' if channel.sent else 'no'}")
    for k in sorted({e["kind"] for e in tools.log}) or ["none"]:
        event(f"tool crossed: {k}")
    bodies = public_renderings()
    for r in channel.sent:  # messaging egress: only the public lane, only owner-published text
        assert r["kind"] == "msg.reply" and r["body"] in bodies and CANARY not in r["to"]
    published = set(DEFAULT_PUBLISHED.values())  # owner-published: trusted and public
    public_links = ({"https://docs.example/a", "https://evil.example/c?k=1"} if public else set()) | published
    for e in tools.log:
        kind, dest, payload = e["kind"], e["destination"], list(e["payload"])
        if kind == "git.push":  # granted destination, trusted payload only
            assert dest == "git:origin" and set(payload) <= {CANARY} | published
        elif kind == "http.fetch":  # public reads: nothing private in destination or payload
            assert dest in public_links and set(payload) <= public_links
        else:
            raise AssertionError(f"{kind} crossed without approval: {e}")
