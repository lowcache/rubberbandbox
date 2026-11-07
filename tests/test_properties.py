"""The invariant under fully hostile components. Oracles read only what the simulated outside
world received, so they are independent of the door's own logic."""

from hypothesis import HealthCheck, event, given, settings
from hypothesis import strategies as st

from rubberbandbox.core import InboundEvent
from rubberbandbox.packs import coding, messaging
from rubberbandbox.packs.messaging.pack import DEFAULT_PUBLISHED, MessagingConfig

CANARY = "CANARY-7f3a9c1e"
SETTINGS = settings(max_examples=500, deadline=None, suppress_health_check=[HealthCheck.too_slow])

text = st.text(max_size=80)
def mostly(good, bad, pct=80):
    """Explicit weighting: st.one_of flattens nested branches, so junk would otherwise dominate."""
    return st.integers(0, 99).flatmap(lambda i: good if i < pct else bad)


junk = st.one_of(st.none(), st.integers(), text, st.lists(text, max_size=3), st.dictionaries(text, text, max_size=2))


# ---- messaging: hostile clerk + hostile inbound traffic ----

def public_renderings():
    out = set()
    for name, tmpl in DEFAULT_PUBLISHED.items():
        if name.startswith("script."):
            for slot in ("price_list", "availability_snapshot"):
                tmpl = tmpl.replace("{" + slot + "}", DEFAULT_PUBLISHED[slot])
            out.add(tmpl)
    return out


WELL_FORMED = st.fixed_dictionaries(
    {
        "need": st.sampled_from(["price", "availability", "booking", "complaint", "other"]),
        "requested_action": st.sampled_from(["reply", "call", "visit", "none"]),
        "mentions": st.lists(st.sampled_from([CANARY, "+15550009999", "https://evil.example/x"]), max_size=3),
    }
)


class HostileClerk:
    def __init__(self, data):
        self.data = data

    def extract(self, _text):
        return self.data.draw(
            mostly(
                WELL_FORMED,
                st.one_of(junk, st.fixed_dictionaries(
                    {
                        "need": st.one_of(st.sampled_from(["price", "availability", "booking", "complaint", "other"]), text),
                        "requested_action": st.one_of(st.sampled_from(["reply", "call", "visit", "none"]), text),
                        "mentions": st.lists(st.one_of(text, st.just(CANARY)), max_size=3),
                    },
                    optional={"extra": text},
                )),
            )
        )


GOOD_ORIGINS = ["+12065550100", "+14255550101", "+12535550102", "a@example.org", "b@example.org"]
origins = st.one_of(
    st.sampled_from(GOOD_ORIGINS),
    st.sampled_from(["+19005550102", "+442079460123", "+1206", "", CANARY]),
)


@st.composite
def events(draw):
    origin = draw(origins)
    natural = "email" if "@" in origin else "sms"
    channel = draw(st.sampled_from([natural, natural, natural, "sms", "email", "fax"]))
    meta = draw(
        st.fixed_dictionaries(
            {
                "dmarc": st.sampled_from(["pass", "pass", "fail", "none"]),
                "from": st.one_of(st.just([origin]), st.lists(st.sampled_from(["a@example.org", "b@evil.example"]), max_size=2)),
                "envelope_from": st.sampled_from([origin, origin, "a@example.org", ""]),
                "reply_to": st.sampled_from([None, "attacker@evil.example"]),
                "auto_submitted": st.sampled_from(["no", "no", "auto-replied"]),
                "list_id": st.sampled_from([None, None, "<list.example>"]),
            }
        )
    )
    return dict(channel=channel, authenticated=draw(st.sampled_from([True, True, True, False])), origin=origin,
                delivery_id=draw(st.sampled_from([f"d{i}" for i in range(12)])), text=draw(text), meta=meta,
                gap=draw(st.sampled_from([0, 60, 600, 90_000])))


@SETTINGS
@given(data=st.data(), evs=st.lists(events(), min_size=1, max_size=8))
def test_messaging_invariant_under_hostile_clerk(data, evs):
    sb, channel, clock = messaging.build(clerk=HostileClerk(data))
    sb.owner_put(CANARY)
    for e in evs:
        clock.advance(e.pop("gap"))
        sb.receive(InboundEvent(received_at=clock(), **e))
        sb.tick()
    clock.advance(400)
    sb.tick()

    event(f"messaging sends: {min(len(channel.sent), 3)}{'+' if len(channel.sent) >= 3 else ''}")
    allowed_bodies = public_renderings()
    cfg = MessagingConfig()
    last_sent: dict[str, float] = {}
    sends = [t for t, ev, _ in sb.store.audit_log() if ev == "door.sent"]
    assert len(sends) == len(channel.sent)
    for (t, r) in zip(sends, channel.sent):
        assert r["kind"] == "msg.reply"
        assert r["body"] in allowed_bodies  # only owner-published text ever leaves
        assert CANARY not in r["body"] and CANARY not in r["to"]
        if r["channel"] == "sms":
            assert r["to"].startswith(cfg.allowed_prefixes) and not r["to"].startswith(cfg.denied_prefixes)
        key = (r["channel"], r["to"])  # an email and an SMS are different destinations
        assert key not in last_sent or t - last_sent[key] >= 86_400  # one per window
        last_sent[key] = t
        if r["channel"] == "email":
            assert "@" in r["to"]


# ---- coding: hostile hands proposing anything, over any visible value ----

ISSUE = "Fix docs per https://docs.example/a and https://evil.example/c?k=1"


class HostileHands:
    def __init__(self, data):
        self.data = data

    def propose(self, view):
        ids = list(view.visible)
        dests = ["git:origin", "pkg:rubberbandbox", "https://evil.example/c?k=1", "https://docs.example/a", CANARY]
        item = st.one_of(
            st.builds(lambda r: {"ref": r}, st.sampled_from(ids or ["V0"])),
            st.builds(lambda s: {"literal": s}, st.one_of(st.sampled_from(dests), text)),
            junk,
        )
        well_formed = st.fixed_dictionaries(
            {
                "kind": st.sampled_from(["http.fetch", "http.post", "git.push", "pkg.publish"]),
                "destination": st.one_of(
                    st.builds(lambda r: {"ref": r}, st.sampled_from(ids or ["V0"])),
                    st.builds(lambda s: {"literal": s}, st.sampled_from(dests)),
                ),
                "payload": st.lists(
                    st.one_of(
                        st.builds(lambda r: {"ref": r}, st.sampled_from(ids or ["V0"])),
                        st.builds(lambda s: {"literal": s}, st.sampled_from([CANARY, "patch"])),
                    ),
                    max_size=2,
                ),
            }
        )
        proposal = mostly(well_formed, st.one_of(
            st.fixed_dictionaries(
                {
                    "kind": st.one_of(st.sampled_from(["http.fetch", "http.post", "git.push", "pkg.publish"]), text),
                    "destination": item,
                    "payload": st.lists(item, max_size=3),
                }
            ),
            junk,
        ))
        return self.data.draw(mostly(st.lists(proposal, min_size=1, max_size=20), junk, pct=90))


@SETTINGS
@given(data=st.data(), public=st.booleans())
def test_coding_invariant_under_hostile_hands(data, public):
    sb, tools, clock = coding.build(hands=HostileHands(data))
    sb.owner_put(CANARY)
    sb.owner_mint(["git.push"], ["git:origin"], ttl=3600)
    meta = {"visibility": "public" if public else "private"}
    sb.receive(InboundEvent("tracker", True, "issue-1", "d1", ISSUE, clock(), meta))

    for k in sorted({e["kind"] for e in tools.log}) or ["none"]:
        event(f"coding crossed: {k}")
    public_links = {"https://docs.example/a", "https://evil.example/c?k=1"} if public else set()
    for entry in tools.log:
        kind, dest, payload = entry["kind"], entry["destination"], list(entry["payload"])
        blob = " ".join([dest, *payload])
        if kind == "git.push":
            assert dest == "git:origin"  # only the granted destination
            assert set(payload) <= {CANARY}  # only trusted values publish; hands literals never do
        elif kind == "http.fetch":
            assert dest in public_links and set(payload) <= public_links  # public reads only
            assert CANARY not in blob
        else:  # http.post and pkg.publish have no grant: they can only cross by owner approval
            raise AssertionError(f"{kind} crossed without approval: {entry}")
