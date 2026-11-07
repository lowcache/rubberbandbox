# Rubber Sandbox — reference implementation (v1)

A domain-agnostic sandbox for LLM agents, built from the doctrine in
`rubber-sandbox-design-spec-v0.3.md`. The core knows nothing about any workflow. Workflows
plug in as **packs**, and v1 ships two of them so generality is tested rather than claimed:

- `packs/messaging`: inbound SMS and email for a small service business. It has no hands;
  replies leave only through the public lane (the spec's "mail slot").
- `packs/coding`: an issue-driven coding agent whose hands propose fetches, pushes, posts and
  publishes. It was written by a separate author against the core's public API only, with
  zero core edits.

## Run

```sh
nix develop -c python -m pytest -q          # full suite (property tests included)
nix develop -c python -m rubbersand.cli attacks   # adversarial messaging corpus
nix develop -c python -m rubbersand.cli clean     # benign corpus: replies, holds, owner notices
nix develop -c python -m rubbersand.cli clean --clerk claude   # same, with the Claude clerk (needs API credentials)
```

The runtime uses only the Python standard library. Development needs pytest and Hypothesis,
both provided by the flake.

## The invariant

Every egress (send, fetch, push, publish, anything) crosses one door, and the door checks the
invariant itself on every crossing, independently of the routing logic, and again at dispatch:

| Path | Allowed when |
|---|---|
| `approval` | the owner approved exactly this egress; single use |
| `grant` | an active, owner-minted, expiring grant covers kind + destination; publishes need trusted payload |
| `lane` | an unexpired public-lane receipt for exactly this egress; payload is owner-published |
| `public_read` | a read-only kind whose destination and payload are all public |

Anything else is held for the owner (fail closed) or silently dropped (public lane refusals).

## Layout

```
rubbersand/core/      labels · store · casefile (airlock) · grants · invariant · public_lane
                      approvals (digest) · door · sandbox (wiring + routing) · types (plug points)
rubbersand/packs/     one directory per workflow; imports only `rubbersand.core`
corpus/               messaging attack corpus (32 cases) and clean corpus (40 messages)
tests/                unit, corpus, structural guards, and property tests
```

A pack supplies a schema (enums and references only), its egress kinds, inbound labelling,
route validation for the public lane, routing rules (`decide`), and a cluster key. Tool adapters
are handed to the sandbox at construction, and only the door holds them.

## What the tests establish

- **Property tests with fully hostile components.** Hypothesis drives a hostile clerk (arbitrary
  output) through the messaging pack, and hostile hands (arbitrary proposals over every visible
  value) through the coding pack. The oracles read only what the simulated outside world
  received, so they don't depend on the door's own logic.
- **Mutation check.** Twelve deliberately broken guards were each caught by the suite,
  including each inner layer of the two-layer defenses.
- **Independent review.** A separate model reviewed the core for correctness. All four of its
  findings were reproduced as failing tests, then fixed: a stale clock across one dispatch batch,
  unauthenticated metadata claiming public provenance, lane receipts usable before their slot,
  and non-canonical id parsing.
- **Structural guards.** The core imports no pack, packs import only the core's public API,
  and no component other than the door holds an adapter.

## Decisions made in the build (not in the spec)

1. **No standing access.** An owner approval authorizes one egress. It does not authorize the
   destination for later sends; repeated sends need a grant, which expires. This is stricter
   than the spec's v1 wording ("approval on first send to anyone new"), and it makes probation
   rate limits unnecessary (open hole #5).
2. **A missed slot cancels the reply.** A public-lane reply not dispatched by `send_at + grace`
   is never sent late, and the per-destination window is measured between delivery times. The
   property tests found the bug that motivated this: a stalled dispatcher bunched two "one per
   day" replies 400 s apart.
3. **The hands see tokens, never data** (`source=… trusted=… public=…`) and act by reference.
   Literals they produce carry the join of everything they were shown.
4. **Fetching is governed by labels.** Fetching a URL from a public source is a public read.
   Fetching anything private-derived (including links in private inbound content) is held for
   the owner. The messaging pack declares no fetch kind, so the spec's "never fetch inbound
   content" rule holds there by construction.
5. **Unreadable clerk output asks, never acts.** It produces an owner notice and no reply.
6. **Unauthenticated provenance is never public or trusted.** The core enforces this whatever
   label the pack assigns.
7. **Pack composition.** A sandbox mounts several packs (`Mount(pack, clerk)`). Each pack owns a
   disjoint set of inbound channels and uniquely named kinds; the sandbox refuses overlaps at
   construction. An event on a channel no pack owns is dropped. A pack's own rules may only
   propose its own kinds; only the hands span domains. Cluster keys are namespaced by pack.
8. **The Claude clerk** (`rubbersand/clerks/claude.py`) is stateless and tool-less, and its
   output is constrained to a JSON schema generated from the pack's `Schema`. It defaults to
   `claude-opus-5-5` at low effort, with server-side refusal fallbacks enabled. Any failure
   (refusal, truncation, malformed output, API error) becomes an owner notice, never an action.

## Known limits

- **Choice channel.** The hands never read private data, but *which* permitted action they
  choose (for example, which public URL to read) can depend on the current case file's enum
  fields. That is a low-bandwidth side channel of the kind CaMeL also documents. Keep public-read
  kinds out of packs that don't need them, as the messaging pack does.
- **Clerk accuracy is a utility limit, not a safety one.** A misclassification selects a
  different public script or misses an owner notice; it can't widen egress.

## Not in v1

Real SMS and email providers, phone approvals, owner-initiated mode, the
learning immune system (v2), and deployment. Plugging any of these in should need only a new
adapter, clerk, or hands implementation, not a core change.
