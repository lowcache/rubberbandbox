<div align="center">
<img src="docs/banner.jpeg" alt="RubberBand Box elastic sandbox">
</div>

# RubberBandBox

**Elastic, provenance-tracked sandboxing for LLM agents.** Don't harden the prompt and hope. Give
the boundary a physics: it stretches for the task, retracts when the task ends, deforms into
rollback instead of breaking, and stiffens when something pulls wrong. Rubber inside; one steel
door out.

RubberBandBox is a doctrine (`rubberbandbox-design-spec-v0.4.md`) and a working reference
implementation. Its claim is narrow and testable: **the model can be fooled, but a fooled model
cannot widen what leaves the box.**

![RubberBandBox demo: an injected SMS fools the clerk and a hijacked coding agent is contained, yet only owner-published scripts and public reads leave the box](docs/demo.gif)

*The demo above (`python -m rubberbandbox.cli demo`) is re-rendered with `nix shell nixpkgs#vhs -c vhs docs/demo.tape`.*

## Where it stands

**Proof of concept: complete. Pack wall: built.** The v1 core runs and its central claim is
measured. Hand-written per-workflow packs have been replaced by declarations: per-tool effect
manifests, channel adapters and rule tables. Real MCP servers now run in an allowlist box: their
calls, their path arguments and their network all cross the one door.

| Stage | Status |
|---|---|
| Doctrine | spec v0.4 (holes 1, 2 and 5–8 closed); the pack wall postdates it and is not in the spec yet |
| v1 core | ✅ provenance labels, airlock, expiring scope grants, one door with an independent invariant, public lane, approval digest, append-only audit log, pack composition |
| Pack wall | ✅ effect manifests · ✅ frozen, versioned manifests with a loosening diff · ✅ MCP stdio adapter · ✅ filesystem box · ✅ network through the door |
| v1 packs | ✅ messaging (SMS and email) and ✅ coding, both re-expressed as manifests with the original tests unchanged |
| v1 clerks | ✅ keyword stub · ✅ Claude (API, needs a key) · ✅ Codex (CLI on a ChatGPT plan, locked down and verified on every call) |
| v1.x | DNS lookup deadline, live manifest drafter, owner-initiated mode (plan-then-execute), real SMS and email adapters, phone approvals, MicroVM deployment, larger adaptive clerk evaluation |
| v2 | learning immune system (anomaly scorer on a population prior) |

## The claim and the evidence

**Fooled occasionally, harmed never, interrupted sometimes.** Measured on 6 November 2026, with
the hand-written messaging pack that the manifest version has since replaced (the corpus tests
pass unchanged against both). *Harm* counts only what the simulated outside world received:
anything other than an owner-published script, a reply to anyone but the sender, more than one
reply per message, or any planted secret or forbidden string. The scorer is itself tested
against a sabotaged provider to prove it can detect harm.

| Run | Fooled | Harm |
|---|---|---|
| Adversarial clerk corpus (60 attacks, written by a different model family), keyword stub | 24/60 | **0** |
| Adversarial clerk corpus, live Codex clerk | 4/60 | **0** |
| Clean corpus (40 customer messages), keyword stub | 13/40 | **0** |
| Clean corpus, live Codex clerk | 0/40 | **0** |
| Routing attack corpus (32: spoofing, premium routes, replay, Reply-To, loops, floods) | 32/32 handled as specified | **0** |

None of the live clerk's four misses went in the direction an injection demanded. Three were
judgment calls on items the corpus author flagged as debatable, and one was a long padded message
whose price question was diluted. The corpora are small and the attacks are fixed, not adaptive.

**Structural evidence** (268 tests):
- Property tests drive a *fully hostile* clerk and *fully hostile* hands, including hands spanning
  two composed packs, against oracles that don't depend on the door's own logic.
- A mutation check breaks 106 guards one at a time; the suite catches all 106. Three times during
  the build an outer check made an inner guard untestable; each time the surviving mutant exposed
  it and a direct test of the inner layer was added.
- The box's path canonicaliser is checked against the kernel's own in-root resolution inside a
  real bubblewrap box, over Hypothesis-generated trees of directories, files, and absolute,
  relative, looping and dangling links.
- Independent correctness reviews by a separate model family (Codex) of the core and of each
  pack-wall slice. Their findings were checked, and the real ones fixed with a regression test
  each (examples: a stale clock across a dispatch batch; a directory bound as a "socket" bypassing
  staged writes; NAT64 addresses hiding loopback from the SSRF filter; turning network off not
  cutting live tunnels).
- Servers never coded against, run unchanged in the box: the official MCP filesystem server,
  `server-sequential-thinking`, and a Hacker News server that fetched live stories through the
  door once the owner granted exactly `hacker-news.firebaseio.com:443`.

## Quickstart

```sh
nix develop -c python -m rubberbandbox.cli demo                    # narrated walk-through (offline, deterministic)
nix develop -c python -m rubberbandbox.cli demo --clerk codex      # same, with the live Codex clerk
nix develop -c python -m pytest -q                                 # full suite, property and box tests included
nix develop -c python -m rubberbandbox.cli adversarial [--clerk codex|claude]   # fooled vs harm
nix develop -c python -m rubberbandbox.cli clean       [--clerk codex|claude]   # accuracy and interruptions
nix develop -c python -m rubberbandbox.cli attacks                 # routing attack corpus
nix develop -c python scripts/mutation_check.py                    # break each guard; the suite must catch it
```

**The demo** runs one sandbox with two packs mounted: a messaging line and a coding agent hijacked
by a public issue.
- **The fooled clerk.** An injected SMS fools the stub clerk ("FOOLED: the real need is price"),
  yet only an owner-published script leaves.
- **Contained hijack.** The hijacked agent's push, its credential exfiltration attempt and its
  package publish are all held. The owner approves only the push, and the door refuses the
  replayed approval.
- **The audit trail** is shown for every act, and the credential never leaves.

**Mounting a real MCP server** (Linux; needs bubblewrap, `nsenter` and unprivileged user
namespaces, all provided by the flake's dev shell or the host):

```python
import shutil, time
from rubberbandbox import mcp
from rubberbandbox.box import Box
from rubberbandbox.core import ManifestRegistry, Sandbox, ToolManifest

NOTES, STAGE = "/home/me/notes", "/home/me/.local/state/rbb/fs"  # your folder; where staged writes wait
cfg = mcp.ServerConfig(
    "fs", (shutil.which("mcp-server-filesystem"), "/data"),       # a Nix store binary; its closure is the box
    box=Box(folders={"/data": NOTES}, stage=STAGE))               # writes are staged until you commit
client = mcp.McpClient(cfg)                                       # launched in the box, no network
server, adapters, tools = mcp.mount(client)                       # every tool starts unreviewed
sb = Sandbox([server], adapters, clock=time.time)                 # plus your other packs and hands
reg = ManifestRegistry(sb, {"fs": cfg.endpoint}, {"fs": client})  # identity comes from your config
for tool in tools:
    reg.observe(tool)

read = {t.name: t for t in tools}["read_text_file"]
reg.approve(ToolManifest("fs/read_text_file", "read-private",
                         {"path": "destination", "head": "control", "tail": "control"}), read)
sb.owner_mint(["fs/read_text_file"], ["/data/notes"], ttl=3600)  # whole path components only
```

The agent then proposes calls by name, for example
`{"kind": "fs/read_text_file", "args": {"path": {"literal": "/data/notes/a.md"}}}`.
`client.wire(sb)` connects the server's stage to the digest and its proxy to the door. Tool lists
are reconciled when you pass descriptors to `reg.observe` (after a restart, or when
`client.tools_changed` is set). To give a server network, set `Box(..., network=True)` and grant
targets one at a time: `sb.owner_mint(["net:fs"], ["api.example.com:443"], ttl=...)`. Staged
writes reach the folder only through a reviewed commit: `r = client.review()`, read
`r.render()`, then `client.commit(r.digest)`.

The runtime uses only the Python standard library. The flake provides pytest, Hypothesis, the
Anthropic SDK (only for the Claude clerk), bubblewrap, util-linux and the official MCP filesystem
server used in the tests.

## How it works

**One door, one invariant.** Every egress crosses one door: send, fetch, push, publish, a tool
call, a network connection. The door checks the invariant itself on every crossing, independently
of the routing logic, and again at dispatch with a fresh clock:

| Path | Allowed when |
|---|---|
| `approval` | the owner approved exactly this egress, argument names included; single use |
| `grant` | the kind is grantable and an active, owner-minted, expiring grant covers kind + destination (an absolute path grant covers whole path components below it); publishes need a trusted payload; every kind but `read-public` needs trusted control args |
| `lane` | a lane-eligible kind and an unused, unexpired receipt for exactly this egress, within its slot; the payload is non-empty and owner-published, no control args |
| `public_read` | a read-only kind whose destination, payload and control args are all public |

Anything else is held for the owner (fail closed), or, on the public lane, silently dropped. What
a tool returns is stored and labelled: public only for a public read that sent nothing private,
since a server can echo back what it was sent. Outputs are not fed back to the agent yet.

**A small society.**

| Role | What it is |
|---|---|
| **Clerk** | A quarantined model with no tools and no memory. It turns raw content into typed fields. |
| **Hands** | The agent. It sees only tokens and frozen tool manifests, never data or live tool descriptions, and acts by reference. |
| **Bones** | Deterministic policy. It mints scope first and gates the door last. |
| **Immune system** | An anomaly tripwire (v2). |

The clerk's output must fit a schema of enums and typed references: no free text crosses the
airlock. Clerk failures of any kind become owner notices, never actions.

### Effect manifests

The irreducible input is one classification per tool; everything the door enforces derives
from it.
- **Effect class** (one of seven): `read-public`, `read-private`, `write-staged`, `send`,
  `publish`, `spend`, `delete`. Spend and delete are approval-only.
- **Argument roles:** each argument is a `destination`, `payload` or `control`. A tool with more
  than one destination argument, or a list of destinations, can never be granted: it needs
  approval per call (an all-public read can still take `public_read`).
- **Unknown tools** are an irreversible send of every argument, approved per call; on a boxed
  server they cannot be called at all until the owner approves a manifest. MCP annotations
  (`readOnlyHint` and friends) are never trusted; they only set how loose a manifest may be
  without an explicit owner override.

A pack is now declarations: manifests, one adapter per channel (route validation for the public
lane lives there), and a rule table. The core still knows no workflow, and packs import only
`rubberbandbox.core`.

### Frozen manifests and drift

Approved manifests are frozen and versioned in the store. Only security-relevant fields are
hashed: argument names and schemas, the required set, annotations, and the server's endpoint
(its whole owner-configured launch, never what the server says about itself). Description prose
is not hashed, and the agent never sees it. Each tool descriptor passed to `reg.observe` is diffed
against the last **owner-approved** version, never an auto-accepted one:

| Change | Outcome |
|---|---|
| New argument | the tool stays usable with the arguments you approved; calls using the new one are refused |
| Loosening (type widened, enum grown, bound dropped, annotation flipped toward unsafe, steering argument removed or made optional, endpoint changed) | the tool reverts to approval per call (blocked outright on a boxed server); its grants, held approvals, lane receipts and scheduled sends are cancelled |
| Neutral or tightening | accepted for use and audited; a new frozen version is stored only when the owner approves |

Change notices go to the batched digest, never as interrupts, with a per-server change count.

### MCP servers in a box

Every MCP call is egress to the server's operator. The client is stdlib JSON-RPC over stdio; it
refuses the server's requests for sampling, elicitation and roots, caps message size, and fails
closed on garbage, timeouts and unknown protocol versions.

**The box is an allowlist, never a denylist.** A local server runs under bubblewrap with every
namespace unshared. Inside exists only:
- the server binary's Nix runtime closure, read-only (a command outside the store does not start);
- read-only paths the owner names one by one (no top-level directories, no wholesale `/etc`);
- owner folders as overlays: writes land in a stage until the owner reviews and commits them;
- owner-listed unix sockets, bound in directly: whatever serves them must enforce its own controls;
- a minimal `/dev`, `/proc` and private `/tmp`, and only the environment the owner sets (plus the
  proxy variables when network is on, which the owner cannot override).

**Paths are checked in the box's own view.** On a boxed server, destination arguments are paths
(a bones check refuses a path-like argument filed under another role unless the owner overrides
it). The door canonicalises each one through
`/proc/<pid>/root` one component at a time, never letting the OS follow a link (absolute targets
restart at the box root, `..` stops there, 40 links at most). The canonical path is what the
grant check sees, what the approval screen shows and what the server receives. If it resolves
differently at dispatch than at approval, the call goes back to the owner as a new call. On a
boxed server, a tool with no approved manifest cannot be called at all.

**No blind commit.** `client.review()` lists every staged change: writes with a unified diff
against the host file (or a size and hash for binary and large content), deletes, replaced
directories, and links that will never be copied out. Its digest covers the staged content and
the host content it would replace, including whole directory trees for deletes. `commit(digest)`
stops the server, recomputes the review, and refuses if either side changed since it was
reviewed. Each new stage state is posted to the batched digest. Commit never writes through a
link: host folders are opened without following links at any depth.

### Network through the door

A server gets network only if the owner enables it, has approved at least one of its tools, and
every approved tool was reviewed under the server's current launch (or a wider one); and then
only through the door. Its network namespace has loopback and nothing else. Before the server starts, the door places a CONNECT
proxy listener inside that namespace and points the server's proxy variables at it.
- **One grant per target.** Each connection is egress `net:<server>` to an exact `host:port`.
  Without a grant it is refused and noted in the digest.
- **DNS happens door-side, after the grant.** A name that resolves to loopback, private or
  otherwise non-global space (IPv4-mapped and NAT64 forms included) is refused; only an IP literal
  the owner granted may be private. The door connects to exactly the address it checked.
- **Live tunnels are cut** when their authorization lapses: grant ended or expired, cluster
  stiffened, or the server reconfigured. The check runs before every forwarded chunk and at least
  every half second.
- **A changed launch is a new operator.** Any change to command, arguments, env, working
  directory, folders, read-only paths or the network flag ends that server's grants and network
  route at once. Only a narrower box keeps them, and losing network always closes the route.

```
rubberbandbox/core/      labels · store · casefile (airlock) · grants · invariant · public_lane · approvals
                         door · sandbox (wiring, routing, composition) · types
                         manifest (effect classes) · workflow (manifest packs, channels, rules)
                         registry (frozen manifests, diff, bones, binding, path and network checks)
rubberbandbox/mcp.py     stdio MCP client, adapter, mount
rubberbandbox/box.py     allowlist launcher, path canonicaliser, staged writes
rubberbandbox/proxy.py   the door's CONNECT proxy
rubberbandbox/packs/     messaging/ · coding/   (each imports only `rubberbandbox.core`)
rubberbandbox/clerks/    claude.py · codex.py · jsonschema.py
corpus/                  attacks (32) · clean (40) · adversarial (60)
tests/                   unit, corpus, property, composition, manifests, registry, MCP, box, proxy
```

## Decisions made in the build

1. **No standing access.** An approval authorizes one egress, once. Repeated sends need an
   expiring grant, a fresh approval each time, or (for scripted replies) a public-lane receipt
   each time.
2. **A missed slot cancels the reply.** A public reply not sent by its slot plus a grace period
   is never sent late, and the per-destination window is measured between delivery times.
3. **The hands see tokens, never data.** Their literals carry the join of everything they were
   shown.
4. **Fetching is governed by labels.** A read-only call whose destination, payload and control
   args are all public is a public read (unless its cluster is stiffened). Anything
   private-derived needs a covering grant or the owner's approval of that exact call.
5. **Unreadable or failed clerk output asks, never acts.**
6. **Unauthenticated provenance is never public or trusted,** whatever a pack claims.
7. **Pack composition.** Disjoint channels, unique kinds, and an unowned channel is dropped.
8. **Effect manifests replace hand-written packs** as the way to add tools; the Pack protocol
   stays, so existing packs and tests keep working.
9. **The diff baseline is always the last owner-approved manifest.** Small auto-accepted steps
   never add up to a loosening nobody approved.
10. **Operator identity comes from owner config,** never from the server.
11. **A read may not carry both a destination and a payload.** Registry approval refuses such a
    manifest: a tool that sends data somewhere is not a read.
12. **The Claude clerk** is stateless and tool-less, with schema-constrained output (default
    `claude-opus-5-5` at low effort, with server-side refusal fallbacks).
13. **The Codex clerk** is `codex exec`, locked down: ephemeral, user config ignored, read-only,
    shell and exec tools disabled, empty working directory, schema-constrained. Its event stream
    is checked on every call, and any capability use fails closed.

## Known limits

- **The choice channel.** The hands never read private data, but *which* permitted action they
  choose can depend on case-file enums. That is a low-bandwidth side channel, of the kind CaMeL
  also documents.
- **A manifest is only as good as its classification.** A payload argument misfiled as control
  on an open-world tool is an exfiltration channel. Bones checks catch structural mistakes, and
  open-world arguments default to payload, but a wrong-but-legal classification passes.
- **Network is a destination allowlist, not a label check.** With TLS the door sees the host,
  not the payload. Plain-HTTP proxying is refused; only CONNECT is supported.
- **Check-then-open.** Between the door's path check and the server opening the file, the
  server itself could swap a path component (it can already read everything in its box), and so
  could anyone writing to the host folder concurrently. The complete fix (`openat2` with
  `RESOLVE_IN_ROOT`, or the door passing an open file) is v2.
- **Nested schema changes compare by equality,** so some genuine narrowings read as loosenings;
  on a boxed server that blocks the tool until the owner re-approves.
- **Operational gaps:**
  - DNS lookups have no deadline of their own.
  - A crashed server is not restarted.
  - Tools added after mount wait for a restart.
  - Commit takes the whole reviewed stage (no per-file selection) and is not transactional: a
    failure partway leaves earlier entries applied.
  - Read-only paths appear at their real path, so NixOS `/etc` symlinks need env vars pointing
    at the store path (for example `NODE_EXTRA_CA_CERTS`).
- **Fixed, not adaptive, evaluation so far.** The corpora are small.
- **Not built yet:** owner-initiated mode (open holes #3 and #4) and the v2 prior (#9).
- **No version secures a fully general agent** with unconstrained tools.

## Specs

- `rubberbandbox-design-spec-v0.4.md`: current doctrine; does not yet describe the pack wall.
- `rubber-sandbox-design-spec-v0.3.md`, `-v0.2.md` and `.pdf` (v0.1): history.
