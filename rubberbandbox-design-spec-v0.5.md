# RubberBandBox

**Design spec — agent security architecture** · Elastic permissions, a small society, an airlock, and one door.
8 November 2026 · v0.5 · Doctrine + reference implementation (`rubberbandbox/`)

> **Core idea:** Do not harden the prompt and hope. Give the boundary a physics — it **stretches** for the task, **retracts** when the task ends, **deforms** into rollback instead of breaking, and **stiffens** when something pulls wrong. Rubber inside; one steel door out.
>
> **What this is:** a doctrine, not an invention — existing defenses synthesized under one metaphor (see *Evidence & prior art*). v0.4 added a working reference implementation and measurements; v0.5 adds the pack wall.

**The problem.** A language model receives instructions and untrusted content as the same stream of language, so no prompt wording reliably separates them: injection is an architectural problem, not a phrasing problem. Static permissions make it worse — access granted once stays forever, and the moment a fooled agent can send, spend, publish, or delete, a trick becomes a loss.

**Two modes.**
- **Inbound.** The hands never see raw content. They work from case files only, and replies are fixed scripts — there is nothing to draft.
- **Owner-initiated.** The owner supplies or summons the content. Free-form drafting exists only here, and everything produced is a draft that commits through the steel door with the owner's approval. *(Not yet implemented.)*

**What changed in v0.5: the pack wall.**
- Hand-written per-workflow packs are replaced by declarations: one **effect manifest** per tool, channel adapters and a rule table (§5).
- Manifests are **frozen and versioned**; live tools are diffed against the last owner-approved version, and loosening fails closed (§5.2).
- Every MCP call is egress to its **operator**, whose identity comes from owner config (§5.3).
- Local servers run in an **allowlist box**: files through canonical paths and reviewed commits, network through the door's CONNECT proxy (§5.4, §5.5).

*v0.4 folded in the build's first decisions (no standing access, missed slots cancel, unauthenticated content never public, tokens-only hands, pack composition) and the first measurements.*

---

## 1. The elastic boundary — *permissions as physics*

- **Stretch per task.** Permissions are minted from the owner's actual request — these kinds, these destinations, this long — never as standing access. Only strings the owner types or selects mint clean scope; anything that *resolves* a reference produces tainted output and passes the door like any other untrusted value.
- **Retract on its own.** Grants expire at their owner-set TTL, or the owner ends them sooner (task completion is not tracked yet). Nothing accumulates.
- **No standing access.** *(New in v0.4.)* An owner approval authorizes **exactly one egress, once**. It does not authorize the destination for later sends; repeated sends to a destination need a grant, which expires. This replaces v0.3's probation and rate limits for newly approved recipients (closes hole #5).
- **Deform, don't break.** Work inside is provisional — drafts, staged changes, snapshots — so a trick rearranges a sandbox that can roll back.
- **Stiffen under stress — on private work only.** Stiffening tightens private work (grants, holds) addressed to a destination cluster. It never touches public replies, which go out on a fixed schedule regardless of suspicion. Fetching is governed by labels: a pack may read URLs from authenticated *public* content, while anything private-derived needs a grant or the owner. The messaging pack declares no fetch kind, so it never fetches inbound content. Owner follow-ups and rate limits can still reveal different handling.
- **One steel door — for all egress.** Every send, spend, publish, delete, fetch, search or API call crosses one door. The door checks the invariant itself on every crossing, independently of the routing logic, and again at dispatch with a fresh clock:

  | Path | Allowed when |
  |---|---|
  | `approval` | the owner approved exactly this egress; single use |
  | `grant` | an active, owner-minted grant covers kind + destination; the kind is grantable; publishes need a trusted payload; control arguments must be trusted unless the kind is `read-public` |
  | `lane` | an unexpired public-lane receipt for exactly this egress, within its slot; payload is owner-published; no control arguments |
  | `public_read` | a `read-public` kind whose destination, payload and control arguments are all public |

  Routing holds anything else for the owner (fail closed); unknown kinds and public-lane misfits are dropped silently. A crossing the door itself refuses is refused, never sent.

- **The mail slot (public lane).** One narrow opening lets fixed, owner-published replies reach new senders without the owner's tap. It is owner-enabled and admits only what fits:
  1. **Public content only.** Owner-approved literals and owner-published slot values; availability from a published snapshot, never the live calendar.
  2. **Fixed script table.** Enums map to scripts; `other` gets the generic script; selection never depends on private data; nothing is auto-called or auto-booked. The owner publishes only scripts that are safe for an attacker to trigger; the code does not judge script content (closes hole #7 by that contract).
  3. **Blind to suspicion.** Eligibility and content depend only on public rules.
  4. **Constrained return route.** Authenticated provider events only, one response per delivery ID. SMS goes to the provider-reported origin (a *reported route*, not an identity). Email requires a DMARC pass, a plausible mailbox, and a single `From` equal to the envelope sender; `Reply-To` and addresses in content are ignored.
  5. **Bounded output.** By default at most 160 ASCII characters for SMS (an exact GSM-7 segment count is a v1.x item) or a fixed email size; in the simulated provider, email replies carry `Auto-Submitted: auto-replied` and an empty envelope sender (real adapters are v1.x).
  6. **Fixed schedule.** Arrival plus independent jitter. **A reply not dispatched by its slot plus a grace period is cancelled, never sent late**, and the per-destination window holds between delivery times as the recipient sees them: each admitted reply is counted at its latest possible delivery. *(New in v0.4: a stalled dispatcher otherwise delivered two "one per day" replies 400 s apart.)*
  7. **Shrink.** Geographic allowlist and, by default, one auto-reply per number per window.
  8. **Cap.** Atomic per-destination and service-wide budgets, unknown-cost routes denied, and a provider-level hard cap that holds even if this code fails (enforced by the simulated provider; real adapters are v1.x).

## 2. A small society — *hands / immune system / bones / clerk*

| **Clerk** (extractor) | → | **Immune system** (guard) | → | **Hands** (smart model) | → | **Bones** (policy) |
|---|---|---|---|---|---|---|
| Quarantined LLM. No tools, no memory. Turns raw content into typed fields. Outputs are inert data, never verdicts. | | Not an LLM. Deterministic features plus a learned scorer. A tripwire, not a wall. *(v2.)* | | Does the work. Never sees raw inbound content **or any value's data: only tokens** (`source= trusted= public=`), acting by reference. | | Deterministic rules + provenance tags. The wall. |

- **The bones act at both ends.** Only the owner mints scope, never the clerk or the hands, and the bones gate every door crossing.
- **Clerk failures ask, never act.** A refusal, truncation, malformed output, API error, or any tool use by the clerk becomes an owner notice. *(New in v0.4: the clerk is pluggable. A clerk built on an agent CLI is locked down by flags **and** has its event stream checked on every call; any capability use fails closed.)*
- **Hands literals carry their context.** Anything the hands write is labeled with the join of everything they were shown, on a private baseline.
- **Unauthenticated provenance is never trusted or public**, whatever label a pack assigns. *(New in v0.4.)*
- **The immune system** (unchanged from v0.3, still v2) is a scorer over coarse features that starts from a population prior. It can tighten on its own; loosening needs owner-confirmed examples.

## 3. The airlock protocol — *forms, not conversation*

- **Case files, not content.** Every case-file field is an enum, a typed value, or a reference to a tagged value. No free-text string crosses. Spans the clerk extracts are stored as values that inherit the source's taint; only their ids cross.
- **Constrained decoding plus validation.** The clerk's output is schema-constrained at generation. The airlock re-validates it afterwards, including the bounds that structured outputs cannot express.
- **Scores stay with the scorer.** Scores never enter a case file.

## 4. Asymmetric trust — *the key rule*

> **The hands may convict tainted content, but they may never acquit it.**

- This is the integrity rule of information-flow control applied to model verdicts. Anyone may raise a taint label; only the owner may lower it.
- **Defaults are private.** A value is treated as privately derived unless its provenance proves it public (closes hole #8).
- **Interrupting the owner is the scarce currency.** Interruptions are budgeted per cluster (keyed by the held egress's destination), batched into a digest released at most once per interval, and repeats of the same pending egress collapse into one entry. Holds never cross on their own, including when the budget runs out (closes hole #6).
- **Approval screens must show provenance in the largest type,** for example "This destination came from hands (untrusted)". v1 supplies the provenance string with every digest entry; the screen itself arrives with phone approvals (v1.x). In owner-initiated mode (not yet built), draft approvals must also say the content was summoned.
- **Only the owner mints gold labels.**

## 5. The pack wall — *declare effects, don't write workflows* (new in v0.5)

The core knows no workflow. A pack is now declarations, not code:
- **Effect manifests**, one per tool: what the tool *does*, declared once.
- **Channel adapters**, one per inbound channel: labelling and public-lane route validation.
- **A rule table**: which case-file values raise owner notices and which owner-published script answers.

A sandbox mounts several packs behind one door. Each owns disjoint channels and uniquely named kinds; a pack's rules may only propose its own kinds; only the hands span domains; only the door holds tool adapters. The Pack protocol itself stays, so hand-written packs still compose.

### 5.1 Effect manifests

The irreducible input is per-tool classification; everything the door enforces derives from it.
- **Effect class:** `read-public`, `read-private`, `write-staged`, `send`, `publish`, `spend` or `delete`. Spend and delete are approval-only; publishes need a trusted payload under a grant.
- **Argument roles:** `destination`, `payload` (carries confidentiality) or `control` (steers the tool; must be trusted under a grant unless the tool is `read-public`). A tool with more than one destination, or a list of them, is never grantable.
- **Unknown means dangerous:** an unclassified tool is an irreversible send of every argument, approved per call. Tool annotations are never trusted; they only cap how loose a manifest may be without an explicit owner override.
- **The planner reads frozen manifests only,** never a server's live descriptions.
- **Outputs are stored and labelled,** public only for a public read that sent nothing private. Feeding them back to the hands waits for plan-then-execute.

### 5.2 Frozen manifests and drift

An owner-approved manifest is frozen and versioned. Only security-relevant fields are hashed: argument names and schemas, the required set, annotations, and the operator's endpoint; never description prose. Live tools are diffed against the **last owner-approved** version, so auto-accepted steps never add up to an unapproved loosening.
- **Additive** (new argument): known arguments keep working; calls using the new one are refused.
- **Loosening** (type widened, enum grown, bound dropped, annotation flipped toward unsafe, steering argument removed or made optional, endpoint changed): the tool reverts to approval per call, and every grant, held approval, lane receipt and scheduled send for it is cancelled.
- **Neutral or tightening:** accepted and audited. Nested schemas compare by equality, so some genuine narrowings count as loosenings (fails safe).

Bones checks run before the owner sees a draft: every tool fully classified, no read that carries both destination and payload, nothing looser than the tool's own annotations, on open-world tools nothing destination-like filed under another role without an override, and on boxed servers nothing path-like. Change notices go to the batched digest, never as interrupts.

### 5.3 Operators

Every remote tool call is egress through its operator, under that server's own kind: a call with no destination argument is authorized against `mcp:<server>`, one with a destination argument against that destination. **Operator identity comes from owner config, never from the server:** the whole launch for a local server (command, arguments, environment, working directory, box allowlists, network flag), the URL for a remote one (only local stdio servers are built so far). Any change is a new operator, except a narrowing (the box only lost entries). A new operator loses every grant, approval and receipt for its tools and its network route at once, its tools revert until re-approved, and live tunnels are cut. Losing network always closes the route.

### 5.4 The box — *allowlist, never denylist*

A local server runs in its own namespaces (bubblewrap; MicroVM later). Inside exists only:
- the server's runtime closure, read-only;
- read-only paths the owner names one by one, each at least two components deep (never a wholesale `/etc` or `/home`; a named home directory is the owner's call);
- owner folders as overlays, so writes are staged;
- sockets the owner lists, bound one by one;
- a minimal `/dev`, `/proc`, private `/tmp`, and only the environment the owner sets, plus the door's proxy variables when network is on.

**Paths are canonicalised in the box's own view.** The door walks each path argument one component at a time through the box's root, never letting the OS follow a link: absolute targets restart at the box root, `..` stops there, 40 links at most. Grants match whole path components. The checked path is the sent path; one that resolves differently at dispatch is refused, and on an owner-approved call it comes back to the owner as a new call. An unreviewed tool on a boxed server cannot be called at all, because only its manifest says which arguments are paths.

**No blind commit.** The owner reviews every staged change (diffs for text, size and hash otherwise; any host directory a change removes is pinned by its whole content; links and special files listed, never copied out; file modes are applied but not reviewed) and commits by the review's digest. A commit refuses if the stage or the host changed since the review.

### 5.5 Network through the door

A box has no network unless the owner enables it, and then only one route: a CONNECT proxy the door places inside the box's namespace before the server starts.
- **Each connection is egress** to an exact `host:port`, allowed only by an owner grant and only while the server is reviewed as currently launched. A connection no grant covers is noted in the digest; other refusals and failures are audited.
- **DNS is the door's:** names resolve after the grant check; a name that lands in private or otherwise non-global space is refused; only an owner-granted IP literal may be private. The door connects to exactly what it checked. A lookup past its deadline refuses the CONNECT and frees its connection slot; each server's resolver pool bounds stalled lookups.
- **A tunnel lives only while its authorization holds,** re-checked on every revocation and at least every 0.5 s. Revocation, stiffening or reconfiguration cuts it at once and expiry within 0.5 s; at most one already-checked chunk per direction crosses after a revocation.

---

## 6. Honest limits

- **The clerk can be fooled.** Classifiers and constrained LLMs catch known shapes, and adaptive attackers will fool them more often than static corpora show. The design's claim is not that the clerk resists. It is that a fooled clerk cannot widen egress.
- **Normal can be boiled** through owner approvals, and the owner is phishable.
- **The choice channel.** The hands never read private data, but *which* permitted action they choose can depend on case-file enums. That is a low-bandwidth side channel, so keep public-read kinds out of packs that don't need them.
- **The mail slot is observable.** Script choice reveals classification, owner follow-ups and exhausted rate limits reveal different handling, a spoofed SMS origin can reflect one public message to a bystander, and SMS cost is capped, not eliminated.
- **Owner-initiated mode** puts the hands back in front of raw content; the door is its only protection.
- **A manifest is only as good as its classification.** A payload argument misfiled as control on an open-world tool is an exfiltration channel. Bones checks catch structural mistakes and open-world arguments default to payload; a wrong-but-legal classification still passes. A future LLM drafter (v1.x) would read untrusted tool descriptions, so the owner's approval of its drafts stays mandatory.
- **A remote operator can misuse legitimate access** to the owner's accounts. The box bounds what it is given; it cannot make the operator honest.
- **Network is a destination allowlist, not a label check.** With TLS the door sees the host, never the payload.
- **Check-then-open.** Between the door's path check and the server opening the file, the server itself (or a concurrent host writer) could swap a path component. The complete fix (`openat2` with `RESOLVE_IN_ROOT`, or the door passing an open file) is v2.
- **No version secures a fully general agent** with unconstrained tools.

## 7. Open holes

| # | Hole | Status |
|---|---|---|
| 1 | Inbound replies vs first-send approval | **Closed:** the mail slot |
| 2 | Stiffening observable by timing | **Closed** (claim reworded); residuals under limits |
| 3 | "Select" endorses a tainted address behind a displayed name | Open; owner-initiated mode. The selection UI must show the real address. |
| 4 | Draft approval also approves embedded links and destinations | Partly closed: provenance label. Open: list every destination on the approval screen. |
| 5 | Probation caps volume, not sensitivity | **Closed:** no standing access |
| 6 | Interruption budget exhaustion | **Closed:** fail closed, per-cluster budget (destination cluster) |
| 7 | Clerk steered to any enum | **Closed** by owner contract: only scripts safe for an attacker to trigger are published |
| 8 | "Privately derived" decided by labels | **Closed:** private by default |
| 9 | No population for the prior in a solo deployment | Open; v2 ships a hand-set prior |

## 8. Build order and status

- **v1 — built (reference implementation).**
  - **Core:** provenance labels, airlock, scope grants, the door and its invariant, the public lane, the approval digest, an append-only audit log, and pack composition.
  - **Packs:** messaging (SMS and email) and coding, the second written by a separate author against the public API with zero core edits; both since re-expressed as manifests with their original tests unchanged.
  - **Clerks:** keyword stub, Claude (API), Codex (CLI, locked down).
- **Pack wall — built.** Effect manifests; frozen, versioned manifests with the loosening diff; the MCP stdio adapter; the filesystem box with reviewed commits; network through the door.
- **v1.x — next.**
  - A live manifest drafter (the owner still approves every draft).
  - Remote MCP servers (HTTP transport); today only local stdio servers run.
  - Real SMS and email adapters.
  - Phone approvals.
  - Owner-initiated mode (holes #3 and #4).
  - MicroVM deployment with the door as the only egress.
  - A larger, adaptive clerk evaluation.
- **v2.** The learning immune system on a population prior, plus anomaly stiffening.

## Evidence

Reference implementation runs, 6 November 2026. *Harm* counts only what the simulated outside world received.

| Evidence | Result |
|---|---|
| Attack corpus (32 routing attacks: spoofing, premium routes, replay, Reply-To, loops, floods) | 32/32 behave as specified |
| Property tests: fully hostile clerk; fully hostile hands; hostile hands across two composed packs | invariant holds; oracles independent of the door |
| Mutation check (deliberately broken guards; `scripts/mutation_check.py`) | 12/12 caught (6 Nov); 101/101 after the pack wall (7 Nov); 111/111 (8 Nov) |
| Independent correctness reviews (separate model family) | core: 4 defects, each reproduced as a failing test and fixed; each pack-wall slice reviewed, real findings fixed with regression tests |
| Path canonicaliser vs the kernel's own in-root resolution, inside a real box | Hypothesis-generated trees of files and absolute, relative, looping and dangling links: identical results |
| Unseen MCP servers, run unchanged in the box | official filesystem server; `server-sequential-thinking`; a Hacker News server fetching live stories through the door on one granted target |
| Clean corpus, live Codex clerk | fooled 0/40, harm 0 |
| Adversarial clerk corpus (60, written by a different model family), keyword stub | fooled 24/60, **harm 0** |
| Adversarial clerk corpus, live Codex clerk | fooled 4/60 (none in an injection's demanded direction), **harm 0** |

## Evidence & prior art

Not new in parts, and not claimed to be.

- **Dual LLM pattern** — Willison, 2023. <https://simonwillison.net/2023/Apr/25/dual-llm-pattern/>
- **Six design patterns for securing LLM agents** — Beurer-Kellner et al., 2025. arXiv:2506.08837
- **CaMeL** — Debenedetti et al., 2025: 77% of AgentDojo tasks with provable security vs. 84% undefended (v2 figures). arXiv:2503.18813
- **Task-minted privileges** — Progent, Shi et al., 2025. arXiv:2504.11703
- **Agents Rule of Two** — Meta, 2025. <https://ai.meta.com/blog/practical-ai-agent-security/>
- **Taint rule** — information-flow control: Denning, "A Lattice Model of Secure Information Flow," CACM, 1976; Biba, "Integrity Considerations for Secure Computer Systems," MITRE, 1977.
- **Retraction** — just-in-time access, standard IAM practice.
- **Auto-reply hygiene** — RFC 3834 (2004); DMARC, RFC 9989 (2026).
- **Why the guard is a tripwire** — Nasr et al., "The Attacker Moves Second," 2025. arXiv:2510.09023

**Claimed here:**
- The synthesis under one metaphor.
- The one-way learning rule (tighten autonomously, loosen only on owner-confirmed labels) on a per-owner baseline.
- A pack architecture in which one door and one invariant serve unrelated workflows, with evidence that a separately authored pack needed no core change.

---

**Success looks like:** fooled occasionally, interrupted sometimes, and no irreversible harm without an owner decision in the loop. *Measured so far: fooled 4–24 times in 60, harmed 0.*
