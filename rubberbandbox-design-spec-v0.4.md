# RubberBandBox

**Design spec — agent security architecture** · Elastic permissions, a small society, an airlock, and one door.
6 November 2026 · v0.4 · Doctrine + reference implementation (`rubberbandbox/`)

> **Core idea:** Do not harden the prompt and hope. Give the boundary a physics — it **stretches** for the task, **retracts** when the task ends, **deforms** into rollback instead of breaking, and **stiffens** when something pulls wrong. Rubber inside; one steel door out.
>
> **What this is:** a doctrine, not an invention — existing defenses synthesized under one metaphor (see *Evidence & prior art*). v0.4 adds a working reference implementation and measurements.

**The problem.** A language model receives instructions and untrusted content as the same stream of language, so no prompt wording reliably separates them: injection is an architectural problem, not a phrasing problem. Static permissions make it worse — access granted once stays forever, and the moment a fooled agent can send, spend, publish, or delete, a trick becomes a loss.

**Two modes.**
- **Inbound.** The hands never see raw content. They work from case files only, and replies are fixed scripts — there is nothing to draft.
- **Owner-initiated.** The owner supplies or summons the content. Free-form drafting exists only here, and everything produced is a draft that commits through the steel door with the owner's approval. *(Not yet implemented.)*

**What changed in v0.4.**
- The build's decisions are folded in: no standing access, missed slots cancel, unauthenticated content is never public, the hands see tokens only, and packs can be composed.
- The open-holes list is updated.
- The measured results are added.

---

## 1. The elastic boundary — *permissions as physics*

- **Stretch per task.** Permissions are minted from the owner's actual request — these kinds, these destinations, this long — never as standing access. Only strings the owner types or selects mint clean scope; anything that *resolves* a reference produces tainted output and passes the door like any other untrusted value.
- **Retract on its own.** Grants expire, or end with the task. Nothing accumulates.
- **No standing access.** *(New in v0.4.)* An owner approval authorizes **exactly one egress, once**. It does not authorize the destination for later sends; repeated sends to a destination need a grant, which expires. This replaces v0.3's probation and rate limits for newly approved recipients (closes hole #5).
- **Deform, don't break.** Work inside is provisional — drafts, staged changes, snapshots — so a trick rearranges a sandbox that can roll back.
- **Stiffen under stress — on private work only.** Stiffening tightens private work (grants, holds) for a source cluster. It never touches public replies, which go out on a fixed schedule regardless of suspicion. Fetching is governed by labels: a pack may read URLs from authenticated *public* content, while anything private-derived needs a grant or the owner. The messaging pack declares no fetch kind, so it never fetches inbound content. Owner follow-ups and rate limits can still reveal different handling.
- **One steel door — for all egress.** Every send, spend, publish, delete, fetch, search or API call crosses one door. The door checks the invariant itself on every crossing, independently of the routing logic, and again at dispatch with a fresh clock:

  | Path | Allowed when |
  |---|---|
  | `approval` | the owner approved exactly this egress; single use |
  | `grant` | an active, owner-minted grant covers kind + destination; publishes need a trusted payload |
  | `lane` | an unexpired public-lane receipt for exactly this egress, within its slot; payload is owner-published |
  | `public_read` | a read-only kind whose destination and payload are all public |

  Anything else is held for the owner (fail closed) or, on the public lane, silently dropped.

- **The mail slot (public lane).** One narrow opening lets fixed, owner-published replies reach new senders without the owner's tap. It is owner-enabled and admits only what fits:
  1. **Public content only.** Owner-approved literals and typed owner-data slots; availability from a published snapshot, never the live calendar.
  2. **Fixed script table.** Enums map to scripts; `other` gets the generic script; selection never depends on private data; nothing is auto-called or auto-booked. Every script is safe to trigger by an attacker (closes hole #7).
  3. **Blind to suspicion.** Eligibility and content depend only on public rules.
  4. **Constrained return route.** Authenticated provider events only, one response per delivery ID. SMS goes to the provider-reported origin (a *reported route*, not an identity). Email requires a DMARC pass, a plausible mailbox, and a single `From` equal to the envelope sender; `Reply-To` and addresses in content are ignored.
  5. **Bounded output.** At most 160 ASCII characters for SMS (an exact GSM-7 segment count is a v1.x item) or a fixed email size; email replies carry `Auto-Submitted: auto-replied` and an empty envelope sender.
  6. **Fixed schedule.** Arrival plus independent jitter. **A reply not dispatched by its slot plus a grace period is cancelled, never sent late**, and the per-destination window is measured between delivery times as the recipient sees them. *(New in v0.4: a stalled dispatcher otherwise delivered two "one per day" replies 400 s apart.)*
  7. **Shrink.** Geographic allowlist and one auto-reply per number per window.
  8. **Cap.** Atomic per-destination and service-wide budgets, unknown-cost routes denied, and a provider-level hard cap that holds even if this code fails.

## 2. A small society — *hands / immune system / bones / clerk*

| **Clerk** (extractor) | → | **Immune system** (guard) | → | **Hands** (smart model) | → | **Bones** (policy) |
|---|---|---|---|---|---|---|
| Quarantined LLM. No tools, no memory. Turns raw content into typed fields. Outputs are inert data, never verdicts. | | Not an LLM. Deterministic features plus a learned scorer. A tripwire, not a wall. *(v2.)* | | Does the work. Never sees raw inbound content **or any value's data: only tokens** (`source= trusted= public=`), acting by reference. | | Deterministic rules + provenance tags. The wall. |

- **The bones act at both ends.** Policy mints scope before the clerk runs and gates every door crossing after.
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
- **Interrupting the owner is the scarce currency.** Interruptions are budgeted per cluster (keyed by the held egress's destination), batched into a fixed-schedule digest, and repeats of the same pending egress collapse into one entry. Holds never cross on their own, including when the budget runs out (closes hole #6).
- **Approval screens must show provenance in the largest type,** for example "This destination came from hands (untrusted)". v1 supplies the provenance string with every digest entry; the screen itself arrives with phone approvals (v1.x). In owner-initiated mode (not yet built), draft approvals must also say the content was summoned.
- **Only the owner mints gold labels.**

## 5. Composition — *one door, many workflows* (new in v0.4)

The core knows no workflow. A **pack** supplies:
- a case-file schema;
- its egress kinds;
- inbound labelling;
- route validation for the public lane;
- routing rules;
- a cluster key.

A sandbox **mounts several packs**, each with its own clerk, behind one door. The rules:
- Each pack owns a disjoint set of inbound channels and uniquely named kinds. Overlaps are refused at construction.
- An event on a channel no pack owns is dropped.
- A pack's rules may only propose its own kinds. Only the hands span domains.

Tool adapters are held by the door alone.

---

## 6. Honest limits

- **The clerk can be fooled.** Classifiers and constrained LLMs catch known shapes, and adaptive attackers will fool them more often than static corpora show. The design's claim is not that the clerk resists. It is that a fooled clerk cannot widen egress.
- **Normal can be boiled** through owner approvals, and the owner is phishable.
- **The choice channel.** The hands never read private data, but *which* permitted action they choose can depend on case-file enums. That is a low-bandwidth side channel, so keep public-read kinds out of packs that don't need them.
- **The mail slot is observable.** Script choice reveals classification, owner follow-ups and exhausted rate limits reveal different handling, a spoofed SMS origin can reflect one public message to a bystander, and SMS cost is capped, not eliminated.
- **Owner-initiated mode** puts the hands back in front of raw content; the door is its only protection.
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
| 7 | Clerk steered to any enum | **Closed:** every script is safe to trigger by an attacker |
| 8 | "Privately derived" decided by labels | **Closed:** private by default |
| 9 | No population for the prior in a solo deployment | Open; v2 ships a hand-set prior |

## 8. Build order and status

- **v1 — built (reference implementation).**
  - **Core:** provenance labels, airlock, scope grants, the door and its invariant, the public lane, the approval digest, an append-only audit log, and pack composition.
  - **Packs:** messaging (SMS and email) and coding, the second written by a separate author against the public API with zero core edits.
  - **Clerks:** keyword stub, Claude (API), Codex (CLI, locked down).
- **v1.x — next.**
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
| Mutation check (deliberately broken guards; `scripts/mutation_check.py`) | 12/12 caught |
| Independent correctness review (separate model) | 4 defects found, reproduced as failing tests, fixed |
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
