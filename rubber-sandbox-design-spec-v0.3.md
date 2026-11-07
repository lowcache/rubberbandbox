# The Rubber Sandbox

**Design spec — agent security architecture** · Elastic permissions, a small society, and an airlock.
6 November 2026 · v0.3 · One-page spec

> **Core idea:** Do not harden the prompt and hope. Give the boundary a physics — it **stretches** for the task, **retracts** when the task ends, **deforms** into rollback instead of breaking, and **stiffens** when something pulls wrong. Rubber inside; one steel door out.
>
> **What this is:** a doctrine, not an invention — existing defenses synthesized under one metaphor (see *Evidence & prior art*).

**The problem.** A language model receives instructions and untrusted content as the same stream of language, so no prompt wording reliably separates them: injection is an architectural problem, not a phrasing problem. Static permissions make it worse — access granted once stays forever, and the moment a fooled agent can send, spend, publish, or delete, a trick becomes a loss.

**Two modes.**
- **Inbound.** The hands never see raw content. They work from case files only, and replies are fixed scripts — there is nothing to draft.
- **Owner-initiated.** The owner supplies or summons the content. Free-form drafting exists only here, and everything produced is a draft that commits through the steel door with the owner's approval.

---

## 1. The elastic boundary — *permissions as physics*

- **Stretch per task.** Permissions are minted from the owner's actual request — this agent, these contacts, ten minutes — never as standing access. Only references the owner types or selects mint clean scope. Anything that *resolves* a reference ("the people from yesterday's meeting") produces tainted output: resolved recipients inherit the taint of the data that named them and pass the door like any other untrusted recipient.
- **Retract on its own.** When the task ends, access evaporates (just-in-time access). Nothing accumulates.
- **Deform, don't break.** Work inside is provisional — drafts, staged changes, snapshots — so a trick rearranges a sandbox that can roll back.
- **Stiffen under stress — silently.** Anomalous reach — unrelated contacts, a new destination, an unusual hour — narrows scope and adds checks, like a bank freezing a card. Stiffening changes only private work: public replies go out on a fixed schedule regardless of suspicion, and nothing in inbound content is ever fetched. Owner follow-ups and rate limits can still reveal different handling.
- **One steel door — for all egress.** The outside world has no undo. Sends, spends, publishes, deletes, *and* any outbound fetch, search query, API call, or image load whose payload derives from private sources cross as committed transactions with the owner's tap. Fetches carrying no privately derived data may stay inside the sandbox — but nothing named by inbound content is ever fetched: no URLs, images, previews, redirects, or DNS lookups, including when rendering the owner's digest.
- **The mail slot — public auto-replies.** One narrow opening in the steel door lets fixed public replies out to new senders without the owner's tap. It is owner-enabled and admits only what fits:
  1. **Public content only.** Versioned, owner-approved literals and typed owner-data slots. Availability comes from a published snapshot, never the live calendar.
  2. **Fixed script table.** Case-file enums map to script IDs through a fixed table; `other` gets the generic script. Selection never depends on private data. Nothing is auto-called or auto-booked.
  3. **Blind to suspicion.** Eligibility and content depend only on public rules, never on scores or private history. Releasing held private work never triggers an automatic send.
  4. **Constrained return route.** Authenticated provider/mail-server events only, each with a unique delivery ID. SMS replies go to the provider-reported origin — a *reported route*, not a verified identity. Email requires a DMARC pass and a single `From` equal to the envelope sender; `Reply-To` and addresses in content are ignored. An address match never confers identity or history: numbers get recycled. The destination keeps its taint; every other send to it needs approval.
  5. **Bounded output.** One response per delivery ID, one SMS segment or a fixed email size, no quoting of inbound content. Automated, list, and bounce mail is ignored; email replies are marked `Auto-Submitted: auto-replied` with an empty envelope sender.
  6. **Fixed schedule.** Each reply goes out at arrival plus independent jitter (e.g. 2–5 min), never rescheduled by suspicion. Read receipts and typing indicators are off where the channel allows.
  7. **Shrink.** A geographic allowlist — the service area only, no premium or international routes — and at most one auto-reply per number per window.
  8. **Cap.** Per-destination and service-wide budgets are reserved atomically before a reply is queued; routes of unknown cost are denied; a provider-level hard spending cap holds even if this code fails. The window, budgets, and cap are set at deployment.

## 2. A small society — *hands / immune system / bones / clerk*

| **Clerk** (extractor) | → | **Immune system** (guard) | → | **Hands** (smart model) | → | **Bones** (policy) |
|---|---|---|---|---|---|---|
| Quarantined LLM. No tools, no memory. Turns raw content into typed fields. Outputs are inert data, never verdicts. | | Not an LLM. Deterministic feature extraction plus a learned scorer. A tripwire, not a wall. | | Inside the box. Does the work. Never holds the scissors. Never sees raw inbound content. | | Deterministic rules + provenance tags. The wall. Decide what is possible. |

- **The bones act at both ends.** The flow above is the inbound path only. Policy acts *first* — it mints the task's scope (Section 1) before the clerk ever runs — and *last*, gating every door crossing. It is not a purely downstream gate.
- **Why the immune system is not an LLM.** The hands are persuadable by design — following language is their job. A scorer over deterministic features cannot be argued with, but it *can* be evaded: adaptive attacks have bypassed published detectors. So it senses and scores; the bones decide.
- **What it learns.** What normal looks like *for this owner* — usual recipients, hours, message classes, thread patterns. It is the tension sensor that tells the rubber when to stiffen.
- **Population prior — a requirement, not an enhancement.** The learner starts from a population-level prior and adjusts per owner. In the scoped workflow the features are coarse (known/unknown sender, hour, message class), which keeps cold-start noise survivable.
- **Bounded learning.** The immune system may tighten on its own; loosening requires the owner's confirmed examples. Normal *can* be boiled — but only through owner approvals.

## 3. The airlock protocol — *forms, not conversation*

The components communicate, but never in free-form dialogue — conversation is the medium the attacker speaks. Forward raw text, and the injection rides the elevator up.

- **Case files, not content.** The clerk compiles a dossier of typed fields: provenance tags, extracted features, suspicious elements as inert tokens — e.g. `RECIPIENT_7 [source: webpage, first seen: today]`. Meaning survives; instruction-ness does not.
- **Typed fields only.** Every case-file field is an enum, a typed value, or a reference to a tagged value. The clerk uses constrained decoding into those sets. No free-text string crosses the airlock. For the messaging workflow:
  - `need ∈ {price, availability, booking, complaint, other}`
  - `requested_action ∈ {reply, call, visit, none}`
- **Scores stay with the scorer.** The immune system's scores feed the bones; they never enter a case file.
- **Narrow questions, constrained answers.** Policy poses one templated question ("Does `RECIPIENT_7` plausibly relate to the stated task?"); the hands reply only with a verdict from a short list, a confidence, and evidence pointers. No free text flows back.

## 4. Asymmetric trust — *the key rule*

> **The hands may convict tainted content, but they may never acquit it.**

This is the integrity rule of information-flow control applied to model verdicts: anyone may raise a taint label; only the owner may lower it.

- **Convictions raise suspicion silently.** Content is quarantined; nothing nags.
- **Acquittals are one vote.** If the hands call tainted material "fine," policy still routes the case to the owner, who judges outside evidence.
- **Interrupting the owner is a scarcer currency.** Owner-visible interruptions are budgeted, batched into one digest on a fixed schedule, and repeated stiffens from the same thread collapse into one entry. Asymmetric trust governs silent suspicion; an interruption needs corroboration.
- **Clean but unusual material.** On untainted material the hands' judgment may carry the decision: the risk there is a false alarm, not a hijack.
- **Only the owner mints gold labels.** Model verdicts never enter training data as ground truth, or an attacker could teach the immune system to bless a pattern. Every stiffen-and-ask moment labels the owner's risk taste — prompts fade as the system gets more *owner*, not more permissive.
- **First-send safeguards.**
  - Approval screens show provenance in the largest type on the screen ("**This number came from a web page**").
  - Draft approval screens in owner-initiated mode show provenance the same way: "**This draft was composed from content you summoned, not content you wrote.**"
  - Newly approved recipients stay probationary, with rate limits, for a fixed window.
  - The owner gets a periodic review list of everything the immune system currently treats as normal.

---

## 5. Honest limits

- Classifiers catch known shapes; novel phrasing can score clean, and adaptive attackers evade scorers. Provenance decides — and the clerk is the soft spot: uncertain means ask, never act.
- Normal can be boiled through owner approvals; the owner is phishable.
- The mail slot is observable: the script reveals the classification, and owner follow-ups and exhausted rate limits reveal different handling. A spoofed SMS origin can reflect one public message to a bystander; SMS cost is capped, not eliminated.
- No version secures a fully general agent with unconstrained tools.

## 6. Build order — boring first

- **v1:** fixed, word-for-word scripts; provenance tags on every value; an action allowlist; owner approval on first send to anyone new, except through the mail slot with its budgets and cap.
- **v2:** the learning immune system on a population prior, silent stiffening, and the full airlock. In a scoped workflow — contact, log, fixed script, schedule — provenance is crisp: boring reliability.

## Evidence & prior art

Not new in parts, and not claimed to be.

- **Dual LLM pattern** — Willison, 2023. <https://simonwillison.net/2023/Apr/25/dual-llm-pattern/>
- **Six design patterns for securing LLM agents** — Beurer-Kellner et al., 2025. arXiv:2506.08837
- **CaMeL** — Debenedetti et al., 2025: 77% of AgentDojo tasks with provable security vs. 84% undefended (v2 figures). arXiv:2503.18813
- **Task-minted privileges (stretch per task)** — Progent, Shi et al., 2025. arXiv:2504.11703
- **Agents Rule of Two** — Meta, 2025. <https://ai.meta.com/blog/practical-ai-agent-security/>
- **Taint rule (asymmetric trust)** — information-flow control: Denning, "A Lattice Model of Secure Information Flow," CACM, 1976; Biba, "Integrity Considerations for Secure Computer Systems," MITRE, 1977.
- **Retraction** — just-in-time access, standard IAM practice.
- **Auto-reply hygiene** — RFC 3834, "Recommendations for Automatic Responses to Electronic Mail," 2004; DMARC, RFC 9989, 2026.
- **Why the guard is a tripwire** — Nasr et al., "The Attacker Moves Second," 2025. arXiv:2510.09023

**Claimed here:** the synthesis under one metaphor, and one application — the one-way learning rule (tighten autonomously, loosen only on owner-confirmed labels) on a per-owner baseline.

---

**Success looks like:** fooled occasionally, interrupted sometimes, and no irreversible harm without an owner decision in the loop.
