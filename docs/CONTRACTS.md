# Extensible contracts

Four seams in this codebase are contracts rather than incidental interfaces: each
has more than one implementation, each was introduced to make something possible
that a monolith would have foreclosed, and each can take a new implementation
without the rest of the system knowing.

Two are code (`AgentRunner`, `scanCommandsWith`). Two are process contracts
enforced by gates rather than by types (the figure contract, the ratchet
contract) — they constrain what a *document* or a *benchmark* may claim, and they
are the two most portable things this project produced.

For each: what the seam is, what implements it today, and what a new
implementation has to provide.

---

## 1. `AgentRunner` — how a turn is executed

**The seam.** Everything above it — the API, `AgentService`, the store, the
approval loop and the policy engine — is written against three methods and knows
nothing about containers, child processes or models.

```ts
export interface AgentRunner {
  run(request: RunnerRequest): Promise<RunnerResult>;
  cancel(agentId: string): Promise<boolean>;
  isAvailable(): Promise<boolean>;
}
```

**What flows through it.** `RunnerRequest` carries `agentId`, `workspacePath`,
`prompt`, `threadId`, and optionally `extraAllowedHosts` — hosts granted for this
single execution because a human approved a held Run. That field is the entire
mechanism by which an approval is *scoped*: it is passed to one execution and
never persisted to config, so approving a request cannot widen the policy.

`RunnerResult` returns `output`, `threadId`, `usage`, and `violations` — the last
populated only in monitor mode, where a Run completes despite denials. In enforce
mode a denial ends the Run, so there is nothing to report at the end.

**Implementations today — three.**

| Implementation | Executes | Declares as write roots | Notes |
| --- | --- | --- | --- |
| `ContainerCodexRunner` | One disposable container per turn | `/workspace`, `/tmp`, `/var/tmp` | `--rm`, two bind mounts |
| `CodexRunner` | Codex child process | `request.workspacePath` only | `/tmp` here is the real host `/tmp` |
| `ReplayRunner` | Nothing — recorded output | n/a | No key, no network, no spawn |

**What a new implementation must provide.**

1. **Argv-only execution.** No shell on any path. This is not stylistic: passing
   the prompt through a shell is remote code execution, verified by making it
   create a file during this project.
2. **A stream the enforcement point can read.** Commands must be observable
   *before* they complete. A runner that only returns a transcript at the end
   moves enforcement from prevention to forensics.
3. **Its own write roots.** "Inside the sandbox" is a property of the runner, not
   a platform constant. An empty list fails closed.
4. **Honest termination.** `cancel` returns whether it actually cancelled
   something. `ReplayRunner` returning `true` when no run was in flight was a real
   bug caught in review.
5. **A declaration of what it does not prove.** `ReplayRunner` spawns nothing, so
   it cannot demonstrate containment, and it prints that at the end of every run
   rather than letting a green result imply more than it earned.

---

## 2. `scanCommandsWith` — the injectable evaluator

**The seam.** The overhead harness needs to answer "what does the policy cost?",
which requires running the identical workload with policy on and policy off.
Without a seam that means either measuring a different code path (and reporting
it as the same one) or adding a bypass to the enforcement path.

```ts
export function scanCommandsWith(
  actor: Actor,
  commands: readonly string[],
  startIndex: number,
  context: PolicyContext,
  evaluate: (actor, command, context) => PolicyViolation | null,
): DetectedViolation[]
```

`scanCommands` keeps a byte-identical signature and delegates to it with the real
evaluator bound.

**Why it is shaped this way.** The obvious version — a `policyEnabled` flag on
`scanCommands` — was rejected: it puts a disable switch on the enforcement path
itself, where a config mistake becomes a silent bypass. Delegation means the
entry point the runners call has **no injectable evaluator on it at all**; the
seam exists one level down, reachable only by a caller that constructs it
deliberately. That distinction is what made the seam acceptable to add to a
security control.

**Implementations today — two.** The real capability engine, and a policy-off
evaluator that returns `null`, used by `bench:overhead` to measure the delta.

**What a new implementation must provide.** A pure function of
`(actor, command, context)`. It must not mutate context, must not perform I/O,
and must be deterministic — the harness runs it thousands of times and reports
percentiles, so a non-deterministic evaluator produces a latency figure that
describes nothing. A shadow implementation that logs and returns `null` is the
natural way to trial a rule change against production traffic.

---

## 3. The figure contract — every number traces to a run

**The contract.** In this repository, a published numeric claim must satisfy one
of exactly three conditions:

1. **Traceable** — the number appears in the CI run its surrounding text cites,
   at the precision the text states it to. `0.62` is satisfied by a logged
   `0.6197`; `58.19` is *not* satisfied by `58.2`.
2. **Declared local** — the document itself wraps the block in
   `<!-- figures: local reason="..." -->`, stating why no run can contain it
   (a code state that was never committed, a before/after on one machine).
3. **Registered** — an entry in `docs/figures-exempt.json` with a written reason
   a reader can evaluate.

Anything else fails the build. The failure state deliberately does **not**
distinguish "stale" from "fabricated": from the document's side they are one
defect, and only the author knows which.

**Provenance labels are a second clause.** A label such as "measured locally,
pending CI" is a claim with an expiry date. Every label must register the
condition that retires it, and the check fails when that condition is met — an
expired label misleads every reader from the moment it expires, so unlike a stale
citation it is not ratcheted.

**Implementation today.** `scripts/verify-figures.mjs`, gated in CI. See
[FIGURE_CONTRACT.md](FIGURE_CONTRACT.md) for what a second project needs to adopt
it.

**What a new implementation must provide.** A way to resolve a citation to
evidence (here: `gh run view --log`), numeric-token extraction that is *not*
shaped like the figures it expects to find, and both ratchets. The extraction
breadth is the load-bearing part: the check exists because a prose clause —
"still under 0.5% of a run's wall time" — was never checked, having never
presented itself as a figure.

---

## 4. The ratchet contract — residuals are named, and the gate fails both ways

**The contract.** A benchmark that can only report success is advertising. Every
adversarial harness here publishes:

- a **named signature list** of accepted residuals, each with a reason in the
  source;
- a **count** that may not be exceeded;
- a gate that fails when the count goes **up** *or* **down**.

Failing on a decrease is the unusual half and the one that matters. A ratchet
left above its residual is headroom: someone closes half a gap, the number stays
high, and a later regression back to the old ceiling passes silently. So a stale
ratchet is a build failure with the message "lower it".

**Implementations today — three.** `bench:generate` (6,860 variants),
`bench:injection` (3,750), `verify:figures` (two independent ratchets:
untraceable figures and uncited figures, kept separate so repairing one cannot
create room for the other).

**What a new implementation must provide.**

1. **Signatures, not just a count.** A count alone cannot tell a new bypass from
   an old one. The signature is what makes "did this regress?" answerable.
2. **A reason per signature, in the source.** The residual list is where a gap
   gets accepted, so accepting one should cost a paragraph.
3. **Failure in both directions.**
4. **Separation of unlike failures.** `bench:injection` gates containment
   separately from detection, because a rule firing is not a process dying, and
   `direct`-class leaks separately from carrier leaks, because a regression in
   the ordinary rules must never be absorbed into a carrier ratchet.

**A worked warning.** During this project the ratchet was about to accept three
signatures that were not real: the benchmark had generated malformed shell
(nested single quotes) and was scoring its own quoting bug as a product defect.
Publishing a false residual is worse than missing a real one — a missing residual
is a gap someone may yet find, while a false one sends a person hunting a bypass
that does not exist. It was caught by reading the generated commands rather than
the count, which is the one check here that no gate performs.

---

## The pattern the four share

Each seam exists because a claim needed to be *checkable* by something other than
the person making it.

- `AgentRunner` makes "the container dies" checkable separately from "the rule
  fired", because a second implementation can spawn nothing and prove the
  difference matters.
- `scanCommandsWith` makes "the policy costs X" checkable without measuring a
  different code path and calling it the same one.
- The figure contract makes "this number came from that run" checkable
  mechanically, instead of by the author re-reading their own work.
- The ratchet contract makes "nothing regressed" checkable, instead of inferred
  from a number that only ever goes up.

That is the throughline worth taking to another codebase: a contract is worth
extracting where it converts a claim into something a machine can refuse.
