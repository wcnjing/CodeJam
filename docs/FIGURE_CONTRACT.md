# The figure contract

A portable rule for documents that publish measurements, and what it takes to
adopt it in another project.

This is the most transferable thing this lane produced. The benchmarks are
specific to a command-policy engine; the failure modes they exposed are not.

---

## The problem it solves

A project that publishes numbers accumulates three defects that nothing catches:

1. **A stale number.** The measurement was real and the code has moved. Nothing
   fails, because the number is still a number.
2. **A number from the wrong run.** The text cites run A; the value came from run
   B. The citation is *present and correct-looking*, which is what lets it
   survive review.
3. **A number from nowhere.** Nobody measured it. It reads like the others.

None announces itself, and all three survive a careful reader, because a reader
checks the numbers that look like claims. This project found eight wrong claims
by hand before writing the check, and the eighth — *"still under 0.5% of a run's
wall time"*, where the run says 0.62–0.70% — is the one that defines the design:
it survived because it was a **reassuring clause at the end of a sentence about
something else**, and a verification habit shaped like "check the figures" only
ever checks things shaped like figures.

So the contract does not look for figures.

---

## The contract

**C1 — Documents declare their runs.** A numeric claim is checked against the CI
run its surrounding text cites. Citation scope runs from a citation to the next
one, in both directions within a short lookahead, because documents cite both
before and after the number.

**C2 — Every numeric token is traceable.** Not every *figure* — every token
carrying a unit, a percent sign, or a denominator. Each must land in exactly one
of three states:

| State | Meaning |
| --- | --- |
| `MATCHED` | The value appears in the cited run's log, **at the precision the text states**. `0.62` is satisfied by a logged `0.6197`; `58.19` is not satisfied by `58.2`. |
| `DECLARED LOCAL` | The document itself wraps the block in a marker giving the reason no run can contain it. |
| `EXEMPT` | Registered in a file, with a written reason a reader can evaluate. |

Anything else is `UNEXPLAINED` and fails the build. **The failure state does not
distinguish stale from fabricated**, deliberately: from the document's side they
are one defect and only the author knows which.

**C3 — Provenance labels register their retirement condition.** "Measured
locally, pending CI" is a claim with an expiry date. It was accurate when written
in this project and false about ten hours later when the relevant branch's CI
ran — nothing was edited, the world moved. Every such label registers the
condition that retires it, and the check fails when the condition is met. Not
ratcheted: an expired label misleads every reader from the moment it expires.

**C4 — Ratchets fail in both directions.** A ratchet above its residual is
headroom, and headroom is how a later regression passes silently. A stale ratchet
is a build failure whose message is "lower it".

---

## Two mechanisms worth copying exactly

**Distinguish misattributed from invented.** When a value is absent from its
cited run, search every other known run before reporting. A value found elsewhere
is a *citation to repair*; a value found nowhere is a *claim to retract*. These
need different fixes, and collapsing them into one number tells the author
nothing. In this project 70 of 70 initial failures were misattributions — the
measurements existed, the citations pointed at the wrong run — which is a
completely different remediation from 70 fabrications.

**Declare provenance in the document, not only in a config.** Registering an
exemption by *value* exempts that value everywhere, and a number that is a local
measurement in one paragraph is often a genuine CI figure in another — `1.19%`
was both here. An inline marker scopes the exemption to the block and, more
importantly, **puts the reason in front of the reader**. An exemption a reader
can see is reviewable; one in a JSON file is not.

---

## Adopting it in another project

### What is portable as-is

The extraction, the precision-aware matching, the three-state classification, the
misattribution search, the inline `figures: local` marker, both ratchets, and the
provenance-label evaluation. That is the whole of the logic.

### What must be replaced — three couplings

`scripts/verify-figures.mjs` is coupled to this repo in exactly three places.

**1. The evidence resolver.** Two calls shell out to `gh run view --log`.

```js
execFileSync("gh", ["run", "view", runId, "--log"], …)
```

Replace with whatever produces a log for a build id — `gitlab-ci`, Buildkite's
API, a bucket of archived logs, or a local directory of files named by build.
The only requirement is `(runId) => string`. Cache it; the check fetches each
build once.

**2. The citation pattern.** `RUN_URL = /actions\/runs\/(\d+)/` recognises a
GitHub Actions link. Replace with your CI's URL shape. This is the one place the
contract touches your documents' prose.

**3. The document list and unit vocabulary.** `DOCS` names five files.
`FIGURE` recognises `%`, `µs`, `us`, `ms`, `MB`, `GB`, `x` and `n/m`
denominators. Add units your project publishes — a latency-free project may want
`req/s`, `MiB`, `bp`.

### What to calibrate, not copy

**The ratchet's starting value is yours, and switching this on will not be
clean.** It found 70 untraceable figures on the first run here. Set the ratchet
to what you actually find, record *why* in the note beside it, and work it down.
A gate that is red on arrival gets disabled rather than fixed.

**The ratchet is a property of the corpus, not a quality score.** It read 24 on
one branch and 28 on another with no figure having changed, purely because the
two trees carried different documents. After a merge or rebase, check whether the
*documents* moved before concluding a figure went wrong. This cost real
confusion here and is worth knowing in advance.

### Adoption order

1. Point the resolver and citation pattern at your CI. Run in `--report` mode.
2. Read the output before changing any document. The first run is a survey.
3. Set both ratchets to the measured values, with a note saying what they were.
4. Gate it in CI.
5. Work the number down by *citing correctly*, not by exempting. Exemptions are
   for figures that genuinely cannot come from a run.

### What it will not catch

It reads **figures, not code**. Three times in this project, generated code was
written that read correctly in every tool and behaved differently — most sharply,
Python-heredoc escaping that wrote literal backspace characters into two regex
literals, which displayed correctly under `grep`, under an editor, and in review,
tested `true` when retyped by hand, and never matched anything in place. That
class is invisible to this check by construction, and the mitigation remains
procedural: prefer structured editing over generated text for anything containing
escapes, and run `cat -A` on a suspect line.

It also cannot tell you a number is *the wrong measurement of the right thing* —
that a percentage describes one workload and is quoted as if it described the
system. That is a wrong-level error, and only measuring the thing you assumed was
the lever catches it.

---

## Related

- [CONTRACTS.md](CONTRACTS.md) — the other three seams, including the ratchet
  contract this shares its failure discipline with.
- [EVALUATION_RELIABILITY_PLAN.md](EVALUATION_RELIABILITY_PLAN.md) — the five
  failure modes, with the worked examples each was derived from.
