# Evaluation & Reliability — work plan (Person 4)

> **Status:** plan only. No implementation code has been written on this branch yet.
> **Branch:** `feat/evaluation-reliability`, cut from `origin/main` @ `295939c`.
> **Scope:** benchmark runner, metrics, overhead measurement, clean installation,
> E2E integration testing, demo reliability. Nothing in Persons 1–3's lanes.

## 0. Baseline verified on this branch

Everything below was actually run, not assumed. The test-suite rows are no longer
a single-machine assertion: they are **CI-verified on clean runners** —
[run 33232530058](https://github.com/wcnjing/CodeJam/actions/runs/33232530058).

Environments:

- **CI** — `ubuntu-latest` on Node 22 and Node 24; `windows-latest` on Node 24
- **Local POSIX** — Linux, Node 22.22.2
- **Local Windows** — Node 24.16.0

| Check | Environment | Result |
| --- | --- | --- |
| `npm install` from lockfile | local POSIX | 196 packages, ~5s, exit 0 |
| `rm -rf node_modules && npm ci` | local POSIX | ~6s, exit 0 |
| `npm run eval:policy` | both | runs, prints scorecard |
| `npm run bench:security` | both | runs, headline escape rate 1.4%, p50 2.3 µs / p95 4.5 µs |
| `npm run test` | **CI ubuntu, Node 22** | exit 0 — **106/106 pass** across 16 test files, 2.77s |
| `npm run test` | **CI ubuntu, Node 24** | exit 0 — **106/106 pass** across 16 test files, 2.04s |
| `npm run test` | **CI windows, Node 24** | exit 1 — **94/106 pass, 12 fail** across 16 files, 3.24s |
| `npm run check` | local Windows | exit 1 — the same 12 failures (see below) |

The suite has grown since this document was written: 78 tests across 14 files
then, **106 across 16** now, after Phase 1 added `bench/metrics.test.ts` and
`evaluation-contract.test.ts`. The figures above are the current ones. The ~25s
local `npm run check` figure is superseded by CI's measured `npm run test` times,
which are the ones a reader can click through and check.

**The platform-vs-Node-major confound is resolved — by measurement, not
inference.** This section previously carried a caveat: the POSIX and Windows
baselines differed in *two* variables at once, platform and Node major, so
attributing the failures to platform rested on reading the failure mechanisms
rather than on evidence. The ubuntu matrix settles it — **Node 22 and Node 24
both pass 106/106 on the same OS**, so the Node major is not the variable. And the
Windows leg reproduced **12 failures out of 106, byte-identically to the local
Windows run**, on a clean GitHub runner with no contributor machine involved.
Both platform claims now rest on the same public evidence.

Local repo note: this working tree was nested one directory below the remote's
layout with no commits on `main`. It has been flattened so the tree matches
`origin/main` byte-for-byte. No content was changed.

### Finding: the validation command is green on POSIX, red on Windows out of the box

This is a **platform** defect, not a broken suite. On Linux, `npm ci && npm run
check` is exit 0 with all 106 tests passing, on both Node 22 and Node 24. On
Windows the same command fails: 94 pass, 12 fail, across 4 files —
`runner-policy.test.ts` (8/8), `budget.test.ts` (2/2),
`container-runner-policy.test.ts` (1/1) and `container-codex-runner.test.ts`
(1/2). Two distinct POSIX-only assumptions account for all 12:

- **11 failures — `spawn EFTYPE`.** `runner-policy.test.ts`, `budget.test.ts` and
  `container-runner-policy.test.ts` write a stand-in `codex.mjs` with a
  `#!/usr/bin/env node` shebang, `chmod 0o755` it, and spawn it directly. Windows
  does not dispatch on the executable bit or the shebang, so every spawn throws
  `EFTYPE`. This takes out **the entire runtime enforcement test suite** — the
  tests that prove the container is killed, monitor mode observes, the agent slot
  is released, the protected asset is untouched, and evidence is redacted.
- **1 failure — hardcoded POSIX paths.** `container-codex-runner.test.ts` asserts
  bind-mount arguments containing literal `/tmp/codex-home` and
  `/tmp/agent-workspace`.

Everything that does not spawn a process passes: policy evaluation, the corpus
scorecard, the security benchmark, the threat model, the store, the HTTP boundary,
agent lifecycle, and approvals.

#### The Windows problem is narrower than "the suite is broken"

The first CI run stopped at the failing test step, so it verified `typecheck` and
`test` and nothing else. Adding `if: always()` to the steps after it settled what
the rest of the toolchain does on Windows, and the answer is: **it all works.**

| Windows step | Result |
| --- | --- |
| `npm ci`, `npm run typecheck` | pass |
| `npm run test` | **12 of 106 fail** — the spawn and `/tmp` assumptions |
| `npm run build` | pass (vite 1.03s, then `tsc`) |
| `eval:policy`, `bench:security`, `threat-model` | pass |
| `npm run bench:store` | pass |
| `npm run demo:offline` | pass — "All three harnesses completed" |

So a Windows contributor can install, typecheck, build, run every evaluation
harness and open the zero-config front door. What they cannot run is the runtime
enforcement suite. That is a materially smaller claim than "Windows is broken",
and it sharpens the §4 ask: the fix really is confined to two of Persons 1–2's
test files, not to the project's Windows support in general.

#### The security metrics are platform-independent

`bench:security` produced **identical headline numbers on Windows and Linux**:
98.6% attack block rate, 1.4% predicted escape rate, 0 secret leaks, 6/6 verified
controls. Not close — the same.

This is worth stating rather than assuming. It is a reproducibility result: the
policy engine is pure text matching over a fixed corpus with no clock, no
randomness and no external state, and the numbers demonstrate that rather than
merely asserting it. It also means the headline figures in the writeup are a
property of the engine, not of the machine that produced them — which is exactly
the claim a reviewer should be most sceptical of, and the one CI now answers on
every push. Note the contrast with the *timing* figures in §2.2 and §2.3, which
are strongly platform-dependent: correctness reproduces exactly, latency does not.

**Why this matters to my lane specifically.** On Windows, items 4 (clean
installation), 5 (E2E integration testing) and 6 (demo reliability) are all
directly compromised: a teammate or judge who clones on Windows sees a failing
test suite, and the integration tests I need to build on cannot run on my own
machine. It also means any CI I write must either be a matrix, or must state
plainly that the runtime suite is POSIX-only. This is a cross-lane issue — the tests belong to Persons 1 and 2 —
so it is logged as a dependency in §4, not fixed here.

## 1. What already exists that I can build on

The starter kit already ships a substantial slice of my lane. I should extend
these rather than rebuild them.

| Component | File | Covers |
| --- | --- | --- |
| Labeled corpus (114 entries: 69 attack, 45 benign) | `apps/server/src/policy-corpus.ts` | Input data for every harness |
| Classifier scorecard | `apps/server/src/policy-eval.ts`, `policy-eval-cli.ts` | Recall, FPR, precision, F1, blind-set recall, per-category |
| Escape-rate benchmark | `apps/server/src/security-benchmark.ts`, `security-benchmark-cli.ts` | Escape rate, per-family, baseline-vs-protected, p50/p95 |
| Live summary API | `apps/server/src/evaluation-summary.ts` → `GET /api/evaluation` | Same numbers computed from the running engine |
| Threat register + coverage gate | `apps/server/src/threat-model.ts`, `threat-model-cli.ts` | `@covers <id>` test tagging |
| Runtime integration tests | `apps/server/src/runner-policy.test.ts` | Fake-Codex stand-in, real streaming + termination path |
| Service-level tests | `agent-service.test.ts`, `approval.test.ts`, `budget.test.ts` | Blocked/held/terminated runs, recovery, scoped grants |
| Ad-hoc red-team probes | `apps/server/redteam.ts` | Not wired to any npm script |
| Demo support scripts | `scripts/mock-collector.mjs`, `scripts/plant-injection.mjs`, `scripts/start-local-poc.sh` | Live demo mechanics |

**Key structural fact:** every harness above calls `evaluateCommand()` from
`command-policy.ts` *directly*. That is the coupling point described in §3.

## 2. What does not exist yet — mapped to my six scope items

### 2.1 Benchmark runner
- No single entry point. Three separate CLIs (`eval:policy`, `bench:security`,
  `threat-model`) with overlapping computation and no combined machine-readable
  output.
- No JSON/artifact output at all — everything is `console.log` for humans. Nothing
  can be diffed run-over-run or trended.
- No run metadata (policy version, corpus version, host, node version, commit),
  so a number cannot be attributed to a build.
- `redteam.ts` is orphaned — not in `package.json`, not in CI, not in `npm run check`.

### 2.2 Metrics
- **Three duplicate latency implementations**: `measureThroughput()` in
  `policy-eval.ts` (mean only, 200 iterations), `latency()` in
  `evaluation-summary.ts` (p50/p95/mean, 30 rounds), `policyLatency()` in
  `security-benchmark-cli.ts` (p50/p95/mean, 50 rounds). They disagree by
  construction and will drift.
- **No p99.** My scope asks for p50/p95/p99; only p50/p95 exist.
- **No throughput figure** (decisions/second sustained).
- **No warmup phase.** Timing starts on a cold JIT, so the first samples inflate
  the tail. This is why p95 (4.5 µs) is ~2× p50 (2.3 µs) on a pure-regex function.
- **No stability measure** — single run, no repetitions, no confidence interval.
  A CI threshold on a single noisy sample will flake.
- **No resource usage**: no RSS/heap delta, no CPU time, no measurement of the
  policy layer's memory footprint under sustained load.
- **Latency stability is itself unstable — measured, and it settles what we can
  gate on.** Running the sweep five times and taking the coefficient of variation
  across runs gives, on one machine: p50 ~3.5%, p95 7.5%, mean ~11%, p99 ~17%.
  But **CV is not reproducible between process invocations** — p95 CV alone
  measured 7.5%, 19.8%, 36.5% and 40.9% across four separate runs of the same
  code on the same machine. So:
  - **The durable finding is the ordering: p50 < p95 < mean < p99.** That held in
    every run. p50 is the statistic worth gating; p99 and `max` are not.
  - **CV is a smell, not a threshold.** It is worth printing and worth
    investigating when it jumps, but a CI gate on a number that moves 5x between
    invocations is a gate on the runner, not the code. Recorded here so it is not
    proposed again.
- **The measurement is aimed at the cheap layer.** All three timers measure
  `evaluateCommand()` in isolation — single-digit microseconds. The dominant
  per-decision cost in the *running* system is the store write that records the
  decision: 10–15 ms once a few thousand events have accumulated, three orders
  of magnitude larger and measured on two platforms (§2.3). Metrics that report
  only the µs figure describe the cheap half of the price.

### 2.3 Overhead measurement
This is the largest genuine gap. The existing "baseline" in
`security-benchmark.ts` is a *decision-layer* baseline (a mode that returns ALLOW
for everything) — it measures how much safety the policy adds, **not** how much
time it costs. Nothing measures:
- Added wall-clock per Run: `scanCommands()` over the event stream, the
  `PolicyDecision` write folded into the atomic store update, redaction cost.
- Cost as a fraction of a real turn (which is dominated by model latency) — the
  honest framing of "the policy layer is free".
- Container teardown latency on denial (time from `item.started` to process death)
  — this is also the *containment race window* the README describes, so it is a
  safety number as well as a performance number.
- Throughput ceiling of the store's single-writer JSON path under policy events.
  **Partly measured now — see "the store write is the largest real overhead"
  below.**

#### Monitor mode is *not* a policy-off baseline

The obvious way to get a policy-off number is `POLICY_ENFORCEMENT=monitor`. It
does not give one, and the code says why. In the `applyPolicy()` closure in
**both** `codex-runner.ts` and `container-codex-runner.ts`, `scanCommands()` is
called unconditionally on every parsed chunk; the enforcement mode gates only the
`terminate()` / `removeContainer()` call and the terminal throw. Monitor mode
does exactly the same evaluation work and then declines to act on it, so it
isolates *teardown* cost, not *policy* cost.

Measured with the real `CodexRunner` against a fake codex binary:

| Commands per run | enforce p50 | monitor p50 |
| --- | --- | --- |
| 5 | 25.6 ms | 25.2 ms |
| 50 | 25.6 ms | 25.5 ms |

Flat across both modes and flat across command count — as expected, because both
modes run the same scan and the wall-clock is dominated by process spawn.

**Prerequisite for a real baseline: an injectable evaluator on `scanCommands`.**
`guardedEvaluate(command, context, evaluate = evaluateCommand)` already takes an
injectable third parameter. `scanCommands(commands, startIndex, context)` does
not — it calls `guardedEvaluate(command, context)` and gets the default. Adding
the same optional seam to `scanCommands` and forwarding it is a one-line change
that makes a genuine policy-off run possible (inject a no-op evaluator) without
touching a single rule. It is the **minimum prerequisite for the overhead
harness** (task 1.2). It lands in `command-policy.ts` — Person 1's file — so it
must be agreed with them before I write it; logged in §4.

#### Measured: the store write is the largest real overhead

This is the number the project does not have, and it is not in the policy engine
at all. `JsonStore.mutate()` in `store.ts` `structuredClone`s the **entire**
`Database` and rewrites the **entire** file with `JSON.stringify(data, null, 2)`
on every call; `snapshot()` `structuredClone`s the whole `Database` too.
Recording a denial goes through `store.mutate()` in `agent-service.ts`, which
pushes a `PolicyDecision` onto `database.policyEvents`. So the cost of writing
one policy event is **O(total policy events already stored)**.

Cost of appending one policy event, by number of events already in the store,
measured on **both** environments from §0 (`mutate()` p50 unless noted):

| Events already stored | POSIX p50 | Windows p50 | Win/POSIX | POSIX p95 | POSIX `snapshot()` |
| --- | --- | --- | --- | --- | --- |
| 0 | 0.20 ms | 0.59 ms | 3.0× | 0.56 ms | 0.00 ms |
| 100 | 0.39 ms | 1.08 ms | 2.8× | 0.75 ms | — |
| 1000 | 2.38 ms | 3.54 ms | 1.5× | 4.25 ms | 1.07 ms |
| 5000 | 10.44 ms | 14.90 ms | 1.4× | 16.80 ms | 5.13 ms |

**Carry this as a range, not a point.** The two platforms diverge unevenly, and
the shape of the divergence is itself informative:

- The **fixed** cost — open, write, rename — is about **3× more expensive on
  Windows** (0.20 ms → 0.59 ms at an empty store). That is filesystem syscall
  overhead, and it dominates only while the store is small.
- The **linear** term — `structuredClone` plus full `JSON.stringify` — is much
  closer: **~2.0 µs per stored event on POSIX vs ~2.9 µs on Windows** (1.4×),
  and it is clean linear on both from 0 to 5000. This is the term that matters,
  and it is a property of `JsonStore`, not of one machine: two independent
  platforms, two Node majors, same curve.
- `snapshot()` shows the same shape on Windows (0.03 / 0.10 / 0.87 / 5.52 ms at
  0 / 100 / 1000 / 5000).

#### Decision: store-write gates are set on the slope, not the absolute

This is settled, not an open caveat. The regression gate for store-write cost
(tasks 1.5 and 1.6) is split by where it runs:

- **Everywhere — local and CI.** Assert that the **marginal cost per stored
  event** stays under a bound. Measured 2.0 µs/event on POSIX and 2.9 µs/event on
  Windows: a 1.4× spread, portable enough to gate on without a per-platform
  threshold table.
- **CI only — `ubuntu-latest`, pinned platform.** *Additionally* assert absolute
  p50/p95 at fixed event counts. Local runs treat the absolutes as **advisory**
  and never fail on them.

**Rationale.** A threshold tuned to 10.44 ms at 5000 events goes red on a Windows
dev box with nothing regressed — it would train the team to ignore the gate. The
slope is also the property we actually care about: the claim under test is that
`JsonStore` scales **linearly with stored evidence**, and the slope is the direct
measurement of that. It is roughly 2× more portable than the fixed cost, which is
filesystem-bound and shows a ~3× platform gap. Pinning the platform is what buys
back the right to assert an absolute, so the absolutes live only where the
platform is pinned.

This decision depends on the fixed-vs-marginal decomposition above; keep both
terms reported separately or the gate loses its basis.

For contrast, one `evaluateCommand()` call is ~4 µs p50 on POSIX. At 5000 stored
events the write that *records* a decision costs roughly **2,600×** the decision
itself — three orders of magnitude, and the Windows pair lands in the same
bracket. The README's "~2 µs added per-command decision latency" is the cheap
half of the middleware's price, not the price.

Three consequences that land squarely in my lane:

- **It degrades over a long demo session.** Every denial, every monitor-mode
  observation, every approval makes the next one slower. A rehearsal loop or a
  repeated demo is the exact workload that walks up this curve.
- **`snapshot()` puts the same clone cost on every GET**, including the 900 ms
  run-status poll in `apps/web/src/App.tsx` — so the cost is paid continuously by
  an idle browser tab, not only on denial.
- **The retention gap is already tracked.** `threat-model.ts` carries it as
  **TM-OPS-001** ("Unbounded audit-log growth", status `open`; the residual note
  records retention as the tracked next step). What is new here is that unbounded
  growth is not only an audit-surface risk — it is a live performance regression.

A bounded `policyEvents` window, or an append-only event log instead of a
whole-file rewrite, is therefore the highest-leverage reliability fix I can name.

It is measurable today without waiting on anyone, and **task 1.6 measures it
without changing it**. `npm run bench:store` builds its own `JsonStore` in a temp
directory, so the curve is reproduced from the real class with **zero edits to
shared files** and no owner sign-off.

#### Fix options: scoped, and deliberately not built

The measurement does not need the fix, and the fix is not mine to land —
`store.ts` is imported by `agent-service.ts`, `index.ts` and three test files.
All three options are recorded here so the trade-offs are on the record for
whoever owns the decision.

| Option | Removes the O(n) term? | Cost |
| --- | --- | --- |
| **Cap `policyEvents` with `slice(-N)` in `mutate()`** | **No** — bounds the ceiling only, and `slice` is itself O(n) | Silently discards audit evidence. ~2.4 ms at the cap instead of ~11.7 ms at 5000 |
| **Config-driven retention** (`POLICY_EVENT_RETENTION`) | No — same mechanism, made explicit | Same evidence loss, but declared rather than hidden. Widens the change into `config.ts` |
| **Append-only JSONL event log** | **Yes** — one line appended per decision, no clone, no whole-file rewrite | Largest change. `policyEvents` leaves `Database`; `getPolicyEvents` and the store's single-writer model both need rework |

**Recommendation: none of them yet, and specifically not the first two.** For a
project whose thesis is *trustworthy evidence*, an audit log that silently drops
records to go faster is a demo liability rather than a fix — a judge who asks
"where did event 1001 go?" gets a worse answer than one who asks "why is this
11 ms?". The slice cap also fails on its own terms: it caps the worst case
without removing the linear growth. The JSONL log is the only option that
actually removes the term, and it is a design change that wants its own review.

What this lane owes the decision is the number, not the patch. The number is now
in CI on every push.

### 2.4 Clean installation
- **No CI exists.** There is no `.github/` directory. The README says thresholds
  are "asserted in CI" and `docs/POLICY_EVALUATION.md` refers to "the CI
  threshold" — the only false word in either is **CI**. The thresholds themselves
  *are* gated: `policy-eval.test.ts`, `security-benchmark.test.ts` and
  `threat-model.test.ts` assert hard numeric bounds (core recall = 1, FPR ≤ 0.03,
  evasion recall ≥ 0.8, holdout recall = 1, mean ≤ 50 µs, corpus ≥ 100 entries,
  escape rate ≤ 0.02, secret leaks = 0, 100% of mitigated threats covered), and
  `npm run check` runs `vitest run` — so a regression already fails the build.
  What is missing is a machine that runs it on every push. Fixing that is my lane.
- `npm ci` (lockfile-exact, the actual clean-install command) is never exercised;
  only `npm install` is documented.
- No preflight/doctor check. A fresh clone needs Node 22+, npm 10+, a container
  engine, an Ark key, and a reachable regional `ARK_BASE_URL`. Every one of these
  is a failure mode discovered *after* a long build.
- **There is no way to see the project work without a model key and a container
  engine.** `npm run eval:policy` / `bench:security` are the only zero-config
  entry points and they are not presented as the front door.

#### Finding: the setup tooling nearly shipped a shell injection

Found while building `scripts/preflight.mjs` (task 0.3). Recorded here for where
it happened rather than how large it was.

The container-engine check shells out to `<engine> info`, where the engine name
comes from `CONTAINER_ENGINE` — an operator-supplied environment variable. The
first version passed it to `spawnSync` as `(command, args)`, which is safe: an
args array is not shell-interpreted. Clearing an unrelated Node deprecation
(DEP0190, which fires on an args array combined with `shell: true`) meant
collapsing that into a single command string — and that one change turned an
inert variable into a shell metacharacter sink.
`CONTAINER_ENGINE='docker; echo PWNED'` would have executed `echo PWNED`.

`shell: true` cannot simply be dropped; it is what makes `npm` resolve to
`npm.cmd` on Windows. So the interpolated value is constrained instead:
`CONTAINER_ENGINE` must match `/^[A-Za-z0-9._-]+$/`, or the check fails without
running anything.

Three reasons this is a finding and not a footnote:

- **It is this project's own threat model turned inward.** The product exists to
  deny commands that splice in a second command or reach a non-allowlisted
  destination. Nearly shipping that exact defect class in our own setup script is
  the sharpest evidence available that the adversarial discipline here is real
  rather than self-congratulatory — the same reading that produced the corpus is
  what caught it.
- **It was introduced by a safety fix**, not by the original code. Clearing a
  deprecation warning is the kind of change that gets waved through, and this one
  silently moved a trust boundary in the line beside it.
- **No test would have caught it.** It is not a wrong answer, it is a wrong
  capability. It surfaced from asking "what does this variable reach?" — a
  question none of the harnesses in §2.1–§2.3 are shaped to ask.

Verified: `CONTAINER_ENGINE='docker; echo PWNED'` is rejected as "not a plain
executable name", and `PWNED` never appears in the output.

### 2.5 E2E integration testing
- `runner-policy.test.ts` is a real integration test but stops at the runner
  boundary — it never goes through HTTP.
- `app.test.ts` only covers the auth boundary (2 tests).
- Nothing exercises the full four-component loop in one test:
  HTTP → AgentService → runner → policy decision → store → approval endpoint →
  scoped grant → continuation run → recovery.
- No test asserts the `/api/evaluation` payload shape, which Person 3's dashboard
  renders — a rename there silently breaks their UI.

### 2.6 Demo reliability
- The README itself flags the demo as **model-dependent**: step 3 (secret
  exfiltration) depends on the model being willing to attempt an attack, and in
  their recorded live run *it declined*. Step 2 is called "the deterministic
  spine" but still requires a live model to emit a network command.
- No offline/recorded demo path. If the Ark endpoint is slow, rate-limited, or the
  network is bad on demo day, there is no fallback.
- No pre-demo smoke script that proves the whole path works before presenting.
- No port-conflict / stale-container check (3000, 5173, mock-collector port).

## 3. Dependency on Person 1 — the correctness label space, not the lane

**The contract I would be measuring today:**

```ts
// apps/server/src/command-policy.ts
evaluateCommand(command: string, context: PolicyContext): PolicyViolation | null
guardedEvaluate(command, context, evaluate?): PolicyViolation | null   // fail-closed
scanCommands(commands: readonly string[], startIndex: number, context): DetectedViolation[]
policyContextFrom(arkBaseUrl, extraHosts?, secretValues?): PolicyContext

interface PolicyContext  { allowedHosts: string[]; secretValues?: string[] }
interface PolicyViolation { rule: string; detail: string; hosts?: string[] }
const REVIEWABLE_RULES: readonly string[]   // "held" vs "blocked" is derived from this
```

**Why this contract matters.** Person 1's lane is
`actor + action + resource + context → decision, capabilities`. The current
signature has **no actor**, **no resource**, **no capability model**, and returns
`violation | null` rather than a decision value. Person 1's work will almost
certainly *replace* this function. Six call sites depend on it directly
(`policy-eval.ts`, `security-benchmark.ts`, `evaluation-summary.ts`,
`redteam.ts`, `codex-runner.ts`, `container-codex-runner.ts`), so a *correctness*
harness written against today's signature is throwaway work.

**But what is blocked is narrower than the lane.** Only the **correctness-metric
label space** genuinely depends on Person 1's final signature: recall, FPR,
precision, F1 and the per-rule tables are all computed over `violation | null`
today, and become uncomputable-as-written the moment the outcome becomes
first-class `allow | deny | hold`. That is one axis of one scope item — not a
reason to stop.

Explicitly **not** blocked on Person 1, and therefore not waiting:

- **The store-write overhead measurement (§2.3)** — it measures `JsonStore`, not
  the policy engine, and is already measured.
- **`scripts/preflight.mjs` / doctor check** (0.3).
- **The CI workflow** (0.2).
- **The offline demo entry point** (2.3) and the **pre-demo smoke script** (2.4)
  — a team decision on the first, but not a Person 1 decision.
- **The full-loop E2E test over HTTP** (2.1) — it asserts run *status*
  transitions (`blocked` / `held` / `terminated`), approval records and scoped
  grants, which are `agent-service.ts`'s vocabulary, not `command-policy.ts`'s.
  Those names survive a policy-engine rewrite.

### What I need to ask Person 1 for — in priority order

1. **Is the decision synchronous and pure, or async?** *(Highest impact.)* If it
   becomes `Promise<Decision>` — because capability lookup does I/O — then latency
   distribution, p99, throughput, and the fail-closed guarantee all change shape,
   and the runner's streaming enforcement point needs re-testing. I cannot design
   the timing harness without this answer.
2. **The exact final type signature** — input type (actor, action, resource,
   context) and output type, as TypeScript.
3. **Is it deterministic?** Same input → same decision, no clock, no randomness,
   no external state. CI thresholds and reproducible benchmarks require this. If
   it is not deterministic, I need to know what varies so I can pin it.
4. **The decision outcome enum.** Today it is `null | violation`, with
   `held` vs `blocked` derived downstream via `isReviewableRule()`. If Person 1
   introduces first-class `allow | deny | hold`, my correctness metrics need the
   new label space — and the corpus's binary `benign` / `malicious` labels may
   need a third value (coordinate with Person 2).
5. **Capability seeding.** If a decision depends on which capabilities an actor
   holds, I need a *factory* from Person 1 to construct deterministic actor and
   capability fixtures. I should not be hand-assembling those objects in my
   harness — that would encode assumptions about their model.
6. **Stable rule/decision identifiers**, so per-rule and per-family metrics
   survive internal refactors.
7. **Keep `evaluateCommand` as a thin deprecated adapter** over the new engine
   until my harness has migrated. This lets both lanes move in parallel instead
   of serially.
8. **A policy-set version or hash** exposed at runtime, so a benchmark result can
   be attributed to a specific policy version.

### My mitigation for the part that is blocked

Define a **`PolicyProbe` adapter interface** inside my own new files — a single
narrow seam that wraps whatever the policy engine exposes. All my harness code
targets the adapter. When Person 1 lands, I rewrite one small file instead of the
whole harness. This makes items 1.1–1.4 of my scope startable today — and per
the list above, most of Phases 0–2 does not need the adapter at all.

## 4. Other cross-lane dependencies (note, do not implement)

| From | What I need | Risk if not agreed |
| --- | --- | --- |
| **Person 2** | Stable `CorpusEntry` schema and stable `category` strings | `familyOf()` in `security-benchmark.ts` maps categories by string prefix (`c.startsWith("rt-")`). Renaming a category silently reclassifies attacks and moves my headline number. |
| **Person 2** | Corpus growth to be additive, with new categories announced | Per-family coverage tables and CI thresholds shift under me otherwise. |
| **Person 3** | Agreement on the `EvaluationSummary` payload boundary — I own the fields, they own the rendering | I want to add `p99`, `throughput`, `resourceUsage`, `runMetadata`. Additive fields are safe; a rename breaks their dashboard. |
| **Person 3** | Whether the dashboard should show overhead-vs-baseline | Changes what I compute and expose. |
| **Persons 1–3** | Someone to own fixing the "asserted in CI" claim in `README.md` and `docs/POLICY_EVALUATION.md` once CI actually exists | Those are shared docs; I will not edit them unilaterally. |
| **Person 1** | Agreement to add an optional injectable `evaluate` parameter to `scanCommands()` in `command-policy.ts`, matching the one `guardedEvaluate()` already has | One line in their file, but without it there is no policy-off run: monitor mode still evaluates every command (§2.3), so the overhead harness (1.2) has no baseline to subtract. |
| **Person 1 / Person 2** | A decision on the Windows test failures (§0). Either make the fake-Codex spawn cross-platform (`spawn(process.execPath, [script])` instead of relying on the shebang) and de-hardcode the `/tmp` paths, or declare the runtime suite POSIX-only | These are their test files. Until resolved, `npm run check` is red on Windows and I cannot run the integration tests I need to extend. |

## 5. Ordered task list

### Phase 0 — today, fully unblocked

**Why the clean-installation cluster (0.2–0.4) leads.** This is deliberate
sequencing, not convenience:

- **CI retires the last unverified line in this document.** The POSIX row in §0
  rests on a single run on one machine. A green Ubuntu build turns it into a
  clickable artifact instead of an assertion — and that row is load-bearing for
  the Windows finding underneath it.
- **It fixes the one outright false sentence in our public docs.** The README
  says thresholds are "asserted in CI". The thresholds *are* gated — by vitest
  inside `npm run check` (§2.4) — so only the word "CI" is false, and 0.2 is what
  makes it true.
- **It is cheap and blocks nobody.** CI and preflight cost far less than the
  measurement work in Phase 1, touch no existing file, and hold up no other
  lane — so there is no reason for them to queue behind a harness.

| # | Task | Notes |
| --- | --- | --- |
| 0.1 | `PolicyProbe` adapter seam (new file, my lane) | The de-risking move for §3 |
| 0.2 | **DONE** — `.github/workflows/ci.yml`: `npm ci` → `typecheck` → `test` → `build` → `eval:policy` → `bench:security` → `threat-model` | Blocking job on ubuntu-latest × Node 22 and 24. Separate **non-blocking** windows-latest leg, `continue-on-error: true`, named so its state is unambiguous — see the note below. `redteam` deliberately not wired in; that is 1.4 |
| 0.3 | **DONE** — `scripts/preflight.mjs`, `npm run doctor` | Node/npm versions, container engine, ports 3000/5173/9099, Ark key shape, `ARK_MODEL`, and a live `ARK_BASE_URL` probe with the BytePlus-vs-Volcengine 401 hint. Exits non-zero on hard failure; warnings never block |
| 0.4 | **DONE** — `npm run demo:offline` + README front door | `npm ci` → `npm run demo:offline` is now the documented zero-config path. The clean-install *timing* rehearsal on a fresh clone is still outstanding |
| 0.5 | Unified metrics module: warmup, repetitions, p50/p95/**p99**, throughput, RSS/CPU delta | Replaces three duplicate timers — **ownership question, see §6** |
| 0.6 | **DONE** — folded into 0.4. `npm run demo:offline` runs `eval:policy` + `bench:security` + `threat-model` with no Ark key and no container engine | Verified exit 0 with `ARK_API_KEY`, `ARK_MODEL` and `ARK_BASE_URL` all unset and no engine running. **Still not the same thing as 2.3** — see below |

#### Why the Windows CI leg is non-blocking rather than absent

The original plan for 0.2 said "Ubuntu first; add a Windows leg once §0's
failures are resolved, otherwise CI would be born red". That was the wrong call,
and the reason is §0 itself: the Windows figures there were as much a
single-machine assertion as the POSIX ones were. Deferring the leg would have
left one platform claim verifiable and the other not.

`continue-on-error: true` resolves it — both platforms run on every push, the
branch badge stays green, and the 12 known failures are visible rather than
asserted. The job name states the expectation outright, so a reader does not have
to guess whether red means broken. **The signal worth watching is the failure
COUNT**: a change either means a new POSIX-only assumption was introduced, or one
was fixed.

The ubuntu matrix runs **Node 22 and 24** for a related reason. §0 records that
the POSIX and Windows baselines differed in two variables at once — platform and
Node major — so attributing the failures to platform was an inference, however
well supported by the mechanisms. Passing on both Node majors on one OS turns
that inference into a measurement.

### Phase 1 — after Phase 0, still unblocked

| # | Task | Notes |
| --- | --- | --- |
| 1.1 | Single benchmark runner entry point emitting JSON + human report, with run metadata | |
| 1.2 | Overhead harness: policy-on vs policy-off wall-clock per simulated Run, using the existing fake-Codex stand-in | The genuinely missing measurement (§2.3). Gates it produces follow the slope-not-absolute decision in §2.3 — portable assertions everywhere, absolutes only on pinned-platform CI |
| 1.3 | Container-teardown latency measurement (also the containment race window) | Safety number as well as perf |
| 1.4 | Wire `redteam.ts` into an npm script and into CI | Currently orphaned |
| 1.5 | Benchmark result baseline file + regression gate with tolerance bands | **Gate on p50 only**; report CV alongside as a smell, never as a threshold (§2.2). Tolerance bands follow §2.3's slope-not-absolute decision |
| 1.6 | **DONE — measure and document only.** `npm run bench:store` (`bench/store-overhead.ts`), reporting the curve, the fixed/marginal decomposition and r² | Constructs its own `JsonStore` in a temp dir: **no edit to `store.ts`, no owner sign-off**. Runs in CI on both platforms, so the curve is no longer a laptop figure. The fix is scoped in §2.3 and deliberately **not built** |

### Phase 2 — E2E and demo, mostly unblocked

| # | Task | Blocked on |
| --- | --- | --- |
| 2.1 | Full-loop E2E test over HTTP: create agent → run → denial → held → approve → scoped grant → continuation → recovery | **Nothing.** Asserts run status + approval records — `agent-service.ts` vocabulary, which survives a policy-engine rewrite |
| 2.2 | `/api/evaluation` payload contract test | Person 3 agreeing the field set |
| 2.3 | Deterministic offline demo mode (recorded/scripted runner, no live model) | **Team decision — see §6** |
| 2.4 | Pre-demo smoke script running the full happy path + the deny path end to end | 2.1, 2.3 — sequencing only; neither is blocked on Person 1 |
| 2.5 | Final overhead + metrics numbers for the writeup, against the final policy engine | Person 1 landing |

**0.6 and 2.3 are different things and both are wanted.** 0.6 is a *front door*:
a reviewer with no credentials and no container engine runs one command and sees
the evaluation harnesses produce real numbers. 2.3 is a *replay runner* for the
live demo: a recorded event stream substituted for the model so the denial path
can be shown when the network or the endpoint is unreliable. Neither substitutes
for the other — do not merge them.

## 6. Open questions I need answered before I go further

1. **Ownership of `policy-eval.ts` and `security-benchmark.ts`.** These are
   measurement harnesses (my lane by scope) but they consume Person 2's corpus and
   encode attack taxonomy (their lane). Task 0.5 needs to edit them to remove the
   duplicate timers. **Do I own these two files, or do I raise the change with
   Person 2?**
2. **Is a deterministic offline demo mode acceptable to the team?** It is the
   single highest-value demo-reliability item, but it means adding a runner that
   replays recorded events instead of calling the model — which touches the
   runner factory, arguably Person 1's or shared territory.
3. **What is the demo environment?** Live model + container engine on a laptop, or
   pre-recorded? This determines whether 2.3/2.4 are essential or optional.
4. **The eval thresholds are already gated by `npm run check`** — via
   `policy-eval.test.ts`, `security-benchmark.test.ts` and
   `threat-model.test.ts`, which assert numeric bounds and run under `vitest run`
   (§2.4). What is missing is CI, not the assertions. So the real question is:
   should CI *additionally* run the `eval:policy` / `bench:security` /
   `threat-model` CLIs as **reporting output** — a scorecard attached to every
   build for a human to read and trend — given the thresholds themselves are
   already enforced by vitest? My view is yes, as non-gating artifacts, so that
   there is never a second set of thresholds to keep in sync with the first.
5. **What decision outcome enum is Person 1 targeting, and when?** Not "should I
   wait" — waiting is the wrong move, because only the correctness-metric label
   space depends on their final signature (§3) and everything else in Phases 0
   and 1 is startable now. What I need from them is a shape and a date for
   `allow | deny | hold`, so the `PolicyProbe` adapter is written once against
   the intended label space instead of twice.
6. **Who fixes the Windows test failures (§0), and is Windows a supported dev
   platform for this team at all?** If the answer is "POSIX only, use WSL", that
   is a legitimate call — but it needs to be written down, and it changes the
   clean-installation instructions I am responsible for. If Windows is supported,
   the fix is small (`spawn(process.execPath, [script])` and `path.join` instead
   of literal `/tmp`) but it lands in Persons 1–2's test files.

## 7. Explicit non-goals for this lane

- Writing or extending policy rules (Person 1).
- Writing new attack cases or obfuscations for the corpus (Person 2).
- Dashboard, approval UI, audit timeline, or recovery UX (Person 3).
- Network-layer egress enforcement — deliberately deferred by the project, see
  [docs/KILL_SWITCH_PLAN.md](KILL_SWITCH_PLAN.md).
