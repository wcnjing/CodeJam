# Evaluation & Reliability — work plan (Person 4)

> **Status:** plan only. No implementation code has been written on this branch yet.
> **Branch:** `feat/evaluation-reliability`, cut from `origin/main` @ `295939c`.
> **Scope:** benchmark runner, metrics, overhead measurement, clean installation,
> E2E integration testing, demo reliability. Nothing in Persons 1–3's lanes.

## 0. Baseline verified on this branch

Everything below was actually run, not assumed:

| Check | Result |
| --- | --- |
| `npm install` from lockfile | 196 packages, ~5s, exit 0 |
| `npm run eval:policy` | runs, prints scorecard |
| `npm run bench:security` | runs, headline escape rate 1.4%, p50 2.3 µs / p95 4.5 µs |
| `npm run check` | **FAILS on Windows** — 12 of 78 tests fail (see below) |

Local repo note: this working tree was nested one directory below the remote's
layout with no commits on `main`. It has been flattened so the tree matches
`origin/main` byte-for-byte. No content was changed.

### Finding: the validation command is red on Windows out of the box

`npm run check` fails on a clean Windows clone. 66 tests pass, 12 fail, across
4 files. Two distinct POSIX-only assumptions:

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

**Why this matters to my lane specifically.** Items 4 (clean installation),
5 (E2E integration testing) and 6 (demo reliability) are all directly compromised:
a teammate or judge who clones on Windows sees a failing test suite, and the
integration tests I need to build on cannot run on my own machine. It also means
any CI I write must be a matrix, or must state plainly that the runtime suite is
POSIX-only. This is a cross-lane issue — the tests belong to Persons 1 and 2 —
so it is logged as a dependency in §4, not fixed here.

## 1. What already exists that I can build on

The starter kit already ships a substantial slice of my lane. I should extend
these rather than rebuild them.

| Component | File | Covers |
| --- | --- | --- |
| Labeled corpus (115 entries) | `apps/server/src/policy-corpus.ts` | Input data for every harness |
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

### 2.4 Clean installation
- **No CI exists.** There is no `.github/` directory. `docs/POLICY_EVALUATION.md`
  and the README both state thresholds are "asserted in CI" — that claim is
  currently false. Fixing it is my lane.
- `npm ci` (lockfile-exact, the actual clean-install command) is never exercised;
  only `npm install` is documented.
- No preflight/doctor check. A fresh clone needs Node 22+, npm 10+, a container
  engine, an Ark key, and a reachable regional `ARK_BASE_URL`. Every one of these
  is a failure mode discovered *after* a long build.
- **There is no way to see the project work without a model key and a container
  engine.** `npm run eval:policy` / `bench:security` are the only zero-config
  entry points and they are not presented as the front door.

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

## 3. Hard dependency on Person 1 — I am blocked on the policy contract

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

**Why this is a blocker.** Person 1's lane is
`actor + action + resource + context → decision, capabilities`. The current
signature has **no actor**, **no resource**, **no capability model**, and returns
`violation | null` rather than a decision value. Person 1's work will almost
certainly *replace* this function. Six call sites depend on it directly
(`policy-eval.ts`, `security-benchmark.ts`, `evaluation-summary.ts`,
`redteam.ts`, `codex-runner.ts`, `container-codex-runner.ts`), so a harness
written against today's signature is throwaway work.

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

### My mitigation while blocked

Define a **`PolicyProbe` adapter interface** inside my own new files — a single
narrow seam that wraps whatever the policy engine exposes. All my harness code
targets the adapter. When Person 1 lands, I rewrite one small file instead of the
whole harness. This makes items 1.1–1.4 of my scope startable today.

## 4. Other cross-lane dependencies (note, do not implement)

| From | What I need | Risk if not agreed |
| --- | --- | --- |
| **Person 2** | Stable `CorpusEntry` schema and stable `category` strings | `familyOf()` in `security-benchmark.ts` maps categories by string prefix (`c.startsWith("rt-")`). Renaming a category silently reclassifies attacks and moves my headline number. |
| **Person 2** | Corpus growth to be additive, with new categories announced | Per-family coverage tables and CI thresholds shift under me otherwise. |
| **Person 3** | Agreement on the `EvaluationSummary` payload boundary — I own the fields, they own the rendering | I want to add `p99`, `throughput`, `resourceUsage`, `runMetadata`. Additive fields are safe; a rename breaks their dashboard. |
| **Person 3** | Whether the dashboard should show overhead-vs-baseline | Changes what I compute and expose. |
| **Persons 1–3** | Someone to own fixing the "asserted in CI" claim in `README.md` and `docs/POLICY_EVALUATION.md` once CI actually exists | Those are shared docs; I will not edit them unilaterally. |
| **Person 1 / Person 2** | A decision on the Windows test failures (§0). Either make the fake-Codex spawn cross-platform (`spawn(process.execPath, [script])` instead of relying on the shebang) and de-hardcode the `/tmp` paths, or declare the runtime suite POSIX-only | These are their test files. Until resolved, `npm run check` is red on Windows and I cannot run the integration tests I need to extend. |

## 5. Ordered task list

### Phase 0 — today, fully unblocked

| # | Task | Notes |
| --- | --- | --- |
| 0.1 | `PolicyProbe` adapter seam (new file, my lane) | The de-risking move for §3 |
| 0.2 | CI workflow: `npm ci` → `typecheck` → `test` → `build` → `eval:policy` → `bench:security` → `threat-model` | Makes the "asserted in CI" claim true; pure addition, no existing file touched. Ubuntu first; add a Windows leg once §0's failures are resolved, otherwise CI would be born red |
| 0.3 | `scripts/preflight.mjs` — Node/npm version, container engine, free ports, `ARK_BASE_URL` reachability, `.env` sanity | Demo reliability + clean install |
| 0.4 | Clean-install rehearsal: fresh clone → `npm ci` → zero-config eval, timed and documented | Produces the real "minimal steps" number |
| 0.5 | Unified metrics module: warmup, repetitions, p50/p95/**p99**, throughput, RSS/CPU delta | Replaces three duplicate timers — **ownership question, see §6** |

### Phase 1 — after Phase 0, still unblocked

| # | Task | Notes |
| --- | --- | --- |
| 1.1 | Single benchmark runner entry point emitting JSON + human report, with run metadata | |
| 1.2 | Overhead harness: policy-on vs policy-off wall-clock per simulated Run, using the existing fake-Codex stand-in | The genuinely missing measurement (§2.3) |
| 1.3 | Container-teardown latency measurement (also the containment race window) | Safety number as well as perf |
| 1.4 | Wire `redteam.ts` into an npm script and into CI | Currently orphaned |
| 1.5 | Benchmark result baseline file + regression gate with tolerance bands | Needs 0.5's stability work first |

### Phase 2 — E2E and demo, partially blocked

| # | Task | Blocked on |
| --- | --- | --- |
| 2.1 | Full-loop E2E test over HTTP: create agent → run → denial → held → approve → scoped grant → continuation → recovery | Person 1's decision shape (labels/outcomes) |
| 2.2 | `/api/evaluation` payload contract test | Person 3 agreeing the field set |
| 2.3 | Deterministic offline demo mode (recorded/scripted runner, no live model) | **Team decision — see §6** |
| 2.4 | Pre-demo smoke script running the full happy path + the deny path end to end | 2.1, 2.3 |
| 2.5 | Final overhead + metrics numbers for the writeup, against the final policy engine | Person 1 landing |

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
4. **`npm run check` currently does not include the eval harnesses.** Should CI
   gate on `eval:policy` / `bench:security` thresholds, or run them as reporting
   only for the first iteration?
5. **Has Person 1 started?** If their engine is close, I should wait rather than
   write an adapter against a signature that dies this week.
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
