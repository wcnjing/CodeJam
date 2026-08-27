# Sentinel middleware pentest suite

A test-and-bypass suite for the **Sentinel** agent middleware (command policy
engine, evidence redaction, step budget, human approval, monitor mode, config
invariants), per `AGENTS.md`:

- test the **baseline** and save scores in `scores/`
- test each **middleware individually and as a whole** (regression) against a
  tagged, categorized case catalog
- test **performance and operational cost** of each middleware
- curate test cases **from past examples** (corpus, red-team probes, defect
  history) and from escalated red-teaming

The suite is deliberately read-only against the platform: it imports the
server's middleware functions and drives the real `CodexRunner` with fake
`codex` binaries, but never modifies `apps/`, `server/`, `deploy/`, `docs/` or
`scripts/`. All suite code lives under `tests/`.

## Layout

```
tests/
  cases/
    past-examples.json      # curated from policy-corpus.ts + redteam.ts (170 cases)
    generated-advanced.json # deepseek-pro escalated red-team cases (70 cases)
  docs/
    regression-matrix.md    # Sol escalated: per-tag layer matrix + gap analysis
    threat-coverage.json    # Sol escalated: tag -> threat/control coverage map
  lib/                      # harness, middleware profiles, perf, report, catalog
  scripts/
    import-past-examples.ts # regenerate past-examples.json from the corpus
  suites/                   # one suite per middleware layer + baseline + regression + perf
  scores/                   # JSON scores per suite + summary.json (committed)
  runner.ts                 # CLI entry point
  Dockerfile                # disposable test image
docker-compose.tests.yml    # separate compose for the suite (repo root)
```

## Run

Local (needs `npm ci` at the repo root once):

```bash
npx tsx tests/runner.ts                     # all suites
npx tsx tests/runner.ts --suite baseline    # one suite
npx tsx tests/runner.ts --perf              # operational cost only
npx tsx tests/runner.ts --out /tmp/scores   # custom scores dir
npx tsx tests/scripts/import-past-examples.ts   # re-curate after corpus changes
```

Container (separate compose, builds only the test harness):

```bash
docker compose -f docker-compose.tests.yml up --build
docker compose -f docker-compose.tests.yml run --rm pentest \
  npx tsx tests/runner.ts --suite baseline
```

Scores are written to `tests/scores/<suite>.json` plus `tests/scores/summary.json`
(the `scores` folder `AGENTS.md` requires; it lives under `tests/` because that
is the suite's only writable area). A suite exits non-zero when protected-layer
verdicts fail expectations, so CI can gate on regressions; the baseline suite is
a measurement (everything escapes by design) and does not fail the run.

## Middleware layers under test

| Suite | Profile | What it measures |
| --- | --- | --- |
| `baseline` | `none` | No middleware: the starter-kit escape rate (the before number) |
| `command-policy` | `command-policy` | `evaluateCommand`/`guardedEvaluate` recall, FPR, per-tag coverage |
| `redaction` | `redaction` | `redactCommand`: no protected value survives into evidence |
| `budget` | `budget` | Step budget: real `CodexRunner` behavioral tests (over-budget kill, always-on in monitor mode) |
| `approval` | `approval` | Reviewable-set invariant; only `network-egress-denied` may hold; secret rules never reviewable |
| `monitor` | `monitor` | Shadow mode observes and records without terminating (real runner) |
| `config` | `config` | `REVIEWABLE_RULES` fixed; forbidden review config rejected; fail-closed `guardedEvaluate` |
| `regression` | `all` | Whole stack chained + the project's own `npm test -w @launchpad/server` as a gate |
| `perf` | — | µs per decision (p50/p95/mean), ops/s, scan throughput, redaction cost, config-load cost |

Scoring notes: `redaction`, `budget` and `config` are **not classifiers** —
a `pass` there means no leak / no runaway / invariants hold, not that an attack
was detected. Only `command-policy` (and, through it, `approval`, `monitor` and
`all`) scores detection. See `tests/docs/regression-matrix.md` (Sol) for the
layer-combination analysis.

## Case catalog

Every case is `{ id, command, label, expected, tags[], category, wrapped?,
threatIds?, middleware?, note? }` (see `tests/lib/types.ts`). Tags come from a
closed vocabulary in `tests/lib/tags.ts`: `egress`, `obfuscation`, `encoding`,
`indirection`, `quoting`, `path`, `alternate-channel`, `dns`, `staging`,
`allowlist-abuse`, `env-dump`, `secret-read`, `reverse-shell`, `interpreter`,
`proxy`, `untrusted-fetch`, `benign`, `near-miss`, `wrapper`, `fail-closed`,
`reviewability`, `budget`, `redaction`, `monitor`, `tunnel`.

Sources:

- **past-examples.json** — the project's labeled corpus
  (`apps/server/src/evaluation/policy-corpus.ts`: direct egress, secret reads, reverse
  shells, interpreter egress, evasion, alternate channels, live-observed
  `/bin/bash -lc` wrapped forms, red-team probes, review literals) plus all 56
  named probes from `apps/server/redteam.ts`. This is the "past examples" the
  suite curates: every defect in `docs/POLICY_EVALUATION.md` is represented.
- **generated-advanced.json** — 70 new adversarial cases produced by an
  **escalated deepseek-pro red-team pass** (base64/hex/ANSI-C/octal fully
  encoded payloads, eval chains, xargs decode pipes, here-strings, dotted
  octal/hex IPv4, trailing-dot hosts, encoded interpreter payloads, DNS exfil,
  plus 14 benign near-misses for false-positive probing).

## Current scores (revision 295939c, 231 unique commands)

| Suite | Block rate | Escape rate | False positives | Notes |
| --- | ---: | ---: | ---: | --- |
| baseline | 0.0% | 100.0% | 0.0% | no middleware |
| command-policy | 89.1% | 10.9% | 5.4% | 19 escapes: fully-encoded commands, dotted octal/hex IPv4, trailing-dot hosts, eval chains, encoded interpreters; 3 FPs incl. the documented build-constant URL |
| redaction | — | — | — | 100% of cases leak-free |
| budget | — | — | — | over-budget run terminated; budget enforced in monitor mode |
| approval | — | — | — | reviewable-set invariants hold; secret rules never reviewable |
| monitor | — | — | — | shadow mode observes without terminating; config rejects unknown modes |
| config | — | — | — | invariants hold; fail-closed verified |
| regression | 89.1% | 10.9% | 5.4% | whole stack ≈ command-policy recall + disposition; server test gate passed |

The gap between baseline (100% escape) and protected (~11% escape) is the
middleware's measured contribution; the residual escapes are the documented
text-only-detector limits the escalated cases quantified — see
`tests/docs/regression-matrix.md` and `tests/scores/command-policy.json` for
the per-case verdicts. A note on honesty: the catalog is authored by us and by
the escalated models, so these are corpus numbers, not a real-world bypass
rate — exactly as `docs/POLICY_EVALUATION.md` frames the project's own
benchmarks.

## Escalation trail

Per the working instructions, harder reasoning was escalated:

- **deepseek pro** (`deepseek-v4-pro`) — generated the adversarial bypass
  corpus in `tests/cases/generated-advanced.json`.
- **Sol** (`openai/gpt-5.6-sol`) — cross-field (security × systems ×
  measurement) design of the whole-stack regression matrix and the
  tag→threat/control coverage map in `tests/docs/`.

## Notes / hardlines respected

- Only `tests/` (plus the separate `docker-compose.tests.yml`) is written by
  this suite; no frontend or backend code is modified — the suite is a
  black-box pentest harness, not a fix.
- Middleware is server-side: the suite never exercises a user-facing toggle;
  the layers are reached through their real code paths (imported functions and
  the real `CodexRunner`).
