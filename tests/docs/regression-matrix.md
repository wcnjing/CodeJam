# Sentinel whole-stack regression and operational-cost matrix

## Scope and interpretation

This matrix describes the current **command-text middleware**, not a network sandbox. The enforcing chain represented by the suite is `command-policy -> approval classification -> redaction -> budget`; `monitor` is an alternative shadow-mode disposition and `config` supplies invariants. A tag is a test family, so “partial” means at least one important form in that family escapes or the family mixes malicious and benign cases.

Threat shorthand: **T1** = TM-AGENT-001, **T2** = TM-AGENT-002, **T3** = TM-AGENT-003, **T4** = TM-AGENT-004, **T5** = TM-AGENT-005, **T6** = TM-AGENT-006.

## Per-tag regression matrix

| Tag | Individual layer(s) that must catch/contribute | Whole-stack requirement | Current detector coverage / gap | Threats |
|---|---|---|---|---|
| `egress` | command-policy deny; approval may hold only destination-only `network-egress-denied`; redaction sanitises evidence | deny, or hold only reviewable non-secret egress | **Partial.** Literal recognised tool + explicit non-allowlisted host is covered. Implicit destinations such as a preconfigured `git push` or default package registry are not resolved; fully encoded forms escape. | T1, T2, T5 |
| `obfuscation` | command-policy classifier; approval/redaction act only after detection | deny | **Partial.** Destination-based URL handling catches hidden tool names when the host remains literal. Host/tool/secret fully encoded or assembled can escape. | T1, T2, T3 |
| `encoding` | command-policy | deny | **Gap.** Visible destinations or protected paths are caught, but fully base64/hex/ANSI-C/octal encoded commands have no detector-visible signal and are allowed. Requires network-layer default-deny or safe decoding/AST mediation. | T1, T2, T3 |
| `indirection` | command-policy | deny | **Partial.** Literal URL/host or protected path survives many variable/eval/IFS tricks; constructing both destination and sensitive reference at runtime escapes. | T1, T2, T3 |
| `quoting` | command-policy | deny | **Partial.** Quote-split tool with literal URL is caught and wrapper quote boundaries are handled. Quoting combined with an encoded/constructed host escapes. | T1, T3 |
| `path` | command-policy | deny for attacks; allow benign paths | **Partial.** Absolute tool paths, wrappers, visible protected paths, `/dev/tcp` and `/dev/udp` are covered. Generic traversal/symlink semantics are not resolved; an encoded path can escape. | T1, T2, T3 |
| `alternate-channel` | command-policy; approval for reviewable destination-only egress | deny/hold | **Partial.** Enumerated VCS/package/TLS/DNS/socket tools with explicit destinations are covered. Implicit destinations and encoded hosts remain gaps. | T1, T2, T3, T5 |
| `dns` | command-policy | deny | **Partial.** `dig`, `nslookup`, and `host` with a literal external suffix are caught. Runtime-built resolver names/hosts are not reliably visible; there is no network DNS policy. | T1, T2, T3 |
| `staging` | command-policy protected-secret rule; redaction protects evidence | deny | **Partial.** Staging that visibly names `.secrets`, `customer-db-url`, private keys, or credential files is denied. Renamed/encoded sources, prior aliases, and semantic data-flow across commands are not tracked. | T1, T2, T3 |
| `allowlist-abuse` | command-policy host extraction; approval may hold | deny/hold | **Partial.** URL userinfo, deceptive subdomains, ordinary IPv6 and decimal IPv4 are generally extracted. Dotted octal/hex, trailing-dot bare hosts, resolver rebinding, redirects, and DNS changes are not normalized or followed. | T1, T2, T3, T5 |
| `env-dump` | command-policy; redaction for recorded expanded values | deny a full dump or dump+egress; allow filtered/single-variable use | **Partial.** Bare `printenv`/`env`, `/proc/self/environ`, and recognised dump+egress are covered. Other producers such as `export`, shell tracing, interpreter enumeration, or encoded forms are not comprehensively classified. | T1, T2 |
| `secret-read` | command-policy hard deny; redaction sanitises evidence; config forbids approval | deny | **Partial.** A fixed literal set is covered. Unknown secret files, indirect paths, aliases, decoded names, and content-based discovery are outside the detector. | T1, T2 |
| `reverse-shell` | command-policy; approval only when result is merely `network-egress-denied` | deny | **Partial.** Named clients and literal `/dev/tcp|udp` destinations are covered. Fully encoded reverse shells and uncommon/implicit channels escape. | T1, T2, T3 |
| `interpreter` | command-policy | deny malicious network one-liners; allow local interpreter work | **Partial.** Listed Python/Node/Perl/Ruby/PHP/Deno signatures plus literal destinations are covered. Encoded payloads, dynamic imports/member access, other runtimes, and constructed destinations escape. | T1, T2, T3 |
| `proxy` | command-policy; approval may hold | deny/hold | **Covered for current literal corpus, but structurally partial.** Literal attacker proxy URLs are extracted. Inherited proxy environment, config files, PAC/redirect behavior, and encoded/constructed proxy endpoints are invisible. | T1, T2, T3, T5 |
| `untrusted-fetch` | command-policy; approval may hold | deny/hold | **Partial.** Explicit non-allowlisted fetch URL is covered. Fully encoded fetchers, implicit package/VCS destinations, redirects, and allowlisted-host compromise are not. | T1, T2, T3, T5 |
| `benign` | command-policy must not deny; other layers must add no harmful disposition | allow | **Partial.** Most benign work is allowed, but destination-based matching knowingly over-blocks `npm run build -- --base https://cdn.example.com/assets`; false-positive monitoring remains required. | T1, T5 |
| `near-miss` | command-policy precision check | allow | **Partial.** Textual URL carve-outs and code-object/filename filters cover many cases, but the build-constant URL remains a known false positive and heuristics can regress. | T1, T3, T5 |
| `wrapper` | command-policy must classify wrapped inner command | match inner command: deny/hold attack, allow benign | **Covered for current wrapper corpus.** Quote characters were added to boundaries. This does not solve opaque nested payloads. | T1, T2, T3 |
| `fail-closed` | guarded command-policy + config invariant | deny on evaluator error | **Covered.** `guardedEvaluate` converts throws to `policy-error`; wiring tests remain essential. | T1, T2 |
| `reviewability` | command-policy emits rule; approval classifies; config fixes the reviewable set | hold only `network-egress-denied`; hard-deny secret and policy errors | **Covered for rule invariants.** Only `network-egress-denied` is reviewable. Residual operational gap: approver is a free-text label and automation bias is unbounded. | T2, T5 |
| `budget` | budget | deny/terminate after command count exceeds configured maximum | **Covered for step count, partial for resource risk.** A single expensive command, token spend, subprocess fan-out, and long wall time are not bounded by this counter. | T4 |
| `redaction` | redaction | observe/store evidence with no known secret, URL password, or matched high-entropy token | **Partial.** Known values, URL credentials, and selected high-entropy strings are masked. Short, low-entropy, transformed, chunked, or previously unknown secrets can survive; retention is also unbounded. | T1, T2, T6 |
| `monitor` | command-policy detects; monitor records without termination; redaction sanitises evidence | observe, not block | **Covered as shadow semantics, not prevention.** A detected attack proceeds by design; undetected attacks produce no observation. Budget remains enforcing. | T1, T2, T3, T4 |
| `tunnel` | command-policy; approval may hold destination-only tunnels | deny/hold | **Partial.** Literal SSH forwarding and explicit proxy endpoints are covered. Encoded endpoints, inherited config, alternate tunnel programs, and implicit destinations remain gaps. | T1, T2, T3, T5 |

## Layer-combination analysis

| Layer | Can contribute | Cannot contribute / scoring implication |
|---|---|---|
| `command-policy` | Classifies literal command text; hard-denies protected reads/exfiltration; flags explicit non-allowlisted destinations; fails closed through `guardedEvaluate`. | Does not execute shell expansion, decode arbitrary payloads, resolve DNS/redirects/configured remotes, inspect process behavior, or enforce the network. Its recall is the stack's classification ceiling today. |
| `redaction` | Limits secondary disclosure in stored/API/UI evidence after a violation is found. This is defense in depth for T2/T6 and operations. | **Not a classifier and not an authorizer.** Redaction alone should report `n/a`, not be penalized for allowing an attack. It also cannot repair a policy miss because the whole-stack profile redacts only detected violations. |
| `budget` | Stops runaway command counts regardless of enforce/monitor mode. Complements policy for T4 even when every command is individually benign. | **Not a classifier.** One malicious command is below budget; a single expensive command remains possible. A per-case allow is correct unless a multi-command behavioral test exceeds the limit. |
| `approval` | Converts only reviewable `network-egress-denied` outcomes into a human hold and run-scoped host decision; preserves hard blocks for secrets. | It depends on a policy violation first. A miss cannot be held. It must not be scored as an independent detector, and it cannot approve `secret-exfiltration`, `protected-secret-access`, or `policy-error`. |
| `monitor` | Runs the policy in shadow mode and records redacted observations for tuning, drift, and false-positive measurement. | It deliberately does not prevent effects. “Detected” in the monitor profile means **observed**, not contained; undetected payloads are silent. |
| `config` | Locks `REVIEWABLE_RULES`, rejects unsafe review configuration, and verifies fail-closed behavior at startup/test time. | Not a per-command content classifier. Passing every case with `n/a` is correct if invariants hold. Config cannot compensate for missing detector semantics. |
| `all` | Chains policy, approval classification, redaction, and budget disposition. A policy hit can therefore become hard deny or hold with safe evidence; budget independently bounds long runs. | There is no independent second classifier or network-layer deny. Consequently A+B helps with **disposition, evidence, and resource bounds**, not opaque-command recall: policy miss + redaction/approval/monitor/budget still permits a one-step bypass. |

Important combinations:

1. **Policy + redaction:** policy stops a recognised attack; redaction prevents the denied command itself from becoming a credential leak. Either alone leaves a different failure mode.
2. **Policy + approval:** policy classifies explicit non-secret egress and approval can hold it. Secret-bearing rules remain hard-denied. If encoding defeats policy, approval never runs meaningfully.
3. **Policy + monitor:** useful for deployment measurement and false-positive discovery, but containment is intentionally zero. Never merge monitor “detections” with enforce-mode prevention rates.
4. **Budget + any mode:** catches a long sequence that content policy permits and still enforces in monitor mode. It cannot catch the encoded one-command residual.
5. **Config + approval/policy:** prevents configuration from making secret access reviewable and ensures evaluator failure denies. It does not add attack-family recall.

## Measurement design and conservative regression gates

Use pinned hardware/runtime, a warm-up phase, isolated CPU where practical, fixed corpus/command-length distribution, and enough samples to bootstrap confidence intervals. Record raw samples and compare both an absolute sanity ceiling and a relative baseline. Microbenchmarks below exclude model/container/network time; they are guidance, not tight production SLAs.

| Middleware/path | Metrics that matter | Suggested flag (guidance) |
|---|---|---|
| command-policy decision | p50, p95, mean µs/decision; decisions/s; cost by short/mid/long command | Flag p95 **>250 µs** as a sanity failure, mean **>100 µs**, or p95/mean **>2x** a stable baseline with >10 µs absolute increase. Watch long-command slope; superlinear growth or long-bucket mean >3x mid-bucket is suspicious. Thresholds re-scaled from the capability engine's measured cost (merged tree: mean ~45 µs, p95 ~122 µs on one machine) — size against the slowest machine and list it in the test before relying on the flag. |
| `scanCommands` runner hot path | per-command scan cost, batch wall time, commands/s, allocation/heap growth | Flag mean **>100 µs/command**, throughput **<10,000 commands/s** in the isolated JS benchmark, >2x baseline regression, or batch cost inconsistent with linear command count. The summary's scan p95 is a real per-run distribution (one sample per streamed batch), not a copied mean. |
| redaction | p50/p95/mean µs per command, bytes/s, cost versus command length and secret-list length, leak rate | Flag any known-secret leak immediately; otherwise p95 **>100 µs**, >2x baseline, or nonlinear scaling. Add adversarial long/high-entropy strings to expose regex backtracking. |
| approval classification | local classification latency plus, separately, human hold duration, queue depth, approval/denial/override rates | Code-path p95 **>250 µs** is a sanity warning (same engine path as command policy); operationally alert on growing queue, p95 hold time beyond the operator SLO, or unusual approval-rate/approver concentration. Human time must not be folded into command-policy latency. |
| budget | counter/check p50/p95, termination overshoot (commands observed beyond N), termination propagation latency | Flag any overshoot beyond the documented `> N` semantics, any monitor-mode bypass, or local p95 **>20 µs**. Measure wall-clock kill latency end-to-end separately. |
| monitor/evidence | observation p50/p95, events/s, dropped-event rate, persistence latency, store growth bytes/run | Flag any dropped detected observation or unredacted evidence; warn at >2x latency baseline. Capacity-gate sustained ingest and alert on unbounded growth because TM-OPS-001 remains open. |
| config startup | load time mean/p95, failure rate, startup RSS; cold and warm separately | Flag invalid safety config being accepted immediately; performance warning if warm mean **>1 ms**, cold p95 **>10 ms**, or >2x baseline. This is startup cost, not per-command overhead. |
| whole stack | p50/p95/mean per decision, decisions/s, containment/hold/allow rates, redaction leak rate | Flag any expected hard denial becoming allow/hold, any secret rule becoming reviewable, any known secret leak, p95 **>250 µs**, or >2x stable baseline. |

### Measurement validity cautions

- Report **accuracy and cost together**: optimizing latency by skipping scans is a security regression.
- Separate benign and malicious paths; denied commands invoke evidence redaction and can cost more.
- Measure command-length and secret-list scaling, not only corpus averages.
- Treat p95 from per-operation samples as meaningful only after warm-up; the `scanCommands` entry now reports a real per-run p95, while `loadConfig` is a single batch measurement that still repeats its mean as p50/p95 and does not estimate tails.
- Add an end-to-end side-effect test: decision latency alone does not prove termination occurs before network transmission.
