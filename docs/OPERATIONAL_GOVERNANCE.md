# Operational governance: where this control stands

Operational guardrails are the ones that decide what happens *after* deployment
— not principles like "fairness," but controls over oversight, monitoring,
incidents, and authority. This document maps the Kill Switch honestly against
that lens, crediting real coverage and naming the gaps.

## Coverage

| Operational control | Status | Where |
| --- | --- | --- |
| **Agent authority limits** | **Strong.** Recognisable-egress denial (a command-text guard, not a network allowlist), scoped allowlist for known destinations, container + policy sandboxing, execution limits, tested prompt-injection and obfuscation resistance, and — now — human approval before a reviewable action proceeds. | `command-policy.ts`, both runners, `resolveApproval` |
| **Meaningful human oversight** | **Implemented.** A held run gives a named human the exact command and reason, with authority to deny or grant a scoped exception. Override data (who, when, why) is recorded to detect rubber-stamping. | `ApprovalRequest`, `resolveApproval`, held-run UI |
| **Incident & near-miss handling** | **Strong.** Enforced denials are incidents; monitor-mode observations are recorded near-misses; evidence is redacted and preserved; rollback (container destroyed, workspace intact) is automatic. | `policyEvents` (`enforced` flag), monitor mode |
| **Explicit use boundaries** | Partial. Tool/host boundaries enforced at the Runtime; not yet re-triggered on environment change (see gaps). | allowlist, `.secrets/`, `AGENTS.md` |
| **Change-management triggers** | Partial. CI ratchets fail on policy-rule regressions. But the policy's correctness depends on the Runtime image's toolset (curl absent, node present) and the model — neither is a governed trigger. | `policy-eval.test.ts` |
| **Data & log governance** | Strong. Redaction is enforced before storage/display, and `policyEvents`/resolved `approvals` are now pruned past `AUDIT_RETENTION_DAYS` on every store write. Access/deletion controls beyond retention are still out of scope for the POC. | `redactCommand`, `JsonStore.prune` |
| **Post-deployment monitoring** | Partial. The substrate exists (persisted decisions, enforce-vs-monitor, override records); no drift/subgroup/rate dashboard yet. | `policyEvents`, `approvals` |
| **Appeal & redress** | Partial. The approval workflow is a structured reconsideration path for a held run — reviewable egress, an unresolved write target, or an exceeded step budget (one continuation with a raised ceiling). There is no path for an already-hard-blocked run. | `resolveApproval` |
| **Supply-chain, decommissioning, independent challenge** | Minor / out of scope. Pinned runtime image and `POLICY_ENFORCEMENT` off-switch exist; the rest is contractual or organizational, not a POC concern. | `Dockerfile.runtime`, config |

## The design choice that makes approval safe

Not every denial is reviewable. The reviewable set — egress to a
plausibly-legitimate destination (`network-egress-denied`, and its implicit
form `network-egress-denied-implicit`), a write whose destination the command
text cannot settle (`file-write-unresolved-target`), and an exceeded step
budget (`step-budget-exceeded`) — is exactly where a human plausibly knows
something the engine does not, or the agent is compounding a mistake rather
than attacking. `secret-exfiltration`, `protected-secret-access` and
`file-write-outside-workspace` are **always hard-denied and never subject to
approval**, so no operator can be socially-engineered or fatigued into waving
through the theft of a protected secret or a write past the sandbox boundary.
The reviewable set is `POLICY_REVIEW_RULES`, defaulting to
`network-egress-denied,network-egress-denied-implicit,file-write-unresolved-target,step-budget-exceeded`;
removing `step-budget-exceeded` restores the old hard terminate for runaway
runs.

That third rule is why the container runner declares `/tmp` and `/var/tmp` as
write roots alongside `/workspace`: its container is `--rm` with two bind mounts,
so a scratch write there escapes nothing, and a rule with no appeal path must not
kill an ordinary run over `git diff > /tmp/patch.diff`. The host-process runner,
where `/tmp` is the real host `/tmp`, declares only the workspace path.

The granted exception is **scoped to the exact hosts named and consumed by a
single run** — proven live: after an approval let one task reach the npm
registry, the next task to the same registry was held again. Approval is never
a standing allowlist change. The same discipline now covers the step budget:
an approval grants a **run-scoped ceiling raise** (limit + observed) on the
one continuation run, so approving a runaway never lowers the standing
`POLICY_MAX_COMMANDS` for the next task — and a continuation that exceeds even
the raised ceiling is hard-terminated, because a second miss was an approval
the human already made and regretted.

## Named, honest gaps

1. **No access control on the audit store.** `policyEvents` and `approvals` are
   now time-bounded (`AUDIT_RETENTION_DAYS`), but who can *read* the store once
   it's persisted is still ungoverned — this POC has no access-control layer.
2. **Ungoverned environment changes.** The policy assumes a specific runtime
   image and model. Adding `curl` to the image, or swapping the model, shifts the
   risk surface with nothing to re-trigger evaluation.
3. **Authenticated, not authorized.** "Approver" is now an authenticated
   principal resolved from the credential (`APP_PRINCIPALS`), so a decision can
   no longer be recorded under a name the decider simply typed. What remains is
   authorization: every principal may approve every held run, including one its
   own request caused, and the registry is static — no roles, no rotation, no
   segregation of duties.
4. **Hard-blocked runs have no appeal.** Only held (reviewable) runs can be
   reconsidered; a `secret-exfiltration`, `protected-secret-access` or
   `file-write-outside-workspace` block is final by design.
5. **The write boundary is enforced by tool name, not destination.**
   `file-write-outside-workspace` is a governance claim (no operator may approve
   it) resting on a detector that inspects only redirects and
   `cp`/`mv`/`tee`/`rm`/`mkdir`; `touch`, `dd`, `sed -i`, `install`, `ln`,
   `chmod` and interpreter writes are not seen. The authority limit is real; its
   coverage is first-pass. Recorded as unreduced residual likelihood on
   TM-AGENT-007 rather than as a solved control.
